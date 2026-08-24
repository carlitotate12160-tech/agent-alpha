"""Origin-flank reach primitives (§12.46 / §12.61) — extracted from ``scout.py``.

An external red team facing a CDN/WAF edge does not brute the edge; it flanks to the
origin (§12.61). These primitives are that flank, lifted out of ``Alpha`` so
``scout.py`` stays under the GAP-161 size ratchet (anti-#8 god object, §12.47) while the
autonomous OODA loop keeps orchestrating them:

- ``resolve_authorized_origin`` — per-host cached candidate → PROVE-bind (ownership-token
  canary via ``resolve_and_bind_origin``); fail-closed to ``[]``.
- ``origin_direct_probe`` — §12.46-gated origin-direct dispatch over the bound origins.
- ``attempt_reach_transport_dead`` — the transport-dead front-door entry (the niagamas
  lesson): a root connect/read timeout is the origin-direct PRECONDITION, not an abort.
- ``fingerprint_flank`` — §12.67-S1 lazy origin-flank for service headers when the edge
  gave no version-bearing product (CF-passthrough). Consent fail-closed.
- ``maybe_fingerprint_flank`` — trigger wrapper called by ``_detect_service_evidence``;
  checks CVE-eligibility + edge-fronted + bounded guard, then delegates to
  ``fingerprint_flank``. Keeps ``scout.py`` to ~2 lines (anti-#8).

They are Alpha *collaborators* (they read/emit through the injected Alpha recon context —
``event_store``, ``_bound_origin``, ``_origin_discovery``, ``_engagement_profile``,
``_emit``, ``_reach_attempted``), mirroring the existing ``fingerprint.seed_fingerprint_first``
seam — NOT a second reach path (anti-#6). ``scout._attempt_reach`` and
``fingerprint.seed_fingerprint_first`` both delegate here; there is exactly one origin
binding and one origin-direct dispatch in the codebase.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlparse

from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import ServiceProperties
from agent_alpha.recon.origin_binding import resolve_and_bind_origin
from agent_alpha.recon.reach_strategy import is_cloudflare_ip
from agent_alpha.recon.reach_transport import origin_direct_fetch
from agent_alpha.recon.response_classifier import Verdict, classify_response


class _ReachResponse:
    """Adapter so origin-direct / browser_solve results feed into the existing
    OBSERVE→ORIENT→ACT flow which expects ``.status_code`` / ``.text`` / ``.headers``.

    NOT a reimplementation of reach (anti-#6) — just a response-shaped wrapper so the rest
    of ``_step_once`` can consume the reach result unchanged.
    """

    __slots__ = ("status_code", "text", "headers", "origin_ip")

    def __init__(
        self,
        status_code: int,
        body: str,
        headers: dict[str, str],
        origin_ip: str = "",
    ) -> None:
        self.status_code = status_code
        self.text = body
        self.headers = headers
        self.origin_ip = origin_ip


def resolve_authorized_origin(alpha: Any, host: str) -> list[str]:
    """Resolve authorized origin IPs for ``host`` (per-host cached, §12.46).

    BOTH the response-blocked path and the transport-dead path reuse this ONE binding —
    no duplicate origin path (anti-#6). resp-independent: needs only ``host``.

    Candidates are filtered against signed authorized_origins (C9: candidate ≠
    authorization) AND Cloudflare edge IPs are dropped (hitting CF edge with a Host header
    is NOT origin-direct). §12.46 discovery path PROVE-binds one candidate via the
    ownership-token canary (``resolve_and_bind_origin`` emits ORIGIN_BINDING_PROVEN).
    Fail-closed: returns ``[]`` when nothing binds.

    PER-HOST cache (perf + opsec): discovery (crt.sh, 30s timeout when down) + token-canary
    binding are IDENTICAL for every path on the same host — including the empty "tried,
    nothing authorized" negative case. Mirrors the _reach_class cache.
    """
    if alpha._engagement_profile is None:
        return []

    cached_origins = alpha._bound_origin.get(host)
    if isinstance(cached_origins, list):
        return cached_origins

    authorized_origins_list: list[str] = []
    if alpha._origin_discovery is not None and getattr(
        alpha._engagement_profile, "authorized_origins", None
    ):
        # Static/cooperative path: client pre-signed the origin IPs.
        candidates = alpha._origin_discovery.candidates(host)
        authorized_origins_list = [
            ip
            for ip in candidates
            if ip in alpha._engagement_profile.authorized_origins
            and not is_cloudflare_ip(ip)  # CF edge IPs are not valid origins
        ]

    # §12.46 discovery path: no pre-signed origin, but the signed profile consented to
    # allow_origin_discovery → discover candidates and PROVE-bind one (ownership-token
    # canary). Fail-closed: [] (no reach) when nothing binds.
    if (
        not authorized_origins_list
        and alpha._origin_discovery is not None
        and getattr(alpha._engagement_profile, "allow_origin_discovery", False)
    ):
        bound_ip = resolve_and_bind_origin(
            fronted_host=host,
            profile=alpha._engagement_profile,
            event_store=alpha.event_store,
            engagement_id=alpha._engagement_id,
            discovery=alpha._origin_discovery,
        )
        if bound_ip is not None:
            authorized_origins_list = [bound_ip]

    alpha._bound_origin[host] = authorized_origins_list
    return authorized_origins_list


def origin_direct_probe(
    alpha: Any, url: str, host: str, authorized_origins_list: list[str]
) -> _ReachResponse | None:
    """Origin-direct dispatch over ``authorized_origins_list`` (§12.46-gated).

    Every origin passes the composed auth gate (``assert_origin_authorized_or_bound``)
    BEFORE any fetch — a gate RAISE is an honest block (returns None), never an
    engagement-killing exception (GAP-040). Returns the first useful (non-block,
    non-redirect/404) origin body, else the last response seen, else None. resp-independent:
    strategy is already decided.
    """
    if alpha._engagement_profile is None:
        return None

    # Request-target = path + query. origin_direct_fetch builds https://<ip><target>,
    # so passing path ALONE drops the query and yields a false negative on
    # /path?token=... (Sourcery/Qodo). Carry the full request-target from `url`.
    _p = urlparse(url)
    request_target = _p.path + (f"?{_p.query}" if _p.query else "")
    # Audit MUST NOT persist secrets: query VALUES can be tokens/keys and the event store
    # is append-only (Qodo HIGH). Redact values, KEEP keys, for the audit event only —
    # the full request_target above is used for the fetch, never stored.
    audit_target = _p.path
    if _p.query:
        _keys = [k for k, _ in parse_qsl(_p.query, keep_blank_values=True)]
        audit_target = f"{_p.path}?" + "&".join(f"{k}=REDACTED" for k in _keys)

    from agent_alpha.conductor.engagement_profile import (
        OriginNotAuthorizedError,
        assert_origin_authorized_or_bound,
    )

    last_response: _ReachResponse | None = None
    last_ip = ""
    for origin_ip in authorized_origins_list:
        last_ip = origin_ip
        # §12.46 composed gate — fail-closed. Authorizes iff the IP is in the signed
        # authorized_origins OR (allow_origin_discovery AND an ORIGIN_BINDING_PROVEN
        # event exists for this IP + fronted host).
        try:
            assert_origin_authorized_or_bound(
                origin_ip,
                host,
                alpha._engagement_profile,
                alpha.event_store,
                alpha._engagement_id,
            )
        except OriginNotAuthorizedError:
            alpha._emit(
                "OBSERVE",
                f"Reach: ORIGIN_DIRECT refused by auth gate for {host} — honest block",
            )
            return None

        # audit_target (query VALUES redacted) in narration too — the monologue stream
        # must not carry secrets any more than the event store does.
        alpha._emit(
            "OBSERVE",
            f"Reach: ORIGIN_DIRECT for {audit_target} via {origin_ip}",
        )

        # Audit event (origin-direct bypasses WAF — audit-sensitive)
        alpha.event_store.append(
            EventType.ORIGIN_DIRECT_ATTEMPT,
            alpha._engagement_id,
            "alpha",
            {
                "host": host,
                "origin_ip": origin_ip,
                "authorized": True,
                "discovered_via": "origin_discovery",
                # GAP-196: sub-paths are origin-directed too — audit WHICH request-target
                # was flanked, not just the host (per-path coverage honesty, anti-#3).
                # Query VALUES redacted (keys kept) — never persist secrets (Qodo HIGH).
                "path": audit_target,
            },
        )

        try:
            result = origin_direct_fetch(host, origin_ip, request_target)
        except RuntimeError:
            alpha._emit(
                "OBSERVE",
                f"Reach: origin_direct_fetch failed for {audit_target} via {origin_ip}",
            )
            continue

        candidate = _ReachResponse(
            status_code=result.status_code,
            body=result.body,
            headers=dict(result.headers),
            origin_ip=origin_ip,
        )
        last_response = candidate

        origin_verdict = classify_response(
            status_code=candidate.status_code,
            body=candidate.text,
            headers=dict(candidate.headers),
        )

        # Useful = real content, not a WAF block, not a redirect/not-found
        if origin_verdict not in (Verdict.BLOCKED, Verdict.CHALLENGE) and (
            candidate.status_code not in (301, 302, 303, 307, 308, 404)
        ):
            return candidate

    # No origin returned useful content — return the last response seen (honest: caller
    # re-classifies; a 404/redirect is still non-block evidence) or None.
    if last_response is not None and not last_response.origin_ip:
        last_response.origin_ip = last_ip
    return last_response


def attempt_reach_transport_dead(
    alpha: Any, url: str, *, require_bound: bool = False
) -> _ReachResponse | None:
    """Front-door transport-dead (no resp) → origin-flank (§12.61).

    A root front-door connect/read timeout is the origin-direct PRECONDITION, not an abort:
    the edge is stonewalling at transport, so pivot to the discovered origin instead of
    marking the host dead (the niagamas lesson). Reuses the SAME binding
    (``resolve_authorized_origin``) and the SAME §12.46-gated dispatch
    (``origin_direct_probe``) as the response-blocked path — no 2nd reach path (#6).

    ``require_bound`` (sub-path caller, GAP-196): route origin-direct ONLY when the host
    ALREADY has a cached binding — a sub-path must never TRIGGER fresh discovery/binding
    (crt.sh + canary). Binding is a host-level decision owned by the ROOT flank; sub-paths
    only ride the cache. Without this a sub-path could kick off discovery (Qodo).

    Fail-closed: returns None when no candidate binds (stale/co-tenant) or the profile did
    not consent to discovery — the caller then marks the host dead / non-analyzable as
    before. Bounded: one attempt per url (shared ``alpha._reach_attempted``).
    """
    # No engagement profile → no reach deps → honest block (mirror _attempt_reach).
    if alpha._engagement_profile is None:
        return None

    host = urlparse(url).hostname or urlparse(url).netloc

    # Sub-path: reuse an EXISTING per-host binding ONLY; never trigger fresh discovery.
    # Checked BEFORE consuming the one-shot so an unbound host stays retryable at its root.
    # skipcq PYL-W0212: origin_reach is a declared Alpha reach-collaborator (module
    # docstring) — same tolerated `alpha._<state>` seam as fingerprint.seed_fingerprint_first.
    if require_bound and not alpha._bound_origin.get(host):  # skipcq: PYL-W0212
        return None

    if url in alpha._reach_attempted:  # skipcq: PYL-W0212
        return None
    alpha._reach_attempted.add(url)  # skipcq: PYL-W0212

    origins = resolve_authorized_origin(alpha, host)
    if not origins:
        return None  # fail-closed: nothing bound → caller abandons the host

    # Strategy is KNOWN = ORIGIN_DIRECT (no resp to classify_mitigation/choose_reach).
    # The §12.46 auth gate is enforced INSIDE origin_direct_probe.
    return origin_direct_probe(alpha, url, host, origins)


# ── §12.67-S1: fingerprint-flank (lazy origin headers on CF-passthrough) ─────


def is_edge_fronted_host(alpha: Any, host: str, resp: Any) -> bool:
    """True when *host* is behind a CDN/WAF edge.

    Three-signal detection (no target hostname literal — Universal-by-Design):
    1. Graph ``asset:{host}`` has ``cf_protected=True`` (NS-hint confirmed vendor).
    2. Graph ``asset:{host}`` has ``edge_fronted=True`` (behaviourally proven, GAP-197).
    3. Current response ``Server`` header matches a ``CDN_IDENTITY_SERVERS`` entry.
    """
    from agent_alpha.recon.service_fingerprint import CDN_IDENTITY_SERVERS

    asset_node = alpha.graph_store.get_node(f"asset:{host}")
    if asset_node is not None:
        props = asset_node.properties
        if getattr(props, "cf_protected", False) or getattr(props, "edge_fronted", False):
            return True

    server = (getattr(resp, "headers", {}).get("server") or "").lower()
    return any(edge in server for edge in CDN_IDENTITY_SERVERS)


def fingerprint_flank(alpha: Any, host: str, url: str) -> list[Any]:
    """§12.67-S1 + §12.61: edge gave no version-bearing service → flank to origin
    for the real stack headers.  Consent fail-closed (§12.46); returns ``[]`` on
    unbound/unreachable.  Headers/cookies/CSP only — no body/frontier analysis
    on the origin response.

    Emits FINGERPRINT_FLANK_ATTEMPTED on every exit (§12.64 / §8o-1) so the event
    stream, not the graph alone, is the machine-readable proof of the flank."""
    engagement_id = alpha._engagement_id  # skipcq: PYL-W0212
    origins = resolve_authorized_origin(alpha, host)
    if not origins:
        alpha._emit(  # skipcq: PYL-W0212
            "OBSERVE",
            f"S1 fingerprint-flank: {host} edge-only (origin unbound/unconsented); "
            "coverage note: edge-only fingerprint, origin unreachable",
        )
        alpha.event_store.append(  # skipcq: PYL-W0212
            EventType.FINGERPRINT_FLANK_ATTEMPTED,
            engagement_id,
            "alpha",
            {
                "host": host,
                "outcome": "origin_unbound",
                "origin_ip": "",
                "products": [],
            },
        )
        return []

    parsed = urlparse(url)
    root_url = f"{parsed.scheme}://{parsed.hostname}/"
    origin_resp = origin_direct_probe(alpha, root_url, host, origins)
    if origin_resp is None:
        alpha._emit(  # skipcq: PYL-W0212
            "OBSERVE",
            f"S1 fingerprint-flank: {host} origin probe returned None; "
            "coverage note: edge-only fingerprint, origin unreachable",
        )
        alpha.event_store.append(  # skipcq: PYL-W0212
            EventType.FINGERPRINT_FLANK_ATTEMPTED,
            engagement_id,
            "alpha",
            {
                "host": host,
                "outcome": "origin_unreachable",
                "origin_ip": origins[0] if origins else "",
                "products": [],
            },
        )
        return []

    from agent_alpha.recon.service_fingerprint import get_merged_service_nodes

    flank_nodes = get_merged_service_nodes(origin_resp, url)
    outcome = "minted" if flank_nodes else "no_new_service"
    products = []
    for n in flank_nodes:
        props = n.properties
        assert isinstance(props, ServiceProperties)
        products.append({"name": props.name, "version": props.version})
    alpha.event_store.append(  # skipcq: PYL-W0212
        EventType.FINGERPRINT_FLANK_ATTEMPTED,
        engagement_id,
        "alpha",
        {
            "host": host,
            "outcome": outcome,
            "origin_ip": getattr(origin_resp, "origin_ip", ""),
            "products": products,
        },
    )
    return flank_nodes


def maybe_fingerprint_flank(alpha: Any, resp: Any, url: str, nodes: list[Any]) -> list[Any]:
    """Trigger wrapper for ``fingerprint_flank`` (§12.67-S1).

    Called by ``scout._detect_service_evidence``.  Checks:
    1. No CVE-correlation-eligible (version-bearing) node in *nodes*.
    2. Host is edge-fronted (3-signal: cf_protected / edge_fronted / Server CDN).
    3. Host not already fingerprint-flanked this run (``alpha._fp_flanked``).

    Returns *nodes* **merged** with origin nodes (edge info kept), or *nodes*
    unchanged when no flank is needed/possible.
    """
    from agent_alpha.recon.service_fingerprint import is_cve_correlation_eligible

    if any(is_cve_correlation_eligible(n.properties) for n in nodes):
        return nodes  # edge already has version-bearing signal → no flank needed

    host = urlparse(url).hostname or urlparse(url).netloc
    if not host or host in alpha._fp_flanked:  # skipcq: PYL-W0212
        return nodes

    if not is_edge_fronted_host(alpha, host, resp):
        return nodes

    alpha._fp_flanked.add(host)  # skipcq: PYL-W0212  — bounded: one attempt per host
    flank_nodes = fingerprint_flank(alpha, host, url)
    return nodes + flank_nodes  # MERGE: keep edge product info, append origin
