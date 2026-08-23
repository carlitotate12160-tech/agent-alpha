"""Origin-flank reach primitives (§12.46 / §12.61) — extracted from ``scout.py``.

An external red team facing a CDN/WAF edge does not brute the edge; it flanks to the
origin (§12.61). These three primitives are that flank, lifted out of ``Alpha`` so
``scout.py`` stays under the GAP-161 size ratchet (anti-#8 god object, §12.47) while the
autonomous OODA loop keeps orchestrating them:

- ``resolve_authorized_origin`` — per-host cached candidate → PROVE-bind (ownership-token
  canary via ``resolve_and_bind_origin``); fail-closed to ``[]``.
- ``origin_direct_probe`` — §12.46-gated origin-direct dispatch over the bound origins.
- ``attempt_reach_transport_dead`` — the transport-dead front-door entry (the niagamas
  lesson): a root connect/read timeout is the origin-direct PRECONDITION, not an abort.

They are Alpha *collaborators* (they read/emit through the injected Alpha recon context —
``event_store``, ``_bound_origin``, ``_origin_discovery``, ``_engagement_profile``,
``_emit``, ``_reach_attempted``), mirroring the existing ``fingerprint.seed_fingerprint_first``
seam — NOT a second reach path (anti-#6). ``scout._attempt_reach`` and
``fingerprint.seed_fingerprint_first`` both delegate here; there is exactly one origin
binding and one origin-direct dispatch in the codebase.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from agent_alpha.events.event_types import EventType
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

    __slots__ = ("status_code", "text", "headers")

    def __init__(self, status_code: int, body: str, headers: dict[str, str]) -> None:
        self.status_code = status_code
        self.text = body
        self.headers = headers


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
    if cached_origins is not None:
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
    alpha: Any, url: str, host: str, path: str, authorized_origins_list: list[str]
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

    from agent_alpha.conductor.engagement_profile import (
        OriginNotAuthorizedError,
        assert_origin_authorized_or_bound,
    )

    last_response: _ReachResponse | None = None
    for origin_ip in authorized_origins_list:
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

        alpha._emit(
            "OBSERVE",
            f"Reach: ORIGIN_DIRECT for {url} via {origin_ip}",
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
            },
        )

        try:
            result = origin_direct_fetch(host, origin_ip, path)
        except RuntimeError:
            alpha._emit(
                "OBSERVE",
                f"Reach: origin_direct_fetch failed for {url} via {origin_ip}",
            )
            continue

        candidate = _ReachResponse(
            status_code=result.status_code,
            body=result.body,
            headers=dict(result.headers),
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
    return last_response


def attempt_reach_transport_dead(alpha: Any, url: str) -> _ReachResponse | None:
    """Root front-door transport-dead (no resp) → origin-flank (§12.61).

    A root front-door connect/read timeout is the origin-direct PRECONDITION, not an abort:
    the edge is stonewalling at transport, so pivot to the discovered origin instead of
    marking the host dead (the niagamas lesson). Reuses the SAME binding
    (``resolve_authorized_origin``) and the SAME §12.46-gated dispatch
    (``origin_direct_probe``) as the response-blocked path — no 2nd reach path (#6).

    Fail-closed: returns None when no candidate binds (stale/co-tenant) or the profile did
    not consent to discovery — the caller then marks the host dead exactly as before.
    Bounded: one attempt per url (shared ``alpha._reach_attempted``).
    """
    if url in alpha._reach_attempted:
        return None
    alpha._reach_attempted.add(url)

    # No engagement profile → no reach deps → honest block (mirror _attempt_reach).
    if alpha._engagement_profile is None:
        return None

    host = urlparse(url).hostname or urlparse(url).netloc
    origins = resolve_authorized_origin(alpha, host)
    if not origins:
        return None  # fail-closed: nothing bound → caller abandons the host

    # Strategy is KNOWN = ORIGIN_DIRECT (no resp to classify_mitigation/choose_reach).
    # The §12.46 auth gate is enforced INSIDE origin_direct_probe.
    return origin_direct_probe(alpha, url, host, urlparse(url).path, origins)
