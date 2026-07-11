# tests/phase_2_5/test_passive_discovery.py
"""RED contract: R2 slice-1 — passive subdomain discovery (crt.sh) → frontier.

Scope of THIS slice (decided with Natanael 2026-07-10):
  * Source: crt.sh ONLY (pure-passive CT logs, zero API key). subfinder/reverse-IP
    are later slices, behind the tool abstraction.
  * Gate: DEFAULT-DENY via the EXISTING ``authorization.is_in_scope`` (exact-host).
    A discovered host enters the ACTIVE frontier ONLY if it is already explicitly
    in the SOW scope. Everything else (unlisted subdomains, co-tenants) is
    ENUMERATED — recorded as a candidate, NEVER probed.
  * Wildcard SOW autonomy (auto-authorize ``*.example.com``) is DEFERRED to R2
    slice-2: ``is_in_scope`` is exact-match today (authorization.py:334), and adding
    wildcard support is an auth-gate change that gets its own RED-first slice.

Non-negotiables this slice must honour:
  * ZERO ACTIVE PACKET to any target during discovery — the ONLY network call is
    to crt.sh (T1, T4).
  * Scope truth stays in the Conductor auth gate; discovery NEVER re-derives scope
    (reuses ``is_in_scope``) — anti-Lyndon #7.
  * Enumerated (out-of-scope) hosts are RECORDED, never silently dropped — anti-#3
    (T6), and never enter the frontier — scope/legal boundary (T5).

RED at current HEAD (#127): ``agent_alpha/recon/passive_discovery.py`` does not exist
(``grep -rn crt.sh agent_alpha/`` → 0). Import fails → all tests RED until R2 lands.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_passive_discovery.py -v
"""

from __future__ import annotations

import dataclasses

import pytest  # noqa: F401

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore

# Net-new R2 interface (RED: module does not exist yet).
from agent_alpha.recon.passive_discovery import (  # noqa: E402
    CRTSH_URL_TEMPLATE,
    PassiveDiscovery,
    PassiveDiscoveryResult,
    parse_crtsh_names,
    seed_frontier_from_passive,
)

_DOMAIN = "example.com"

# crt.sh returns a JSON array; ``name_value`` may be newline-joined and include a
# leading-wildcard SAN. A multi-SAN cert can also carry an UNRELATED domain.
_CRTSH_JSON = (
    "["
    '{"common_name":"example.com","name_value":"example.com\\nwww.example.com"},'
    '{"common_name":"app.example.com","name_value":"app.example.com"},'
    '{"common_name":"*.example.com","name_value":"*.example.com\\nshop.example.com"},'
    '{"common_name":"cdn.other.net","name_value":"cdn.other.net"}'
    "]"
)


@dataclasses.dataclass(frozen=True)
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str]
    url: str


class _FakeHttpClient:
    """Records every fetched URL. Only the crt.sh URL is routed; anything else
    (i.e. an accidental target probe) returns 404 and — more importantly — shows
    up in ``calls`` so the zero-active-packet invariant can be asserted."""

    def __init__(self, routes: dict[str, _Resp]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:  # noqa: ARG002
        self.calls.append(url)
        return self._routes.get(url, _Resp(404, "", {}, url))


def _crtsh_url(domain: str) -> str:
    return CRTSH_URL_TEMPLATE.format(domain=domain)


def _recon_auth() -> tuple[AuthorizationStateMachine, str]:
    """Engagement cleared to RECON_ONLY, scope = {app.example.com, example.com}
    (explicit hosts — www./shop. are deliberately NOT authorized)."""
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="client_lab", target=_DOMAIN)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=["app.example.com", "example.com"], exclusions=[]),
    )
    return auth, rec.engagement_id


def _discovery(
    routes: dict[str, _Resp] | None = None,
) -> tuple[PassiveDiscovery, str, _FakeHttpClient]:
    auth, eng = _recon_auth()
    http = _FakeHttpClient(
        routes or {_crtsh_url(_DOMAIN): _Resp(200, _CRTSH_JSON, {}, _crtsh_url(_DOMAIN))}
    )
    return (
        PassiveDiscovery(http_client=http, authorization=auth, event_store=InMemoryEventStore()),
        eng,
        http,
    )


# ---------------------------------------------------------------------------
# T0 — interface exists
# ---------------------------------------------------------------------------


def test_interface_exists() -> None:
    assert hasattr(PassiveDiscovery, "discover")
    assert callable(parse_crtsh_names)
    assert callable(seed_frontier_from_passive)
    assert "{domain}" in CRTSH_URL_TEMPLATE


# ---------------------------------------------------------------------------
# T1 — ZERO ACTIVE PACKET: the only network call is crt.sh
# ---------------------------------------------------------------------------


def test_discovery_touches_only_crtsh() -> None:
    disc, eng, http = _discovery()
    disc.discover(eng, _DOMAIN)
    assert http.calls == [_crtsh_url(_DOMAIN)], (
        "discovery made a network call to something other than crt.sh — "
        f"zero-active-packet invariant broken. calls={http.calls}"
    )
    # No discovered host was ever fetched during discovery.
    assert not any(
        h in c
        for c in http.calls
        for h in ("www.example.com", "shop.example.com", "app.example.com")
    )


# ---------------------------------------------------------------------------
# T2 — parser: newline-joined, wildcard-stripped, in-domain-only, deduped
# ---------------------------------------------------------------------------


def test_parse_crtsh_names() -> None:
    names = parse_crtsh_names(_CRTSH_JSON, _DOMAIN)
    assert names == ["app.example.com", "example.com", "shop.example.com", "www.example.com"], names
    assert "*.example.com" not in names  # wildcard stripped
    assert "cdn.other.net" not in names  # unrelated SAN dropped


# ---------------------------------------------------------------------------
# T3 — DEFAULT-DENY partition via existing is_in_scope (exact-host)
# ---------------------------------------------------------------------------


def test_partition_default_deny() -> None:
    disc, eng, _ = _discovery()
    result = disc.discover(eng, _DOMAIN)
    assert isinstance(result, PassiveDiscoveryResult)
    # Only SOW-listed hosts are frontier-eligible.
    assert set(result.in_scope) == {"app.example.com", "example.com"}
    # Discovered-but-unauthorized subdomains are enumerated, NOT in_scope.
    assert {"www.example.com", "shop.example.com"}.issubset(set(result.enumerated))
    assert not (set(result.in_scope) & set(result.enumerated))  # disjoint


# ---------------------------------------------------------------------------
# T4 — tier-gate fail-closed: below RECON, crt.sh is NEVER queried
# ---------------------------------------------------------------------------


def test_below_recon_refuses_without_touching_network() -> None:
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(
        client_id="client_lab", target=_DOMAIN
    )  # state=CREATED, no enable_recon
    http = _FakeHttpClient({_crtsh_url(_DOMAIN): _Resp(200, _CRTSH_JSON, {}, _crtsh_url(_DOMAIN))})
    disc = PassiveDiscovery(http_client=http, authorization=auth, event_store=InMemoryEventStore())

    result = disc.discover(rec.engagement_id, _DOMAIN)

    assert http.calls == [], "discovery hit the network before the RECON tier-gate passed"
    assert result.in_scope == () and result.enumerated == ()


# ---------------------------------------------------------------------------
# T5 — only in_scope enters the frontier; enumerated is NEVER probed
# ---------------------------------------------------------------------------


def test_seed_frontier_only_in_scope() -> None:
    from agent_alpha.agents.alpha.scout import Alpha
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    auth, eng = _recon_auth()
    http = _FakeHttpClient({_crtsh_url(_DOMAIN): _Resp(200, _CRTSH_JSON, {}, _crtsh_url(_DOMAIN))})
    disc = PassiveDiscovery(http_client=http, authorization=auth, event_store=InMemoryEventStore())
    result = disc.discover(eng, _DOMAIN)

    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
        orchestrator=object(),  # not used: seeding does not run the loop
        http_client=_FakeHttpClient({}),
    )
    alpha._engagement_id = eng
    alpha._work_queue = []
    alpha._probed = set()

    enqueued = seed_frontier_from_passive(alpha, result)

    frontier_hosts = {u.split("//", 1)[-1].rstrip("/") for u in alpha._work_queue}
    assert frontier_hosts == {"app.example.com", "example.com"}, frontier_hosts
    assert enqueued == 2
    # Enumerated co-tenant/unlisted subdomains never entered the frontier.
    assert not ({"www.example.com", "shop.example.com"} & frontier_hosts)


# ---------------------------------------------------------------------------
# T6 — enumerated hosts are RECORDED, not silently dropped (anti-#3)
# ---------------------------------------------------------------------------


def test_enumerated_is_visible_not_dropped() -> None:
    disc, eng, _ = _discovery()
    result = disc.discover(eng, _DOMAIN)
    # The whole point of enumerate-only: a discovered-but-unauthorized host must
    # remain VISIBLE (as a candidate for the client / SOW expansion), never lost.
    assert result.enumerated, (
        "enumerated hosts were dropped — a co-tenant/subdomain finding vanished (silent success, #3)"
    )
    assert "www.example.com" in result.enumerated


# ---------------------------------------------------------------------------
# T7 — idempotent seeding (reuses enqueue dedup; no link-cycle blowup)
# ---------------------------------------------------------------------------


def test_seed_is_idempotent() -> None:
    from agent_alpha.agents.alpha.scout import Alpha
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    auth, eng = _recon_auth()
    http = _FakeHttpClient({_crtsh_url(_DOMAIN): _Resp(200, _CRTSH_JSON, {}, _crtsh_url(_DOMAIN))})
    disc = PassiveDiscovery(http_client=http, authorization=auth, event_store=InMemoryEventStore())
    result = disc.discover(eng, _DOMAIN)

    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
        orchestrator=object(),
        http_client=_FakeHttpClient({}),
    )
    alpha._engagement_id = eng
    alpha._work_queue = []
    alpha._probed = set()

    seed_frontier_from_passive(alpha, result)
    seed_frontier_from_passive(alpha, result)  # second pass must add nothing

    assert len(alpha._work_queue) == 2


# ---------------------------------------------------------------------------
# T8 — event-sourced audit trail: the "found-not-probed" record is APPENDED
#      (non-negotiable: State is event-sourced/append-only for legal + replay;
#       enumerated hosts must survive in the audit stream, not only in a
#       transient result object)
# ---------------------------------------------------------------------------


def test_discover_emits_passive_discovery_audit_event() -> None:
    auth, eng = _recon_auth()
    event_store = InMemoryEventStore()
    http = _FakeHttpClient({_crtsh_url(_DOMAIN): _Resp(200, _CRTSH_JSON, {}, _crtsh_url(_DOMAIN))})
    disc = PassiveDiscovery(http_client=http, authorization=auth, event_store=event_store)

    disc.discover(eng, _DOMAIN)

    events = [e for e in event_store.get_events(eng) if e.event_type == EventType.PASSIVE_DISCOVERY]
    assert len(events) == 1, "exactly one append-only PASSIVE_DISCOVERY event must be recorded"
    payload = events[0].payload
    # The legally-important set: discovered-but-NOT-probed hosts, preserved for audit.
    assert set(payload.get("enumerated", [])) == {"www.example.com", "shop.example.com"}, (
        "audit event lost the enumerated (found-not-probed) hosts — event-sourced "
        "non-negotiable breached"
    )
    assert set(payload.get("in_scope", [])) == {"app.example.com", "example.com"}


def test_below_recon_emits_no_discovery_event() -> None:
    """Fail-closed: refused discovery must not fabricate a discovery record."""
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="client_lab", target=_DOMAIN)  # CREATED, no recon
    event_store = InMemoryEventStore()
    http = _FakeHttpClient({_crtsh_url(_DOMAIN): _Resp(200, _CRTSH_JSON, {}, _crtsh_url(_DOMAIN))})
    disc = PassiveDiscovery(http_client=http, authorization=auth, event_store=event_store)

    disc.discover(rec.engagement_id, _DOMAIN)

    assert event_store.get_events(rec.engagement_id) == [], (
        "a discovery event was emitted despite the RECON tier-gate refusing"
    )
