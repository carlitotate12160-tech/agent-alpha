# tests/phase_2_5/test_origin_binding.py
# §12.46 — Origin-binding authorization mechanism tests (Slice 1).
#
# Test contract:
#   1. CARDINAL SAFETY: co-tenant IP is never authorized (body without token)
#   2. POSITIVE: proven origin authorizes with capability on
#   3. CAPABILITY OFF: allow_origin_discovery=False blocks proven origin
#   4. SIGNED PATH UNCHANGED: IP in signed authorized_origins still authorizes
#   5. SIGNATURE INTEGRITY: proving an origin does not change profile bytes
#   6. CONSENT ENFORCEMENT: allow_origin_discovery=True without consent is REJECTED

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_alpha.conductor.authorization import (
    ConsentRequiredError,
    authorize_engagement,
)
from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    OriginNotAuthorizedError,
    assert_origin_authorized_or_bound,
    proven_origins,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.recon.origin_binding import (
    WELL_KNOWN_TOKEN_PATH,
    verify_origin_binding,
)
from agent_alpha.recon.reach_transport import OriginDirectResult

# ── Fixtures ──────────────────────────────────────────────────

_TEST_ALLOWLIST: frozenset[str] = frozenset({"lab.example.com"})

_VALID_DOMAIN = "client-target.com"
_ORIGIN_IP = "203.0.113.10"
_COTENANT_IP = "203.0.113.99"
_ENGAGEMENT_ID = "eng-bind-001"
_TOKEN = "engagement-abc123"
_KEY = b"12345678901234567890123456789012"


def _make_profile(
    *,
    allow_origin_discovery: bool = False,
    authorized_origins: frozenset[str] = frozenset(),
    scope_targets: frozenset[str] | None = None,
) -> EngagementProfile:
    return EngagementProfile(
        engagement_id=_ENGAGEMENT_ID,
        client_id="client-42",
        scope_targets=scope_targets or frozenset({_VALID_DOMAIN}),
        authorized_origins=authorized_origins,
        allow_origin_discovery=allow_origin_discovery,
    )


def _emit_proven_event(
    event_store: InMemoryEventStore,
    origin_ip: str,
    fronted_host: str = _VALID_DOMAIN,
) -> None:
    """Manually inject an ORIGIN_BINDING_PROVEN event (slice-1: mechanism test,
    the caller that emits this is slice-2)."""
    event_store.append(
        event_type=EventType.ORIGIN_BINDING_PROVEN,
        engagement_id=_ENGAGEMENT_ID,
        agent="CONDUCTOR",
        payload={
            "engagement_id": _ENGAGEMENT_ID,
            "fronted_host": fronted_host,
            "origin_ip": origin_ip,
            "proof_type": "well_known_token",
        },
    )


# ── 1. CARDINAL SAFETY: co-tenant IP is never authorized ──────


def test_cotenant_ip_is_never_authorized() -> None:
    """A candidate IP whose origin_direct_fetch returns 200 but body WITHOUT
    the token ⇒ verify_origin_binding == False; no ORIGIN_BINDING_PROVEN event;
    assert_origin_authorized_or_bound RAISES for that IP.
    (Co-tenant collateral protection — the whole point.)"""

    # Simulate co-tenant: 200 OK but body is a different site's content.
    cotenant_result = OriginDirectResult(
        status_code=200,
        body="<html>Welcome to co-tenant site!</html>",
        headers={},
    )

    with (
        patch("agent_alpha.recon.origin_binding.is_internal_ip", return_value=False),
        patch(
            "agent_alpha.recon.origin_binding.origin_direct_fetch",
            return_value=cotenant_result,
        ),
    ):
        # verify_origin_binding must be False — token not in body.
        assert (
            verify_origin_binding(
                origin_ip=_COTENANT_IP,
                fronted_host=_VALID_DOMAIN,
                ownership_token=_TOKEN,
            )
            is False
        )

    # No event emitted (slice-1: verify is False, caller would not emit).
    event_store = InMemoryEventStore()
    # Do NOT emit any event — the verify was False.

    # The composed gate must RAISE.
    profile = _make_profile(allow_origin_discovery=True)
    with pytest.raises(OriginNotAuthorizedError, match="not proven-bound"):
        assert_origin_authorized_or_bound(
            origin_ip=_COTENANT_IP,
            fronted_host=_VALID_DOMAIN,
            profile=profile,
            event_store=event_store,
            engagement_id=_ENGAGEMENT_ID,
            lab_allowlist=_TEST_ALLOWLIST,
        )


# ── 2. POSITIVE: proven origin authorizes with capability on ──


def test_proven_origin_authorizes_with_capability() -> None:
    """Body echoes token ⇒ verify True ⇒ event emitted ⇒
    assert_origin_authorized_or_bound passes (allow_origin_discovery=True
    + host in scope)."""

    # Simulate origin serving the token.
    token_result = OriginDirectResult(
        status_code=200,
        body=_TOKEN,
        headers={},
    )

    with (
        patch("agent_alpha.recon.origin_binding.is_internal_ip", return_value=False),
        patch(
            "agent_alpha.recon.origin_binding.origin_direct_fetch",
            return_value=token_result,
        ) as mock_fetch,
    ):
        assert (
            verify_origin_binding(
                origin_ip=_ORIGIN_IP,
                fronted_host=_VALID_DOMAIN,
                ownership_token=_TOKEN,
            )
            is True
        )

        # Verify the correct path was requested.
        expected_path = WELL_KNOWN_TOKEN_PATH.format(token=_TOKEN)
        mock_fetch.assert_called_once_with(_VALID_DOMAIN, _ORIGIN_IP, expected_path)

    # Caller would emit the event on True (slice-2); we inject it manually.
    event_store = InMemoryEventStore()
    _emit_proven_event(event_store, _ORIGIN_IP)

    # The composed gate must PASS.
    profile = _make_profile(allow_origin_discovery=True)
    assert_origin_authorized_or_bound(
        origin_ip=_ORIGIN_IP,
        fronted_host=_VALID_DOMAIN,
        profile=profile,
        event_store=event_store,
        engagement_id=_ENGAGEMENT_ID,
        lab_allowlist=_TEST_ALLOWLIST,
    )  # no raise


# ── 3. CAPABILITY OFF: allow_origin_discovery=False blocks ────


def test_capability_off_blocks_proven_origin() -> None:
    """allow_origin_discovery=False + a proven event present ⇒
    assert_origin_authorized_or_bound RAISES (capability gate)."""

    event_store = InMemoryEventStore()
    _emit_proven_event(event_store, _ORIGIN_IP)

    # Verify the event is there.
    assert _ORIGIN_IP in proven_origins(event_store, _ENGAGEMENT_ID, _VALID_DOMAIN)

    # But the profile has the capability OFF.
    profile = _make_profile(allow_origin_discovery=False)
    with pytest.raises(OriginNotAuthorizedError, match="allow_origin_discovery=False"):
        assert_origin_authorized_or_bound(
            origin_ip=_ORIGIN_IP,
            fronted_host=_VALID_DOMAIN,
            profile=profile,
            event_store=event_store,
            engagement_id=_ENGAGEMENT_ID,
            lab_allowlist=_TEST_ALLOWLIST,
        )


# ── 4. SIGNED PATH UNCHANGED: signed authorized_origins still works ──


def test_signed_authorized_origins_still_works() -> None:
    """An IP in signed authorized_origins ⇒ assert_origin_authorized_or_bound
    passes (no events needed) — regression guard for the existing path."""

    event_store = InMemoryEventStore()  # empty — no proven events

    profile = _make_profile(
        authorized_origins=frozenset({_ORIGIN_IP}),
        allow_origin_discovery=False,
    )
    # Must pass via the signed/cooperative path.
    assert_origin_authorized_or_bound(
        origin_ip=_ORIGIN_IP,
        fronted_host=_VALID_DOMAIN,
        profile=profile,
        event_store=event_store,
        engagement_id=_ENGAGEMENT_ID,
        lab_allowlist=_TEST_ALLOWLIST,
    )  # no raise


# ── 4b. GAP-040: consented subdomain of an owned apex passes the ownership gate ──


def test_subdomain_of_owned_apex_passes_ownership_gate() -> None:
    """GAP-040 (field niagamas 2026-08-10): is_in_scope probes subdomains of scope
    domains when allow_subdomain_enum is consented, but _assert_fronted_host_owned
    demanded an EXACT scope_targets hit → OriginNotAuthorizedError crash on every
    CF-fronted subdomain. Subdomain of an owned apex IS owned (same token scope)."""
    profile = EngagementProfile(
        engagement_id=_ENGAGEMENT_ID,
        client_id="client-42",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_origin_discovery=True,
        allow_subdomain_enum=True,
    )
    store = InMemoryEventStore()
    _emit_proven_event(store, _ORIGIN_IP, fronted_host=f"pos.{_VALID_DOMAIN}")
    assert_origin_authorized_or_bound(
        origin_ip=_ORIGIN_IP,
        fronted_host=f"pos.{_VALID_DOMAIN}",
        profile=profile,
        event_store=store,
        engagement_id=_ENGAGEMENT_ID,
        lab_allowlist=_TEST_ALLOWLIST,
    )  # no raise — subdomain inherits apex ownership when subdomain enum consented


def test_subdomain_rejected_without_subdomain_consent() -> None:
    """allow_subdomain_enum=False → subdomain does NOT inherit apex ownership.
    Consent gate stays fail-closed."""
    profile = EngagementProfile(
        engagement_id=_ENGAGEMENT_ID,
        client_id="client-42",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_origin_discovery=True,
        allow_subdomain_enum=False,
    )
    store = InMemoryEventStore()
    _emit_proven_event(store, _ORIGIN_IP, fronted_host=f"pos.{_VALID_DOMAIN}")
    with pytest.raises(OriginNotAuthorizedError, match="not a proven-owned target"):
        assert_origin_authorized_or_bound(
            origin_ip=_ORIGIN_IP,
            fronted_host=f"pos.{_VALID_DOMAIN}",
            profile=profile,
            event_store=store,
            engagement_id=_ENGAGEMENT_ID,
            lab_allowlist=_TEST_ALLOWLIST,
        )


def test_lookalike_domain_never_inherits_ownership() -> None:
    """Dot-boundary: not{_VALID_DOMAIN} endswith({_VALID_DOMAIN}) but is NOT a
    subdomain — must never inherit ownership (suffix-attack guard)."""
    profile = EngagementProfile(
        engagement_id=_ENGAGEMENT_ID,
        client_id="client-42",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_origin_discovery=True,
        allow_subdomain_enum=True,
    )
    store = InMemoryEventStore()
    with pytest.raises(OriginNotAuthorizedError, match="not a proven-owned target"):
        assert_origin_authorized_or_bound(
            origin_ip=_ORIGIN_IP,
            fronted_host=f"not{_VALID_DOMAIN}",  # notclient-target.com
            profile=profile,
            event_store=store,
            engagement_id=_ENGAGEMENT_ID,
            lab_allowlist=_TEST_ALLOWLIST,
        )


# ── 5. SIGNATURE INTEGRITY: proving doesn't change profile ────


def test_proving_origin_does_not_change_profile_signature() -> None:
    """Before/after proving, profile.sign(key) is identical — profile bytes
    are immutable (frozen dataclass). Proving lives in events, not the profile."""

    profile = _make_profile(allow_origin_discovery=True)
    sig_before = profile.sign(_KEY)

    # Simulate a proof cycle: emit the event.
    event_store = InMemoryEventStore()
    _emit_proven_event(event_store, _ORIGIN_IP)

    # The profile signature MUST NOT change (profile is frozen).
    sig_after = profile.sign(_KEY)
    assert sig_before == sig_after

    # The proven_origins reflect the event, but the profile is untouched.
    assert _ORIGIN_IP in proven_origins(event_store, _ENGAGEMENT_ID, _VALID_DOMAIN)


# ── 6. CONSENT ENFORCEMENT: allow_origin_discovery requires consent ──


class _StubDNS:
    def resolve_txt(self, domain: str) -> list[str]:
        return ["agent-alpha=verify-abc"]


def test_origin_discovery_requires_signed_consent() -> None:
    """§12.36: allow_origin_discovery=True without consent_items/signed_by/
    signed_at is REJECTED by authorize_engagement."""
    with pytest.raises(ConsentRequiredError):
        authorize_engagement(
            engagement_id="eng-consent-test",
            client_id="client-1",
            targets=["consent-test.com"],
            allow_origin_discovery=True,
            consent_items=None,
            signed_by="",
            signed_at="",
            ownership_tokens={"consent-test.com": "dns-txt:agent-alpha=verify-abc"},
            dns_resolver=_StubDNS(),
            skip_domain_verification=True,
            key=_KEY,
        )


# ── Edge cases: verify_origin_binding error paths ─────────────


def test_verify_origin_binding_empty_inputs() -> None:
    """Empty origin_ip / fronted_host / ownership_token ⇒ False (fail-closed)."""
    assert verify_origin_binding(origin_ip="", fronted_host="x", ownership_token="t") is False
    assert verify_origin_binding(origin_ip="1.2.3.4", fronted_host="", ownership_token="t") is False
    assert verify_origin_binding(origin_ip="1.2.3.4", fronted_host="x", ownership_token="") is False


# ── 7. PER-HOST BINDING: proof for one host does not authorize another ──


def test_proof_for_one_host_does_not_authorize_another() -> None:
    """A proof for host A must NOT authorize host B in the same engagement
    (per-host binding is the cardinal safety invariant, FIX 1)."""
    store = InMemoryEventStore()
    eng = "eng-multi"
    profile = _make_profile(
        scope_targets=frozenset({"a.example", "b.example"}),
        allow_origin_discovery=True,
        authorized_origins=frozenset(),
    )
    store.append(
        event_type=EventType.ORIGIN_BINDING_PROVEN,
        engagement_id=eng,
        agent="CONDUCTOR",
        payload={
            "fronted_host": "a.example",
            "origin_ip": "203.0.113.9",
            "proof_type": "well_known_token",
        },
    )
    # proof holds for A
    assert_origin_authorized_or_bound(
        "203.0.113.9",
        "a.example",
        profile,
        store,
        eng,
        lab_allowlist=frozenset(),
    )
    # …but must NOT leak to B
    with pytest.raises(OriginNotAuthorizedError, match="not proven-bound"):
        assert_origin_authorized_or_bound(
            "203.0.113.9",
            "b.example",
            profile,
            store,
            eng,
            lab_allowlist=frozenset(),
        )


# ── 8. SSRF GUARD: internal/metadata IPs rejected before connecting ──


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1", "::1", "0.0.0.0"],
)
def test_internal_ip_is_rejected_without_connecting(ip: str) -> None:
    """Internal/metadata IPs are rejected BEFORE origin_direct_fetch is called
    (SSRF guard, CWE-918 — FIX 2)."""

    def _must_not_call(*a: object, **k: object) -> object:
        raise AssertionError("origin_direct_fetch called for internal IP — SSRF guard breached")

    with patch("agent_alpha.recon.origin_binding.origin_direct_fetch", side_effect=_must_not_call):
        assert (
            verify_origin_binding(origin_ip=ip, fronted_host="x.example", ownership_token="tok")
            is False
        )


def test_verify_origin_binding_runtime_error() -> None:
    """origin_direct_fetch raising RuntimeError ⇒ False (fail-closed)."""
    with (
        patch("agent_alpha.recon.origin_binding.is_internal_ip", return_value=False),
        patch(
            "agent_alpha.recon.origin_binding.origin_direct_fetch",
            side_effect=RuntimeError("connection refused"),
        ),
    ):
        assert (
            verify_origin_binding(
                origin_ip=_ORIGIN_IP,
                fronted_host=_VALID_DOMAIN,
                ownership_token=_TOKEN,
            )
            is False
        )


def test_verify_origin_binding_non_200() -> None:
    """origin_direct_fetch returning non-200 ⇒ False."""
    result_403 = OriginDirectResult(status_code=403, body="Forbidden", headers={})
    with (
        patch("agent_alpha.recon.origin_binding.is_internal_ip", return_value=False),
        patch(
            "agent_alpha.recon.origin_binding.origin_direct_fetch",
            return_value=result_403,
        ),
    ):
        assert (
            verify_origin_binding(
                origin_ip=_ORIGIN_IP,
                fronted_host=_VALID_DOMAIN,
                ownership_token=_TOKEN,
            )
            is False
        )


# ══════════════════════════════════════════════════════════════════════
# GAP-017 consumer — OTX origin_ip_candidates → CompositeOriginDiscovery → binding
# ══════════════════════════════════════════════════════════════════════

from types import SimpleNamespace  # noqa: E402

import agent_alpha.recon.origin_binding as _origin_binding  # noqa: E402
from agent_alpha.recon.origin_binding import resolve_and_bind_origin  # noqa: E402
from agent_alpha.recon.origin_discovery import (  # noqa: E402
    CompositeOriginDiscovery,
    StaticOriginDiscovery,
)

_OTX_IP = "45.33.32.156"  # public, non-Cloudflare — a plausible origin


def _record_otx_candidate(store: InMemoryEventStore, eng: str, ip: str) -> None:
    store.append(
        event_type=EventType.PASSIVE_INTEL_GATHERED,
        engagement_id=eng,
        agent="alpha",
        payload={"domain": "ex.com", "origin_ip_candidates": [ip], "sources_used": ["otx"]},
    )


# ── UNIT: composite unions base + event candidates ────────────────────


def test_composite_unions_base_and_otx_candidates() -> None:
    store = InMemoryEventStore()
    eng = "eng-comp-1"
    _record_otx_candidate(store, eng, _OTX_IP)
    comp = CompositeOriginDiscovery(StaticOriginDiscovery(["198.51.100.5"]), store, eng)
    cands = comp.candidates("ex.com")
    assert cands[0] == "198.51.100.5"  # base preserved first
    assert _OTX_IP in cands  # OTX candidate unioned


def test_composite_dedups_and_base_only_without_events() -> None:
    store = InMemoryEventStore()
    eng = "eng-comp-2"
    # OTX repeats a base IP → no duplicate
    _record_otx_candidate(store, eng, _OTX_IP)
    comp = CompositeOriginDiscovery(StaticOriginDiscovery([_OTX_IP]), store, eng)
    assert comp.candidates("ex.com").count(_OTX_IP) == 1
    # no PASSIVE_INTEL_GATHERED events → base only
    empty = CompositeOriginDiscovery(StaticOriginDiscovery(["1.2.3.4"]), InMemoryEventStore(), "e")
    assert empty.candidates("ex.com") == ["1.2.3.4"]


def test_composite_excludes_candidates_from_a_different_domain() -> None:
    """SECURITY (CodeRabbit): an origin IP discovered for domain A must NOT be
    surfaced as a candidate for host B — else it would be probed under B's token
    + Host header (cross-host token leak / collateral)."""
    store = InMemoryEventStore()
    eng = "eng-comp-xdomain"
    store.append(
        event_type=EventType.PASSIVE_INTEL_GATHERED,
        engagement_id=eng,
        agent="alpha",
        payload={"domain": "other.com", "origin_ip_candidates": [_OTX_IP], "sources_used": ["otx"]},
    )
    comp = CompositeOriginDiscovery(StaticOriginDiscovery(["1.2.3.4"]), store, eng)
    cands = comp.candidates("ex.com")  # different host than the event's domain
    assert cands == ["1.2.3.4"]  # base only — the other.com IP is NOT leaked to ex.com


def test_composite_subdomain_inherits_apex_candidates() -> None:
    """GAP-039 (field niagamas run 2026-08-10): passive intel is gathered per APEX
    domain, but origin binding is requested per blocked HOST — a subdomain. The
    apex event's OTX/VT candidates MUST flow to subdomain fronted hosts, or
    ORIGIN_DIRECT_ATTEMPT stays 0 on every CF-fronted subdomain."""
    store = InMemoryEventStore()
    eng = "eng-comp-apex"
    _record_otx_candidate(store, eng, _OTX_IP)  # event domain = ex.com (apex)
    comp = CompositeOriginDiscovery(StaticOriginDiscovery([]), store, eng)
    cands = comp.candidates("pos.ex.com")  # blocked host = subdomain of the apex
    assert _OTX_IP in cands


def test_composite_dot_boundary_no_false_suffix() -> None:
    """Suffix match must be dot-bounded: notex.com must NOT inherit ex.com's
    candidates (raw endswith would leak across domains)."""
    store = InMemoryEventStore()
    eng = "eng-comp-suffix"
    _record_otx_candidate(store, eng, _OTX_IP)  # event domain = ex.com
    comp = CompositeOriginDiscovery(StaticOriginDiscovery(["1.2.3.4"]), store, eng)
    cands = comp.candidates("notex.com")  # endswith("ex.com") but NOT a subdomain
    assert cands == ["1.2.3.4"]  # base only


class _BoomStore:
    def get_events(self, engagement_id: str) -> list[object]:
        raise RuntimeError("event store down")


def test_composite_fail_open_on_event_read_error() -> None:
    comp = CompositeOriginDiscovery(StaticOriginDiscovery(["1.2.3.4"]), _BoomStore(), "e")
    assert comp.candidates("ex.com") == ["1.2.3.4"]  # degrades to base, no raise


# ── CARDINAL (consumer wired): OTX IP reaches binding + is PROVEN ─────


def test_otx_candidate_reaches_binding_and_is_proven(monkeypatch: pytest.MonkeyPatch) -> None:
    """An OTX-surfaced origin IP (absent from base discovery) flows through
    CompositeOriginDiscovery into resolve_and_bind_origin, passes the
    verify_origin_binding token canary, and is authorized (ORIGIN_BINDING_PROVEN).
    Closes the GAP-017 dead-end: origin_ip_candidates now has a live consumer."""
    store = InMemoryEventStore()
    eng = "eng-otx-bind"
    _record_otx_candidate(store, eng, _OTX_IP)
    # base discovery finds NOTHING — the IP can only come from the OTX event.
    discovery = CompositeOriginDiscovery(StaticOriginDiscovery([]), store, eng)

    # prove the OTX IP serves the owned host (canary), without network:
    monkeypatch.setattr(
        _origin_binding,
        "verify_origin_binding",
        lambda *, origin_ip, fronted_host, ownership_token: origin_ip == _OTX_IP,
    )
    monkeypatch.setattr(
        "agent_alpha.conductor.engagement_profile.token_for",
        lambda profile, host: "TOKEN",
    )
    profile = SimpleNamespace(allow_origin_discovery=True)

    bound = resolve_and_bind_origin(
        fronted_host="ex.com",
        profile=profile,
        event_store=store,
        engagement_id=eng,
        discovery=discovery,
    )
    assert bound == _OTX_IP
    proven = [e for e in store.get_events(eng) if e.event_type == EventType.ORIGIN_BINDING_PROVEN]
    assert len(proven) == 1
    assert proven[0].payload["origin_ip"] == _OTX_IP


# ── §12.61 A1: Mnemonic PDNS Historical A Records ────────────────────────────


def test_composite_mnemonic_cf_era_boundary_derived() -> None:
    """T5a: CF-era boundary derived: origin with last_seen < cf_first_seen ranks
    BEFORE one with last_seen >= cf_first_seen; both rank before an is_cloudflare_ip
    edge IP (edge excluded)."""
    store = InMemoryEventStore()
    eng = "eng-mnemonic"
    # CF first seen = 150.
    # IP1 last seen = 100 (pre-CF era) -> tier 1
    # IP2 last seen = 200 (CF era) -> tier 2
    # CF IP (edge) -> filtered out
    triples = (
        ("104.16.0.1", 150, 300),  # CF edge
        ("198.51.100.1", 50, 100),  # Pre-CF
        ("198.51.100.2", 160, 200),  # CF-era
    )
    store.append(
        event_type=EventType.PASSIVE_INTEL_GATHERED,
        engagement_id=eng,
        agent="alpha",
        payload={"domain": "ex.com", "historical_a_records": triples, "sources_used": ["mnemonic_pdns"]},
    )
    comp = CompositeOriginDiscovery(StaticOriginDiscovery([]), store, eng)
    cands = comp.candidates("ex.com")
    assert len(cands) == 2
    assert cands[0] == "198.51.100.1"  # tier 1 (pre-CF) FIRST
    assert cands[1] == "198.51.100.2"  # tier 2 SECOND
    assert "1.1.1.1" not in cands      # edge excluded


def test_composite_mnemonic_no_cf_fallback() -> None:
    """T5b: no CF-range IP in history -> deterministic option-1 fallback, never raises."""
    store = InMemoryEventStore()
    eng = "eng-mnemonic"
    triples = (
        ("198.51.100.1", 50, 100),
        ("198.51.100.2", 160, 200),
    )
    store.append(
        event_type=EventType.PASSIVE_INTEL_GATHERED,
        engagement_id=eng,
        agent="alpha",
        payload={"domain": "ex.com", "historical_a_records": triples, "sources_used": ["mnemonic_pdns"]},
    )
    comp = CompositeOriginDiscovery(StaticOriginDiscovery([]), store, eng)
    cands = comp.candidates("ex.com")
    assert len(cands) == 2
    assert cands[0] == "198.51.100.2"  # simple last_seen DESC fallback
    assert cands[1] == "198.51.100.1"


def test_composite_excludes_multi_cdn_edges() -> None:
    """GAP-160: Verify Shopify and Fastly IPs are excluded, real origin survives, and CF tier boundary holds."""
    store = InMemoryEventStore()
    eng = "eng-multi-cdn"
    triples = (
        ("198.51.100.1", 50, 100),       # Pre-CF (should survive, Tier 1)
        ("104.16.0.1", 150, 300),        # CF edge (excluded, but anchors Tier boundary)
        ("68.183.237.190", 160, 200),    # DO origin post-CF (should survive, Tier 2)
        ("23.227.38.65", 170, 250),      # Shopify edge (excluded)
        ("151.101.1.1", 180, 260),       # Fastly edge (excluded)
    )
    store.append(
        event_type=EventType.PASSIVE_INTEL_GATHERED,
        engagement_id=eng,
        agent="alpha",
        payload={"domain": "multi-cdn.com", "historical_a_records": triples, "sources_used": ["mnemonic_pdns"]},
    )
    comp = CompositeOriginDiscovery(StaticOriginDiscovery([]), store, eng)
    cands = comp.candidates("multi-cdn.com")
    
    # T1/T2: CDN edges excluded, T3: DO origin survives
    assert "23.227.38.65" not in cands
    assert "151.101.1.1" not in cands
    assert "104.16.0.1" not in cands
    
    # T4: CF boundary holds (198.51.100.1 was before CF's 150, DO was after)
    assert len(cands) == 2
    assert cands[0] == "198.51.100.1"  # Tier 1
    assert cands[1] == "68.183.237.190"  # Tier 2
