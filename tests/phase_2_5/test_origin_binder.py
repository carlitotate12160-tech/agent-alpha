# tests/phase_2_5/test_origin_binder.py
# §12.46 — Delegated orchestrator tests (Slice 2).
#
# Test contract:
#   1. CARDINAL: discovery yields [CF-edge, co-tenant, REAL-origin] → binds REAL
#   2. SAFETY: internal/metadata IP (169.254.169.254) skipped by REAL SSRF guard
#   3. CAPABILITY OFF: allow_origin_discovery=False → None, no discovery call
#   4. NO TOKEN: profile without token for host → None, no event
#   5. GOVERNOR CAP: N+1 non-binding candidates + governor capped at N → stops
#   6. SIGNATURE INTEGRITY: ownership_tokens + sign/verify consistent; no mutation

from __future__ import annotations

from unittest.mock import patch

from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    dump_signed_profile,
    load_signed_profile_from_dict,
    token_for,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.recon.origin_binding import resolve_and_bind_origin
from agent_alpha.recon.transport_resilience import LockoutGovernor

# ── Fixtures ──────────────────────────────────────────────────

_HOST = "client-target.com"
_ENG = "eng-binder-001"
_TOKEN = "engagement-abc123"
_KEY = b"12345678901234567890123456789012"

_CF_EDGE_IP = "104.16.132.229"  # Cloudflare range
_COTENANT_IP = "203.0.113.99"
_REAL_ORIGIN_IP = "198.51.100.42"
_INTERNAL_IP = "169.254.169.254"


def _profile(
    *,
    allow_origin_discovery: bool = True,
    token: str | None = _TOKEN,
    host: str = _HOST,
) -> EngagementProfile:
    tokens = frozenset({(host, token)}) if token else frozenset()
    return EngagementProfile(
        engagement_id=_ENG,
        client_id="client-42",
        scope_targets=frozenset({host}),
        allow_origin_discovery=allow_origin_discovery,
        ownership_tokens=tokens,
    )


class _FakeDiscovery:
    """Test double: yields a fixed candidate list; tracks whether .candidates() was called."""

    def __init__(self, ips: list[str]) -> None:
        self._ips = ips
        self.called = False

    def candidates(self, fronted_host: str) -> list[str]:
        self.called = True
        return list(self._ips)


# ── 1. CARDINAL: binds first proven candidate ─────────────────


def test_binds_first_proven_candidate() -> None:
    """discovery yields [CF-edge, co-tenant(no token), REAL-origin(serves token)]
    → returns the REAL-origin IP; exactly one ORIGIN_BINDING_PROVEN event with
    fronted_host + that IP; CF-edge + co-tenant skipped."""

    def _mock_verify(*, origin_ip: str, fronted_host: str, ownership_token: str) -> bool:
        # CF-edge is filtered by is_cloudflare_ip before verify is called.
        # Co-tenant: verify returns False (token not in body).
        # Real origin: verify returns True.
        return origin_ip == _REAL_ORIGIN_IP

    discovery = _FakeDiscovery([_CF_EDGE_IP, _COTENANT_IP, _REAL_ORIGIN_IP])
    store = InMemoryEventStore()

    with patch(
        "agent_alpha.recon.origin_binding.verify_origin_binding",
        side_effect=_mock_verify,
    ):
        result = resolve_and_bind_origin(
            fronted_host=_HOST,
            profile=_profile(),
            event_store=store,
            engagement_id=_ENG,
            discovery=discovery,
        )

    assert result == _REAL_ORIGIN_IP

    # Exactly one ORIGIN_BINDING_PROVEN event.
    events = store.get_events(_ENG)
    proven_events = [e for e in events if e.event_type == EventType.ORIGIN_BINDING_PROVEN]
    assert len(proven_events) == 1
    payload = proven_events[0].payload
    assert payload["fronted_host"] == _HOST
    assert payload["origin_ip"] == _REAL_ORIGIN_IP
    assert payload["proof_type"] == "well_known_token"


# ── 2. SAFETY: internal/metadata IP skipped (REAL verify) ─────


def test_internal_metadata_ip_skipped() -> None:
    """Internal/metadata IPs (169.254.169.254, 10.0.0.1) are rejected by the
    REAL verify_origin_binding — the SSRF guard must fire in-context
    (defense-in-depth). origin_direct_fetch is NEVER called."""

    with patch(
        "agent_alpha.recon.origin_binding.origin_direct_fetch",
        side_effect=AssertionError("must not connect to internal IP"),
    ):
        discovery = _FakeDiscovery([_INTERNAL_IP, "10.0.0.1"])
        store = InMemoryEventStore()

        result = resolve_and_bind_origin(
            fronted_host=_HOST,
            profile=_profile(allow_origin_discovery=True, token=_TOKEN),
            event_store=store,
            engagement_id=_ENG,
            discovery=discovery,
        )

    assert result is None
    # No events emitted.
    assert len(store.get_events(_ENG)) == 0


# ── 3. CAPABILITY OFF: allow_origin_discovery=False ───────────


def test_capability_off_returns_none() -> None:
    """allow_origin_discovery=False ⇒ returns None, no discovery.candidates()
    call, no event."""

    discovery = _FakeDiscovery([_REAL_ORIGIN_IP])
    store = InMemoryEventStore()

    result = resolve_and_bind_origin(
        fronted_host=_HOST,
        profile=_profile(allow_origin_discovery=False),
        event_store=store,
        engagement_id=_ENG,
        discovery=discovery,
    )

    assert result is None
    assert not discovery.called  # discovery.candidates() never invoked
    assert len(store.get_events(_ENG)) == 0


# ── 4. NO TOKEN: profile without a token for the host ─────────


def test_no_token_returns_none() -> None:
    """Profile without a token for the host ⇒ returns None, no event."""

    discovery = _FakeDiscovery([_REAL_ORIGIN_IP])
    store = InMemoryEventStore()

    result = resolve_and_bind_origin(
        fronted_host=_HOST,
        profile=_profile(allow_origin_discovery=True, token=None),
        event_store=store,
        engagement_id=_ENG,
        discovery=discovery,
    )

    assert result is None
    assert not discovery.called  # token check fails before discovery
    assert len(store.get_events(_ENG)) == 0


# ── 5. GOVERNOR CAP: N+1 non-binding + governor at N ─────────


def test_governor_cap_bounds_probes() -> None:
    """N+1 non-binding candidates + a governor capped at N ⇒ stops after N
    probes (bounded opsec). The (N+1)th candidate is never probed."""
    n = 3
    # n+1 unique non-CF, non-internal IPs that all fail verification.
    candidates = [f"198.51.100.{i}" for i in range(n + 1)]

    governor = LockoutGovernor(max_escalations=n)
    discovery = _FakeDiscovery(candidates)
    store = InMemoryEventStore()

    with patch(
        "agent_alpha.recon.origin_binding.verify_origin_binding",
        return_value=False,
    ) as mock_verify:
        result = resolve_and_bind_origin(
            fronted_host=_HOST,
            profile=_profile(),
            event_store=store,
            engagement_id=_ENG,
            discovery=discovery,
            governor=governor,
        )

    assert result is None
    # verify was called exactly n times (governor capped before n+1).
    assert mock_verify.call_count == n
    # Governor is now locked out.
    assert governor.is_locked_out(_HOST)


# ── 6. SIGNATURE INTEGRITY: ownership_tokens + sign/verify ────


def test_ownership_tokens_sign_verify_consistent() -> None:
    """Adding ownership_tokens keeps sign()/verify() consistent — a proven
    origin does NOT mutate the profile."""

    profile = _profile(allow_origin_discovery=True)
    sig_before = profile.sign(_KEY)

    # Round-trip through dump/load.
    envelope = dump_signed_profile(profile, key=_KEY)
    loaded = load_signed_profile_from_dict(envelope, key=_KEY)

    # Signature is stable.
    assert loaded.sign(_KEY) == sig_before
    # ownership_tokens survive round-trip.
    assert loaded.ownership_tokens == profile.ownership_tokens
    assert token_for(loaded, _HOST) == _TOKEN

    # Simulate a proof cycle (event, not profile mutation).
    store = InMemoryEventStore()
    store.append(
        EventType.ORIGIN_BINDING_PROVEN,
        _ENG,
        "alpha",
        {"fronted_host": _HOST, "origin_ip": _REAL_ORIGIN_IP, "proof_type": "well_known_token"},
    )

    # Profile signature MUST NOT change (frozen dataclass).
    sig_after = profile.sign(_KEY)
    assert sig_before == sig_after


# ── token_for edge cases ──────────────────────────────────────


def test_token_for_returns_none_when_no_match() -> None:
    """token_for returns None when the host is not in ownership_tokens."""
    profile = _profile(token=_TOKEN, host=_HOST)
    assert token_for(profile, "other-host.com") is None


def test_token_for_returns_token_when_match() -> None:
    """token_for returns the token when the host matches."""
    profile = _profile(token=_TOKEN, host=_HOST)
    assert token_for(profile, _HOST) == _TOKEN
