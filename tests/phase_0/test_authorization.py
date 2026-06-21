"""Phase 0 — AuthorizationStateMachine test contract.

18 tests covering state transitions, scope validation, SOW handling,
emergency stop idempotency, per-agent gating, scope membership, event
emission, and SOW hash storage.

C1.0: AuthorizationStateMachine is now event-sourced — constructor takes
an EventStore, not an event_callback. All tests updated accordingly.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_authorization.py -v
"""

import hashlib

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import (
    AuthorizationStateMachine,
    EngagementRecord,
    InvalidScopeError,
    Scope,
    SOWError,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore


def _store() -> InMemoryEventStore:
    return InMemoryEventStore()


def _valid_scope() -> Scope:
    # /24 == 256 addresses == MAX_SCOPE_IPS, within the limit.
    return Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=["example.com"],
        exclusions=["10.0.0.5"],
    )


def _engagement_in_recon(sm: AuthorizationStateMachine) -> str:
    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    sm.enable_recon(rec.engagement_id, _valid_scope())
    return rec.engagement_id


def _engagement_in_active(sm: AuthorizationStateMachine) -> str:
    eid = _engagement_in_recon(sm)
    sm.enable_active(eid)
    return eid


def _engagement_in_offensive(sm: AuthorizationStateMachine) -> str:
    eid = _engagement_in_active(sm)
    sm.enable_offensive(eid, b"statement of work content")
    return eid


# ── Test 1 ────────────────────────────────────────────────────
def test_create_engagement_state_created() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    assert isinstance(rec, EngagementRecord)
    assert rec.state == a2a_pb2.CREATED


# ── Test 2 ────────────────────────────────────────────────────
def test_enable_recon_valid_scope() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    assert sm.enable_recon(rec.engagement_id, _valid_scope()) is True
    assert sm.get_state(rec.engagement_id) == a2a_pb2.RECON_ONLY


# ── Test 3 ────────────────────────────────────────────────────
def test_enable_recon_invalid_cidr() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    rec = sm.create_engagement("client_a", "x")
    bad = Scope(ip_ranges=["not-a-cidr"], domains=[], exclusions=[])
    with pytest.raises(InvalidScopeError):
        sm.enable_recon(rec.engagement_id, bad)


# ── Test 4 ────────────────────────────────────────────────────
def test_enable_recon_too_many_ips() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    rec = sm.create_engagement("client_a", "x")
    # /23 == 512 addresses > MAX_SCOPE_IPS (256)
    big = Scope(ip_ranges=["10.0.0.0/23"], domains=[], exclusions=[])
    with pytest.raises(InvalidScopeError):
        sm.enable_recon(rec.engagement_id, big)


# ── Test 5 ────────────────────────────────────────────────────
def test_enable_active_without_recon_raises() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    rec = sm.create_engagement("client_a", "x")
    with pytest.raises(ValueError):
        sm.enable_active(rec.engagement_id)


# ── Test 6 ────────────────────────────────────────────────────
def test_enable_active_after_recon() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_recon(sm)
    assert sm.enable_active(eid) is True
    assert sm.get_state(eid) == a2a_pb2.ACTIVE_APPROVED


# ── Test 7 ────────────────────────────────────────────────────
def test_enable_offensive_valid_sow() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_active(sm)
    assert sm.enable_offensive(eid, b"sow bytes") is True
    assert sm.get_state(eid) == a2a_pb2.OFFENSIVE_APPROVED


# ── Test 8 ────────────────────────────────────────────────────
def test_enable_offensive_empty_sow_raises() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_active(sm)
    with pytest.raises(SOWError):
        sm.enable_offensive(eid, b"")


# ── Test 9 ────────────────────────────────────────────────────
def test_emergency_stop_from_any_state() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    rec = sm.create_engagement("client_a", "x")
    assert sm.emergency_stop(rec.engagement_id, "manual abort") is True
    assert sm.get_state(rec.engagement_id) == a2a_pb2.EMERGENCY_STOP


# ── Test 10 ───────────────────────────────────────────────────
def test_emergency_stop_idempotent() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    rec = sm.create_engagement("client_a", "x")
    assert sm.emergency_stop(rec.engagement_id, "first") is True
    assert sm.emergency_stop(rec.engagement_id, "second") is True
    assert sm.get_state(rec.engagement_id) == a2a_pb2.EMERGENCY_STOP


# ── Test 11 ───────────────────────────────────────────────────
def test_alpha_can_proceed_recon() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_recon(sm)
    assert sm.can_agent_proceed(a2a_pb2.ALPHA, eid) is True


# ── Test 12 ───────────────────────────────────────────────────
def test_gamma_cannot_proceed_active() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_active(sm)
    assert sm.can_agent_proceed(a2a_pb2.GAMMA, eid) is False


# ── Test 13 ───────────────────────────────────────────────────
def test_gamma_can_proceed_offensive() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_offensive(sm)
    assert sm.can_agent_proceed(a2a_pb2.GAMMA, eid) is True


# ── Test 14 ───────────────────────────────────────────────────
def test_no_agent_proceeds_emergency_stop() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_offensive(sm)
    sm.emergency_stop(eid, "halt")
    for role in (
        a2a_pb2.CONDUCTOR,
        a2a_pb2.ALPHA,
        a2a_pb2.BETA,
        a2a_pb2.GAMMA,
        a2a_pb2.DELTA,
        a2a_pb2.EPSILON,
        a2a_pb2.OMEGA,
    ):
        assert sm.can_agent_proceed(role, eid) is False


# ── Test 15 ───────────────────────────────────────────────────
def test_is_in_scope_ip_inside_range() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_recon(sm)
    assert sm.is_in_scope(eid, "10.0.0.42") is True


# ── Test 16 ───────────────────────────────────────────────────
def test_is_in_scope_ip_excluded() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_recon(sm)
    assert sm.is_in_scope(eid, "10.0.0.5") is False


# ── Test 17 ───────────────────────────────────────────────────
def test_events_appended_to_store_on_transition() -> None:
    """C1.0: events are appended to the EventStore, not a callback."""
    store = _store()
    sm = AuthorizationStateMachine(event_store=store)
    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    sm.enable_recon(rec.engagement_id, _valid_scope())

    events = store.get_events(rec.engagement_id)
    event_types = [e.event_type for e in events]
    assert EventType.ENGAGEMENT_CREATED in event_types
    assert EventType.STATE_TRANSITIONED in event_types


# ── Test 18 ───────────────────────────────────────────────────
def test_sow_hash_stored_as_digest_not_raw() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    eid = _engagement_in_active(sm)
    sow_bytes = b"the full statement of work content"
    sm.enable_offensive(eid, sow_bytes)

    state = sm.get_state(eid)
    assert state == a2a_pb2.OFFENSIVE_APPROVED

    expected = hashlib.sha256(sow_bytes).digest()
    # C1.0: use public API (get_record), not private dict.
    record = sm.get_record(eid)
    assert record.sow_hash == expected
    assert record.sow_hash != sow_bytes
