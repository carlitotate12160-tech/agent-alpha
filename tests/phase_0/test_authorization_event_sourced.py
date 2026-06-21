"""Phase 0 — AuthorizationStateMachine event-sourced properties.

5 tests proving the event-sourced invariants: shared store visibility,
cache-is-not-truth, event ordering, scope survives rebuild, sow_hash
survives rebuild.

These are IN-MEMORY tests (fast) — they prove the reducer, not cross-
process reconstruction. The real cross-process proof lives in
tests/integration/test_cross_process_auth.py (Postgres, separate connections).

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_authorization_event_sourced.py -v
"""

import hashlib

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import (
    AuthorizationStateMachine,
    EngagementRecord,
    Scope,
)
from agent_alpha.conductor.engagement_reducer import rebuild_engagement
from agent_alpha.config.constants import SOW_HASH_ALGORITHM
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore


def _valid_scope() -> Scope:
    return Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=["example.com"],
        exclusions=["10.0.0.5"],
    )


# ── Test 1 ────────────────────────────────────────────────────
def test_separate_sm_instances_share_state_via_store() -> None:
    """SM2 sees engagements created by SM1 through the shared store.

    Proves reducer correctness with a shared InMemoryEventStore, NOT
    cross-process (the Postgres integration test proves that).
    """
    store = InMemoryEventStore()
    sm1 = AuthorizationStateMachine(event_store=store)
    sm2 = AuthorizationStateMachine(event_store=store)

    rec = sm1.create_engagement("client_a", "10.0.0.0/24")
    sm1.enable_recon(rec.engagement_id, _valid_scope())

    # SM2 must see the engagement and its current state.
    state = sm2.get_state(rec.engagement_id)
    assert state == a2a_pb2.RECON_ONLY

    record = sm2.get_record(rec.engagement_id)
    assert record.client_id == "client_a"
    assert record.scope is not None
    assert record.scope.verified is True


# ── Test 2 ────────────────────────────────────────────────────
def test_cache_is_not_source_of_truth() -> None:
    """Corrupt the cache — the SM must still return the correct state
    because _rebuild reads from the event store, not the cache."""
    store = InMemoryEventStore()
    sm = AuthorizationStateMachine(event_store=store)

    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    sm.enable_recon(rec.engagement_id, _valid_scope())

    # Corrupt the cache.
    sm._cache[rec.engagement_id] = EngagementRecord(  # noqa: SLF001
        engagement_id=rec.engagement_id,
        client_id="CORRUPTED",
        target="CORRUPTED",
        state=a2a_pb2.EMERGENCY_STOP,
        scope=None,
        sow_hash=None,
        created_at="",
        updated_at="",
        stopped_reason="CORRUPTED",
    )

    # The SM must read through the store, not the corrupted cache.
    state = sm.get_state(rec.engagement_id)
    assert state == a2a_pb2.RECON_ONLY
    record = sm.get_record(rec.engagement_id)
    assert record.client_id == "client_a"


# ── Test 3 ────────────────────────────────────────────────────
def test_transition_events_appended_to_store() -> None:
    """Full lifecycle → events in the store match expected types + order."""
    store = InMemoryEventStore()
    sm = AuthorizationStateMachine(event_store=store)

    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    eid = rec.engagement_id
    sm.enable_recon(eid, _valid_scope())
    sm.enable_active(eid)
    sm.enable_offensive(eid, b"sow content")
    sm.emergency_stop(eid, "halt")

    events = store.get_events(eid)
    event_types = [e.event_type for e in events]
    assert event_types == [
        EventType.ENGAGEMENT_CREATED,
        EventType.STATE_TRANSITIONED,  # → RECON_ONLY
        EventType.STATE_TRANSITIONED,  # → ACTIVE_APPROVED
        EventType.STATE_TRANSITIONED,  # → OFFENSIVE_APPROVED
        EventType.EMERGENCY_STOP,
    ]


# ── Test 4 ────────────────────────────────────────────────────
def test_scope_survives_rebuild() -> None:
    """Create + enable_recon, rebuild from events → scope intact,
    is_in_scope works, enable_active succeeds."""
    store = InMemoryEventStore()
    sm = AuthorizationStateMachine(event_store=store)

    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    eid = rec.engagement_id
    original_scope = _valid_scope()
    sm.enable_recon(eid, original_scope)

    # Rebuild from raw events (simulating a fresh process).
    events = store.get_events(eid)
    rebuilt = rebuild_engagement(events)
    assert rebuilt is not None
    assert rebuilt.scope is not None
    assert rebuilt.scope.ip_ranges == original_scope.ip_ranges
    assert rebuilt.scope.domains == original_scope.domains
    assert rebuilt.scope.exclusions == original_scope.exclusions
    assert rebuilt.scope.verified is True

    # is_in_scope must work on the rebuilt state.
    assert sm.is_in_scope(eid, "10.0.0.42") is True
    assert sm.is_in_scope(eid, "10.0.0.5") is False  # excluded

    # enable_active must succeed (requires verified scope).
    assert sm.enable_active(eid) is True
    assert sm.get_state(eid) == a2a_pb2.ACTIVE_APPROVED


# ── Test 5 ────────────────────────────────────────────────────
def test_sow_hash_survives_rebuild() -> None:
    """Full lifecycle through enable_offensive, rebuild → sow_hash matches."""
    store = InMemoryEventStore()
    sm = AuthorizationStateMachine(event_store=store)

    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    eid = rec.engagement_id
    sm.enable_recon(eid, _valid_scope())
    sm.enable_active(eid)
    sow_bytes = b"the full statement of work content"
    sm.enable_offensive(eid, sow_bytes)

    expected_hash = hashlib.new(SOW_HASH_ALGORITHM, sow_bytes).digest()

    # Verify via the SM public API.
    record = sm.get_record(eid)
    assert record.sow_hash == expected_hash

    # Rebuild from raw events — sow_hash must roundtrip through hex encoding.
    events = store.get_events(eid)
    rebuilt = rebuild_engagement(events)
    assert rebuilt is not None
    assert rebuilt.sow_hash == expected_hash
