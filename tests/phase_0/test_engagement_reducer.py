"""Phase 0 — Engagement reducer test contract.

9 tests covering the pure reducer: event folding, scope roundtrip,
sow_hash roundtrip, unknown event no-op, orphan event, missing optional
fields, empty stream, full lifecycle, and cross-instance reconstruction proof.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_engagement_reducer.py -v
"""

import hashlib

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import EngagementRecord, Scope
from agent_alpha.conductor.engagement_reducer import apply_event, rebuild_engagement
from agent_alpha.config.constants import SOW_HASH_ALGORITHM
from agent_alpha.events.store import AgentEvent, InMemoryEventStore


def _created_event(
    engagement_id: str = "eng_test0001",
    client_id: str = "client_a",
    target: str = "10.0.0.0/24",
    tenant_id: str | None = None,
    seq: int = 1,
) -> AgentEvent:
    payload: dict[str, object] = {
        "client_id": client_id,
        "target": target,
        "state": a2a_pb2.CREATED,
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    return AgentEvent(
        event_id="evt_1",
        event_type="EngagementCreated",
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        timestamp_utc="2026-01-01T00:00:00Z",
        payload=payload,
        sequence_number=seq,
    )


def _transitioned_event(
    engagement_id: str = "eng_test0001",
    from_state: int = a2a_pb2.CREATED,
    to_state: int = a2a_pb2.RECON_ONLY,
    scope: dict[str, object] | None = None,
    sow_hash: str | None = None,
    seq: int = 2,
) -> AgentEvent:
    payload: dict[str, object] = {"from_state": from_state, "to_state": to_state}
    if scope is not None:
        payload["scope"] = scope
    if sow_hash is not None:
        payload["sow_hash"] = sow_hash
    return AgentEvent(
        event_id="evt_2",
        event_type="StateTransitioned",
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        timestamp_utc="2026-01-01T00:01:00Z",
        payload=payload,
        sequence_number=seq,
    )


def _estop_event(
    engagement_id: str = "eng_test0001",
    from_state: int = a2a_pb2.CREATED,
    reason: str = "manual abort",
    seq: int = 2,
) -> AgentEvent:
    return AgentEvent(
        event_id="evt_3",
        event_type="EmergencyStop",
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        timestamp_utc="2026-01-01T00:02:00Z",
        payload={
            "from_state": from_state,
            "to_state": a2a_pb2.EMERGENCY_STOP,
            "reason": reason,
            "timeout_sec": 30,
        },
        sequence_number=seq,
    )


def _scope_dict() -> dict[str, object]:
    return {
        "ip_ranges": ["10.0.0.0/24"],
        "domains": ["example.com"],
        "exclusions": ["10.0.0.5"],
        "verified": True,
    }


# ── Test 1 ────────────────────────────────────────────────────
def test_engagement_created_produces_record() -> None:
    event = _created_event()
    record = apply_event(None, event)
    assert record is not None
    assert isinstance(record, EngagementRecord)
    assert record.engagement_id == "eng_test0001"
    assert record.client_id == "client_a"
    assert record.target == "10.0.0.0/24"
    assert record.state == a2a_pb2.CREATED
    assert record.scope is None
    assert record.sow_hash is None


# ── Test 2 ────────────────────────────────────────────────────
def test_state_transitioned_updates_state() -> None:
    record = apply_event(None, _created_event())
    assert record is not None
    record = apply_event(
        record,
        _transitioned_event(
            from_state=a2a_pb2.CREATED,
            to_state=a2a_pb2.RECON_ONLY,
            scope=_scope_dict(),
        ),
    )
    assert record is not None
    assert record.state == a2a_pb2.RECON_ONLY
    # Scope must survive the roundtrip (gate-critical).
    assert record.scope is not None
    assert record.scope.ip_ranges == ["10.0.0.0/24"]
    assert record.scope.domains == ["example.com"]
    assert record.scope.exclusions == ["10.0.0.5"]
    assert record.scope.verified is True


# ── Test 3 ────────────────────────────────────────────────────
def test_emergency_stop_overrides_state() -> None:
    record = apply_event(None, _created_event())
    assert record is not None
    record = apply_event(record, _estop_event(from_state=a2a_pb2.CREATED))
    assert record is not None
    assert record.state == a2a_pb2.EMERGENCY_STOP
    assert record.stopped_reason == "manual abort"


# ── Test 4 ────────────────────────────────────────────────────
def test_unknown_event_is_noop() -> None:
    record = apply_event(None, _created_event())
    assert record is not None
    original_state = record.state
    unknown = AgentEvent(
        event_id="evt_x",
        event_type="SomeUnknownFutureEvent",
        engagement_id="eng_test0001",
        agent="CONDUCTOR",
        timestamp_utc="2026-01-01T00:05:00Z",
        payload={"foo": "bar"},
        sequence_number=99,
    )
    result = apply_event(record, unknown)
    assert result is not None
    assert result.state == original_state


# ── Test 5 ────────────────────────────────────────────────────
def test_orphan_event_returns_none() -> None:
    """Event without a preceding ENGAGEMENT_CREATED (orphan) → None."""
    # No ENGAGEMENT_CREATED event, just a STATE_TRANSITIONED
    event = _transitioned_event()
    result = apply_event(None, event)
    assert result is None


# ── Test 6 ────────────────────────────────────────────────────
def test_rebuild_returns_none_for_empty_stream() -> None:
    assert rebuild_engagement([]) is None


# ── Test 7 ────────────────────────────────────────────────────
def test_missing_optional_fields_are_safe() -> None:
    """Event payload missing optional fields (no scope, no reason) does not crash."""
    record = apply_event(None, _created_event())
    assert record is not None

    # STATE_TRANSITIONED without scope
    event_no_scope = _transitioned_event(
        from_state=a2a_pb2.CREATED,
        to_state=a2a_pb2.RECON_ONLY,
        scope=None,  # missing optional field
    )
    result = apply_event(record, event_no_scope)
    assert result is not None
    assert result.state == a2a_pb2.RECON_ONLY
    assert result.scope is None  # safely remains None

    # EMERGENCY_STOP without reason
    event_no_reason = _estop_event(
        from_state=a2a_pb2.RECON_ONLY,
        reason="",  # empty/missing optional field
    )
    result = apply_event(result, event_no_reason)
    assert result is not None
    assert result.state == a2a_pb2.EMERGENCY_STOP
    # stopped_reason may be empty string (safe default)


# ── Test 8 ────────────────────────────────────────────────────
def test_rebuild_full_lifecycle() -> None:
    scope = _scope_dict()
    sow_bytes = b"statement of work content"
    sow_hash_hex = hashlib.new(SOW_HASH_ALGORITHM, sow_bytes).digest().hex()

    events = [
        _created_event(seq=1),
        _transitioned_event(
            from_state=a2a_pb2.CREATED,
            to_state=a2a_pb2.RECON_ONLY,
            scope=scope,
            seq=2,
        ),
        _transitioned_event(
            from_state=a2a_pb2.RECON_ONLY,
            to_state=a2a_pb2.ACTIVE_APPROVED,
            seq=3,
        ),
        _transitioned_event(
            from_state=a2a_pb2.ACTIVE_APPROVED,
            to_state=a2a_pb2.OFFENSIVE_APPROVED,
            sow_hash=sow_hash_hex,
            seq=4,
        ),
    ]
    record = rebuild_engagement(events)
    assert record is not None
    assert record.state == a2a_pb2.OFFENSIVE_APPROVED
    assert record.scope is not None
    assert record.scope.verified is True
    assert record.sow_hash == bytes.fromhex(sow_hash_hex)


# ── Test 9 ────────────────────────────────────────────────────
def test_fresh_process_reconstruction() -> None:
    """Build a store, run transitions via the SM, then independently
    rebuild from events — proving any fresh process converges to the
    same state."""
    from agent_alpha.conductor.authorization import AuthorizationStateMachine

    store = InMemoryEventStore()
    sm = AuthorizationStateMachine(event_store=store)

    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    sm.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=["10.0.0.0/24"],
            domains=["example.com"],
            exclusions=["10.0.0.5"],
        ),
    )
    sm.enable_active(rec.engagement_id)
    sm.enable_offensive(rec.engagement_id, b"sow content bytes")

    # "Fresh process" — rebuild from the raw event stream, no SM involved.
    events = store.get_events(rec.engagement_id)
    rebuilt = rebuild_engagement(events)
    assert rebuilt is not None
    assert rebuilt.state == sm.get_state(rec.engagement_id)
    assert rebuilt.scope is not None
    assert rebuilt.scope.ip_ranges == ["10.0.0.0/24"]
    assert rebuilt.scope.verified is True
    assert rebuilt.sow_hash is not None
    assert rebuilt.sow_hash == sm.get_record(rec.engagement_id).sow_hash
