"""Phase 0 — EmergencyStopHandler test contract.

10 tests covering the single-authority kill switch: success path, auth state
transition, event emission, None-revoker (Phase 0 mock), idempotent double
stop, elapsed timing, is_stopped queries, and exception isolation.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_emergency.py -v
"""

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.emergency import EmergencyStopHandler
from agent_alpha.events.store import EventStore


class _MockRevoker:
    def __init__(self, count: int = 3) -> None:
        self._count = count

    def revoke_engagement_tasks(self, engagement_id: str) -> int:
        return self._count


class _RaisingRevoker:
    def revoke_engagement_tasks(self, engagement_id: str) -> int:
        raise RuntimeError("celery broker unreachable")


def _make_engagement(auth: AuthorizationStateMachine) -> str:
    return auth.create_engagement("client_a", "10.0.0.0/24").engagement_id


def _handler(
    revoker: object | None = None,
) -> tuple[EmergencyStopHandler, AuthorizationStateMachine, EventStore, str]:
    auth = AuthorizationStateMachine()
    store = EventStore()
    handler = EmergencyStopHandler(auth, store, celery_revoker=revoker)  # type: ignore[arg-type]
    engagement_id = _make_engagement(auth)
    return handler, auth, store, engagement_id


def test_execute_with_mock_revoker_succeeds() -> None:
    handler, _auth, _store, eng = _handler(_MockRevoker(count=2))
    result = handler.execute(eng, "abort", "operator")
    assert result.success is True


def test_execute_transitions_state_to_emergency_stop() -> None:
    handler, auth, _store, eng = _handler(_MockRevoker())
    handler.execute(eng, "abort", "operator")
    assert auth.get_state(eng) == a2a_pb2.EMERGENCY_STOP


def test_execute_emits_event() -> None:
    handler, _auth, store, eng = _handler(_MockRevoker())
    handler.execute(eng, "abort", "operator")
    events = store.get_events(eng)
    assert any(e.event_type == "EmergencyStopExecuted" for e in events)


def test_execute_with_none_revoker() -> None:
    handler, _auth, _store, eng = _handler(None)
    result = handler.execute(eng, "abort", "operator")
    assert result.success is True
    assert result.tasks_revoked == 0


def test_execute_twice_is_idempotent() -> None:
    handler, _auth, _store, eng = _handler(_MockRevoker())
    first = handler.execute(eng, "abort", "operator")
    second = handler.execute(eng, "abort again", "operator")
    assert first.success is True
    assert second.success is True


def test_execute_records_positive_elapsed_ms() -> None:
    handler, _auth, _store, eng = _handler(_MockRevoker())
    result = handler.execute(eng, "abort", "operator")
    assert result.elapsed_ms > 0


def test_is_stopped_true_after_execute() -> None:
    handler, _auth, _store, eng = _handler(_MockRevoker())
    handler.execute(eng, "abort", "operator")
    assert handler.is_stopped(eng) is True


def test_is_stopped_false_for_unknown_engagement() -> None:
    handler, _auth, _store, _eng = _handler(_MockRevoker())
    assert handler.is_stopped("eng_does_not_exist") is False


def test_execute_with_raising_revoker_does_not_propagate() -> None:
    handler, _auth, _store, eng = _handler(_RaisingRevoker())
    result = handler.execute(eng, "abort", "operator")
    assert result.success is False


def test_tasks_revoked_matches_mock_count() -> None:
    handler, _auth, _store, eng = _handler(_MockRevoker(count=7))
    result = handler.execute(eng, "abort", "operator")
    assert result.tasks_revoked == 7
