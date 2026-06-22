"""C4 contract: real Celery revoker for the emergency kill switch.

Two units + one integration, all hermetic (a fake control stands in for the
Celery broker — no network, no worker):

  * `collect_run_task_ids` returns EVERY queued task_id (deduped, ordered) — not
    just the latest like `project_run_status` (the split that would otherwise let
    a fan-out engagement keep a task alive through a stop).
  * `CeleryTaskRevoker` revokes each task_id with terminate=True + SIGKILL, returns
    the count issued, survives a per-task broker error, and is best-effort.
  * End-to-end via `EmergencyStopHandler`: a stop revokes all queued tasks AND
    flips auth to EMERGENCY_STOP (can_agent_proceed denied) within the 5s budget.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_emergency_revoker.py -v
"""

from __future__ import annotations

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.emergency import EmergencyStopHandler
from agent_alpha.conductor.revoker import CeleryTaskRevoker
from agent_alpha.conductor.run_status import collect_run_task_ids
from agent_alpha.config.constants import EMERGENCY_STOP_TIMEOUT_SEC
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import EventStore, InMemoryEventStore


class _FakeControl:
    """Records revoke broadcasts instead of hitting a broker."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bool, str]] = []

    def revoke(self, task_id: str, *, terminate: bool = False, signal: str = "SIGTERM") -> None:
        self.calls.append((task_id, terminate, signal))


class _RaisingControl:
    """Fails the second revoke to prove best-effort continuation."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def revoke(self, task_id: str, *, terminate: bool = False, signal: str = "SIGTERM") -> None:
        self.calls.append(task_id)
        if task_id == "t2":
            raise RuntimeError("broker unreachable")


def _queue(store: EventStore, engagement_id: str, task_id: str) -> None:
    store.append(
        event_type=EventType.ENGAGEMENT_RUN_QUEUED,
        engagement_id=engagement_id,
        agent="API",
        payload={"task_id": task_id},
    )


# ── collect_run_task_ids ──────────────────────────────────────────────


def test_collect_returns_all_queued_task_ids_in_order() -> None:
    store = InMemoryEventStore()
    _queue(store, "eng1", "t1")
    _queue(store, "eng1", "t2")
    assert collect_run_task_ids(store.get_events("eng1")) == ["t1", "t2"]


def test_collect_dedupes_and_ignores_non_queued() -> None:
    store = InMemoryEventStore()
    _queue(store, "eng1", "t1")
    _queue(store, "eng1", "t1")  # duplicate dispatch record
    store.append(
        event_type=EventType.ENGAGEMENT_RUN_STARTED,
        engagement_id="eng1",
        agent="CONDUCTOR",
        payload={},
    )
    assert collect_run_task_ids(store.get_events("eng1")) == ["t1"]


def test_collect_empty_when_no_queued() -> None:
    store = InMemoryEventStore()
    assert collect_run_task_ids(store.get_events("eng1")) == []


# ── CeleryTaskRevoker ─────────────────────────────────────────────────


def test_revoker_revokes_every_task_with_terminate_sigkill() -> None:
    store = InMemoryEventStore()
    _queue(store, "eng1", "t1")
    _queue(store, "eng1", "t2")
    control = _FakeControl()

    revoked = CeleryTaskRevoker(control, store).revoke_engagement_tasks("eng1")

    assert revoked == 2
    assert control.calls == [("t1", True, "SIGKILL"), ("t2", True, "SIGKILL")]


def test_revoker_returns_zero_when_nothing_queued() -> None:
    store = InMemoryEventStore()
    control = _FakeControl()
    assert CeleryTaskRevoker(control, store).revoke_engagement_tasks("eng1") == 0
    assert control.calls == []


def test_revoker_is_best_effort_on_broker_error() -> None:
    store = InMemoryEventStore()
    for tid in ("t1", "t2", "t3"):
        _queue(store, "eng1", tid)
    control = _RaisingControl()

    revoked = CeleryTaskRevoker(control, store).revoke_engagement_tasks("eng1")

    assert control.calls == ["t1", "t2", "t3"]  # t2 raised but t3 still attempted
    assert revoked == 2  # t1 + t3 issued; t2 failed


# ── integration via EmergencyStopHandler ──────────────────────────────


def test_emergency_stop_revokes_all_and_blocks_within_budget() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    control = _FakeControl()
    handler = EmergencyStopHandler(auth, store, celery_revoker=CeleryTaskRevoker(control, store))

    eng = auth.create_engagement("client_a", "10.0.0.0/24").engagement_id
    _queue(store, eng, "t1")
    _queue(store, eng, "t2")

    result = handler.execute(eng, reason="abort", issued_by="operator")

    assert result.success is True
    assert result.tasks_revoked == 2
    assert {c[0] for c in control.calls} == {"t1", "t2"}
    # authoritative guarantee: gate flipped + no agent may proceed
    assert auth.get_state(eng) == a2a_pb2.EMERGENCY_STOP
    assert auth.can_agent_proceed(a2a_pb2.ALPHA, eng) is False
    # budget (single source of truth)
    assert result.elapsed_ms < EMERGENCY_STOP_TIMEOUT_SEC * 1000
