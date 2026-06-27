"""Phase 0 — Run status projection test contract.

Tests the project_run_status pure projection function:
- Empty events → status "none" with no task_id
- QUEUED → status "queued" + task_id present
- QUEUED → STARTED → "running"
- COMPLETED → "done"
- FAILED → "failed"
- REFUSED → "refused"
- Unrelated events (ENGAGEMENT_CREATED, NODE_DISCOVERED) ignored
- Pure function: input events not mutated

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_run_status.py -v
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_alpha.conductor.run_status import project_run_status
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent


def _make_event(
    event_type: EventType,
    engagement_id: str = "eng_1",
    payload: dict | None = None,
) -> AgentEvent:
    """Helper to create a test event."""
    return AgentEvent(
        event_id="test-event-id",
        event_type=event_type,
        engagement_id=engagement_id,
        agent="API",
        timestamp_utc=datetime.now(UTC).isoformat(),
        payload=payload or {},
        sequence_number=1,
    )


def test_empty_events_returns_none_status() -> None:
    """Empty events → status "none" with no task_id."""
    events: list[AgentEvent] = []
    status = project_run_status(events)

    assert status.status == "none"
    assert status.task_id is None
    assert status.updated_at is None


def test_queued_event_sets_status_queued_with_task_id() -> None:
    """QUEUED → status "queued" + task_id present."""
    events = [
        _make_event(
            EventType.ENGAGEMENT_RUN_QUEUED,
            payload={"task_id": "task-123", "tenant_id": "tenant-a"},
        )
    ]
    status = project_run_status(events)

    assert status.status == "queued"
    assert status.task_id == "task-123"
    assert status.updated_at is not None


def test_queued_then_started_sets_status_running() -> None:
    """QUEUED → STARTED → "running"."""
    events = [
        _make_event(
            EventType.ENGAGEMENT_RUN_QUEUED,
            payload={"task_id": "task-123", "tenant_id": "tenant-a"},
        ),
        _make_event(EventType.ENGAGEMENT_RUN_STARTED),
    ]
    status = project_run_status(events)

    assert status.status == "running"
    assert status.task_id == "task-123"  # task_id preserved from QUEUED
    assert status.updated_at is not None


def test_completed_sets_status_done() -> None:
    """COMPLETED → "done"."""
    events = [
        _make_event(
            EventType.ENGAGEMENT_RUN_QUEUED,
            payload={"task_id": "task-123", "tenant_id": "tenant-a"},
        ),
        _make_event(EventType.ENGAGEMENT_RUN_STARTED),
        _make_event(EventType.ENGAGEMENT_RUN_COMPLETED),
    ]
    status = project_run_status(events)

    assert status.status == "done"
    assert status.task_id == "task-123"
    assert status.updated_at is not None


def test_failed_sets_status_failed() -> None:
    """FAILED → "failed"."""
    events = [
        _make_event(
            EventType.ENGAGEMENT_RUN_QUEUED,
            payload={"task_id": "task-123", "tenant_id": "tenant-a"},
        ),
        _make_event(EventType.ENGAGEMENT_RUN_STARTED),
        _make_event(EventType.ENGAGEMENT_RUN_FAILED),
    ]
    status = project_run_status(events)

    assert status.status == "failed"
    assert status.task_id == "task-123"
    assert status.updated_at is not None


def test_refused_sets_status_refused() -> None:
    """REFUSED → "refused"."""
    events = [
        _make_event(
            EventType.ENGAGEMENT_RUN_REFUSED,
            payload={"reason": "unauthorized"},
        )
    ]
    status = project_run_status(events)

    assert status.status == "refused"
    assert status.task_id is None  # no task_id for refused
    assert status.updated_at is not None


def test_unrelated_events_ignored() -> None:
    """Unrelated events (ENGAGEMENT_CREATED, NODE_DISCOVERED) ignored."""
    events = [
        _make_event(EventType.ENGAGEMENT_CREATED),
        _make_event(EventType.NODE_DISCOVERED),
    ]
    status = project_run_status(events)

    assert status.status == "none"
    assert status.task_id is None
    assert status.updated_at is None


def test_pure_function_does_not_mutate_input_events() -> None:
    """Pure function: input events not mutated."""
    events = [
        _make_event(
            EventType.ENGAGEMENT_RUN_QUEUED,
            payload={"task_id": "task-123", "tenant_id": "tenant-a"},
        )
    ]
    original_payload = events[0].payload.copy()

    project_run_status(events)

    # Input events should not be mutated
    assert events[0].payload == original_payload
