# agent_alpha/conductor/run_status.py
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent

RunStatusLiteral = Literal["queued", "running", "done", "failed", "refused", "none"]


@dataclass(frozen=True)
class RunStatus:
    status: RunStatusLiteral
    task_id: str | None
    updated_at: str | None


def project_run_status(events: Iterable[AgentEvent]) -> RunStatus:
    """Pure projection folding run events into a single RunStatus.

    Reads only run events; ignores others.
    """
    status: RunStatusLiteral = "none"
    task_id: str | None = None
    updated_at: str | None = None

    for event in events:
        if event.event_type == EventType.ENGAGEMENT_RUN_QUEUED:
            status = "queued"
            payload_task_id = event.payload.get("task_id")
            if isinstance(payload_task_id, str):
                task_id = payload_task_id
            updated_at = event.timestamp_utc
        elif event.event_type == EventType.ENGAGEMENT_RUN_STARTED:
            status = "running"
            updated_at = event.timestamp_utc
        elif event.event_type == EventType.ENGAGEMENT_RUN_COMPLETED:
            status = "done"
            updated_at = event.timestamp_utc
        elif event.event_type == EventType.ENGAGEMENT_RUN_FAILED:
            status = "failed"
            updated_at = event.timestamp_utc
        elif event.event_type == EventType.ENGAGEMENT_RUN_REFUSED:
            status = "refused"
            updated_at = event.timestamp_utc

    return RunStatus(
        status=status,
        task_id=task_id,
        updated_at=updated_at,
    )
