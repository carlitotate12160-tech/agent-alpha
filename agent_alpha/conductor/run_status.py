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


def collect_run_task_ids(events: Iterable[AgentEvent]) -> list[str]:
    """Return EVERY task_id ever dispatched for an engagement, in order, deduped.

    `project_run_status` deliberately collapses to the *latest* task_id (for a
    status read). Emergency revocation (C4) must instead revoke ALL tasks an
    engagement ever queued — a single engagement can map to many tasks once
    fan-out (§12.13 / C5) lands. This is the single source of truth for the
    RUN_QUEUED -> task_id mapping; the revoker reuses it rather than re-deriving
    it (anti-Lyndon #7).
    """
    task_ids: list[str] = []
    seen: set[str] = set()
    for event in events:
        if event.event_type != EventType.ENGAGEMENT_RUN_QUEUED:
            continue
        task_id = event.payload.get("task_id")
        if isinstance(task_id, str) and task_id and task_id not in seen:
            seen.add(task_id)
            task_ids.append(task_id)
    return task_ids
