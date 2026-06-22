"""Real Celery task revoker for the emergency kill switch (Phase 3 / C4).

`EmergencyStopHandler` flips the authorization gate to EMERGENCY_STOP — that is the
SYNCHRONOUS, authoritative guarantee that no agent proceeds (can_agent_proceed →
False). This revoker is the second arm: it terminates work already in flight by
broadcasting a Celery revoke for every task the engagement ever queued.

Honesty about the guarantee (anti-Lyndon #3 — no false success):
`control.revoke` is a fire-and-forget control broadcast to the workers; it does
NOT block for, or confirm, actual task death. The hard "blocks further actions"
guarantee is the auth-state flip (already done by the handler before this runs);
revocation is best-effort termination of in-flight tasks. The count returned is
the number of task_ids we *issued a revoke for*, not a death certificate.

Tenant scope: the revoker is built per-tenant in `main.emergency_for(tenant_id)`,
closing over that tenant's EventStore, so it reads task_ids from the correct
RLS-scoped store. The `CeleryRevoker` Protocol (emergency.py) stays
`revoke_engagement_tasks(engagement_id) -> int` — no signature change
(anti-Lyndon #10).
"""

from __future__ import annotations

import logging
import typing

from agent_alpha.conductor.run_status import collect_run_task_ids
from agent_alpha.events.store import EventStore

_log = logging.getLogger(__name__)

# SIGKILL: the kill switch must not rely on a graceful handler the task may ignore.
_REVOKE_SIGNAL = "SIGKILL"


class TaskControl(typing.Protocol):
    """The slice of Celery's ``app.control`` the revoker needs. Declared
    structurally so the revoker is testable without a live broker."""

    def revoke(
        self,
        task_id: str,
        *,
        terminate: bool = ...,
        signal: str = ...,
    ) -> typing.Any: ...


class CeleryTaskRevoker:
    """Revoke ALL Celery tasks an engagement queued, via a tenant-scoped store."""

    def __init__(self, control: TaskControl, store: EventStore) -> None:
        self._control = control
        self._store = store

    def revoke_engagement_tasks(self, engagement_id: str) -> int:
        """Revoke every task_id the engagement ever queued; return the count issued.

        Best-effort per task (a single broker error must not abort the rest, nor
        crash the kill switch): each failure is logged and skipped. Returns the
        number of tasks for which a revoke was successfully issued.
        """
        task_ids = collect_run_task_ids(self._store.get_events(engagement_id))
        revoked = 0
        for task_id in task_ids:
            try:
                self._control.revoke(task_id, terminate=True, signal=_REVOKE_SIGNAL)
            except Exception:  # noqa: BLE001 — one broker hiccup must not stop the rest
                _log.exception(
                    "revoke failed for task_id=%s (engagement_id=%s)", task_id, engagement_id
                )
                continue
            revoked += 1
        return revoked
