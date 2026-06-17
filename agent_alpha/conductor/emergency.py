# agent_alpha/conductor/emergency.py
# Phase 0 — Emergency stop, the single-authority kill switch (ADR §1).
#
# Emergency stop is a single authority that lives in the Conductor. When
# triggered it truly stops ALL agents for an engagement by (a) forcing the
# AuthorizationStateMachine into EMERGENCY_STOP (which makes can_agent_proceed
# return False for everyone) and (b) revoking every outstanding Celery task.
#
# Phase 0: Celery is not running yet, so revocation goes through an injected
# CeleryRevoker Protocol (None = Phase 0 mock — zero tasks). The real Celery
# revoke is wired in Phase 3 by passing a concrete revoker.

import datetime
import logging
import time
import typing
from dataclasses import dataclass

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.config.constants import EMERGENCY_STOP_TIMEOUT_SEC
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import EventStore

_log = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with a 'Z' suffix."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"


@dataclass(frozen=True)
class EmergencyStopResult:
    engagement_id: str
    success: bool
    tasks_revoked: int
    elapsed_ms: float
    reason: str
    timestamp_utc: str


class CeleryRevoker(typing.Protocol):
    def revoke_engagement_tasks(self, engagement_id: str) -> int:
        """Revoke all Celery tasks for the engagement; return the count revoked."""
        ...


class EmergencyStopHandler:
    """Single-authority kill switch coordinating auth + Celery revocation."""

    def __init__(
        self,
        auth: AuthorizationStateMachine,
        event_store: EventStore,
        celery_revoker: CeleryRevoker | None = None,
    ) -> None:
        self._auth = auth
        self._event_store = event_store
        self._celery_revoker = celery_revoker

    def execute(
        self,
        engagement_id: str,
        reason: str,
        issued_by: str,
    ) -> EmergencyStopResult:
        """Stop ALL agents for an engagement. Best-effort; NEVER raises."""
        start_ns = time.perf_counter_ns()
        tasks_revoked = 0
        success = True

        try:
            # Step 2: force the authorization gate into EMERGENCY_STOP.
            self._auth.emergency_stop(engagement_id, reason)

            # Step 3: revoke all Celery tasks (None revoker = Phase 0 mock).
            if self._celery_revoker is None:
                _log.warning(
                    "No CeleryRevoker injected (Phase 0): skipping task revocation "
                    "for engagement_id=%s",
                    engagement_id,
                )
            else:
                tasks_revoked = self._celery_revoker.revoke_engagement_tasks(engagement_id)

            # Step 4: emit the audit event.
            self._event_store.append(
                event_type=EventType.EMERGENCY_STOP_EXECUTED,
                engagement_id=engagement_id,
                agent="CONDUCTOR",
                payload={
                    "reason": reason,
                    "issued_by": issued_by,
                    "tasks_revoked": tasks_revoked,
                },
            )
        except Exception:  # noqa: BLE001 — kill switch must never propagate errors
            _log.exception("Emergency stop failed for engagement_id=%s", engagement_id)
            success = False

        # Step 5: compute elapsed wall-clock time in milliseconds.
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

        # Step 6: warn (do not fail) if the stop exceeded the budget.
        if elapsed_ms > EMERGENCY_STOP_TIMEOUT_SEC * 1000:
            _log.warning(
                "Emergency stop for engagement_id=%s took %.1fms, exceeding budget of %dms",
                engagement_id,
                elapsed_ms,
                EMERGENCY_STOP_TIMEOUT_SEC * 1000,
            )

        return EmergencyStopResult(
            engagement_id=engagement_id,
            success=success,
            tasks_revoked=tasks_revoked,
            elapsed_ms=elapsed_ms,
            reason=reason,
            timestamp_utc=_utc_now_iso(),
        )

    def is_stopped(self, engagement_id: str) -> bool:
        """Return True if the engagement is in EMERGENCY_STOP. Never raises."""
        try:
            return bool(self._auth.get_state(engagement_id) == a2a_pb2.EMERGENCY_STOP)
        except Exception:  # noqa: BLE001 — unknown engagement is simply "not stopped"
            return False
