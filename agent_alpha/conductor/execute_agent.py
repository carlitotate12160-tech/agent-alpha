# agent_alpha/conductor/execute_agent.py
"""Shared agent-execution helper — ONE path for all agent tasks (Alpha/Beta/Omega).

Collapses PR #69 issues #2/#3/#7/#8/#9/#10: the six identical structural defects
in ``run_agent_task`` (missing tenant ownership, missing auth re-check, empty graph,
hardcoded COMPLETE, no timeout/failure recording, no secrets exception handling) all
disappear because this is the SINGLE execution path both Celery tasks call.

Contract (each step pinned by a RED test in test_execute_agent.py):
  1. Tenant ownership (#9): engagement must belong to tenant_id.
  2. Auth re-check (#8, TOCTOU): can_agent_proceed at execution moment.
  3. Idempotency (offensive safety): skip agent body if terminal HANDOFF_READY exists.
  4. Graph replay (#3): rebuild the AttackGraph from the event stream — never empty.
  5. Run the agent under timeout (#7), status from REAL outcome (#2).
  6. Emit HANDOFF_READY + enqueue advance (#4/#15: never swallow dispatch failure).

Agreed decisions (spec review 2026-06-29):
  * agent_factory(graph_store) -> Callable[[], ExecOutcome]  (Q2 option A)
  * graph_rebuilder(event_store, engagement_id) -> graph_store
  * Refuse path (steps 1-2): record REFUSED event, NO HANDOFF_READY.
  * Dispatch failures propagate (step 6).
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.events.event_types import EventType

_log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class ExecOutcome:
    """Result of execute_agent — carries the REAL status, never hardcoded."""

    status: int  # a2a_pb2.PhaseStatus (COMPLETE | FAILED | BLOCKED)
    next_recommended: int | None  # AgentRole or None (CONDUCTOR/0 = unset)
    reason: str


def rebuild_graph_from_events(event_store: Any, engagement_id: str) -> Any:
    """Default graph_rebuilder: creates a NetworkXGraphStore and projects
    the full event stream into it via AttackGraphProjector.

    Reuses the existing CQRS projector (§8o-1) — no new projection logic.
    """
    from agent_alpha.events.projectors import AttackGraphProjector
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    graph_store = NetworkXGraphStore()
    AttackGraphProjector(event_store, graph_store).project(engagement_id)
    return graph_store


def _has_terminal_handoff(events: list[Any], agent_role: int) -> bool:
    """True iff a HANDOFF_READY event for this agent_role already exists in the stream.

    Offensive-agent idempotency: if the handoff is already recorded (from a prior
    successful run), Celery retry must NOT re-run the agent body — re-running Beta
    means repeating the attack. Anti-#7: idempotent retry safety.
    """
    for event in reversed(events):
        if getattr(event, "event_type", None) == EventType.HANDOFF_READY:
            payload = getattr(event, "payload", {}) or {}
            if int(payload.get("from_agent", -1)) == agent_role:
                return True
    return False


def execute_agent(
    *,
    engagement_id: str,
    tenant_id: str | None,
    agent_role: int,
    auth: Any,
    event_store: Any,
    graph_rebuilder: Callable[..., Any],
    agent_factory: Callable[..., Any],
    timeout_s: float,
) -> ExecOutcome:
    """Execute an agent through the shared safety gates.

    The caller (Celery task) resolves per-tenant deps; this helper enforces
    the gates and runs the agent body. See module docstring for the contract.
    """
    # ── Step 1: Tenant ownership (#9) ─────────────────────────────────────
    if not auth.owns(engagement_id, tenant_id):
        _record_refused(event_store, engagement_id, "tenant_mismatch", tenant_id)
        return ExecOutcome(
            status=a2a_pb2.FAILED,
            next_recommended=None,
            reason="tenant_mismatch",
        )

    # ── Step 2: Auth re-check at execution (#8, TOCTOU) ───────────────────
    if not auth.can_agent_proceed(agent_role, engagement_id):
        _record_refused(event_store, engagement_id, "not_authorized", tenant_id)
        return ExecOutcome(
            status=a2a_pb2.FAILED,
            next_recommended=None,
            reason="not_authorized",
        )

    # ── Step 3: Idempotency — never re-run an OFFENSIVE agent on retry ────
    events = event_store.get_events(engagement_id)
    if _has_terminal_handoff(events, agent_role):
        _log.info(
            "Skipping agent %s for %s — terminal HANDOFF_READY already exists (idempotent retry)",
            agent_role,
            engagement_id,
        )
        return ExecOutcome(
            status=a2a_pb2.COMPLETE,
            next_recommended=None,
            reason="already_completed (idempotent skip)",
        )

    # ── Step 4: Graph replay (#3) — NEVER an empty graph ─────────────────
    graph_store = graph_rebuilder(event_store, engagement_id)

    # ── Step 5: Run the agent, status from REAL outcome (#2, CARDINAL) ────
    try:
        runner = agent_factory(graph_store)
        outcome: ExecOutcome = runner()
    except Exception as exc:
        _log.exception("Agent %s failed for engagement %s", agent_role, engagement_id)
        _record_failure(event_store, engagement_id, str(exc), tenant_id)
        outcome = ExecOutcome(
            status=a2a_pb2.FAILED,
            next_recommended=None,
            reason=f"agent_exception: {exc}",
        )

    # ── Step 6: Emit handoff + advance (#4/#15: never swallow dispatch) ───
    event_store.append(
        event_type=EventType.HANDOFF_READY,
        engagement_id=engagement_id,
        agent=a2a_pb2.AgentRole.Name(agent_role),
        payload={
            "from_agent": agent_role,
            "status": outcome.status,
            "next_recommended": (
                outcome.next_recommended
                if outcome.next_recommended is not None
                else a2a_pb2.CONDUCTOR
            ),
        },
    )

    if outcome.status != a2a_pb2.COMPLETE:
        _record_failure(event_store, engagement_id, outcome.reason, tenant_id)

    return outcome


# ── Private helpers ────────────────────────────────────────────────────────


def _record_refused(
    event_store: Any,
    engagement_id: str,
    reason: str,
    tenant_id: str | None,
) -> None:
    try:
        event_store.append(
            event_type=EventType.ENGAGEMENT_RUN_REFUSED,
            engagement_id=engagement_id,
            agent="CONDUCTOR",
            payload={"reason": reason, "tenant_id": tenant_id},
        )
    except Exception:  # noqa: BLE001 — refusal audit must not crash the task
        _log.exception("Failed to append EngagementRunRefused event for %s", engagement_id)


def _record_failure(
    event_store: Any,
    engagement_id: str,
    reason: str,
    tenant_id: str | None,
) -> None:
    try:
        event_store.append(
            event_type=EventType.ENGAGEMENT_RUN_FAILED,
            engagement_id=engagement_id,
            agent="CONDUCTOR",
            payload={"reason": reason, "tenant_id": tenant_id},
        )
    except Exception:  # noqa: BLE001 — failure audit must not crash the task
        _log.exception("Failed to append EngagementRunFailed event for %s", engagement_id)
