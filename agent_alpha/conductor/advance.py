"""Conductor handoff-consumer — auto-advances the kill chain (Alpha→Beta→…→Omega) on
the Celery path, WITHOUT any agent ever calling another agent (non-negotiable).

Closes audit gap A1 (Conductor does not consume handoffs; the payable chain only runs via
live_fire/chain_runner.py). This module IS the autonomous spine: it moves the chain off
the single-process script onto the Conductor/Celery path, and it is the call-site where
the applicator factory (Step 3c) feeds Beta's cred_reuse task.

THE SEAM (why it's non-bypassable):
  An agent task, on completion, appends a HANDOFF_READY event and signals the Conductor to
  advance. It NEVER enqueues the next agent and NEVER reads authorization state. The
  Conductor's advance_engagement() is the SINGLE place that:
    1. reads the latest handoff from the event stream (event-sourced, replay-safe),
    2. validates the handoff contract (status + a forward, non-replay transition),
    3. checks the authorization gate permits the recommended next agent,
    4. builds the applicators (factory) for the next agent, and
    5. enqueues the next agent's task via an injected dispatcher.

CRITICAL — auto-advance RESPECTS the auth gate, never softens it (anti "auth-gate
softening"):
  Alpha (RECON_ONLY) → Beta (ACTIVE_APPROVED) is an AUTHORIZATION-TIER boundary. The
  Conductor does NOT auto-promote auth state. It auto-advances ONLY to an agent whose
  required tier is ALREADY granted (a human ran enable_active / enable_offensive). If the
  next agent needs a higher tier than currently granted, the engagement PARKS
  (AWAITING_APPROVAL, requires_human_approval=True) — autonomy WITHIN a tier, human gate
  BETWEEN tiers.

Lane: Claude (Conductor orchestration). No offensive body. The agent bodies (Alpha/Beta
cognitive loops) already exist; this only sequences them.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Protocol

from agent_alpha.a2a import a2a_pb2

# Canonical kill-chain topology — single source of truth (#7). Advancement may only go
# FORWARD along this order (or jump to OMEGA, the read-only reporter, at any point). This
# is a secondary anti-injection guard; the auth gate (can_agent_proceed) is the primary.
KILL_CHAIN_ORDER: tuple[int, ...] = (
    a2a_pb2.ALPHA,
    a2a_pb2.BETA,
    a2a_pb2.GAMMA,
    a2a_pb2.DELTA,
    a2a_pb2.EPSILON,
    a2a_pb2.OMEGA,
)

# Agents that consume harvested credentials → the factory must build their applicators at
# dispatch time. Other agents get an empty list (no applicator wiring needed).
_APPLICATOR_CONSUMERS: frozenset[int] = frozenset({a2a_pb2.BETA})


@dataclasses.dataclass(frozen=True)
class Handoff:
    """Read-model of the latest handoff (A2AMessage envelope + HandoffPayload).

    Field SEMANTICS follow proto/a2a.proto EXACTLY (the single source of truth):
      * status — PhaseStatus enum int (a2a_pb2.COMPLETE == 2), NOT a string.
      * next_recommended — AgentRole enum int. proto3 zero-value = CONDUCTOR (0) = "unset
        / no next"; the caller normalizes that to None (we NEVER auto-dispatch to the
        Conductor — that would be the proto3 false-default trap, #3 family).
      * from_agent — the A2AMessage envelope AgentRole (NOT a payload string).
    """

    from_agent: int
    status: int  # PhaseStatus enum (a2a_pb2.COMPLETE / FAILED / ...)
    next_recommended: int | None  # AgentRole; None when unset (CONDUCTOR / 0)
    seq: int  # event sequence — idempotency key vs AGENT_DISPATCHED


@dataclasses.dataclass(frozen=True)
class AdvanceDecision:
    """Pure decision — no side effects. advance_engagement() executes it."""

    action: str  # "dispatch" | "park_awaiting_approval" | "halt_complete" | "noop"
    next_agent: int | None
    reason: str


class Dispatcher(Protocol):
    """Injected Celery enqueuer (mirrors the CeleryRevoker injection pattern). In prod it
    calls run_agent_task.delay(...); in tests it's a spy. Advancement NEVER imports Celery
    directly — keeps advance_engagement testable without a broker."""

    def dispatch(self, *, engagement_id: str, agent: int, applicators: list[Any]) -> None: ...


class ApplicatorBuilder(Protocol):
    """Conductor-side factory wrapper. Returns the BoundApplicator list for an agent that
    consumes credentials (Beta), or [] otherwise. Wraps
    build_applicators_for_engagement so advance stays decoupled from factory internals."""

    def __call__(self, engagement_id: str, agent: int) -> list[Any]: ...


# ── Pure decision ──────────────────────────────────────────────────────────────


def _is_forward_transition(from_agent: int, next_agent: int) -> bool:
    """True iff next_agent is strictly later than from_agent in the kill chain, or is the
    read-only reporter (OMEGA). Blocks backward jumps and phase-skipping injected
    handoffs."""
    if next_agent == a2a_pb2.OMEGA:
        return True
    if from_agent not in KILL_CHAIN_ORDER or next_agent not in KILL_CHAIN_ORDER:
        return False
    return KILL_CHAIN_ORDER.index(next_agent) > KILL_CHAIN_ORDER.index(from_agent)


def decide_advance(
    *,
    status: int,
    from_agent: int,
    next_recommended: int | None,
    current_state: int,
    next_permitted: bool,
    already_dispatched: bool,
) -> AdvanceDecision:
    """Decide the next action for an engagement given its latest handoff. Pure: takes the
    auth verdict (``next_permitted``) as a value rather than reading the gate itself, so it
    is fully unit-testable and the gate read stays in advance_engagement.

    ``status`` is a PhaseStatus enum int; we advance ONLY on a2a_pb2.COMPLETE (PENDING=0,
    the proto3 default, is therefore never mistaken for done — anti false-default #3)."""
    if current_state == a2a_pb2.EMERGENCY_STOP:
        return AdvanceDecision("noop", None, "engagement halted (emergency stop)")
    if status != a2a_pb2.COMPLETE:
        return AdvanceDecision("noop", None, f"handoff status={status}, not COMPLETE")
    if next_recommended is None:
        return AdvanceDecision("halt_complete", None, "no next agent — chain complete")
    if already_dispatched:
        return AdvanceDecision("noop", None, "next agent already dispatched (idempotent)")
    if not _is_forward_transition(from_agent, next_recommended):
        return AdvanceDecision(
            "park_awaiting_approval",
            None,
            "non-forward / phase-skipping transition requested — human review",
        )
    if not next_permitted:
        return AdvanceDecision(
            "park_awaiting_approval",
            next_recommended,
            "authorization tier does not permit next agent — human gate between tiers",
        )
    return AdvanceDecision(
        "dispatch", next_recommended, "validated: forward transition + auth tier granted"
    )


# ── Event-stream helpers ─────────────────────────────────────────────────────────


def latest_handoff(events: list[Any]) -> Handoff | None:
    """Return the most recent handoff as a Handoff, or None if none yet.

    THE ONE REAL UNKNOWN (define/confirm on #61, anti-#2): a HANDOFF_READY A2AMessage
    (message_type=a2a_pb2.HANDOFF_READY, payload=serialized HandoffPayload) must be
    PERSISTED to the event stream when an agent finishes, so the Conductor can consume it
    here. The audit (A1) found NO handoff consumption today → this persistence bridge
    likely does not exist yet. Define it as part of wiring: an agent task, on completion,
    appends EventType.HANDOFF_READY whose payload carries
    {from_agent: AgentRole, status: PhaseStatus, next_recommended: AgentRole, ...}.

    The reads below use proto SEMANTICS (enum ints + the CONDUCTOR/0 = unset rule); adapt
    only the payload KEY NAMES to the chosen event shape, never the types."""
    for event in reversed(events):
        if getattr(event, "event_type", None) == "HANDOFF_READY":
            payload = getattr(event, "payload", {}) or {}
            next_role = int(payload.get("next_recommended", a2a_pb2.CONDUCTOR))
            return Handoff(
                from_agent=int(payload.get("from_agent", a2a_pb2.CONDUCTOR)),
                status=int(payload.get("status", a2a_pb2.PENDING)),
                next_recommended=(None if next_role == a2a_pb2.CONDUCTOR else next_role),
                seq=int(getattr(event, "sequence", 0)),
            )
    return None


def _already_dispatched(events: list[Any], handoff: Handoff) -> bool:
    """True iff an AGENT_DISPATCHED event exists that was appended AFTER this handoff —
    makes advance_engagement idempotent under Celery retries (no double-dispatch)."""
    for event in reversed(events):
        if getattr(event, "event_type", None) == "AGENT_DISPATCHED":
            payload = getattr(event, "payload", {}) or {}
            if int(payload.get("after_handoff_seq", -1)) == handoff.seq:
                return True
    return False


# ── Effectful orchestration (Conductor-owned) ────────────────────────────────────


def advance_engagement(
    *,
    engagement_id: str,
    auth: Any,  # AuthorizationStateMachine — Conductor owns it; read-only here
    event_store: Any,
    dispatcher: Dispatcher,
    applicator_builder: ApplicatorBuilder,
) -> AdvanceDecision:
    """Consume the latest handoff and advance the chain by ONE validated step.

    Called as the tail of each agent's Conductor-owned task (the agent task signals
    "done, please advance" — it does NOT call the next agent). Returns the decision taken.
    """
    events = event_store.get_events(engagement_id)
    handoff = latest_handoff(events)
    if handoff is None:
        return AdvanceDecision("noop", None, "no handoff event yet")

    next_role = handoff.next_recommended  # AgentRole int | None (CONDUCTOR/0 already → None)
    current_state = auth.get_state(engagement_id)
    next_permitted = (
        auth.can_agent_proceed(next_role, engagement_id) if next_role is not None else False
    )
    already = _already_dispatched(events, handoff)

    decision = decide_advance(
        status=handoff.status,
        from_agent=handoff.from_agent,
        next_recommended=next_role,
        current_state=current_state,
        next_permitted=next_permitted,
        already_dispatched=already,
    )

    if decision.action == "dispatch" and decision.next_agent is not None:
        applicators = (
            applicator_builder(engagement_id, decision.next_agent)
            if decision.next_agent in _APPLICATOR_CONSUMERS
            else []
        )
        dispatcher.dispatch(
            engagement_id=engagement_id, agent=decision.next_agent, applicators=applicators
        )
        _append(
            event_store,
            "AGENT_DISPATCHED",
            engagement_id,
            {"dispatched_agent": decision.next_agent, "after_handoff_seq": handoff.seq},
        )
    elif decision.action == "park_awaiting_approval":
        _append(
            event_store,
            "AWAITING_APPROVAL",
            engagement_id,
            {
                "blocked_next_agent": decision.next_agent,
                "reason": decision.reason,
                "requires_human_approval": True,
            },
        )
    elif decision.action == "halt_complete":
        _append(event_store, "CHAIN_COMPLETE", engagement_id, {"reason": decision.reason})

    return decision


def _append(
    event_store: Any, event_type_name: str, engagement_id: str, payload: dict[str, object]
) -> None:
    event_store.append(
        event_type=event_type_name,
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload=payload,
    )
