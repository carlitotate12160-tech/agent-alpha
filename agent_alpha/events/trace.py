# agent_alpha/events/trace.py
# A7 Observability — slice A7-a: per-engagement run trace (read model).
#
# ADR §8n-1: observability is a PROJECTION over the single append-only event
# stream — "all derived from event stream, not written separately". This module
# adds a THIRD read model alongside AttackGraph (events/projectors.py) and the
# run-status fold (conductor/run_status.py). It performs ZERO writes and holds no
# state of its own: it is a pure fold of AgentEvent -> EngagementTrace.
#
# Why a NEW read model and not an extension of EngagementMemoryRecord (anti
# Lyndon #6 / duplicate canonical type): EngagementMemoryRecord is an AGGREGATE
# (tool_success_rates, time_to_*_s — totals/rates). A trace is a chronological
# TIMELINE (step N -> step N+1 with inter-step latency). Different read-model
# shape, not a duplicate of the same concept. Aggregate metrics stay in the
# existing projector; the timeline lives here.

from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Iterable

from agent_alpha.a2a import a2a_pb2
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent


def _parse_ts(ts: str) -> datetime.datetime:
    """Parse an ISO-8601 UTC timestamp.

    Sibling of ``memory.engagement._parse_ts``. Duplicated deliberately: the
    ``events`` package must not import ``memory`` (memory imports events -> import
    cycle). This is a pure stdlib parse with no configurable behaviour, so it is
    NOT a Lyndon #7 "three values for one config" hazard. Promote to a shared
    ``events`` util only if a third consumer appears.
    """
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


# Event types that mark a terminal, auditable per-agent outcome. Each maps to a
# stable, human-readable outcome label. HANDOFF_READY is handled separately
# because its label is derived from the PhaseStatus enum carried in the payload.
_TERMINAL_OUTCOME: dict[str, str] = {
    EventType.EXPLOIT_CONFIRMED: "confirmed",
    EventType.EXPLOIT_FAILED: "failed",
    EventType.ENGAGEMENT_RUN_FAILED: "failed",
    EventType.WAF_BLOCKED: "waf_blocked",
    EventType.CHAIN_COMPLETE: "chain_complete",
}


def _handoff_outcome(payload: dict[str, object]) -> str:
    """Label a HANDOFF_READY outcome from its PhaseStatus int.

    Reuses the proto enum's own ``Name()`` as the single source of truth for the
    label instead of hard-coding integers (anti Lyndon #7). Unknown/missing
    status is reported honestly as ``"unknown"`` — never silently coerced to a
    success (anti Lyndon #3 false-success).
    """
    status = payload.get("status")
    if not isinstance(status, int):
        return "unknown"
    try:
        return str(a2a_pb2.PhaseStatus.Name(status)).lower()
    except ValueError:
        return "unknown"


@dataclasses.dataclass(frozen=True)
class TraceStep:
    """One agent step in the engagement timeline.

    ``latency_s`` is the elapsed time this agent took: measured from its
    AGENT_DISPATCHED event when one exists, else from the previous step's
    timestamp. ``None`` only when no prior time anchor exists (e.g. the very
    first step with no dispatch record) — surfaced as None, not fabricated 0.0.
    """

    agent: str
    outcome: str
    event_type: str
    sequence_number: int
    timestamp_utc: str
    latency_s: float | None


@dataclasses.dataclass(frozen=True)
class EngagementTrace:
    """Chronological read model of an engagement's agent-step outcomes."""

    engagement_id: str
    steps: tuple[TraceStep, ...]
    total_latency_s: float
    last_sequence_number: int


def project_engagement_trace(engagement_id: str, events: Iterable[AgentEvent]) -> EngagementTrace:
    """Pure fold: engagement events -> EngagementTrace.

    ``events`` are assumed to belong to ``engagement_id`` (the caller filters via
    ``EventStore.get_events(engagement_id)``), mirroring ``project_run_status``.
    The fold is deterministic: events are sorted by ``sequence_number`` so the
    timeline is gapless and order-independent of iteration order.
    """
    ordered = sorted(events, key=lambda e: e.sequence_number)

    steps: list[TraceStep] = []
    dispatch_ts: dict[str, str] = {}
    prev_step_ts: str | None = None
    first_ts: str | None = None
    last_seq = 0

    for event in ordered:
        last_seq = max(last_seq, event.sequence_number)
        if first_ts is None:
            first_ts = event.timestamp_utc

        if event.event_type == EventType.AGENT_DISPATCHED:
            dispatched = event.payload.get("dispatched_agent")
            key = _agent_key(dispatched) if dispatched is not None else event.agent
            dispatch_ts[key] = event.timestamp_utc
            continue

        outcome = _outcome_for(event)
        if outcome is None:
            continue  # not a trace-relevant event — ignored, never counted

        agent = event.agent
        anchor = dispatch_ts.get(agent) or dispatch_ts.get(_agent_key(agent)) or prev_step_ts
        latency_s: float | None = None
        if anchor is not None:
            latency_s = (_parse_ts(event.timestamp_utc) - _parse_ts(anchor)).total_seconds()

        steps.append(
            TraceStep(
                agent=agent,
                outcome=outcome,
                event_type=str(event.event_type),
                sequence_number=event.sequence_number,
                timestamp_utc=event.timestamp_utc,
                latency_s=latency_s,
            )
        )
        prev_step_ts = event.timestamp_utc

    total_latency_s = 0.0
    if steps and first_ts is not None:
        total_latency_s = (_parse_ts(steps[-1].timestamp_utc) - _parse_ts(first_ts)).total_seconds()

    return EngagementTrace(
        engagement_id=engagement_id,
        steps=tuple(steps),
        total_latency_s=total_latency_s,
        last_sequence_number=last_seq,
    )


def _outcome_for(event: AgentEvent) -> str | None:
    """Return the outcome label for a trace-relevant event, else None."""
    if event.event_type == EventType.HANDOFF_READY:
        return _handoff_outcome(event.payload)
    return _TERMINAL_OUTCOME.get(event.event_type)


def _agent_key(value: object) -> str:
    """Normalise an agent identifier (AGENT_DISPATCHED carries an AgentRole int,
    HANDOFF_READY events use the AgentRole *name* string). Resolve ints to their
    proto name so a dispatch (int) and an outcome (name) for the same agent
    pair up for latency."""
    if isinstance(value, int):
        try:
            return str(a2a_pb2.AgentRole.Name(value))
        except ValueError:
            return str(value)
    return str(value)
