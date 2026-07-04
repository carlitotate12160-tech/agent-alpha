"""Phase 3 — A7 Observability (slice A7-a): engagement run-trace projection.

Contract for ``project_engagement_trace`` — a PURE fold of the append-only
event stream into a chronological agent-step timeline (ADR §8n-1: observability
is a projection over the event stream, not a separate telemetry write path).

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_3/test_project_engagement_trace.py -v

T1 empty stream            -> empty trace, total 0.0
T2 dispatch->handoff pair  -> one step, outcome from PhaseStatus, latency = Δts
T3 ordering                -> steps sorted by sequence_number regardless of input order
T4 failed outcome          -> ExploitFailed surfaces outcome "failed" (anti-#3, not skipped)
T5 WAF_BLOCKED             -> outcome "waf_blocked", never "clean" (anti false-negative)
T6 no dead field           -> every EngagementTrace/TraceStep field populated from a live
                              emit path (explicit guard vs the time_to_first_proof dead-seam flaw)
"""

from __future__ import annotations

import dataclasses

from agent_alpha.a2a import a2a_pb2
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent
from agent_alpha.events.trace import (
    EngagementTrace,
    TraceStep,
    project_engagement_trace,
)

ENG = "eng_trace_test"


def _event(
    event_type: str,
    *,
    seq: int,
    agent: str = "CONDUCTOR",
    ts: str,
    payload: dict[str, object] | None = None,
) -> AgentEvent:
    return AgentEvent(
        event_id=f"ev-{seq}",
        event_type=event_type,
        engagement_id=ENG,
        agent=agent,
        timestamp_utc=ts,
        payload=payload or {},
        sequence_number=seq,
    )


# ── T1 ────────────────────────────────────────────────────────────────
def test_empty_stream_yields_empty_trace() -> None:
    trace = project_engagement_trace(ENG, [])
    assert trace == EngagementTrace(
        engagement_id=ENG,
        steps=(),
        total_latency_s=0.0,
        last_sequence_number=0,
    )


# ── T2 ────────────────────────────────────────────────────────────────
def test_dispatch_then_handoff_is_one_step_with_latency() -> None:
    events = [
        _event(
            EventType.AGENT_DISPATCHED,
            seq=1,
            agent="CONDUCTOR",
            ts="2026-07-05T00:00:00Z",
            payload={"dispatched_agent": a2a_pb2.ALPHA, "after_handoff_seq": 0},
        ),
        _event(
            EventType.HANDOFF_READY,
            seq=2,
            agent=a2a_pb2.AgentRole.Name(a2a_pb2.ALPHA),
            ts="2026-07-05T00:00:03Z",
            payload={"from_agent": a2a_pb2.ALPHA, "status": a2a_pb2.COMPLETE},
        ),
    ]
    trace = project_engagement_trace(ENG, events)

    assert len(trace.steps) == 1
    step = trace.steps[0]
    assert step.agent == a2a_pb2.AgentRole.Name(a2a_pb2.ALPHA)
    assert step.outcome == "complete"
    assert step.latency_s == 3.0
    assert trace.last_sequence_number == 2


# ── T3 ────────────────────────────────────────────────────────────────
def test_steps_sorted_by_sequence_regardless_of_input_order() -> None:
    a = _event(
        EventType.HANDOFF_READY,
        seq=5,
        agent="ALPHA",
        ts="2026-07-05T00:00:05Z",
        payload={"status": a2a_pb2.COMPLETE},
    )
    b = _event(
        EventType.HANDOFF_READY,
        seq=2,
        agent="ALPHA",
        ts="2026-07-05T00:00:02Z",
        payload={"status": a2a_pb2.COMPLETE},
    )
    # Fed out of order — projection must still emit seq 2 before seq 5.
    trace = project_engagement_trace(ENG, [a, b])
    assert [s.sequence_number for s in trace.steps] == [2, 5]


# ── T4 ────────────────────────────────────────────────────────────────
def test_failed_outcome_is_surfaced_not_skipped() -> None:
    events = [
        _event(
            EventType.EXPLOIT_FAILED,
            seq=1,
            agent="GAMMA",
            ts="2026-07-05T00:00:00Z",
            payload={"reason": "payload rejected"},
        )
    ]
    trace = project_engagement_trace(ENG, events)
    assert len(trace.steps) == 1
    assert trace.steps[0].outcome == "failed"


def test_handoff_failed_status_labels_failed() -> None:
    events = [
        _event(
            EventType.HANDOFF_READY,
            seq=1,
            agent="BETA",
            ts="2026-07-05T00:00:00Z",
            payload={"status": a2a_pb2.FAILED},
        )
    ]
    trace = project_engagement_trace(ENG, events)
    assert trace.steps[0].outcome == "failed"


# ── T5 ────────────────────────────────────────────────────────────────
def test_waf_blocked_is_evidence_never_clean() -> None:
    events = [
        _event(
            EventType.WAF_BLOCKED,
            seq=1,
            agent="ALPHA",
            ts="2026-07-05T00:00:00Z",
            payload={"host": "lab.example", "path": "/", "status_code": 403},
        )
    ]
    trace = project_engagement_trace(ENG, events)
    assert trace.steps[0].outcome == "waf_blocked"
    assert trace.steps[0].outcome != "clean"


# ── T6 ── no dead field: every field wired from a live emit path ────────
def test_every_trace_field_populated_from_live_events() -> None:
    """Guard against the time_to_first_proof dead-seam flaw: assert each field of
    EngagementTrace and TraceStep is driven by real event data, not a default the
    live path never threads."""
    events = [
        _event(
            EventType.AGENT_DISPATCHED,
            seq=1,
            agent="CONDUCTOR",
            ts="2026-07-05T00:00:00Z",
            payload={"dispatched_agent": a2a_pb2.ALPHA},
        ),
        _event(
            EventType.HANDOFF_READY,
            seq=2,
            agent=a2a_pb2.AgentRole.Name(a2a_pb2.ALPHA),
            ts="2026-07-05T00:00:04Z",
            payload={"status": a2a_pb2.COMPLETE},
        ),
    ]
    trace = project_engagement_trace(ENG, events)

    trace_fields = {f.name for f in dataclasses.fields(EngagementTrace)}
    step_fields = {f.name for f in dataclasses.fields(TraceStep)}

    # No field silently absent.
    assert trace.engagement_id == ENG
    assert trace.steps  # non-empty
    assert trace.total_latency_s == 4.0
    assert trace.last_sequence_number == 2

    step = trace.steps[0]
    assert step.agent
    assert step.outcome
    assert step.event_type
    assert step.sequence_number == 2
    assert step.timestamp_utc
    assert step.latency_s == 4.0  # not None — dispatch anchor threaded a real value

    # Structural guard: if a field is added later it must appear in this test.
    assert trace_fields == {
        "engagement_id",
        "steps",
        "total_latency_s",
        "last_sequence_number",
    }
    assert step_fields == {
        "agent",
        "outcome",
        "event_type",
        "sequence_number",
        "timestamp_utc",
        "latency_s",
    }


def test_projection_does_not_mutate_input() -> None:
    events = [
        _event(
            EventType.HANDOFF_READY,
            seq=1,
            agent="ALPHA",
            ts="2026-07-05T00:00:00Z",
            payload={"status": a2a_pb2.COMPLETE},
        )
    ]
    snapshot = list(events)
    project_engagement_trace(ENG, events)
    assert events == snapshot
