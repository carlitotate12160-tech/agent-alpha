"""RED tests for time-to-proof metrics on EngagementMemoryRecord.

The sellable metric ("proved exploitability in X minutes" — the report headline a
client pays for) is a pure PROJECTION over the event stream. Both inputs already
exist and are timestamped: ENGAGEMENT_CREATED (start) and PROOF_ARTIFACT_RECORDED
(the "we have proof" moment).

These tests call EngagementMemoryProjector._build_record directly with hand-built
AgentEvents (so timestamps are controlled, unlike the auto-stamped store) and
assert the derived scalars. They are RED until the projector is extended.

Anti-#3: absence of a proof/created event yields None, NEVER 0.0 (a fabricated
"instant proof" would be a silent false success).

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_1/test_engagement_time_to_proof.py -v
"""

from __future__ import annotations

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent
from agent_alpha.memory.engagement import EngagementMemoryProjector

ENG = "eng_ttp"


def _ev(seq: int, etype: str, ts: str, payload: dict[str, object] | None = None) -> AgentEvent:
    return AgentEvent(
        event_id=f"e{seq}",
        event_type=etype,
        engagement_id=ENG,
        agent="alpha",
        timestamp_utc=ts,
        payload=payload or {},
        sequence_number=seq,
    )


def _created(ts: str) -> AgentEvent:
    return _ev(1, EventType.ENGAGEMENT_CREATED, ts, {"client_id": "c", "target": "t", "state": 0})


# ── time_to_first_proof_s ────────────────────────────────────────────────────


def test_time_to_first_proof_is_seconds_between_created_and_first_proof() -> None:
    events = [
        _created("2026-07-03T00:00:00Z"),
        _ev(2, EventType.PROOF_ARTIFACT_RECORDED, "2026-07-03T00:05:00Z", {"ref": "p1"}),
    ]
    rec = EngagementMemoryProjector._build_record(ENG, events)
    assert rec.time_to_first_proof_s == 300.0


def test_time_to_first_proof_uses_the_earliest_proof_event() -> None:
    events = [
        _created("2026-07-03T00:00:00Z"),
        _ev(2, EventType.PROOF_ARTIFACT_RECORDED, "2026-07-03T00:02:00Z", {"ref": "p1"}),
        _ev(3, EventType.PROOF_ARTIFACT_RECORDED, "2026-07-03T00:09:00Z", {"ref": "p2"}),
    ]
    rec = EngagementMemoryProjector._build_record(ENG, events)
    assert rec.time_to_first_proof_s == 120.0


def test_time_to_first_proof_is_none_when_no_proof_event() -> None:
    # Anti-#3: no proof -> None, not 0.0.
    events = [
        _created("2026-07-03T00:00:00Z"),
        _ev(2, EventType.EXPLOIT_FAILED, "2026-07-03T00:03:00Z", {"why": "hardened"}),
    ]
    rec = EngagementMemoryProjector._build_record(ENG, events)
    assert rec.time_to_first_proof_s is None


def test_time_to_first_proof_is_none_when_no_created_event() -> None:
    events = [
        _ev(2, EventType.PROOF_ARTIFACT_RECORDED, "2026-07-03T00:05:00Z", {"ref": "p1"}),
    ]
    rec = EngagementMemoryProjector._build_record(ENG, events)
    assert rec.time_to_first_proof_s is None


# ── time_to_first_exploit_s (same shape, EXPLOIT_CONFIRMED) ───────────────────


def test_time_to_first_exploit_is_seconds_between_created_and_first_confirm() -> None:
    events = [
        _created("2026-07-03T00:00:00Z"),
        _ev(2, EventType.EXPLOIT_CONFIRMED, "2026-07-03T00:03:30Z", {"node": "n1"}),
    ]
    rec = EngagementMemoryProjector._build_record(ENG, events)
    assert rec.time_to_first_exploit_s == 210.0


def test_time_to_first_exploit_is_none_when_no_confirm() -> None:
    events = [_created("2026-07-03T00:00:00Z")]
    rec = EngagementMemoryProjector._build_record(ENG, events)
    assert rec.time_to_first_exploit_s is None


# ── determinism (event-sourced integrity) ────────────────────────────────────


def test_time_to_proof_is_deterministic_on_replay() -> None:
    events = [
        _created("2026-07-03T00:00:00Z"),
        _ev(2, EventType.EXPLOIT_CONFIRMED, "2026-07-03T00:04:00Z", {"node": "n1"}),
        _ev(3, EventType.PROOF_ARTIFACT_RECORDED, "2026-07-03T00:06:00Z", {"ref": "p1"}),
    ]
    a = EngagementMemoryProjector._build_record(ENG, events)
    b = EngagementMemoryProjector._build_record(ENG, events)
    assert a.time_to_first_proof_s == b.time_to_first_proof_s == 360.0
    assert a.time_to_first_exploit_s == b.time_to_first_exploit_s == 240.0
