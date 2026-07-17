"""RED tests for the Conductor handoff-consumer (audit A1 + Step 3c).

Proves the autonomous spine: Conductor advances Alpha→Beta on the Celery path, respects
the auth gate between tiers (parks, never auto-promotes), is idempotent under retries,
calls the applicator factory only for credential-consuming agents, and NEVER lets an agent
call another agent (advancement is Conductor-owned, gate-validated).

Field semantics follow proto/a2a.proto (single source of truth): status = PhaseStatus
enum, next_recommended = AgentRole enum (CONDUCTOR/0 = unset). NOT strings.

VERIFY: Oracle ARM64 only — `.venv/bin/python3 -m pytest tests/phase_3/test_conductor_advance.py`.
"""

from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.advance import (
    AdvanceDecision,
    advance_engagement,
    decide_advance,
)

ENG = "eng_adv01"


# ── Pure decision tests (no I/O) ─────────────────────────────────────────────────


def _decide(**over: object) -> AdvanceDecision:
    base: dict[str, object] = dict(
        status=a2a_pb2.COMPLETE,
        from_agent=a2a_pb2.ALPHA,
        next_recommended=a2a_pb2.BETA,
        current_state=a2a_pb2.ACTIVE_APPROVED,
        next_permitted=True,
        already_dispatched=False,
    )
    base.update(over)
    return decide_advance(**base)  # type: ignore[arg-type]


def test_dispatch_when_forward_and_tier_granted() -> None:
    d = _decide()
    assert d.action == "dispatch"
    assert d.next_agent == a2a_pb2.BETA


def test_park_when_tier_not_granted() -> None:
    """Alpha recommends Beta but only RECON_ONLY granted → PARK, never dispatch, never
    auto-promote. The auth gate keeps its teeth."""
    d = _decide(current_state=a2a_pb2.RECON_ONLY, next_permitted=False)
    assert d.action == "park_awaiting_approval"
    assert d.next_agent == a2a_pb2.BETA  # recorded so a human knows what's blocked


def test_park_on_phase_skip_without_tier() -> None:
    """Alpha→Gamma (skipping Beta) is 'forward' in the chain, so the GATE is the guard:
    Gamma needs OFFENSIVE_APPROVED; if not granted → park."""
    d = _decide(next_recommended=a2a_pb2.GAMMA, next_permitted=False)
    assert d.action == "park_awaiting_approval"


def test_backward_transition_parked() -> None:
    """Beta handoff recommending Alpha (backward / replay) is rejected even if permitted."""
    d = _decide(from_agent=a2a_pb2.BETA, next_recommended=a2a_pb2.ALPHA, next_permitted=True)
    assert d.action == "park_awaiting_approval"


def test_noop_on_emergency_stop() -> None:
    assert _decide(current_state=a2a_pb2.EMERGENCY_STOP).action == "noop"


def test_noop_when_handoff_not_complete() -> None:
    """Only PhaseStatus.COMPLETE advances; the proto3 default PENDING(0) must NOT."""
    assert _decide(status=a2a_pb2.PENDING).action == "noop"
    assert _decide(status=a2a_pb2.RUNNING).action == "noop"
    assert _decide(status=a2a_pb2.FAILED).action == "noop"
    assert _decide(status=a2a_pb2.BLOCKED).action == "noop"


def test_idempotent_noop_when_already_dispatched() -> None:
    assert _decide(already_dispatched=True).action == "noop"


def test_halt_complete_when_no_next() -> None:
    """next_recommended unset (CONDUCTOR/0 → None) means the chain is done."""
    assert _decide(next_recommended=None).action == "halt_complete"


def test_omega_always_forward() -> None:
    """OMEGA (read-only reporter) may follow any agent."""
    d = _decide(from_agent=a2a_pb2.EPSILON, next_recommended=a2a_pb2.OMEGA, next_permitted=True)
    assert d.action == "dispatch"


# ── Effectful orchestration tests (fakes for gate / store / dispatcher / factory) ──


class FakeAuth:
    def __init__(self, *, state: int, permitted: set[int]) -> None:
        self._state = state
        self._permitted = permitted

    def get_state(self, engagement_id: str) -> int:
        return self._state

    def can_agent_proceed(self, agent_role: int, engagement_id: str) -> bool:
        return agent_role in self._permitted


class FakeEvent:
    def __init__(self, event_type: object, payload: dict, sequence: int) -> None:
        self.event_type = event_type
        self.payload = payload
        self.sequence = sequence
        self.sequence_number = sequence


class FakeStore:
    def __init__(self, events: list[FakeEvent]) -> None:
        self._events = list(events)
        self._seq = len(events)

    def get_events(self, engagement_id: str) -> list[FakeEvent]:
        return list(self._events)

    def append(self, *, event_type: object, engagement_id: str, agent: str, payload: dict) -> None:
        self._seq += 1
        self._events.append(FakeEvent(event_type, payload, self._seq))


class SpyDispatcher:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def dispatch(self, *, engagement_id: str, agent: int) -> None:
        self.calls.append({"agent": agent})


def _handoff_event(
    next_role: int = a2a_pb2.BETA, status: int = a2a_pb2.COMPLETE, seq: int = 1
) -> FakeEvent:
    from agent_alpha.events.event_types import EventType

    return FakeEvent(
        EventType.HANDOFF_READY,
        {"from_agent": a2a_pb2.ALPHA, "status": status, "next_recommended": next_role},
        seq,
    )


def test_advance_dispatches_beta() -> None:
    """ACTIVE_APPROVED + Alpha→Beta handoff → dispatch Beta. advance passes only the agent
    role (serializable); the factory is called later in run_agent_task, NOT here."""
    auth = FakeAuth(state=a2a_pb2.ACTIVE_APPROVED, permitted={a2a_pb2.BETA})
    store = FakeStore([_handoff_event()])
    dispatcher = SpyDispatcher()

    decision = advance_engagement(
        engagement_id=ENG,
        auth=auth,
        event_store=store,
        dispatcher=dispatcher,
    )

    assert decision.action == "dispatch"
    assert dispatcher.calls == [{"agent": a2a_pb2.BETA}]


def test_advance_parks_and_does_not_dispatch_across_tier() -> None:
    """RECON_ONLY: Beta not permitted → park, dispatcher NOT called."""
    auth = FakeAuth(state=a2a_pb2.RECON_ONLY, permitted=set())
    store = FakeStore([_handoff_event()])
    dispatcher = SpyDispatcher()

    decision = advance_engagement(
        engagement_id=ENG,
        auth=auth,
        event_store=store,
        dispatcher=dispatcher,
    )

    assert decision.action == "park_awaiting_approval"
    assert dispatcher.calls == []


def test_advance_idempotent_under_retry() -> None:
    """Running advance twice dispatches Beta exactly once (Celery-retry safe)."""
    auth = FakeAuth(state=a2a_pb2.ACTIVE_APPROVED, permitted={a2a_pb2.BETA})
    store = FakeStore([_handoff_event()])
    dispatcher = SpyDispatcher()

    kwargs = {
        "engagement_id": ENG,
        "auth": auth,
        "event_store": store,
        "dispatcher": dispatcher,
        "policy": type("P", (), {"gate_before_agents": lambda self: frozenset()})(),
        "graph_rebuilder": lambda es, eid: None
    }
    advance_engagement(**kwargs)
    advance_engagement(**kwargs)
    assert len(dispatcher.calls) == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
