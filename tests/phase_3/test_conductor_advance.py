"""RED tests for the Conductor handoff-consumer (audit A1 + Step 3c + routing #6/#7).

Proves the autonomous spine: Conductor advances Alpha→Beta on the Celery path, respects
the auth gate between tiers (parks, never auto-promotes), is idempotent under retries,
and NEVER lets an agent call another agent (advancement is Conductor-owned, gate-validated).

Routing redesign (slice 1a): advance_engagement now computes next_role via route_next(graph)
instead of trusting handoff.next_recommended.  The graph_rebuilder in effectful tests
returns a graph that drives route_next to the expected routing outcome.

Field semantics follow proto/a2a.proto (single source of truth): status = PhaseStatus
enum, next_recommended = AgentRole enum (CONDUCTOR/0 = unset). NOT strings.

VERIFY: Oracle ARM64 only — `.venv312/bin/python3 -m pytest tests/phase_3/test_conductor_advance.py`.
"""

from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.advance import (
    AdvanceDecision,
    advance_engagement,
    decide_advance,
)
from agent_alpha.graph.networkx_store import NetworkXGraphStore

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


def test_noop_when_handoff_not_complete_non_omega() -> None:
    """Non-COMPLETE status with a non-OMEGA next still noops — regression guard that
    the Bug #22 relaxation is OMEGA-only, not a blanket pass-through."""
    assert _decide(status=a2a_pb2.PENDING).action == "noop"
    assert _decide(status=a2a_pb2.RUNNING).action == "noop"
    assert _decide(status=a2a_pb2.FAILED, next_recommended=a2a_pb2.BETA).action == "noop"
    assert _decide(status=a2a_pb2.BLOCKED, next_recommended=a2a_pb2.GAMMA).action == "noop"


def test_bug22_failed_with_omega_dispatches() -> None:
    """Bug #22 relaxation: FAILED + OMEGA target dispatches (was: noop).
    OMEGA is read-only, auth-permitted at RECON_ONLY+, never blast-gated."""
    d = _decide(status=a2a_pb2.FAILED, next_recommended=a2a_pb2.OMEGA, next_permitted=True)
    assert d.action == "dispatch"
    assert d.next_agent == a2a_pb2.OMEGA


def test_bug22_blocked_with_omega_dispatches() -> None:
    """Bug #22 relaxation: BLOCKED + OMEGA target dispatches."""
    d = _decide(status=a2a_pb2.BLOCKED, next_recommended=a2a_pb2.OMEGA, next_permitted=True)
    assert d.action == "dispatch"
    assert d.next_agent == a2a_pb2.OMEGA


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
    from_agent: int = a2a_pb2.ALPHA,
    next_role: int = a2a_pb2.CONDUCTOR,
    status: int = a2a_pb2.COMPLETE,
    seq: int = 1,
) -> FakeEvent:
    from agent_alpha.events.event_types import EventType

    return FakeEvent(
        EventType.HANDOFF_READY,
        {"from_agent": from_agent, "status": status, "next_recommended": next_role},
        seq,
    )


def _graph_alpha_routes_beta() -> NetworkXGraphStore:
    """Graph that makes route_next(from_agent=ALPHA, COMPLETE) → BETA:
    has a vaulted credential + an auth-surface ASSET."""
    g = NetworkXGraphStore()
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "cred:leaked-1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": "secret_wp_1",
                "service": "mysql",
                "access_level": "admin",
            },
            "confidence": 0.95,
        },
    )
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "asset:t.test",
            "type": "asset",
            "properties": {"host": "t.test", "tech_stack": ["wp"]},
            "confidence": 0.9,
        },
    )
    return g


def _graph_beta_routes_omega() -> NetworkXGraphStore:
    """Graph that makes route_next(from_agent=BETA, COMPLETE) → OMEGA:
    has vaulted credential but NO ENABLES edge to ACCESS_LEVEL."""
    g = _graph_alpha_routes_beta()
    # No access level node, no ENABLES edge — Beta found cred but didn't prove access.
    return g


def _graph_beta_access_proven() -> NetworkXGraphStore:
    """Graph that makes route_next(from_agent=BETA, COMPLETE, gamma_authorized) → GAMMA|OMEGA:
    has vaulted CREDENTIAL → ENABLES → ACCESS_LEVEL."""
    g = _graph_alpha_routes_beta()
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "access:admin-wp",
            "type": "access_level",
            "properties": {"level": "admin", "user_context": "wp-admin"},
            "confidence": 0.9,
        },
    )
    g.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "cred:leaked-1",
            "target_id": "access:admin-wp",
            "relationship": "enables",
            "confidence": 0.9,
        },
    )
    return g


def test_advance_dispatches_beta() -> None:
    """ACTIVE_APPROVED + Alpha handoff + graph with cred+auth surface → dispatch Beta.
    advance passes only the agent role (serializable); the factory is called later
    in run_agent_task, NOT here."""
    auth = FakeAuth(state=a2a_pb2.ACTIVE_APPROVED, permitted={a2a_pb2.BETA})
    store = FakeStore([_handoff_event()])
    dispatcher = SpyDispatcher()

    decision = advance_engagement(
        engagement_id=ENG,
        auth=auth,
        event_store=store,
        dispatcher=dispatcher,
        graph_rebuilder=lambda es, eid: _graph_alpha_routes_beta(),
    )

    assert decision.action == "dispatch"
    assert dispatcher.calls == [{"agent": a2a_pb2.BETA}]


def test_advance_parks_and_does_not_dispatch_across_tier() -> None:
    """RECON_ONLY: route_next says BETA (graph has cred+surface) but Beta is not
    permitted → park, dispatcher NOT called."""
    auth = FakeAuth(state=a2a_pb2.RECON_ONLY, permitted={a2a_pb2.OMEGA})
    store = FakeStore([_handoff_event()])
    dispatcher = SpyDispatcher()

    decision = advance_engagement(
        engagement_id=ENG,
        auth=auth,
        event_store=store,
        dispatcher=dispatcher,
        graph_rebuilder=lambda es, eid: _graph_alpha_routes_beta(),
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
        "graph_rebuilder": lambda es, eid: _graph_alpha_routes_beta(),
    }
    advance_engagement(**kwargs)
    advance_engagement(**kwargs)
    assert len(dispatcher.calls) == 1


def test_advance_beta_access_proven_gamma_not_granted_dispatches_omega() -> None:
    """CARDINAL advance-level: Beta COMPLETE + graph has access-from-harvested-cred +
    gamma NOT granted → advance dispatches OMEGA (was: parked/noop in the old hardcoded
    path). route_next returns OMEGA (because gamma_authorized=False), OMEGA is
    auth-permitted at ACTIVE_APPROVED → dispatch."""
    auth = FakeAuth(state=a2a_pb2.ACTIVE_APPROVED, permitted={a2a_pb2.BETA, a2a_pb2.OMEGA})
    store = FakeStore(
        [
            _handoff_event(from_agent=a2a_pb2.BETA, status=a2a_pb2.COMPLETE),
        ]
    )
    dispatcher = SpyDispatcher()

    decision = advance_engagement(
        engagement_id=ENG,
        auth=auth,
        event_store=store,
        dispatcher=dispatcher,
        graph_rebuilder=lambda es, eid: _graph_beta_access_proven(),
    )

    assert decision.action == "dispatch"
    assert decision.next_agent == a2a_pb2.OMEGA
    assert dispatcher.calls == [{"agent": a2a_pb2.OMEGA}]


def test_advance_failed_at_recon_only_dispatches_omega() -> None:
    """Bug #22 closure + OMEGA auth-permit: Alpha FAILED at RECON_ONLY → advance
    dispatches OMEGA for a partial report (was: noop, no report ever produced).

    Depends on verified fact: can_agent_proceed(OMEGA) == True at RECON_ONLY
    (authorization.py:271-278). If OMEGA were NOT permitted, this would park,
    and Bug #22 would remain open."""
    auth = FakeAuth(state=a2a_pb2.RECON_ONLY, permitted={a2a_pb2.ALPHA, a2a_pb2.OMEGA})
    store = FakeStore(
        [
            _handoff_event(from_agent=a2a_pb2.ALPHA, status=a2a_pb2.FAILED),
        ]
    )
    dispatcher = SpyDispatcher()

    decision = advance_engagement(
        engagement_id=ENG,
        auth=auth,
        event_store=store,
        dispatcher=dispatcher,
        graph_rebuilder=lambda es, eid: NetworkXGraphStore(),
    )

    assert decision.action == "dispatch"
    assert decision.next_agent == a2a_pb2.OMEGA
    assert dispatcher.calls == [{"agent": a2a_pb2.OMEGA}]


def test_graph_rebuilt_exactly_once() -> None:
    """Regression: graph_rebuilder must be called EXACTLY once per advance_engagement
    call — the rebuilt graph is reused for both route_next and the blast-gate (#7).
    Previously _assess_blast_gate_for_dispatch rebuilt internally (double rebuild)."""
    auth = FakeAuth(state=a2a_pb2.ACTIVE_APPROVED, permitted={a2a_pb2.BETA})
    store = FakeStore([_handoff_event()])
    dispatcher = SpyDispatcher()

    rebuild_count = 0

    def counting_rebuilder(es: Any, eid: str) -> Any:
        nonlocal rebuild_count
        rebuild_count += 1
        return _graph_alpha_routes_beta()

    advance_engagement(
        engagement_id=ENG,
        auth=auth,
        event_store=store,
        dispatcher=dispatcher,
        policy=type("P", (), {"gate_before_agents": lambda self: frozenset()})(),
        graph_rebuilder=counting_rebuilder,
    )
    assert rebuild_count == 1, (
        f"graph_rebuilder called {rebuild_count} times — must be exactly 1 "
        f"(single rebuild reused for routing + blast-gate, #7)"
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
