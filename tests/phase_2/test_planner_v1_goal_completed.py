"""Planner v1 GOAL_COMPLETED stop condition tests — RED until P2/P3.

Tests verify that the cognitive loop stops with GOAL_COMPLETED when the
agent's objective is satisfied (an ACCESS_LEVEL node in the graph matches
a target_access_levels entry in the objective), and that it does NOT stop
with GOAL_COMPLETED when the objective is unmet or absent.

§12.30: deterministic signal — the goal check is a pure graph query, not
an LLM judgement.
"""

from __future__ import annotations

from agent_alpha.agents.base import BoundedAutonomy, StopReason, run_cognitive_loop
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
    VerificationTier,
)
from agent_alpha.graph.persist import persist_edge, persist_node
from agent_alpha.memory.session import InMemorySessionStore, SessionRecord

OBJECTIVE = {"target_access_levels": ["admin", "root", "db_root"]}


# ── Helpers ──────────────────────────────────────────────────────


def _make_graph_store() -> NetworkXGraphStore:
    return NetworkXGraphStore()


def _make_event_store() -> InMemoryEventStore:
    return InMemoryEventStore()


def _make_session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


def _add_verified_chain(
    store: NetworkXGraphStore,
    event_store: InMemoryEventStore,
    engagement_id: str,
    level: str,
) -> None:
    """VERIFIED CREDENTIAL --ENABLES--> ACCESS_LEVEL(level) — the exact shape is_met() requires."""
    cred = AttackNode(
        id=f"cred_{level}",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="u", secret_ref="r", service="s", access_level=level
        ),
        confidence=0.9,
        agent="alpha",
    )
    acc = AttackNode(
        id=f"access_{level}",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level=level),
        verification=VerificationTier.CROSS_VERIFIED,
        confidence=0.9,
        agent="alpha",
    )
    persist_node(event_store, store, engagement_id, cred, agent="alpha")
    persist_node(event_store, store, engagement_id, acc, agent="alpha")
    persist_edge(
        event_store,
        store,
        engagement_id,
        AttackEdge(
            source_id=cred.id,
            target_id=acc.id,
            relationship=RelationshipType.ENABLES,
            confidence=0.9,
        ),
        agent="alpha",
    )


class _GraphMutatingAgent:
    """Minimal real agent: on step `complete_on`, persists the verified chain
    into ITS graph so the loop's is_met() catches it. Exposes graph_store (the
    loop verifies against it)."""

    def __init__(
        self,
        graph_store: NetworkXGraphStore,
        event_store: InMemoryEventStore,
        engagement_id: str,
        level: str,
        complete_on: int,
    ) -> None:
        self.graph_store = graph_store
        self._es = event_store
        self._eid = engagement_id
        self._level = level
        self._complete_on = complete_on
        self._n = 0

    def step(self, context: dict[str, object]) -> dict[str, object]:
        self._n += 1
        if self._n == self._complete_on:
            _add_verified_chain(self.graph_store, self._es, self._eid, self._level)
        return {"discovered_nodes": 1, "cost_usd": 0.0}


class _SelfReportingAgent:
    """Lies: returns goal_completed=True every step. Used to PROVE the loop
    IGNORES self-reported completion. If the self-report path is ever
    reintroduced, these tests FAIL (regression guard)."""

    def __init__(self, graph_store: NetworkXGraphStore) -> None:
        self.graph_store = graph_store

    def step(self, context: dict[str, object]) -> dict[str, object]:
        return {"discovered_nodes": 1, "cost_usd": 0.0, "goal_completed": True}


def _event_types(event_store: InMemoryEventStore, engagement_id: str) -> list[str]:
    return [
        getattr(e, "event_type", getattr(e, "type", None))
        for e in event_store.get_events(engagement_id)
    ]


def _set_session(
    session_store: InMemorySessionStore,
    engagement_id: str,
    scratchpad: dict[str, object],
) -> None:
    session_store.set(
        SessionRecord(
            engagement_id=engagement_id,
            target_scope={},
            active_agent="alpha",
            current_phase="recon",
            current_phase_iteration=0,
            authorization={},
            scratchpad=scratchpad,
            ttl_seconds=86400,
        )
    )


# ── Tests ────────────────────────────────────────────────────────


def test_stop_reason_enum_has_goal_completed() -> None:
    """StopReason must include GOAL_COMPLETED."""
    assert hasattr(StopReason, "GOAL_COMPLETED"), (
        "StopReason.GOAL_COMPLETED does not exist. "
        "The cognitive loop needs a way to stop when the objective is satisfied, "
        "not just when budgets are exhausted or progress stalls."
    )
    assert StopReason.GOAL_COMPLETED.value == "goal_completed"


def test_goal_completed_via_verified_graph_is_met() -> None:
    """The loop stops GOAL_COMPLETED because objective.is_met() sees a VERIFIED
    CREDENTIAL→ENABLES→ACCESS_LEVEL chain — NOT because the agent self-signals."""
    eid = "goal_met"
    store, es, ss = _make_graph_store(), _make_event_store(), _make_session_store()
    _set_session(ss, eid, {"objective": OBJECTIVE})
    agent = _GraphMutatingAgent(store, es, eid, level="db_root", complete_on=3)
    outcome = run_cognitive_loop(
        agent,
        BoundedAutonomy(max_iterations=50),
        session_store=ss,
        event_store=es,
        engagement_id=eid,
    )
    assert outcome.stop_reason == StopReason.GOAL_COMPLETED
    assert outcome.iterations_run == 3
    assert "GoalCompleted" in _event_types(es, eid)


def test_no_objective_ignores_self_reported_completion() -> None:
    """Agent self-reports goal_completed=True every step, but there is NO objective →
    the loop must NEVER GOAL_COMPLETED (proves the self-report path is dead)."""
    eid = "no_obj_selfreport"
    store, es, ss = _make_graph_store(), _make_event_store(), _make_session_store()
    _set_session(ss, eid, {})  # no objective
    agent = _SelfReportingAgent(store)
    outcome = run_cognitive_loop(
        agent,
        BoundedAutonomy(max_iterations=3),
        session_store=ss,
        event_store=es,
        engagement_id=eid,
    )
    assert outcome.stop_reason != StopReason.GOAL_COMPLETED
    assert "GoalCompleted" not in _event_types(es, eid)


def test_unmet_objective_ignores_self_reported_completion() -> None:
    """Objective present but is_met() False (empty graph), and the agent self-reports
    goal_completed=True → the loop must NOT GOAL_COMPLETED."""
    eid = "unmet_selfreport"
    store, es, ss = _make_graph_store(), _make_event_store(), _make_session_store()
    _set_session(ss, eid, {"objective": OBJECTIVE})  # unmet: no verified chain in graph
    agent = _SelfReportingAgent(store)
    outcome = run_cognitive_loop(
        agent,
        BoundedAutonomy(max_iterations=3),
        session_store=ss,
        event_store=es,
        engagement_id=eid,
    )
    assert outcome.stop_reason != StopReason.GOAL_COMPLETED
    assert "GoalCompleted" not in _event_types(es, eid)


def test_pre_step_completion_on_resume() -> None:
    """Objective ALREADY satisfied before the loop starts (resumed engagement or
    handoff) → stop with ZERO iterations and emit GoalCompleted (§12.29 D4)."""
    eid = "resume"
    store, es, ss = _make_graph_store(), _make_event_store(), _make_session_store()
    _add_verified_chain(store, es, eid, "db_root")  # pre-populate
    _set_session(ss, eid, {"objective": OBJECTIVE})
    agent = _GraphMutatingAgent(store, es, eid, level="db_root", complete_on=999)
    outcome = run_cognitive_loop(
        agent,
        BoundedAutonomy(max_iterations=50),
        session_store=ss,
        event_store=es,
        engagement_id=eid,
    )
    assert outcome.stop_reason == StopReason.GOAL_COMPLETED
    assert outcome.iterations_run == 0
    assert "GoalCompleted" in _event_types(es, eid)
