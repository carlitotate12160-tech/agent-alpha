"""Planner v1 GOAL_COMPLETED stop condition tests — RED until P2/P3.

Tests verify that the cognitive loop stops with GOAL_COMPLETED when the
agent's objective is satisfied (an ACCESS_LEVEL node in the graph matches
a target_access_levels entry in the objective), and that it does NOT stop
with GOAL_COMPLETED when the objective is unmet or absent.

§12.30: deterministic signal — the goal check is a pure graph query, not
an LLM judgement.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.agents.base import BoundedAutonomy, StopReason, run_cognitive_loop
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AccessLevelProperties, AttackNode, NodeType
from agent_alpha.graph.persist import persist_node
from agent_alpha.memory.session import InMemorySessionStore, SessionRecord

OBJECTIVE = {"target_access_levels": ["admin", "root", "db_root"]}


# ── Helpers ──────────────────────────────────────────────────────


def _make_graph_store() -> NetworkXGraphStore:
    return NetworkXGraphStore()


def _make_event_store() -> InMemoryEventStore:
    return InMemoryEventStore()


def _make_session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


def _add_access_level(
    store: NetworkXGraphStore,
    event_store: InMemoryEventStore,
    engagement_id: str,
    level: str,
) -> str:
    """Add an ACCESS_LEVEL node to the graph via the canonical persist seam."""
    node = AttackNode(
        id=f"access_{level}",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level=level),
        confidence=0.9,
        agent="alpha",
    )
    persist_node(event_store, store, engagement_id, node, agent="alpha")
    return node.id


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


# ── Fake agents ──────────────────────────────────────────────────


class _GoalSignallingAgent:
    """Agent that signals goal_completed=True on every step.

    Simulates an agent that has checked the graph and found the objective
    is satisfied.
    """

    def __init__(self) -> None:
        self.steps_run = 0

    def step(self, context: dict[str, object]) -> dict[str, object]:
        self.steps_run += 1
        return {
            "discovered_nodes": 0,
            "cost_usd": 0.0,
            "goal_completed": True,
        }


class _NonGoalAgent:
    """Agent that never signals goal_completed — objective not yet met."""

    def __init__(self) -> None:
        self.steps_run = 0

    def step(self, context: dict[str, object]) -> dict[str, object]:
        self.steps_run += 1
        discovered = 1 if self.steps_run == 1 else 0
        return {
            "discovered_nodes": discovered,
            "cost_usd": 0.001,
        }


class _DelayedGoalAgent:
    """Agent that signals goal_completed after N steps."""

    def __init__(self, delay: int = 3) -> None:
        self.steps_run = 0
        self.delay = delay

    def step(self, context: dict[str, object]) -> dict[str, object]:
        self.steps_run += 1
        result: dict[str, object] = {
            "discovered_nodes": 1,
            "cost_usd": 0.001,
        }
        if self.steps_run >= self.delay:
            result["goal_completed"] = True
        return result


# ── Tests ────────────────────────────────────────────────────────


def test_stop_reason_enum_has_goal_completed() -> None:
    """StopReason must include GOAL_COMPLETED — RED until added to enum.

    The cognitive loop needs a way to stop when the objective is satisfied,
    not just when budgets are exhausted or progress stalls.
    """
    assert hasattr(StopReason, "GOAL_COMPLETED"), (
        "StopReason.GOAL_COMPLETED does not exist. "
        "The cognitive loop needs a way to stop when the objective is satisfied, "
        "not just when budgets are exhausted or progress stalls."
    )
    assert StopReason.GOAL_COMPLETED.value == "goal_completed"


def test_loop_stops_with_goal_completed_when_agent_signals() -> None:
    """When the agent signals goal_completed=True, the loop must stop
    immediately with StopReason.GOAL_COMPLETED — not continue to
    MAX_ITERATIONS or NO_PROGRESS.

    RED until run_cognitive_loop checks for goal_completed in step result.
    """
    agent = _GoalSignallingAgent()
    policy = BoundedAutonomy(max_iterations=50, no_progress_threshold=10)
    outcome = run_cognitive_loop(agent, policy)
    assert outcome.stop_reason is StopReason.GOAL_COMPLETED, (
        f"Expected GOAL_COMPLETED, got {outcome.stop_reason}. "
        "The loop must respect the goal_completed signal from the agent."
    )
    assert outcome.iterations_run == 1, (
        "Goal completion should stop after the first signalling step."
    )


def test_loop_does_not_stop_with_goal_completed_when_agent_does_not_signal() -> None:
    """When the agent never signals goal_completed, the loop must NOT
    stop with GOAL_COMPLETED — it should fall through to NO_PROGRESS
    or MAX_ITERATIONS as before.

    GREEN once GOAL_COMPLETED is wired (no goal_completed key in result
    → no GOAL_COMPLETED stop).
    """
    agent = _NonGoalAgent()
    policy = BoundedAutonomy(max_iterations=50, no_progress_threshold=3)
    outcome = run_cognitive_loop(agent, policy)
    assert outcome.stop_reason is not StopReason.GOAL_COMPLETED, (
        "Loop stopped with GOAL_COMPLETED without the agent signalling it."
    )
    assert outcome.stop_reason is StopReason.NO_PROGRESS


def test_goal_completed_stops_before_max_iterations() -> None:
    """GOAL_COMPLETED must fire before MAX_ITERATIONS when the agent
    signals completion early. This proves the loop checks goal_completed
    BEFORE checking the iteration ceiling.

    RED until run_cognitive_loop checks for goal_completed.
    """
    agent = _DelayedGoalAgent(delay=3)
    policy = BoundedAutonomy(max_iterations=100, no_progress_threshold=100)
    outcome = run_cognitive_loop(agent, policy)
    assert outcome.stop_reason is StopReason.GOAL_COMPLETED
    assert outcome.iterations_run == 3, (
        f"Expected 3 iterations, got {outcome.iterations_run}. "
        "Goal completion should fire exactly when the agent signals it."
    )


def test_goal_completed_with_session_and_event_store() -> None:
    """GOAL_COMPLETED works with session_store and event_store wired in.

    The loop reads the objective from the session scratchpad, the agent
    checks the graph, and when an ACCESS_LEVEL node matches the objective's
    target_access_levels, the agent signals goal_completed.

    RED until the full wiring is implemented.
    """
    engagement_id = "test_goal_completed"
    store = _make_graph_store()
    es = _make_event_store()
    ss = _make_session_store()

    _add_access_level(store, es, engagement_id, "admin")
    _set_session(ss, engagement_id, {"objective": OBJECTIVE})

    agent = _GoalSignallingAgent()
    policy = BoundedAutonomy(max_iterations=50, no_progress_threshold=10)
    outcome = run_cognitive_loop(
        agent,
        policy,
        session_store=ss,
        event_store=es,
        engagement_id=engagement_id,
    )
    assert outcome.stop_reason is StopReason.GOAL_COMPLETED


def test_no_objective_never_goal_completed() -> None:
    """With no objective in the session, the loop must never stop with
    GOAL_COMPLETED — even if the graph contains ACCESS_LEVEL nodes.

    Without an objective, there is no goal to complete. The agent should
    not signal goal_completed, and the loop should fall through to
    NO_PROGRESS or MAX_ITERATIONS.

    GREEN once GOAL_COMPLETED is wired (no objective → agent doesn't
    signal goal_completed → no GOAL_COMPLETED stop).
    """
    engagement_id = "test_no_objective"
    store = _make_graph_store()
    es = _make_event_store()
    ss = _make_session_store()

    _add_access_level(store, es, engagement_id, "admin")
    _set_session(ss, engagement_id, {})

    agent = _NonGoalAgent()
    policy = BoundedAutonomy(max_iterations=50, no_progress_threshold=3)
    outcome = run_cognitive_loop(
        agent,
        policy,
        session_store=ss,
        event_store=es,
        engagement_id=engagement_id,
    )
    assert outcome.stop_reason is not StopReason.GOAL_COMPLETED
