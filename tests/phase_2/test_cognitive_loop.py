"""Contract: cognitive loop + bounded autonomy.

The loop runs OBSERVE → ORIENT → PLAN → ACT → VERIFY → PERSIST and MUST stop
on any of four guards (ADR "Bounded Autonomy"). All four thresholds come from
config/constants.py — never inline (anti-Lyndon #7). Budgets are passed
explicitly here so tests never sleep for the real 4-hour wall-clock budget.
"""

from __future__ import annotations

from agent_alpha.agents.base import BoundedAutonomy, StopReason, run_cognitive_loop
from agent_alpha.config import constants


def test_defaults_come_from_constants() -> None:
    policy = BoundedAutonomy()
    assert policy.max_iterations == constants.MAX_ITERATIONS_PER_AGENT
    assert policy.time_budget_s == constants.MAX_TIME_BUDGET_SECONDS
    assert policy.cost_budget_usd == constants.MAX_COST_BUDGET_USD
    assert policy.no_progress_threshold == constants.NO_PROGRESS_THRESHOLD_ITERS


def test_stops_at_max_iterations() -> None:
    policy = BoundedAutonomy(max_iterations=3)
    assert (
        policy.should_stop(iteration=2, elapsed_s=0, cost_usd=0, iters_without_progress=0) is None
    )
    assert policy.should_stop(iteration=3, elapsed_s=0, cost_usd=0, iters_without_progress=0) is (
        StopReason.MAX_ITERATIONS
    )


def test_stops_on_time_budget() -> None:
    policy = BoundedAutonomy(time_budget_s=60)
    assert policy.should_stop(iteration=1, elapsed_s=61, cost_usd=0, iters_without_progress=0) is (
        StopReason.TIME_BUDGET
    )


def test_stops_on_cost_budget() -> None:
    policy = BoundedAutonomy(cost_budget_usd=1.0)
    assert policy.should_stop(
        iteration=1, elapsed_s=0, cost_usd=1.01, iters_without_progress=0
    ) is (StopReason.COST_BUDGET)


def test_stops_on_no_progress() -> None:
    policy = BoundedAutonomy(no_progress_threshold=5)
    assert policy.should_stop(iteration=9, elapsed_s=0, cost_usd=0, iters_without_progress=5) is (
        StopReason.NO_PROGRESS
    )


class _FakeAgent:
    """Discovers exactly one node on iteration 1, nothing after — the loop
    must terminate via NO_PROGRESS rather than spinning to max_iterations."""

    def __init__(self) -> None:
        self.steps_run = 0

    def step(self, context: dict[str, object]) -> dict[str, object]:
        self.steps_run += 1
        discovered = 1 if self.steps_run == 1 else 0
        return {"discovered_nodes": discovered, "cost_usd": 0.001}


def test_loop_completes_observe_to_persist_without_crash() -> None:
    """Happy path: a finite agent drives the full loop to a clean stop and
    reports WHY it stopped. A loop that ends with no recorded reason is a
    bug (silent termination is a cousin of silent success, anti-Lyndon #3)."""
    agent = _FakeAgent()
    policy = BoundedAutonomy(max_iterations=50, no_progress_threshold=3)
    outcome = run_cognitive_loop(agent, policy)
    assert outcome.stop_reason is StopReason.NO_PROGRESS
    assert outcome.iterations_run == 4  # 1 productive + 3 idle
    assert outcome.nodes_discovered == 1
