# agent_alpha/agents/base.py
"""Bounded Autonomy driver and cognitive loop.

Safety governor for every stepping agent.  The cognitive loop runs
OBSERVE → ORIENT → PLAN → ACT → VERIFY → PERSIST; this driver bounds it
so an agent can never run unbounded in iterations, wall-clock, LLM cost,
or spin with no progress (ADR "Bounded Autonomy").

All four thresholds come from config/constants.py — never inline
(anti-Lyndon #7).  This file is agent-agnostic: it duck-types
``agent.step(context: dict) -> dict``.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent_alpha.config import constants

if TYPE_CHECKING:
    from agent_alpha.agents.objective import EngagementObjective

# ── Stop reasons ────────────────────────────────────────────────


class StopReason(enum.Enum):
    """Why the cognitive loop terminated."""

    MAX_ITERATIONS = "max_iterations"
    TIME_BUDGET = "time_budget"
    COST_BUDGET = "cost_budget"
    NO_PROGRESS = "no_progress"
    GOAL_COMPLETED = "goal_completed"


# ── Loop outcome ────────────────────────────────────────────────


@dataclass(frozen=True)
class LoopOutcome:
    """Immutable record returned by :func:`run_cognitive_loop`."""

    stop_reason: StopReason
    iterations_run: int
    nodes_discovered: int


# ── Bounded autonomy policy ────────────────────────────────────


class BoundedAutonomy:
    """Policy object that decides when the cognitive loop must stop.

    Every threshold defaults to the single-source-of-truth value in
    ``config/constants.py``.  Tests override selectively via keyword args.
    """

    def __init__(
        self,
        max_iterations: int = constants.MAX_ITERATIONS_PER_AGENT,
        time_budget_s: float = constants.MAX_TIME_BUDGET_SECONDS,
        cost_budget_usd: float = constants.MAX_COST_BUDGET_USD,
        no_progress_threshold: int = constants.NO_PROGRESS_THRESHOLD_ITERS,
    ) -> None:
        self.max_iterations = max_iterations
        self.time_budget_s = time_budget_s
        self.cost_budget_usd = cost_budget_usd
        self.no_progress_threshold = no_progress_threshold

    def should_stop(
        self,
        iteration: int,
        elapsed_s: float,
        cost_usd: float,
        iters_without_progress: int,
    ) -> StopReason | None:
        """Return a :class:`StopReason` if any guard is tripped, else ``None``.

        Comparison operators (``>=`` vs ``>``) are exact — tests depend on them.
        """
        if iteration >= self.max_iterations:
            return StopReason.MAX_ITERATIONS
        if elapsed_s > self.time_budget_s:
            return StopReason.TIME_BUDGET
        if cost_usd > self.cost_budget_usd:
            return StopReason.COST_BUDGET
        if iters_without_progress >= self.no_progress_threshold:
            return StopReason.NO_PROGRESS
        return None


# ── Cognitive loop driver ───────────────────────────────────────


def run_cognitive_loop(
    agent: Any,
    policy: BoundedAutonomy,
    session_store: Any | None = None,
    event_store: Any | None = None,
    engagement_id: str | None = None,
    objective: EngagementObjective | None = None,
) -> LoopOutcome:
    """Drive *agent* through OBSERVE→ORIENT→PLAN→ACT→VERIFY→PERSIST cycles.

    The loop is agent-agnostic: *agent* must implement
    ``step(context: dict) -> dict`` returning at least
    ``{"discovered_nodes": int, "cost_usd": float}``.

    Returns a :class:`LoopOutcome` describing why the loop stopped and how
    much work was done.
    """
    iteration = 0
    total_cost_usd = 0.0
    total_nodes_discovered = 0
    iters_without_progress = 0
    t0 = time.monotonic()

    while True:
        iteration += 1

        context = {}
        rec = None
        if session_store is not None and engagement_id is not None:
            rec = session_store.get(engagement_id)
            context = {"scratchpad": rec.scratchpad if rec else {}}

        if objective is not None:
            context["objective"] = objective

        result = agent.step(context)

        if session_store is not None and engagement_id is not None:
            updated_scratchpad = result.get("scratchpad")
            if updated_scratchpad is not None:
                session_store.update_scratchpad(engagement_id, updated_scratchpad)
                if event_store is not None:
                    event_type, payload = session_store.snapshot_scratchpad_event(engagement_id)
                    agent_name = (
                        rec.active_agent
                        if rec
                        else getattr(agent, "__class__", type(agent)).__name__
                    )
                    event_store.append(
                        event_type=event_type,
                        engagement_id=engagement_id,
                        agent=agent_name,
                        payload=payload,
                    )

        total_cost_usd += result["cost_usd"]
        discovered = result["discovered_nodes"]
        total_nodes_discovered += discovered
        # Un-probed frontier size reported by the agent (0 if it does not report).
        work_remaining = int(result.get("work_remaining", 0) or 0)

        if result.get("goal_completed"):
            if event_store is not None and engagement_id is not None:
                agent_name = (
                    rec.active_agent
                    if rec
                    else getattr(agent, "__class__", type(agent)).__name__
                )
                event_store.append(
                    event_type="GoalCompleted",
                    engagement_id=engagement_id,
                    agent=agent_name,
                    payload={"description": objective.description if objective else "Objective met"},
                )
            return LoopOutcome(
                stop_reason=StopReason.GOAL_COMPLETED,
                iterations_run=iteration,
                nodes_discovered=total_nodes_discovered,
            )

        if discovered > 0:
            iters_without_progress = 0
        else:
            iters_without_progress += 1

        elapsed_s = time.monotonic() - t0

        reason = policy.should_stop(
            iteration=iteration,
            elapsed_s=elapsed_s,
            cost_usd=total_cost_usd,
            iters_without_progress=iters_without_progress,
        )
        # A stall (NO_PROGRESS) means the agent is out of productive options — NOT
        # that the last few frontier pops were duds while more un-probed work waits.
        # A real discovery surface (crt.sh always returns dead/irrelevant siblings)
        # must not starve a reachable target that merely sorts later in the queue.
        # Suppress NO_PROGRESS while the frontier is non-empty; the hard ceilings
        # (max_iterations / time_budget / cost_budget) still bound a large dud queue.
        if reason is StopReason.NO_PROGRESS and work_remaining > 0:
            reason = None
        if reason is not None:
            return LoopOutcome(
                stop_reason=reason,
                iterations_run=iteration,
                nodes_discovered=total_nodes_discovered,
            )
