# tests/phase_2/test_bounded_autonomy_frontier.py
"""Contract: a NO_PROGRESS stall must not fire while the frontier still has
un-probed work. A real discovery surface (crt.sh always returns dead/irrelevant
sibling subdomains) must not starve a reachable target that merely sorts later
in the queue. Hard ceilings (max_iterations/time/cost) still bound a dud queue.

RED before the fix: with no_progress_threshold=5 the loop stops at the 5th dud
pop and never reaches the productive 7th — nodes_discovered == 0.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2/test_bounded_autonomy_frontier.py -v
"""

from __future__ import annotations

from typing import Any

from agent_alpha.agents.base import BoundedAutonomy, StopReason, run_cognitive_loop


class _NoisyFrontierAgent:
    """Pops a scripted frontier: each entry is the ``discovered_nodes`` that pop
    yields. Reports ``work_remaining`` like the real Alpha does. Mimics a noisy
    crt.sh surface where the live target sorts after dead siblings."""

    def __init__(self, script: list[int]) -> None:
        self._queue = list(script)
        self.probed = 0

    def step(self, context: dict[str, Any]) -> dict[str, Any]:
        if not self._queue:
            return {"discovered_nodes": 0, "cost_usd": 0.0, "work_remaining": 0}
        nodes = self._queue.pop(0)
        self.probed += 1
        return {
            "discovered_nodes": nodes,
            "cost_usd": 0.0,
            "work_remaining": len(self._queue),
        }


def test_noisy_frontier_does_not_starve_a_later_target() -> None:
    # 6 dead pops (0 nodes), then a productive one. threshold=5 would stop at the
    # 5th dud WITHOUT the fix; WITH it the live target (pop 7) is still reached.
    agent = _NoisyFrontierAgent([0, 0, 0, 0, 0, 0, 1])
    outcome = run_cognitive_loop(agent, BoundedAutonomy(no_progress_threshold=5))
    assert agent.probed == 7
    assert outcome.nodes_discovered == 1


def test_exhausted_frontier_still_stops_on_no_progress() -> None:
    # All duds; once the frontier drains (work_remaining == 0) the stall guard
    # fires normally — the fix must NOT make the loop run forever.
    agent = _NoisyFrontierAgent([0, 0, 0])
    outcome = run_cognitive_loop(agent, BoundedAutonomy(no_progress_threshold=5))
    assert outcome.stop_reason is StopReason.NO_PROGRESS


def test_max_iterations_still_bounds_a_large_dud_queue() -> None:
    # A huge non-empty frontier of duds must be bounded by the hard ceiling, not
    # run unbounded just because work_remaining stays > 0.
    agent = _NoisyFrontierAgent([0] * 10_000)
    outcome = run_cognitive_loop(agent, BoundedAutonomy(max_iterations=50, no_progress_threshold=5))
    assert outcome.stop_reason is StopReason.MAX_ITERATIONS
    assert outcome.iterations_run == 50
