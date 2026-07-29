"""Reach-strategy selection — A1 Slice B.

Decides HOW to reach a target given its mitigation posture.
ORIGIN_DIRECT is scoping (not an EvasionTechnique) — keep the concepts
separate (§12.33).  No network I/O lives here; pure decision logic.
"""

import enum

from agent_alpha.recon.transport_resilience import MitigationClass


class ReachStrategy(enum.StrEnum):
    """Which reach path the planner should use for a given target."""

    DIRECT = "direct"  # normal front-door
    EVASION = "evasion"  # transport_resilience (9a/9b/9c) — residential only
    ORIGIN_DIRECT = "origin_direct"  # scoping: hit authorized origin, bypass CDN


def choose_reach(
    mitigation: MitigationClass | None,
    *,
    browser_solve_viable: bool,
    authorized_origin: str | None,
) -> ReachStrategy:
    """Select a reach strategy based on the mitigation class.

    Decision table (differential — class drives strategy, anti-#11):
    * No mitigation              → DIRECT
    * CHALLENGE + viable solve   → EVASION
    * RULE_DENY, or CHALLENGE without viable solve (e.g. datacenter IP)
        → ORIGIN_DIRECT iff an authorized origin exists;
          else DIRECT (front-door result, honestly blocked — never a silent cheat).
    """
    if mitigation is None:
        return ReachStrategy.DIRECT
    if mitigation is MitigationClass.CHALLENGE and browser_solve_viable:
        return ReachStrategy.EVASION
    if authorized_origin is not None:
        return ReachStrategy.ORIGIN_DIRECT
    return ReachStrategy.DIRECT
