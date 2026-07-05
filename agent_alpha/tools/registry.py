# agent_alpha/tools/registry.py
"""Tool registry — ranked selection over the canonical `Tool` protocol.

Extraction of beta/strike.py's inline "seed of ToolRegistry": rank the
candidate Tools by their OWN ``applies_to(ctx) -> float`` (contracts.py),
highest first, stable on ties. Plan-not-execute: ranking never calls
``Tool.run``. One home for tool ordering, so the K11 "central if-ladder"
cannot creep back — relevance lives in each ``Tool.applies_to``, never here.

No ToolSpec / node-type ladder / second tool-name catalog (that was the
superseded #99 shape = Lyndon #6 + #7 + K11). ``compose(base_template, ctx)``
for Gamma lands in composer.py once Templates (DeepSeek lane) exist — building
it now would be dead code (#2).
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_alpha.tools.contracts import TargetContext, Tool


class ToolRegistry:
    """Holds the candidate Tools for an engagement and orders them by relevance."""

    def __init__(self, tools: Sequence[Tool]) -> None:
        self._tools: tuple[Tool, ...] = tuple(tools)

    def ranked(self, ctx: TargetContext) -> tuple[Tool, ...]:
        """Candidates ordered by ``applies_to(ctx)`` descending, stable on ties.

        Uses the identical call beta used inline
        (``sorted(candidates, key=applies_to, reverse=True)``), so the extraction
        is behaviour-preserving. Every candidate is returned (none dropped): the
        caller runs them in order until one succeeds.
        """
        return tuple(sorted(self._tools, key=lambda t: t.applies_to(ctx), reverse=True))
