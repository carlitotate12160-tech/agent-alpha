# agent_alpha/tools/registry.py
"""Tool catalog + reliability metadata (Phase 4, slice 1).

The registry is the single source of truth for WHICH commodity tools exist
and which graph node types each can act on.  It carries a reliability field
(``success_rate``) but does NOT yet rank by it — there is no engagement
outcome data to populate it (arah A / anti data-starvation, same reasoning
as the IntelligenceBase deferral).  Ranking by reliability is a later slice,
switched on only once real outcome data exists.

Scope note: this holds tool *identifiers and applicability* only — commodity
tools are WRAPPED, never re-implemented (ADR §12.22).  No payload/exploit
bodies live here (that is DeepSeek's lane, inside Template.verify()).
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_alpha.graph.nodes import NodeType


@dataclass(frozen=True)
class ToolSpec:
    """One commodity tool the composer may point at a graph node.

    ``applies_to`` — the node types this tool can act on.
    ``success_rate`` — reserved for reliability ranking; UNUSED until real
    outcome data exists.  ``0.0`` means "no data yet", never "0% reliable".
    """

    name: str
    applies_to: frozenset[NodeType]
    success_rate: float = 0.0


# Default catalog — single source of truth for the built-in tools.
# WRAP commodity (httpx/nuclei/hydra), never re-implement (ADR §12.22).
_DEFAULT_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("httpx", frozenset({NodeType.ASSET})),
    ToolSpec("nuclei", frozenset({NodeType.VULNERABILITY})),
    ToolSpec("hydra", frozenset({NodeType.SERVICE})),
)


class ToolRegistry:
    """Catalog of the tools the composer may plan with."""

    def __init__(self, specs: tuple[ToolSpec, ...]) -> None:
        self._specs = specs

    @classmethod
    def default(cls) -> ToolRegistry:
        """The built-in catalog."""
        return cls(_DEFAULT_SPECS)

    def tools_for(self, node_type: NodeType) -> tuple[ToolSpec, ...]:
        """All tools that can act on *node_type*, deterministic order by name."""
        return tuple(
            sorted(
                (s for s in self._specs if node_type in s.applies_to),
                key=lambda s: s.name,
            )
        )
