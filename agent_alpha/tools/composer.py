# agent_alpha/tools/composer.py
"""ToolComposer — runtime plan composition (Phase 4, slice 1).

Turns the CURRENT AttackGraph state into an ordered exploitation Plan.
Plan-not-execute: it decides *what* to do and *against which node*, and
never runs anything.  Execution is a later slice (Go engine over gRPC);
payload bodies are DeepSeek's lane, only inside ``Template.verify()``.

Anti-Lyndon #11 (hardcoded sequence = tool runner): the plan is a function
of graph state.  A step is emitted ONLY for a node that exists in THIS
graph, so a different fingerprint yields a different first action.  There is
no static pipeline that runs regardless of target.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_alpha.graph.nodes import NodeType
from agent_alpha.graph.store import GraphStore
from agent_alpha.tools.registry import ToolRegistry

# Planning policy: which node types are most directly actionable toward an
# exploit/proof, highest first.  Single source for the ordering (anti-#7).
# This is a priority over node *types*, NOT a fixed action list — which steps
# actually appear still depends entirely on what the graph contains.
NODE_TYPE_EXPLOIT_PRIORITY: tuple[NodeType, ...] = (
    NodeType.VULNERABILITY,
    NodeType.CREDENTIAL,
    NodeType.SERVICE,
    NodeType.ACCESS_LEVEL,
    NodeType.DATA,
    NodeType.ASSET,
)


@dataclass(frozen=True)
class PlanStep:
    """A single planned action: point *tool* at *target_node_id*."""

    tool: str
    target_node_id: str
    rationale: str


@dataclass(frozen=True)
class Plan:
    """An ordered, immutable plan.  Empty when the graph offers nothing."""

    steps: tuple[PlanStep, ...] = ()


class ToolComposer:
    """Composes a Plan from the current AttackGraph state (read-only)."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def plan(self, store: GraphStore) -> Plan:
        """Compose an ordered Plan from what the graph currently contains.

        Deterministic: node types are walked in a fixed exploit-priority
        order and nodes within a type by id, so the same graph always yields
        the same plan.  A node with no applicable tool is skipped (never a
        fabricated step — anti-#3).
        """
        steps: list[PlanStep] = []
        for node_type in NODE_TYPE_EXPLOIT_PRIORITY:
            for node in sorted(store.nodes_by_type(node_type), key=lambda n: n.id):
                tools = self._registry.tools_for(node.type)
                if not tools:
                    continue
                tool = tools[0]  # deterministic; reliability ranking deferred (arah A)
                steps.append(
                    PlanStep(
                        tool=tool.name,
                        target_node_id=node.id,
                        rationale=(f"{tool.name} selected for {node.type.value} node {node.id}"),
                    )
                )
        return Plan(steps=tuple(steps))
