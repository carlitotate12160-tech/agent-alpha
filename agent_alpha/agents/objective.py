from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agent_alpha.graph.nodes import NodeType, RelationshipType

if TYPE_CHECKING:
    from agent_alpha.graph.networkx_store import NetworkXGraphStore


@dataclass(frozen=True)
class EngagementObjective:
    """Engagement objective."""

    target_access_levels: frozenset[str]
    description: str

    def is_met(self, graph_store: NetworkXGraphStore) -> bool:
        """Return True if the graph contains a VERIFIED path to an access_level
        in target_access_levels (an ACCESS_LEVEL node with verified=True
        reached via a CREDENTIAL -ENABLES-> edge).
        """
        for edge in graph_store.edges_by_relationship(RelationshipType.ENABLES):
            target_node = graph_store.get_node(edge.target_id)
            if (
                not target_node
                or target_node.type != NodeType.ACCESS_LEVEL
                or not target_node.verified
            ):
                continue

            level = getattr(target_node.properties, "level", None)
            if level in self.target_access_levels:
                source_node = graph_store.get_node(edge.source_id)
                if source_node and source_node.type == NodeType.CREDENTIAL:
                    return True
        return False
