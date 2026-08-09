from __future__ import annotations

import dataclasses
import logging
from typing import Any, cast

import networkx as nx

from agent_alpha.graph.nodes import (
    AttackEdge,
    AttackNode,
    NodeType,
    RelationshipType,
    VerificationTier,
    _reconstruct_node,
)

logger = logging.getLogger(__name__)


class NetworkXGraphStore:
    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()

    def apply_event(self, event_type: str, payload: dict[str, Any]) -> None:
        if event_type == "NodeDiscovered":
            try:
                node = _reconstruct_node(payload)
            except KeyError:
                # Intel events (e.g. api_endpoint from js_secret_probe) use
                # NODE_DISCOVERED with non-graph-node payloads. Skip them —
                # they are audit trail, not graph nodes.
                logger.debug("Skipping non-graph NODE_DISCOVERED payload: type=%s", payload.get("type"))
                return
            self._graph.add_node(node.id, data=node)
        elif event_type == "EdgeDiscovered":
            edge = AttackEdge(
                source_id=payload["source_id"],
                target_id=payload["target_id"],
                relationship=RelationshipType(payload["relationship"]),
                confidence=payload["confidence"],
                technique_id=payload.get("technique_id", ""),
            )
            self._graph.add_edge(edge.source_id, edge.target_id, data=edge)
        elif event_type == "NodeVerified":
            node_id = payload["node_id"]
            # Provenance gate: only attestor-confirmed events may promote to
            # CROSS_VERIFIED.  The primary guard is at EMISSION — only
            # run_verification_pass emits NodeVerified, always with provenance.
            # This consumption-side check is defense-in-depth.  Silent no-op
            # (not raise) so event replay on legacy/malformed events does not
            # crash; the invariant is enforced by not promoting.
            attestor_name = payload.get("attestor") or payload.get("oracle")  # tolerant: legacy key
            if not attestor_name:
                logger.warning(
                    "NodeVerified event for %s lacks attestor provenance — "
                    "skipping CROSS_VERIFIED promotion (defense-in-depth; "
                    "primary guard is at emission via run_verification_pass)",
                    node_id,
                )
                return
            if node_id in self._graph:
                existing = self._graph.nodes[node_id]["data"]
                updated = dataclasses.replace(
                    existing, verification=VerificationTier.CROSS_VERIFIED
                )
                self._graph.nodes[node_id]["data"] = updated

    def get_node(self, node_id: str) -> AttackNode | None:
        if node_id not in self._graph:
            return None
        return cast(AttackNode, self._graph.nodes[node_id]["data"])

    def get_edge(self, source_id: str, target_id: str) -> AttackEdge | None:
        if not self._graph.has_edge(source_id, target_id):
            return None
        return cast(AttackEdge, self._graph.edges[source_id, target_id]["data"])

    def all_nodes(self) -> list[AttackNode]:
        return [d["data"] for _, d in self._graph.nodes(data=True) if "data" in d]

    def all_edges(self) -> list[AttackEdge]:
        return [d["data"] for _, _, d in self._graph.edges(data=True) if "data" in d]

    def nodes_by_type(self, node_type: NodeType) -> list[AttackNode]:
        return [n for n in self.all_nodes() if n.type == node_type]

    def edges_by_relationship(self, relationship: RelationshipType) -> list[AttackEdge]:
        return [e for e in self.all_edges() if e.relationship == relationship]

    def neighbors(self, node_id: str) -> list[AttackNode]:
        if node_id not in self._graph:
            return []
        result: list[AttackNode] = []
        for n in self._graph.successors(node_id):
            node = self.get_node(n)
            if node is not None:
                result.append(node)
        return result

    def find_paths(self, source_id: str, target_id: str) -> list[list[AttackNode]]:
        if source_id not in self._graph or target_id not in self._graph:
            return []
        try:
            paths = list(nx.all_simple_paths(self._graph, source_id, target_id))
        except nx.NetworkXNoPath:
            return []
        result: list[list[AttackNode]] = []
        for path in paths:
            path_nodes: list[AttackNode] = []
            for nid in path:
                node = self.get_node(nid)
                if node is not None:
                    path_nodes.append(node)
            result.append(path_nodes)
        return result

    def node_count(self) -> int:
        return cast(int, self._graph.number_of_nodes())

    def edge_count(self) -> int:
        return cast(int, self._graph.number_of_edges())

    def clear(self) -> None:
        self._graph = nx.DiGraph()
