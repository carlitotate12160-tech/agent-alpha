# agent_alpha/graph/persist.py
"""ONE canonical persistence seam for AttackNode / AttackEdge (anti-Lyndon #6/#7).

Every agent and recon probe writes graph state the SAME way: append a NODE_DISCOVERED
/ EDGE_DISCOVERED event, then project it into the graph store. Before this module that
6-line pair was copy-pasted into 7 files — and the copies were NOT identical: the
agent-provenance string differed ("alpha" in recon + Alpha, "beta" in Beta). A naive
"one hardcoded function" hoist would have silently misattributed every Beta write to
Alpha, corrupting the event-sourced audit trail (which is legal evidence). So the
provenance is an EXPLICIT, required ``agent`` argument — no default, so a caller can
never forget it and inherit the wrong identity.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import AttackEdge, AttackNode, node_to_dict


def persist_node(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    node: AttackNode,
    *,
    agent: str,
) -> None:
    """Append a NODE_DISCOVERED event as *agent* and project it into *graph_store*."""
    payload = node_to_dict(node)
    event_store.append(EventType.NODE_DISCOVERED, engagement_id, agent, payload)
    graph_store.apply_event("NodeDiscovered", payload)


def persist_edge(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    edge: AttackEdge,
    *,
    agent: str,
) -> None:
    """Append an EDGE_DISCOVERED event as *agent* and project it into *graph_store*."""
    payload = {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relationship": edge.relationship.value,
        "confidence": edge.confidence,
        "technique_id": edge.technique_id,
    }
    event_store.append(EventType.EDGE_DISCOVERED, engagement_id, agent, payload)
    graph_store.apply_event("EdgeDiscovered", payload)
