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

import dataclasses
from typing import Any

from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    NodeType,
    VerificationTier,
    merge_tech_stack,
    node_to_dict,
)


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


def merge_asset_node(
    graph_store: Any,
    host: str,
    *,
    tech_stack_add: list[str] | None = None,
    confidence: float | None = None,
    agent: str = "alpha",
    timestamp_utc: str = "",
    **changes: Any,
) -> AttackNode:
    """Build the ``asset:{host}`` node PRESERVING any prior properties (anti-clobber).

    This is the ONE canonical site that rebuilds an ASSET node. ``apply_event``
    ("NodeDiscovered") REPLACES the stored node wholesale, so every writer that
    constructs a fresh ``AssetProperties(host=..., tech_stack=...)`` silently drops
    every field it did not re-set (``ip``, ``cf_protected``, ``open_ports``,
    ``rest_routes`` + its ``rest_routes_total_count`` / ``rest_routes_truncated``
    companions). A WordPress reprofile — route discovery then a users/woocommerce/
    version check on the same host — is the concrete regression.

    When ``asset:{host}`` already exists this ``dataclasses.replace``\\ s it so every
    unobserved field is carried forward; ``tech_stack`` is UNIONed through
    ``merge_tech_stack`` (never overwritten) and node-level ``confidence`` /
    ``verification`` default to the existing values unless overridden. Observed
    fields are passed as ``**changes`` (e.g. ``open_ports=[80]``,
    ``rest_routes=[...]``); each REPLACES that single field only.

    The node is returned unpersisted — the caller owns provenance and appends via
    ``persist_node(..., agent=...)`` so the audit trail keeps the correct identity.
    """
    asset_id = f"asset:{host}"
    existing = graph_store.get_node(asset_id)
    if existing is not None and isinstance(existing.properties, AssetProperties):
        merged_stack = merge_tech_stack(existing.properties.tech_stack, tech_stack_add or [])
        props = dataclasses.replace(
            existing.properties, host=host, tech_stack=merged_stack, **changes
        )
        resolved_confidence = confidence if confidence is not None else existing.confidence
        verification = existing.verification
    else:
        props = AssetProperties(
            host=host, tech_stack=merge_tech_stack(None, tech_stack_add or []), **changes
        )
        resolved_confidence = confidence if confidence is not None else 0.85
        verification = VerificationTier.UNVERIFIED

    return AttackNode(
        id=asset_id,
        type=NodeType.ASSET,
        properties=props,
        confidence=resolved_confidence,
        agent=agent,
        timestamp_utc=timestamp_utc,
        verification=verification,
    )
