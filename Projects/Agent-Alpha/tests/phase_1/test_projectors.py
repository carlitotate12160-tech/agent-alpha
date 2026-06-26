# tests/phase_1/test_projectors.py
# Integration tests for AttackGraphProjector.
# Uses real InMemoryEventStore (Phase 0) + real NetworkXGraphStore (Phase 1)
# as test fixtures — this is an integration test by nature.

from __future__ import annotations

from agent_alpha.events.projectors import AttackGraphProjector
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    NodeType,
    VulnerabilityProperties,
    node_to_dict,
)

# ── helpers ──────────────────────────────────────────────────────────

ENG_ID = "eng-proj-001"


def _make_asset_node(node_id: str, host: str = "host1") -> AttackNode:
    return AttackNode(
        id=node_id,
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, ip="10.0.0.1"),
        confidence=0.9,
    )


def _make_vuln_node(node_id: str) -> AttackNode:
    return AttackNode(
        id=node_id,
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(cve_id="CVE-2024-0001"),
        confidence=0.7,
    )


def _make_edge_payload(source_id: str, target_id: str) -> dict[str, object]:
    return {
        "source_id": source_id,
        "target_id": target_id,
        "relationship": "exploits",
        "confidence": 0.8,
        "technique_id": "T1190",
    }


# ── Test 1: zero-event engagement ───────────────────────────────────


def test_project_zero_events() -> None:
    """project() on engagement with 0 events -> events_processed=0,
    graph_node_count=0."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    result = projector.project(ENG_ID)

    assert result.events_processed == 0
    assert result.graph_node_count == 0
    assert result.graph_edge_count == 0
    assert result.last_sequence_number == 0
    assert result.engagement_id == ENG_ID


# ── Test 2: single NodeDiscovered ───────────────────────────────────


def test_project_single_node_discovered() -> None:
    """Append a NodeDiscovered event, project(), verify node present."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    node = _make_asset_node("n1")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(node))

    result = projector.project(ENG_ID)

    assert result.events_processed == 1
    assert result.graph_node_count == 1
    retrieved = gs.get_node("n1")
    assert retrieved is not None
    assert retrieved.id == node.id
    assert retrieved.type == node.type


# ── Test 3: two nodes + one edge ────────────────────────────────────


def test_project_nodes_and_edge() -> None:
    """Append NodeDiscovered x2 + EdgeDiscovered -> edge_count == 1."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    n1 = _make_asset_node("n1")
    n2 = _make_vuln_node("n2")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n1))
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n2))
    es.append("EdgeDiscovered", ENG_ID, "recon-agent", _make_edge_payload("n1", "n2"))

    result = projector.project(ENG_ID)

    assert result.events_processed == 3
    assert result.graph_node_count == 2
    assert result.graph_edge_count == 1


# ── Test 4: last_sequence_number tracks highest seq ─────────────────


def test_project_last_sequence_number() -> None:
    """ProjectionResult.last_sequence_number matches the highest
    sequence_number appended."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    n1 = _make_asset_node("n1")
    n2 = _make_vuln_node("n2")
    _ = es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n1))
    ev2 = es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n2))

    result = projector.project(ENG_ID)

    assert result.last_sequence_number == ev2.sequence_number


# ── Test 5: Phase 0 events mixed in (no-op passthrough) ────────────


def test_project_phase0_events_no_op() -> None:
    """Phase 0 events (EngagementCreated) mixed alongside
    NodeDiscovered do not raise and are correctly ignored by the graph."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    # Phase 0 event — should be a no-op in GraphStore
    es.append("EngagementCreated", ENG_ID, "system", {"scope": "full"})
    # Graph-relevant event
    node = _make_asset_node("n1")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(node))
    # Another Phase 0 event
    es.append(
        "StateTransitioned",
        ENG_ID,
        "system",
        {"from": "recon", "to": "exploit"},
    )

    result = projector.project(ENG_ID)

    # All 3 events were processed (passed to apply_event)
    assert result.events_processed == 3
    # But only the NodeDiscovered actually mutated the graph
    assert result.graph_node_count == 1
    assert result.graph_edge_count == 0
    assert gs.get_node("n1") is not None


# ── Test 6: incremental projection ─────────────────────────────────


def test_project_incremental_preserves_existing_graph() -> None:
    """project_incremental() after project(): new node added, previous
    nodes still present (graph NOT cleared)."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    n1 = _make_asset_node("n1")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n1))

    first_result = projector.project(ENG_ID)
    assert first_result.graph_node_count == 1

    # Append a second node *after* the initial projection
    n2 = _make_vuln_node("n2")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n2))

    inc_result = projector.project_incremental(
        ENG_ID,
        after_sequence=first_result.last_sequence_number,
    )

    # Only the 1 new event was processed incrementally
    assert inc_result.events_processed == 1
    # Both old and new nodes present
    assert inc_result.graph_node_count == 2
    assert gs.get_node("n1") is not None
    assert gs.get_node("n2") is not None


# ── Test 7: project() idempotency ──────────────────────────────────


def test_project_idempotent() -> None:
    """project() called twice on same engagement_id -> identical
    ProjectionResult both times (idempotent full rebuild)."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    n1 = _make_asset_node("n1")
    n2 = _make_vuln_node("n2")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n1))
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n2))
    es.append("EdgeDiscovered", ENG_ID, "recon-agent", _make_edge_payload("n1", "n2"))

    result1 = projector.project(ENG_ID)
    result2 = projector.project(ENG_ID)

    assert result1.events_processed == result2.events_processed
    assert result1.graph_node_count == result2.graph_node_count
    assert result1.graph_edge_count == result2.graph_edge_count
    assert result1.last_sequence_number == result2.last_sequence_number


# ── Test 8: verify_projection returns True when consistent ──────────


def test_verify_projection_consistent() -> None:
    """verify_projection() returns True when graph matches a fresh
    rebuild. Factory is a lambda constructing NetworkXGraphStore —
    only the TEST imports the concrete class, not the projector."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    n1 = _make_asset_node("n1")
    n2 = _make_vuln_node("n2")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n1))
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n2))
    es.append("EdgeDiscovered", ENG_ID, "recon-agent", _make_edge_payload("n1", "n2"))

    projector.project(ENG_ID)

    assert (
        projector.verify_projection(
            ENG_ID,
            fresh_store_factory=lambda: NetworkXGraphStore(),
        )
        is True
    )


# ── Test 9: verify_projection detects drift ─────────────────────────


def test_verify_projection_detects_drift() -> None:
    """verify_projection() returns False when self._graph_store was
    mutated out-of-band (extra node injected directly)."""
    es = InMemoryEventStore()
    gs = NetworkXGraphStore()
    projector = AttackGraphProjector(es, gs)

    n1 = _make_asset_node("n1")
    es.append("NodeDiscovered", ENG_ID, "recon-agent", node_to_dict(n1))

    projector.project(ENG_ID)
    assert gs.node_count() == 1

    # Inject an extra node directly — bypassing the projector
    extra_node = _make_asset_node("n-rogue", host="rogue-host")
    gs.apply_event("NodeDiscovered", node_to_dict(extra_node))
    assert gs.node_count() == 2  # drift introduced

    assert (
        projector.verify_projection(
            ENG_ID,
            fresh_store_factory=lambda: NetworkXGraphStore(),
        )
        is False
    )
