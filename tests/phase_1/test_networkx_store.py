from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)
from agent_alpha.graph.store import rebuild_from_events


@dataclass
class DummyEvent:
    event_type: str
    payload: dict[str, Any]


def test_node_discovered_and_get_node() -> None:
    store = NetworkXGraphStore()
    node = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1", ip="10.0.0.1"),
        confidence=0.9,
    )
    store.apply_event("NodeDiscovered", node_to_dict(node))
    retrieved = store.get_node("n1")
    assert retrieved is not None
    assert retrieved.id == node.id
    assert retrieved.type == node.type
    assert retrieved.confidence == node.confidence


def test_edge_discovered_and_get_edge() -> None:
    store = NetworkXGraphStore()
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "n1",
            "target_id": "n2",
            "relationship": "exploits",
            "confidence": 0.8,
            "technique_id": "T1190",
        },
    )
    edge = store.get_edge("n1", "n2")
    assert edge is not None
    assert edge.source_id == "n1"
    assert edge.target_id == "n2"
    assert edge.relationship == RelationshipType.EXPLOITS
    assert edge.confidence == 0.8
    assert edge.technique_id == "T1190"


def test_get_node_missing_returns_none() -> None:
    store = NetworkXGraphStore()
    assert store.get_node("nonexistent") is None


def test_get_edge_missing_returns_none() -> None:
    store = NetworkXGraphStore()
    assert store.get_edge("n1", "n2") is None


def test_unknown_event_type_no_op() -> None:
    store = NetworkXGraphStore()
    initial_count = store.node_count()
    store.apply_event("UnknownEvent", {"foo": "bar"})
    assert store.node_count() == initial_count


def test_all_nodes_returns_all_added_nodes() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    n2 = AttackNode(
        id="n2",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.7,
    )
    n3 = AttackNode(
        id="n3",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="user1", secret_ref="ref1", service="ssh", access_level="root"
        ),
        confidence=0.8,
    )
    store.apply_event("NodeDiscovered", node_to_dict(n1))
    store.apply_event("NodeDiscovered", node_to_dict(n2))
    store.apply_event("NodeDiscovered", node_to_dict(n3))
    nodes = store.all_nodes()
    assert len(nodes) == 3
    node_ids = {n.id for n in nodes}
    assert node_ids == {"n1", "n2", "n3"}


def test_nodes_by_type_filters_correctly() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    n2 = AttackNode(
        id="n2",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.7,
    )
    n3 = AttackNode(
        id="n3",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host2"),
        confidence=0.8,
    )
    store.apply_event("NodeDiscovered", node_to_dict(n1))
    store.apply_event("NodeDiscovered", node_to_dict(n2))
    store.apply_event("NodeDiscovered", node_to_dict(n3))
    assets = store.nodes_by_type(NodeType.ASSET)
    assert len(assets) == 2
    assert {n.id for n in assets} == {"n1", "n3"}


def test_edges_by_relationship_filters_correctly() -> None:
    store = NetworkXGraphStore()
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "n1",
            "target_id": "n2",
            "relationship": "exploits",
            "confidence": 0.8,
        },
    )
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "n2",
            "target_id": "n3",
            "relationship": "enables",
            "confidence": 0.7,
        },
    )
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "n3",
            "target_id": "n4",
            "relationship": "exploits",
            "confidence": 0.9,
        },
    )
    exploits = store.edges_by_relationship(RelationshipType.EXPLOITS)
    assert len(exploits) == 2
    assert {(e.source_id, e.target_id) for e in exploits} == {("n1", "n2"), ("n3", "n4")}


def test_neighbors_returns_direct_successors_only() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    n2 = AttackNode(
        id="n2",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.7,
    )
    n3 = AttackNode(
        id="n3",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="user1", secret_ref="ref1", service="ssh", access_level="root"
        ),
        confidence=0.8,
    )
    store.apply_event("NodeDiscovered", node_to_dict(n1))
    store.apply_event("NodeDiscovered", node_to_dict(n2))
    store.apply_event("NodeDiscovered", node_to_dict(n3))
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": "n1", "target_id": "n2", "relationship": "exploits", "confidence": 0.8},
    )
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": "n2", "target_id": "n3", "relationship": "enables", "confidence": 0.7},
    )
    neighbors = store.neighbors("n1")
    assert len(neighbors) == 1
    assert neighbors[0].id == "n2"


def test_find_paths_discovers_path_through_intermediate() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    n2 = AttackNode(
        id="n2",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.7,
    )
    n3 = AttackNode(
        id="n3",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="user1", secret_ref="ref1", service="ssh", access_level="root"
        ),
        confidence=0.8,
    )
    store.apply_event("NodeDiscovered", node_to_dict(n1))
    store.apply_event("NodeDiscovered", node_to_dict(n2))
    store.apply_event("NodeDiscovered", node_to_dict(n3))
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": "n1", "target_id": "n2", "relationship": "exploits", "confidence": 0.8},
    )
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": "n2", "target_id": "n3", "relationship": "enables", "confidence": 0.7},
    )
    paths = store.find_paths("n1", "n3")
    assert len(paths) == 1
    assert [n.id for n in paths[0]] == ["n1", "n2", "n3"]


def test_find_paths_no_path_returns_empty() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    n2 = AttackNode(
        id="n2",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.7,
    )
    n3 = AttackNode(
        id="n3",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="user1", secret_ref="ref1", service="ssh", access_level="root"
        ),
        confidence=0.8,
    )
    store.apply_event("NodeDiscovered", node_to_dict(n1))
    store.apply_event("NodeDiscovered", node_to_dict(n2))
    store.apply_event("NodeDiscovered", node_to_dict(n3))
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": "n1", "target_id": "n2", "relationship": "exploits", "confidence": 0.8},
    )
    paths = store.find_paths("n1", "n3")
    assert paths == []


def test_find_paths_nonexistent_source_returns_empty() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    store.apply_event("NodeDiscovered", node_to_dict(n1))
    paths = store.find_paths("nonexistent", "n1")
    assert paths == []


def test_node_verified_sets_verified_true() -> None:
    store = NetworkXGraphStore()
    node = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
        verified=False,
    )
    store.apply_event("NodeDiscovered", node_to_dict(node))
    store.apply_event("NodeVerified", {"node_id": "n1", "oracle": "TestOracle"})
    retrieved = store.get_node("n1")
    assert retrieved is not None
    assert retrieved.verified is True
    assert retrieved.id == node.id
    assert retrieved.confidence == node.confidence


def test_node_verified_nonexistent_no_op() -> None:
    store = NetworkXGraphStore()
    initial_count = store.node_count()
    store.apply_event("NodeVerified", {"node_id": "nonexistent", "oracle": "TestOracle"})
    assert store.node_count() == initial_count


def test_clear_resets_counts_to_zero() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    store.apply_event("NodeDiscovered", node_to_dict(n1))
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": "n1", "target_id": "n2", "relationship": "exploits", "confidence": 0.8},
    )
    assert store.node_count() > 0
    assert store.edge_count() > 0
    store.clear()
    assert store.node_count() == 0
    assert store.edge_count() == 0


def test_rebuild_from_events_end_to_end() -> None:
    store = NetworkXGraphStore()
    n1 = AttackNode(
        id="n1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    n2 = AttackNode(
        id="n2",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.7,
    )
    events = [
        DummyEvent("NodeDiscovered", node_to_dict(n1)),
        DummyEvent("NodeDiscovered", node_to_dict(n2)),
        DummyEvent(
            "EdgeDiscovered",
            {
                "source_id": "n1",
                "target_id": "n2",
                "relationship": "exploits",
                "confidence": 0.8,
            },
        ),
    ]
    rebuild_from_events(store, events)
    assert store.node_count() == 2
    assert store.edge_count() == 1
    assert store.get_node("n1") is not None
    assert store.get_node("n2") is not None
    edge = store.get_edge("n1", "n2")
    assert edge is not None
    assert edge.relationship == RelationshipType.EXPLOITS


def test_networkx_import_only_in_networkx_store() -> None:
    agent_alpha_dir = "agent_alpha"
    files_with_networkx = []

    for root, _, files in os.walk(agent_alpha_dir):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                with open(filepath, encoding="utf-8") as f:
                    content = f.read()
                    if "import networkx" in content or "from networkx" in content:
                        files_with_networkx.append(filepath)

    assert len(files_with_networkx) == 1
    assert files_with_networkx[0] == os.path.join(agent_alpha_dir, "graph", "networkx_store.py")
