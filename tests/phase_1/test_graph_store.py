from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_alpha.graph.nodes import AttackEdge, AttackNode, NodeType, RelationshipType
from agent_alpha.graph.store import GraphStore, rebuild_from_events


@dataclass
class DummyEvent:
    event_type: str
    payload: dict[str, Any]


class FakeGraphStore:
    def __init__(self) -> None:
        self.operations: list[tuple[Any, ...]] = []
        self._nodes: dict[str, AttackNode] = {}

    def apply_event(self, event_type: str, payload: dict[str, Any]) -> None:
        self.operations.append(("apply_event", event_type, payload))

    def get_node(self, node_id: str) -> AttackNode | None:
        return self._nodes.get(node_id)

    def get_edge(self, source_id: str, target_id: str) -> AttackEdge | None:
        return None

    def all_nodes(self) -> list[AttackNode]:
        return list(self._nodes.values())

    def all_edges(self) -> list[AttackEdge]:
        return []

    def nodes_by_type(self, node_type: NodeType) -> list[AttackNode]:
        return []

    def edges_by_relationship(self, relationship: RelationshipType) -> list[AttackEdge]:
        return []

    def neighbors(self, node_id: str) -> list[AttackNode]:
        return []

    def find_paths(self, source_id: str, target_id: str) -> list[list[AttackNode]]:
        return []

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return 0

    def clear(self) -> None:
        self.operations.append(("clear", None))


def test_fake_graph_store_satisfies_graph_store_protocol() -> None:
    store = FakeGraphStore()

    assert isinstance(store, GraphStore)


def test_rebuild_from_events_clears_once_before_any_apply_event() -> None:
    store = FakeGraphStore()
    events = [
        DummyEvent("NodeDiscovered", {"id": "n1"}),
        DummyEvent("NodeVerified", {"id": "n1"}),
    ]

    rebuild_from_events(store, events)

    kinds = [op[0] for op in store.operations]

    assert kinds[0] == "clear"
    assert kinds.count("clear") == 1
    assert kinds.count("apply_event") == len(events)


def test_rebuild_from_events_applies_each_event_in_order() -> None:
    store = FakeGraphStore()
    events = [
        DummyEvent("NodeDiscovered", {"id": "n1"}),
        DummyEvent("NodeVerified", {"id": "n1"}),
        DummyEvent("EdgeDiscovered", {"source": "n1", "target": "n2"}),
    ]

    rebuild_from_events(store, events)

    applied_event_types = [op[1] for op in store.operations if op[0] == "apply_event"]

    assert applied_event_types == [e.event_type for e in events]


def test_rebuild_from_events_with_empty_event_list_still_clears() -> None:
    store = FakeGraphStore()

    rebuild_from_events(store, [])

    assert store.operations == [("clear", None)]


def test_fake_graph_store_get_node_missing_returns_none() -> None:
    store = FakeGraphStore()

    assert store.get_node("nonexistent-node-id") is None
