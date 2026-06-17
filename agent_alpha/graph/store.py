from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from agent_alpha.graph.nodes import AttackEdge, AttackNode, NodeType, RelationshipType


@runtime_checkable
class GraphStore(Protocol):
    """Read-model interface for the attack graph.

    This interface is intentionally write-limited: the only mutation
    entry point is ``apply_event``. Implementations are expected to
    build and maintain their internal graph representation purely as
    a projection of the domain event log.
    """

    def apply_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Apply a single domain event to the in-memory graph.

        Unknown ``event_type`` values MUST be treated as a no-op so
        that projections remain forward-compatible with new events.
        """

    def get_node(self, node_id: str) -> AttackNode | None:
        """Return the node with ``node_id``, or ``None`` if missing."""

    def get_edge(self, source_id: str, target_id: str) -> AttackEdge | None:
        """Return the edge from ``source_id`` to ``target_id``, or ``None``."""

    def all_nodes(self) -> list[AttackNode]:
        ...

    def all_edges(self) -> list[AttackEdge]:
        ...

    def nodes_by_type(self, node_type: NodeType) -> list[AttackNode]:
        ...

    def edges_by_relationship(
        self, relationship: RelationshipType
    ) -> list[AttackEdge]:
        ...

    def neighbors(self, node_id: str) -> list[AttackNode]:
        """Nodes directly connected to ``node_id`` via any outgoing edge."""

    def find_paths(self, source_id: str, target_id: str) -> list[list[AttackNode]]:
        """All simple paths from ``source_id`` to ``target_id``.

        Returns an empty list if either endpoint is missing or no path exists.
        """

    def node_count(self) -> int:
        ...

    def edge_count(self) -> int:
        ...

    def clear(self) -> None:
        """Reset the underlying graph to an empty state."""


def rebuild_from_events(store: GraphStore, events: list[Any]) -> None:
    """Rebuild a ``GraphStore`` projection from an ordered event stream.

    The function is generic over any implementation of ``GraphStore`` and
    only relies on the structural interface (duck-typing). The ``events``
    sequence is expected to contain objects with ``event_type`` and
    ``payload`` attributes; this matches the shape of ``AgentEvent`` from
    the event store without importing it directly to avoid a circular
    dependency between ``graph`` and ``events``.
    """

    # Always start from a clean slate so the resulting in-memory graph is
    # a pure projection of the supplied events sequence.
    store.clear()

    for event in events:
        # duck-typed: ``event_type`` and ``payload`` must be attributes
        # on each element; implementations are responsible for treating
        # unknown event types as no-ops.
        store.apply_event(event.event_type, event.payload)
