# agent_alpha/events/projectors.py
# CQRS read-side projector: replays the append-only AgentEvent stream
# into the queryable AttackGraph.
#
# ADR §8o-1: the AttackGraph is a pure projection of the event stream —
# never written to directly.  This module is the intentional integration
# point that may import BOTH events.store AND graph.store, but must NOT
# import any concrete GraphStore implementation (e.g. NetworkXGraphStore).

from __future__ import annotations

import dataclasses
import typing

from agent_alpha.events.store import AgentEvent, EventStore
from agent_alpha.graph.store import GraphStore, rebuild_from_events


@dataclasses.dataclass(frozen=True)
class ProjectionResult:
    """Immutable summary returned after a projection run."""

    engagement_id: str
    events_processed: int
    graph_node_count: int
    graph_edge_count: int
    last_sequence_number: int


class AttackGraphProjector:
    """Replays an ``EventStore`` stream into a ``GraphStore`` projection.

    This class is the glue between the write-side (``EventStore``) and
    the read-side (``GraphStore``).  ``AgentEvent`` already satisfies the
    duck-typed contract expected by ``rebuild_from_events`` (attributes
    ``event_type`` and ``payload``), so no translation layer is needed.
    """

    def __init__(
        self,
        event_store: EventStore,
        graph_store: GraphStore,
    ) -> None:
        self._event_store = event_store
        self._graph_store = graph_store

    # ------------------------------------------------------------------
    # Full rebuild
    # ------------------------------------------------------------------

    def project(self, engagement_id: str) -> ProjectionResult:
        """Full rebuild: clear the graph and replay *all* events.

        This is the canonical projection path.  §12.11: "anything
        reconstructable from the event log MAY be volatile" — we always
        rebuild from scratch for correctness.
        """
        events: list[AgentEvent] = self._event_store.get_events(engagement_id)

        # rebuild_from_events calls store.clear() then apply_event() per
        # event, in order.  It accepts any sequence whose elements have
        # .event_type and .payload — AgentEvent satisfies that contract.
        rebuild_from_events(self._graph_store, events)

        last_seq = events[-1].sequence_number if events else 0

        return ProjectionResult(
            engagement_id=engagement_id,
            events_processed=len(events),
            graph_node_count=self._graph_store.node_count(),
            graph_edge_count=self._graph_store.edge_count(),
            last_sequence_number=last_seq,
        )

    # ------------------------------------------------------------------
    # Incremental projection
    # ------------------------------------------------------------------

    def project_incremental(
        self,
        engagement_id: str,
        after_sequence: int,
    ) -> ProjectionResult:
        """Apply only events newer than *after_sequence* onto the
        **existing** graph state.  Does **not** call ``clear()``.

        Useful for live updates during an active engagement without a
        full graph rebuild every time.
        """
        new_events: list[AgentEvent] = self._event_store.get_events(
            engagement_id,
            after_sequence=after_sequence,
        )

        for event in new_events:
            self._graph_store.apply_event(event.event_type, event.payload)

        last_seq = new_events[-1].sequence_number if new_events else after_sequence

        return ProjectionResult(
            engagement_id=engagement_id,
            events_processed=len(new_events),
            graph_node_count=self._graph_store.node_count(),
            graph_edge_count=self._graph_store.edge_count(),
            last_sequence_number=last_seq,
        )

    # ------------------------------------------------------------------
    # Consistency verification
    # ------------------------------------------------------------------

    def verify_projection(
        self,
        engagement_id: str,
        fresh_store_factory: typing.Callable[[], GraphStore],
    ) -> bool:
        """Replay-and-compare consistency check.

        Builds a **fresh** ``GraphStore`` (via *fresh_store_factory*) and
        projects the full event stream into it, then compares node/edge
        counts against ``self._graph_store``.

        Returns ``True`` when the current projection is drift-free,
        ``False`` otherwise.  This is a read-only check — it does **not**
        replace ``self._graph_store``.

        The factory pattern keeps this class engine-agnostic: only the
        *caller* decides which concrete ``GraphStore`` to construct.
        """
        fresh_store: GraphStore = fresh_store_factory()
        events: list[AgentEvent] = self._event_store.get_events(engagement_id)
        rebuild_from_events(fresh_store, events)

        return (
            self._graph_store.node_count() == fresh_store.node_count()
            and self._graph_store.edge_count() == fresh_store.edge_count()
        )
