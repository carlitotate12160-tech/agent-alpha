# agent_alpha/agents/world_model.py
"""Read-only belief model over the attack graph.

Formalises the implicit verified-vs-hypothesis boundary as ONE typed
read-model.  Every consumer that needs the belief split (planner scorer,
goal-completion check) reads through this facade instead of querying
``graph_store`` directly.

This slice is behaviour-preserving:

* ``all_beliefs()`` == ``graph_store.all_nodes()`` (same ordering).
* ``is_objective_met()`` delegates to ``EngagementObjective.is_met()``.

**D2 extension points (NOT built here):**

* Scratchpad hypotheses merged into ``hypotheses()`` (§12.30).
* Verified > hypothesis weighting in the planner scorer.
* Simulation / graph forking for HTN plan evaluation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_alpha.graph.nodes import AttackNode


class WorldModel:
    """Read-only view of the attack graph partitioned by verification status.

    Parameters
    ----------
    graph_store:
        The backing ``NetworkXGraphStore`` (or duck-type with ``all_nodes``).
        **Never** written to by this class.
    """

    __slots__ = ("_graph_store",)

    def __init__(self, graph_store: Any) -> None:
        self._graph_store = graph_store

    # ── Belief partition ────────────────────────────────────────

    def verified_facts(self) -> list[AttackNode]:
        """Nodes the agent has confirmed (``verified is True``)."""
        return [n for n in self._graph_store.all_nodes() if n.verified]

    def hypotheses(self) -> list[AttackNode]:
        """Nodes still unconfirmed (``verified is False``)."""
        return [n for n in self._graph_store.all_nodes() if not n.verified]

    def all_beliefs(self) -> list[AttackNode]:
        """All nodes — verified facts **and** hypotheses.

        Ordering is identical to ``graph_store.all_nodes()`` so that
        existing consumers (frontier scorer) get byte-for-byte identical
        iteration.
        """
        return list(self._graph_store.all_nodes())

    # ── Objective boundary ──────────────────────────────────────

    def is_objective_met(self, objective: Any) -> bool:
        """ONE verified-boundary entry point for goal-completion checks.

        Delegates to ``objective.is_met(graph_store)``; returns ``False``
        when *objective* is ``None`` or the backing graph store is absent.
        """
        if objective is None:
            return False
        if self._graph_store is None:
            return False
        return bool(objective.is_met(self._graph_store))
