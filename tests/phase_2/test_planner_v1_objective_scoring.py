#!/usr/bin/env python3
"""Planner v1 objective scoring tests — RED until P2/P3.

Tests verify that next=f(graph,objective) via differential test, objective priority,
FIFO fallback when no objective, and deterministic behavior.

Anti-Lyndon #11: plans MUST emerge from f(graph, objective), never a static list.
§12.30: deterministic signal, not improvisation — NO LLM in v1 scorer.
"""

from __future__ import annotations

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, AttackNode, NodeType
from agent_alpha.graph.persist import persist_node
from agent_alpha.memory.session import InMemorySessionStore, SessionRecord


def _make_graph_store() -> NetworkXGraphStore:
    return NetworkXGraphStore()


def _make_session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


def _make_event_store() -> InMemoryEventStore:
    return InMemoryEventStore()


OBJECTIVE = {"target_access_levels": ["admin", "root", "db_root"]}


def _add_asset(
    store: NetworkXGraphStore,
    event_store: InMemoryEventStore,
    engagement_id: str,
    host: str,
    *,
    tech_stack: list[str] | None = None,
) -> str:
    """Add an ASSET node to the graph via the canonical persist seam."""
    node = AttackNode(
        id=f"asset_{host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, tech_stack=tech_stack or []),
        confidence=0.9,
        agent="alpha",
    )
    persist_node(event_store, store, engagement_id, node, agent="alpha")
    return node.id


def _set_session(
    session_store: InMemorySessionStore,
    engagement_id: str,
    scratchpad: dict[str, object],
) -> None:
    session_store.set(
        SessionRecord(
            engagement_id=engagement_id,
            target_scope={},
            active_agent="alpha",
            current_phase="recon",
            current_phase_iteration=0,
            authorization={},
            scratchpad=scratchpad,
            ttl_seconds=86400,
        )
    )


def _make_recording_alpha(
    graph_store: NetworkXGraphStore,
    event_store: InMemoryEventStore,
    session_store: InMemorySessionStore,
    selections: list[str],
) -> Alpha:
    """Build a real Alpha whose _pop_unprobed records every popped URL."""

    class _RecordingAlpha(Alpha):
        def _pop_unprobed(self) -> str | None:
            url = super()._pop_unprobed()
            if url:
                selections.append(url)
            return url

    alpha = _RecordingAlpha(
        authorization=None,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=None,
        http_client=None,
        session_store=session_store,
    )
    alpha._engagement_id = "test"  # overridden per-test
    return alpha


def test_differential_same_frontier_different_graphs_selects_different_first_url() -> None:
    """t_differential (THE anti-#11 proof): same frontier set, TWO different graph states.

    Graph A has an ASSET whose tech_stack signals a login surface (advances the
    objective "reach access_level in {admin,root,db_root}").
    Graph B has a bare ASSET with no such signal.

    The FIRST url the agent selects DIFFERS between A and B.
    A static FIFO would pick the same first url both times; the planner must not.

    RED until P2/P3 — planner not yet wired.
    """
    engagement_id = "test_differential"
    frontier_urls = [
        "http://example.com/page1",
        "http://example.com/page2",
        "http://example.com/page3",
    ]

    # Graph A: ASSET with login-form in tech_stack (advances objective)
    store_a = _make_graph_store()
    es_a = _make_event_store()
    ss_a = _make_session_store()
    _add_asset(store_a, es_a, engagement_id, "example.com", tech_stack=["login-form"])
    _set_session(ss_a, engagement_id, {"objective": OBJECTIVE})

    # Graph B: bare ASSET (does not advance objective)
    store_b = _make_graph_store()
    es_b = _make_event_store()
    ss_b = _make_session_store()
    _add_asset(store_b, es_b, engagement_id, "example.com", tech_stack=[])
    _set_session(ss_b, engagement_id, {"objective": OBJECTIVE})

    selections_a: list[str] = []
    selections_b: list[str] = []

    alpha_a = _make_recording_alpha(store_a, es_a, ss_a, selections_a)
    alpha_a._engagement_id = engagement_id
    alpha_a._work_queue = list(frontier_urls)

    alpha_b = _make_recording_alpha(store_b, es_b, ss_b, selections_b)
    alpha_b._engagement_id = engagement_id
    alpha_b._work_queue = list(frontier_urls)

    # Pop first URL from each — NON-ISLAND: drives the real scout frontier
    alpha_a._pop_unprobed()
    alpha_b._pop_unprobed()

    assert len(selections_a) == 1
    assert len(selections_b) == 1
    assert selections_a[0] != selections_b[0], (
        "Differential FAILED: same first URL for different graph states. "
        "A static FIFO planner picks the same URL regardless of graph state; "
        "an objective-aware planner f(graph, objective) must not. (anti-Lyndon #11)"
    )


def test_objective_priority_advancing_url_selected_before_generic() -> None:
    """t_objective_priority: given an objective, frontier URL that advances objective
    is selected BEFORE a generic URL, regardless of enqueue order.

    RED until P2/P3 — planner not yet wired.
    """
    engagement_id = "test_priority"
    store = _make_graph_store()
    es = _make_event_store()
    ss = _make_session_store()
    _add_asset(store, es, engagement_id, "example.com", tech_stack=["login-form"])
    _set_session(ss, engagement_id, {"objective": OBJECTIVE})

    # Generic URL enqueued FIRST, login URL SECOND.
    # Objective-aware planner should still select login first.
    frontier_urls = ["http://example.com/generic", "http://example.com/login"]

    selections: list[str] = []
    alpha = _make_recording_alpha(store, es, ss, selections)
    alpha._engagement_id = engagement_id
    alpha._work_queue = list(frontier_urls)

    alpha._pop_unprobed()

    assert len(selections) == 1
    assert selections[0] == "http://example.com/login", (
        "Priority FAILED: objective-advancing URL was not selected first. "
        "FIFO picks the first-enqueued generic URL; an objective-aware planner "
        "must prioritise URLs whose graph context advances the objective."
    )


def test_no_objective_is_fifo() -> None:
    """t_no_objective_is_fifo: objective=None → selection order is exactly FIFO (today's behaviour).

    GREEN today — this is the backward-compat fallback.
    """
    engagement_id = "test_fifo"
    store = _make_graph_store()
    es = _make_event_store()
    ss = _make_session_store()
    _set_session(ss, engagement_id, {})  # No objective

    frontier_urls = [
        "http://example.com/page1",
        "http://example.com/page2",
        "http://example.com/page3",
    ]

    selections: list[str] = []
    alpha = _make_recording_alpha(store, es, ss, selections)
    alpha._engagement_id = engagement_id
    alpha._work_queue = list(frontier_urls)

    while alpha._pop_unprobed():
        pass

    assert selections == frontier_urls, "With no objective, selection must be FIFO"


def test_deterministic_same_graph_objective_frontier_same_selection() -> None:
    """t_deterministic: same (graph, objective, frontier) → same selection every run.

    No LLM, no randomness — deterministic scorer.
    GREEN today — current FIFO is deterministic.
    """
    engagement_id = "test_deterministic"
    store = _make_graph_store()
    es = _make_event_store()
    ss = _make_session_store()
    _add_asset(store, es, engagement_id, "example.com", tech_stack=["login-form"])
    _set_session(ss, engagement_id, {"objective": {"target_access_levels": ["admin"]}})

    frontier_urls = ["http://example.com/page1", "http://example.com/page2"]

    selections_run1: list[str] = []
    alpha1 = _make_recording_alpha(store, es, ss, selections_run1)
    alpha1._engagement_id = engagement_id
    alpha1._work_queue = list(frontier_urls)
    while alpha1._pop_unprobed():
        pass

    selections_run2: list[str] = []
    alpha2 = _make_recording_alpha(store, es, ss, selections_run2)
    alpha2._engagement_id = engagement_id
    alpha2._work_queue = list(frontier_urls)
    while alpha2._pop_unprobed():
        pass

    assert selections_run1 == selections_run2, "Selection must be deterministic"
