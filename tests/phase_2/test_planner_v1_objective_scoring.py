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
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    CredentialProperties,
    NodeType,
)
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


def _add_credential(
    store: NetworkXGraphStore,
    event_store: InMemoryEventStore,
    engagement_id: str,
    host: str,
    access_level: str,
) -> str:
    """CREDENTIAL node keyed to *host* via its id (credential props carry no host)."""
    node = AttackNode(
        id=f"cred_{host}",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="u", secret_ref="ref", service="svc", access_level=access_level
        ),
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


def _first_selection(
    store: NetworkXGraphStore,
    event_store: InMemoryEventStore,
    session_store: InMemorySessionStore,
    engagement_id: str,
    frontier: list[str],
    objective: dict[str, object] | None = None,
) -> str | None:
    """Set the objective, build a real Alpha, load the frontier, pop ONCE."""
    _set_session(session_store, engagement_id, {"objective": objective} if objective else {})
    alpha = _make_recording_alpha(store, event_store, session_store, [])
    alpha._engagement_id = engagement_id
    alpha._work_queue = list(frontier)
    alpha._probed = set()
    return alpha._pop_unprobed()


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


def test_differential_objective_evidence_steers_first_host() -> None:
    """Genuine anti-#11 differential: two hosts in the frontier. The graph that
    holds a credential toward the TARGET on host A makes host A's url first; the
    graph that holds it on host B makes host B's url first. A FIFO picks the same
    url regardless of graph — this must not. Passes on SEMANTICS, not a hash."""
    eid = "test_diff"
    frontier = ["http://a.example.com/x", "http://b.example.com/x"]
    obj = {"target_access_levels": ["admin", "root", "db_root"]}

    sa, ea, ssa = _make_graph_store(), _make_event_store(), _make_session_store()
    _add_credential(sa, ea, eid, "a.example.com", "db_root")
    first_a = _first_selection(sa, ea, ssa, eid, frontier, obj)

    sb, eb, ssb = _make_graph_store(), _make_event_store(), _make_session_store()
    _add_credential(sb, eb, eid, "b.example.com", "db_root")
    first_b = _first_selection(sb, eb, ssb, eid, frontier, obj)

    assert first_a == "http://a.example.com/x"
    assert first_b == "http://b.example.com/x"
    assert first_a != first_b  # graph-driven, provably not FIFO


def test_objective_target_changes_ranking() -> None:
    """SAME graph + frontier; changing target_access_levels flips which url is
    first. An objective-BLIND scorer (review claim #2) CANNOT pass this."""
    eid = "test_obj"
    frontier = ["http://a.example.com/x", "http://b.example.com/x"]
    store, es, ss = _make_graph_store(), _make_event_store(), _make_session_store()
    _add_credential(store, es, eid, "a.example.com", "admin")  # cred → admin on host A
    _add_credential(store, es, eid, "b.example.com", "db_root")  # cred → db_root on host B

    first_admin = _first_selection(
        store, es, ss, eid, frontier, {"target_access_levels": ["admin"]}
    )
    first_dbroot = _first_selection(
        store, es, ss, eid, frontier, {"target_access_levels": ["db_root"]}
    )

    assert first_admin == "http://a.example.com/x"
    assert first_dbroot == "http://b.example.com/x"
    assert first_admin != first_dbroot


def test_scoring_is_deterministic_no_hash() -> None:
    """Same (graph, objective, frontier) → identical pick every run. No hash, no
    randomness (review claim #3: differential must not depend on hash noise)."""
    eid = "test_det"
    frontier = ["http://a.example.com/x", "http://b.example.com/x"]
    obj = {"target_access_levels": ["db_root"]}
    picks = set()
    for _ in range(5):
        s, e, ss = _make_graph_store(), _make_event_store(), _make_session_store()
        _add_credential(s, e, eid, "b.example.com", "db_root")
        picks.add(_first_selection(s, e, ss, eid, frontier, obj))
    assert picks == {"http://b.example.com/x"}  # stable, semantic, not permuted by a hash


def test_no_objective_is_fifo() -> None:
    """objective absent → exact FIFO order (backward-compat)."""
    eid = "test_fifo"
    frontier = ["http://x/1", "http://x/2", "http://x/3"]
    s, e, ss = _make_graph_store(), _make_event_store(), _make_session_store()
    assert _first_selection(s, e, ss, eid, frontier, None) == "http://x/1"
