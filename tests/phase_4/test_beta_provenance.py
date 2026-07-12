# tests/phase_4/test_beta_provenance.py
"""Pin the provenance trap: Beta/strike writes emit agent="beta", Alpha recon
writes emit agent="alpha".

This test exists because the 7 _persist copies were NOT identical — the agent
string differed.  A naive hoist that hardcodes "alpha" would silently
misattribute every Beta write, corrupting the event-sourced audit trail (legal
evidence).  The canonical ``persist_node``/``persist_edge`` seam takes an
explicit ``agent=`` kwarg precisely to prevent this.

Contract:
  * Beta NODE_DISCOVERED events carry agent="beta".
  * Alpha NODE_DISCOVERED events carry agent="alpha".
  * Reading from the event_store (not the graph) — the event is the record of
    who wrote what.
"""

from __future__ import annotations

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    CredentialProperties,
    NodeType,
)
from agent_alpha.graph.persist import persist_node

ENG = "test-provenance-eng-001"


def _make_asset_node(host: str, *, agent: str) -> AttackNode:
    return AttackNode(
        id=f"asset:{host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, tech_stack=["test"]),
        confidence=0.85,
        agent=agent,
        timestamp_utc="2026-07-12T00:00:00Z",
    )


def test_beta_persist_node_emits_agent_beta() -> None:
    """Beta/strike writes a node → the NODE_DISCOVERED event's agent field is 'beta'."""
    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()
    node = _make_asset_node("beta-target.invalid", agent="beta")

    persist_node(event_store, graph_store, ENG, node, agent="beta")

    events = event_store.get_events(ENG)
    node_events = [e for e in events if e.event_type == EventType.NODE_DISCOVERED]
    assert len(node_events) == 1
    assert node_events[0].agent == "beta", (
        f"Beta write must emit agent='beta', got '{node_events[0].agent}'"
    )


def test_alpha_persist_node_emits_agent_alpha() -> None:
    """Alpha recon writes a node → the NODE_DISCOVERED event's agent field is 'alpha'."""
    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()
    node = _make_asset_node("alpha-target.invalid", agent="alpha")

    persist_node(event_store, graph_store, ENG, node, agent="alpha")

    events = event_store.get_events(ENG)
    node_events = [e for e in events if e.event_type == EventType.NODE_DISCOVERED]
    assert len(node_events) == 1
    assert node_events[0].agent == "alpha", (
        f"Alpha write must emit agent='alpha', got '{node_events[0].agent}'"
    )


def test_mixed_provenance_preserved_across_agents() -> None:
    """Both agents persist into the same event_store — each event retains its own provenance."""
    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()

    alpha_node = _make_asset_node("shared-target.invalid", agent="alpha")
    persist_node(event_store, graph_store, ENG, alpha_node, agent="alpha")

    beta_node = AttackNode(
        id="cred:shared-target.invalid:admin",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="admin",
            secret_ref="vault://test",
            service="http",
            access_level="user",
        ),
        confidence=0.9,
        agent="beta",
        timestamp_utc="2026-07-12T00:00:01Z",
        verified=True,
    )
    persist_node(event_store, graph_store, ENG, beta_node, agent="beta")

    events = event_store.get_events(ENG)
    node_events = [e for e in events if e.event_type == EventType.NODE_DISCOVERED]
    assert len(node_events) == 2

    agents_by_order = [e.agent for e in node_events]
    assert agents_by_order == ["alpha", "beta"], (
        f"Expected ['alpha', 'beta'], got {agents_by_order}"
    )
