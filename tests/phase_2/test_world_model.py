"""WorldModel belief-boundary seam tests — T1 split, T2 objective, T3 read-only.

These verify the WorldModel facade partitions verified/hypothesis correctly,
delegates is_objective_met accurately, and never mutates the backing store.
Scorer regression (T4) and goal-completion regression (T5) are covered by
the existing test_planner_v1_objective_scoring.py and
test_planner_v1_goal_completed.py suites (must stay GREEN).
"""

from __future__ import annotations

import inspect

from agent_alpha.agents.objective import EngagementObjective
from agent_alpha.agents.world_model import WorldModel
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AssetProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
    VerificationTier,
)
from agent_alpha.graph.persist import persist_edge, persist_node

# ── Helpers ──────────────────────────────────────────────────────


def _make_stores() -> tuple[NetworkXGraphStore, InMemoryEventStore]:
    return NetworkXGraphStore(), InMemoryEventStore()


def _add_node(
    gs: NetworkXGraphStore,
    es: InMemoryEventStore,
    eid: str,
    node: AttackNode,
) -> None:
    persist_node(es, gs, eid, node, agent="test")


# ── T1: verified / hypothesis split ─────────────────────────────


def test_split_verified_vs_hypothesis() -> None:
    """One verified=True ACCESS_LEVEL + one verified=False ASSET.

    verified_facts() contains only the verified node;
    hypotheses() contains only the unverified node;
    all_beliefs() contains both.
    """
    gs, es = _make_stores()
    eid = "t1"

    verified_node = AttackNode(
        id="access_admin",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level="admin"),
        confidence=0.9,
        agent="test",
        verification=VerificationTier.CROSS_VERIFIED,
    )
    unverified_node = AttackNode(
        id="asset_host",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host.example.com", tech_stack=[]),
        confidence=0.7,
        agent="test",
        verified=False,
    )
    _add_node(gs, es, eid, verified_node)
    _add_node(gs, es, eid, unverified_node)

    wm = WorldModel(gs)

    facts = wm.verified_facts()
    hypos = wm.hypotheses()
    beliefs = wm.all_beliefs()

    # Verified node in facts, not in hypotheses
    fact_ids = [n.id for n in facts]
    hypo_ids = [n.id for n in hypos]
    belief_ids = [n.id for n in beliefs]

    assert "access_admin" in fact_ids
    assert "access_admin" not in hypo_ids

    # Unverified node in hypotheses, not in facts
    assert "asset_host" in hypo_ids
    assert "asset_host" not in fact_ids

    # Both in all_beliefs
    assert "access_admin" in belief_ids
    assert "asset_host" in belief_ids
    assert len(beliefs) == 2


# ── T2: objective boundary via WorldModel ────────────────────────


def test_objective_boundary_unverified_then_verified() -> None:
    """is_objective_met() is False while the target ACCESS_LEVEL is
    verified=False; True only after it is verified=True and reached
    via a CREDENTIAL -ENABLES-> edge.
    """
    gs, es = _make_stores()
    eid = "t2"
    obj = EngagementObjective(
        target_access_levels=frozenset(["admin"]),
        description="reach admin",
    )

    # Stage 1: unverified ACCESS_LEVEL + CREDENTIAL + ENABLES edge
    cred = AttackNode(
        id="cred_admin",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="u", secret_ref="r", service="s", access_level="admin"
        ),
        confidence=0.9,
        agent="test",
    )
    acc_unverified = AttackNode(
        id="access_admin",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level="admin"),
        confidence=0.9,
        agent="test",
        verified=False,
    )
    _add_node(gs, es, eid, cred)
    _add_node(gs, es, eid, acc_unverified)
    persist_edge(
        es,
        gs,
        eid,
        AttackEdge(
            source_id="cred_admin",
            target_id="access_admin",
            relationship=RelationshipType.ENABLES,
            confidence=0.9,
        ),
        agent="test",
    )

    wm = WorldModel(gs)
    assert wm.is_objective_met(obj) is False, "unverified ACCESS_LEVEL must not satisfy objective"

    # Stage 2: verify the ACCESS_LEVEL via NodeVerified event
    gs.apply_event("NodeVerified", {"node_id": "access_admin", "oracle": "TestOracle"})

    wm2 = WorldModel(gs)
    assert wm2.is_objective_met(obj) is True, "verified ACCESS_LEVEL + ENABLES edge must satisfy"


def test_objective_met_none_objective() -> None:
    """is_objective_met(None) always returns False."""
    gs, _ = _make_stores()
    wm = WorldModel(gs)
    assert wm.is_objective_met(None) is False


def test_objective_met_none_graph_store() -> None:
    """WorldModel constructed with None graph_store → is_objective_met returns False."""
    wm = WorldModel(None)
    obj = EngagementObjective(
        target_access_levels=frozenset(["admin"]),
        description="",
    )
    assert wm.is_objective_met(obj) is False


# ── T3: read-only — no mutation ──────────────────────────────────


def test_read_only_no_mutation() -> None:
    """Constructing and querying WorldModel does not change the backing
    graph_store's node or edge counts.
    """
    gs, es = _make_stores()
    eid = "t3"

    node = AttackNode(
        id="asset_ro",
        type=NodeType.ASSET,
        properties=AssetProperties(host="ro.example.com", tech_stack=[]),
        confidence=0.8,
        agent="test",
    )
    _add_node(gs, es, eid, node)

    nc_before = gs.node_count()
    ec_before = gs.edge_count()

    wm = WorldModel(gs)
    _ = wm.verified_facts()
    _ = wm.hypotheses()
    _ = wm.all_beliefs()
    _ = wm.is_objective_met(None)

    assert gs.node_count() == nc_before
    assert gs.edge_count() == ec_before


def test_world_model_has_no_write_methods() -> None:
    """WorldModel source exposes no persist / append / apply calls."""
    source = inspect.getsource(WorldModel)
    for forbidden in ("persist_node", "persist_edge", "append", "apply_event"):
        assert forbidden not in source, f"WorldModel must be read-only but references '{forbidden}'"
