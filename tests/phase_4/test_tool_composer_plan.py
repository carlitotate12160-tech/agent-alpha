"""RED test — Phase 4, slice 1: ToolComposer.plan() contract.

This test is written BEFORE the implementation (anti-Lyndon #2: no dead
code, test-as-spec).  It pins the CONTRACT only, never the internals, so
the body author (composer.py) is free on mechanism but bound on behaviour.

What this slice proves:
  - plan() reads target state via the EXISTING ``GraphStore`` protocol
    (agent_alpha.graph.store) — no second "GraphState" canonical type
    (anti-#6).
  - plan == f(graph state), NEVER a static pipeline (anti-#11, the Lyndon
    "hardcoded sequence = tool runner" trap).  A different fingerprint MUST
    yield a different first action.
  - No plan is fabricated from nothing: empty graph -> empty plan, and every
    step targets a node that actually exists (anti-#3, no silent/false plan).

Out of scope for this slice (deliberately, to avoid dead types):
  - Execution / ToolResult (that is the next slice — plan-not-execute here).
  - Payload bodies (DeepSeek lane K21, only inside Template.verify()).

Seal: Oracle ARM64 only —  `.venv312/bin/python3 -m pytest tests/phase_4`
      + `make check`.  Sandbox/x86/Windows results are NOT valid (anti-#9).
"""

from __future__ import annotations

import pytest

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    NodeType,
    RelationshipType,
    ServiceProperties,
    VulnerabilityProperties,
    node_to_dict,
)

# Under test — does not exist yet, so this import fails RED (expected).
from agent_alpha.tools.composer import Plan, PlanStep, ToolComposer
from agent_alpha.tools.registry import ToolRegistry

# ── store builders (mirror tests/phase_3 convention) ────────────────


def _emit(store: NetworkXGraphStore, node: AttackNode) -> None:
    store.apply_event("NodeDiscovered", node_to_dict(node))


def _emit_edge(store: NetworkXGraphStore, edge: AttackEdge) -> None:
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "relationship": edge.relationship.value,
            "confidence": edge.confidence,
            "technique_id": edge.technique_id,
        },
    )


def _web_vuln_store() -> NetworkXGraphStore:
    """Fingerprint A: a web asset with an exploitable web vulnerability."""
    store = NetworkXGraphStore()
    _emit(
        store,
        AttackNode(
            id="asset_web",
            type=NodeType.ASSET,
            properties=AssetProperties(
                host="shop.client.example",
                tech_stack=["php", "laravel"],
                open_ports=[443],
            ),
            confidence=0.9,
            agent="alpha",
        ),
    )
    _emit(
        store,
        AttackNode(
            id="vuln_sqli",
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                cve_id=None,
                cvss_score=8.6,
                affected_service="https",
                exploit_available=True,
            ),
            confidence=0.8,
            agent="alpha",
        ),
    )
    _emit_edge(
        store,
        AttackEdge(
            source_id="asset_web",
            target_id="vuln_sqli",
            relationship=RelationshipType.EXPLOITS,
            confidence=0.8,
        ),
    )
    return store


def _db_service_store() -> NetworkXGraphStore:
    """Fingerprint B: an exposed database service — no web vuln at all."""
    store = NetworkXGraphStore()
    _emit(
        store,
        AttackNode(
            id="asset_db_host",
            type=NodeType.ASSET,
            properties=AssetProperties(
                host="db.client.example",
                ip="10.0.0.5",
                open_ports=[3306],
            ),
            confidence=0.9,
            agent="alpha",
        ),
    )
    _emit(
        store,
        AttackNode(
            id="svc_mysql",
            type=NodeType.SERVICE,
            properties=ServiceProperties(
                name="mysql",
                version="8.0",
                port=3306,
            ),
            confidence=0.85,
            agent="alpha",
        ),
    )
    return store


def _composer() -> ToolComposer:
    return ToolComposer(registry=ToolRegistry.default())


# ── contract: plan() reads via the GraphStore protocol ──────────────


def test_plan_returns_a_plan_over_graphstore() -> None:
    plan = _composer().plan(_web_vuln_store())
    assert isinstance(plan, Plan)
    assert all(isinstance(s, PlanStep) for s in plan.steps)


# ── anti-#3: no plan fabricated from nothing ────────────────────────


def test_empty_graph_yields_empty_plan() -> None:
    plan = _composer().plan(NetworkXGraphStore())
    # No fabricated "default" step when there is nothing to act on.
    assert plan.steps == ()


def test_every_step_targets_an_existing_node() -> None:
    store = _web_vuln_store()
    known_ids = {n.id for n in store.all_nodes()}
    plan = _composer().plan(store)
    assert plan.steps, "a graph with an exploitable vuln must yield >=1 step"
    for step in plan.steps:
        assert step.target_node_id in known_ids


# ── determinism: same state -> same plan ────────────────────────────


def test_plan_is_deterministic() -> None:
    composer = _composer()
    plan_a = composer.plan(_web_vuln_store())
    plan_b = composer.plan(_web_vuln_store())
    assert plan_a == plan_b


# ── anti-#11: plan == f(graph), NOT a static pipeline ───────────────


def test_plan_first_action_depends_on_fingerprint() -> None:
    """The heart of the slice: two different graphs -> different first tool.

    If someone implements plan() as a fixed step list regardless of target
    (the Lyndon "scan example.com the same way every time" failure), both
    first steps collapse to the same tool and this test fails.
    """
    composer = _composer()
    plan_web = composer.plan(_web_vuln_store())
    plan_db = composer.plan(_db_service_store())

    assert plan_web.steps, "web-vuln graph must produce a plan"
    assert plan_db.steps, "db-service graph must produce a plan"
    assert plan_web.steps[0].tool != plan_db.steps[0].tool


# ── immutability: plan is a value, agents never mutate shared state ──


def test_plan_is_immutable() -> None:
    plan = _composer().plan(_web_vuln_store())
    with pytest.raises((AttributeError, TypeError)):
        plan.steps = ()  # type: ignore[misc]
