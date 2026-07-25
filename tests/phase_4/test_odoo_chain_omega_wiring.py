# tests/phase_4/test_odoo_chain_omega_wiring.py
"""Contract: Omega report is WIRED into the Odoo cred-reuse chain (anti-Lyndon #2).

Verified gap (@530ffee / CI #458): odoo_chain_runner is the ONLY chain runner that
never invokes Omega -- its siblings (wp_chain_runner, chain_runner, runner) all call
``Omega(graph_store).generate_report("technical")``. The Odoo graph
(CREDENTIAL --ENABLES--> ACCESS_LEVEL, vaulted secret_ref) already satisfies
summarize_chain_finding(), so the report is producible -- it is simply not called.

The fix exposes a testable module-level seam in odoo_chain_runner.py:

    def report_odoo_chain(graph_store: GraphStore) -> Report:
        return Omega(graph_store).generate_report("technical")

and main() calls it. Placing the reporter inline in main()'s print block (as
wp_chain_runner does) makes it un-testable without live HTTP -- which is exactly how a
dead-seam hides. This suite pins the seam instead.

These tests are RED at 530ffee (ImportError: report_odoo_chain) and go GREEN once the
one-file wiring fix lands.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_4/test_odoo_chain_omega_wiring.py
"""

from __future__ import annotations

import inspect

from agent_alpha.agents.omega.roaster import Report
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
    node_to_dict,
)
from agent_alpha.live_fire import odoo_chain_runner
from agent_alpha.live_fire.odoo_chain_runner import report_odoo_chain

_HOST = "vuln.odoo.lab"
_ASSET_ID = f"asset:{_HOST}"
_CRED_ID = f"cred:{_HOST}:odoo_admin"
_ACCESS_ID = f"access:{_HOST}"


def _emit_node(store: NetworkXGraphStore, node: AttackNode) -> None:
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


def _odoo_reuse_store(level: str, *, verified: bool = True) -> NetworkXGraphStore:
    """Graph the odoo chain produces: Alpha ASSET + Alpha-vaulted CREDENTIAL
    --ENABLES(T1078)--> Beta ACCESS_LEVEL (XML-RPC authenticate)."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(
            _ASSET_ID,
            NodeType.ASSET,
            AssetProperties(host=_HOST, tech_stack=["odoo"]),
            0.90,
            agent="alpha",
        ),
    )
    _emit_node(
        store,
        AttackNode(
            _CRED_ID,
            NodeType.CREDENTIAL,
            CredentialProperties(
                username="admin",
                secret_ref="secret_odoo_reuse",
                service="odoo",
                access_level="unverified",
            ),
            0.85,
            agent="alpha",
        ),
    )
    _emit_node(
        store,
        AttackNode(
            _ACCESS_ID,
            NodeType.ACCESS_LEVEL,
            AccessLevelProperties(level=level, user_context="odoo-xmlrpc"),
            0.80,
            agent="beta",
            verification=VerificationTier.CROSS_VERIFIED
            if verified
            else VerificationTier.UNVERIFIED,
        ),
    )
    # config-leak -> harvested credential, then reuse -> access. A connected
    # ASSET->CRED->ACCESS path is required for find_critical_paths to surface the
    # chain (terminal two nodes CRED->ACCESS are what summarize_chain_finding reads).
    _emit_edge(store, AttackEdge(_ASSET_ID, _CRED_ID, RelationshipType.LEADS_TO, 0.85))
    _emit_edge(store, AttackEdge(_CRED_ID, _ACCESS_ID, RelationshipType.ENABLES, 0.80, "T1078"))
    return store


def _hardened_store() -> NetworkXGraphStore:
    """True-negative: odoo fingerprinted but no reuse succeeded -- ASSET only,
    no ACCESS_LEVEL node. This must yield a valid empty finding, never a crash."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(
            _ASSET_ID,
            NodeType.ASSET,
            AssetProperties(host=_HOST, tech_stack=["odoo"]),
            0.90,
            agent="alpha",
        ),
    )
    return store


def _node_count(store: NetworkXGraphStore) -> int:
    return sum(len(store.nodes_by_type(t)) for t in NodeType)


# -- T1: proven odoo reuse graph -> non-empty chain finding (anti-#3) --------


def test_report_produces_chain_finding_on_admin_reuse() -> None:
    report = report_odoo_chain(_odoo_reuse_store("admin"))

    assert isinstance(report, Report)
    cf = report.chain_finding
    assert cf is not None
    assert cf.severity == "high"
    assert cf.access_level == "admin"
    assert cf.credential_id == _CRED_ID
    assert cf.access_id == _ACCESS_ID


# -- T2: reuse edge carries the ATT&CK technique into the report ------------


def test_report_surfaces_mitre_technique_from_enables_edge() -> None:
    report = report_odoo_chain(_odoo_reuse_store("admin"))

    assert "T1078" in report.mitre_techniques


# -- T3: hardened target -> None finding, valid result not a crash (anti-#3) -


def test_report_none_on_true_negative_without_access_level() -> None:
    report = report_odoo_chain(_hardened_store())

    assert isinstance(report, Report)
    assert report.chain_finding is None


# -- T4: unverified access must not inflate to high (honest severity) -------


def test_unverified_access_is_not_high() -> None:
    report = report_odoo_chain(_odoo_reuse_store("admin", verified=False))

    cf = report.chain_finding
    assert cf is not None
    assert cf.severity == "low"


# -- T5: Omega is READ-ONLY -- reporting must not mutate the graph -----------


def test_report_does_not_mutate_graph() -> None:
    store = _odoo_reuse_store("admin")
    nodes_before, edges_before = _node_count(store), len(store.all_edges())

    report_odoo_chain(store)

    assert (_node_count(store), len(store.all_edges())) == (nodes_before, edges_before)


# -- T6: dead-seam guard -- main() actually invokes the reporter (anti-#2) ---


def test_main_invokes_report_odoo_chain() -> None:
    """The whole point: the reporter must be called from the runnable entrypoint,
    not merely defined. Guards against report_odoo_chain becoming dead code."""
    src = inspect.getsource(odoo_chain_runner.main)
    assert "report_odoo_chain(" in src
