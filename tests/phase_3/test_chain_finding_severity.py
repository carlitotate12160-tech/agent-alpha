# tests/phase_3/test_chain_finding_severity.py
"""Phase-3: chain-derived severity for the cred-reuse finding (ADR Option A).

DECISION (Natanael, 2026-06-28): severity of a cred-reuse finding is derived
from the VERIFIED ``CREDENTIAL --ENABLES--> ACCESS_LEVEL`` chain edge, NOT from
forward blast radius. calculate_blast_radius is left untouched (forward
reachability of the leaf access node is ~0 until Delta/post-exploit exists —
reporting a downstream number now would be Lyndon #3 false-success). The report
states the downstream honestly via ``downstream_mapped``.

These tests pin the severity classifier + the honest downstream flag.
Run on Oracle ARM64 only:  .venv/bin/python3 -m pytest tests/phase_3/test_chain_finding_severity.py
"""

from __future__ import annotations

from agent_alpha.graph.narrative import ChainFinding, summarize_chain_finding
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
    VulnerabilityProperties,
    node_to_dict,
)

_HOST = "lab.target.internal"
_ASSET_ID = f"asset:{_HOST}"
_VULN_ID = f"vuln:{_HOST}:laravel_debug"
_CRED_ID = f"cred:{_HOST}:db_password"
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


def _build_chain_store(access_level: str, *, access_verified: bool = True) -> NetworkXGraphStore:
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(_ASSET_ID, NodeType.ASSET, AssetProperties(host=_HOST), 0.90, agent="alpha"),
    )
    _emit_node(
        store,
        AttackNode(
            _VULN_ID, NodeType.VULNERABILITY, VulnerabilityProperties(), 0.75, agent="alpha"
        ),
    )
    _emit_node(
        store,
        AttackNode(
            _CRED_ID,
            NodeType.CREDENTIAL,
            CredentialProperties(
                username="db_password",
                secret_ref="secret_abc123",
                service="http",
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
            AccessLevelProperties(level=access_level, user_context="web"),
            0.80,
            agent="beta",
            verification=VerificationTier.CROSS_VERIFIED
            if access_verified
            else VerificationTier.UNVERIFIED,
        ),
    )
    _emit_edge(store, AttackEdge(_ASSET_ID, _VULN_ID, RelationshipType.EXPLOITS, 0.90))
    _emit_edge(store, AttackEdge(_VULN_ID, _CRED_ID, RelationshipType.LEADS_TO, 0.85))
    _emit_edge(store, AttackEdge(_CRED_ID, _ACCESS_ID, RelationshipType.ENABLES, 0.80, "T1078"))
    return store


def test_returns_none_when_no_credential_access_chain() -> None:
    """asset -> vuln only (Phase-2 graph): no cred-reuse finding."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(_ASSET_ID, NodeType.ASSET, AssetProperties(host=_HOST), 0.90, agent="alpha"),
    )
    _emit_node(
        store,
        AttackNode(
            _VULN_ID, NodeType.VULNERABILITY, VulnerabilityProperties(), 0.75, agent="alpha"
        ),
    )
    _emit_edge(store, AttackEdge(_ASSET_ID, _VULN_ID, RelationshipType.EXPLOITS, 0.90))

    assert summarize_chain_finding(store) is None


def test_admin_web_access_is_high() -> None:
    finding = summarize_chain_finding(_build_chain_store("admin"))

    assert isinstance(finding, ChainFinding)
    assert finding.severity == "high"
    assert finding.credential_id == _CRED_ID
    assert finding.access_id == _ACCESS_ID
    assert finding.access_level == "admin"


def test_user_access_is_medium() -> None:
    finding = summarize_chain_finding(_build_chain_store("user"))

    assert finding is not None
    assert finding.severity == "medium"


def test_db_root_access_is_critical() -> None:
    finding = summarize_chain_finding(_build_chain_store("db_root"))

    assert finding is not None
    assert finding.severity == "critical"


def test_unverified_access_does_not_inflate_severity() -> None:
    """An access node that was never verified must not be reported as high."""
    finding = summarize_chain_finding(_build_chain_store("admin", access_verified=False))

    assert finding is not None
    assert finding.severity == "low"


def test_downstream_not_mapped_until_delta() -> None:
    """The access node is a leaf (no post-exploit yet) — report it honestly,
    do NOT fabricate a forward blast radius (anti-Lyndon #3)."""
    finding = summarize_chain_finding(_build_chain_store("admin"))

    assert finding is not None
    assert finding.downstream_mapped is False
