# tests/phase_3/test_chain_narrative_and_blast.py
"""Phase-3 guard: the field-proven cred-reuse chain must RENDER in the report.

Phase 2 reported "no attack chains found" because the graph was only
``asset -> vuln`` (no endpoint reachable from ASSET to ACCESS_LEVEL/DATA).
The cred-reuse chain now adds ``credential -> access_level`` (ENABLES), so the
graph is ``asset -> vuln -> credential -> access_level`` and the existing
machinery (find_critical_paths defaults source=[ASSET], target=[DATA,
ACCESS_LEVEL]) SHOULD now find a non-empty chain.

This test PINS that claim (anti-Lyndon #2 "verify wiring, never assume" +
#3 "validated non-empty output"). It builds the exact chain graph through the
event-projection path the agents use, then asserts the chain is rendered by
both the raw narrative and Omega's report. If a future refactor breaks chain
discovery, this goes RED instead of silently regressing to "no chains found".

NOTE: This is a characterization+guard test. It is expected to pass on the
current HEAD — its value is permanent regression protection, and it is the
prerequisite gate before wiring the chain report into chain_runner.
"""

from __future__ import annotations

from agent_alpha.agents.omega.roaster import Omega
from agent_alpha.graph.narrative import highest_impact_chain
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AssetProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)

# Canonical chain ids — mirror the live producers:
#   scout.py  : asset:{host}  --EXPLOITS-->  vuln  --LEADS_TO-->  cred:{host}:db_password
#   strike.py : cred  --ENABLES-->  access:{host}
_HOST = "lab.target.internal"
_ASSET_ID = f"asset:{_HOST}"
_VULN_ID = f"vuln:{_HOST}:laravel_debug"
_CRED_ID = f"cred:{_HOST}:db_password"
_ACCESS_ID = f"access:{_HOST}"

_CHAIN_ORDER = [_ASSET_ID, _VULN_ID, _CRED_ID, _ACCESS_ID]


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


def _build_chain_store() -> NetworkXGraphStore:
    """Project the canonical asset->vuln->credential->access chain."""
    store = NetworkXGraphStore()

    _emit_node(
        store,
        AttackNode(
            id=_ASSET_ID,
            type=NodeType.ASSET,
            properties=AssetProperties(host=_HOST, tech_stack=["laravel"]),
            confidence=0.90,
            agent="alpha",
        ),
    )
    _emit_node(
        store,
        AttackNode(
            id=_VULN_ID,
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(affected_service="http"),
            confidence=0.75,
            agent="alpha",
        ),
    )
    _emit_node(
        store,
        AttackNode(
            id=_CRED_ID,
            type=NodeType.CREDENTIAL,
            properties=CredentialProperties(
                username="db_password",
                secret_ref="vault://eng/secret-1",
                service="http",
                access_level="unverified",
            ),
            confidence=0.85,
            agent="alpha",
        ),
    )
    _emit_node(
        store,
        AttackNode(
            id=_ACCESS_ID,
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(level="admin", user_context="web"),
            confidence=0.80,
            agent="beta",
            verified=True,
        ),
    )

    _emit_edge(
        store,
        AttackEdge(_ASSET_ID, _VULN_ID, RelationshipType.EXPLOITS, 0.90, "T1592.002"),
    )
    _emit_edge(
        store,
        AttackEdge(_VULN_ID, _CRED_ID, RelationshipType.LEADS_TO, 0.85),
    )
    _emit_edge(
        store,
        AttackEdge(_CRED_ID, _ACCESS_ID, RelationshipType.ENABLES, 0.80, "T1078"),
    )
    return store


def test_highest_impact_chain_spans_asset_to_access() -> None:
    """find_attack_chains must return the full 4-hop chain, not None."""
    store = _build_chain_store()

    chain = highest_impact_chain(store)

    assert chain is not None, "chain discovery returned None on a real cred-reuse graph"
    assert [n.id for n in chain.nodes] == _CHAIN_ORDER
    assert chain.chain_length == 4
    # endpoint must be the ACCESS_LEVEL node (the proven compromise), not the vuln
    assert chain.nodes[-1].type == NodeType.ACCESS_LEVEL


def test_technical_narrative_contains_full_chain() -> None:
    """The technical narrative must render the chain, NOT 'no attack chains found'."""
    store = _build_chain_store()

    report = Omega(store).generate_report("technical")

    assert "(no attack chains found)" not in report.narrative
    assert " -> ".join(_CHAIN_ORDER) in report.narrative


def test_omega_report_includes_credential_hop_techniques() -> None:
    """The report's MITRE techniques must include the credential-reuse edge tech id."""
    store = _build_chain_store()

    report = Omega(store).generate_report("technical")

    # T1078 (Valid Accounts) rides the credential->access ENABLES edge.
    assert "T1078" in report.mitre_techniques
