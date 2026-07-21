"""Omega Slice B test contract — attack-flow diagram rendering.

Tests rendering the selected critical path as a Mermaid attack-flow diagram,
populating Report.attack_flow_mermaid. Validates consistency invariant:
diagram path == evidence path (critical_path steps).
"""

from __future__ import annotations

from agent_alpha.agents.omega.roaster import (
    Omega,
    _sanitize_mermaid_id,
    render_attack_flow,
)
from agent_alpha.graph.networkx_store import NetworkXGraphStore


def _build_proven_chain_graph() -> NetworkXGraphStore:
    graph = NetworkXGraphStore()
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "asset-1",
            "type": "asset",
            "properties": {"host": "example.com", "ip": "1.2.3.4"},
            "confidence": 1.0,
            "verified": False,
        },
    )
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "cred-1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": "vault://secret-1",
                "service": "odoo",
                "access_level": "admin",
            },
            "confidence": 0.9,
            "verified": False,
        },
    )
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "access-1",
            "type": "access_level",
            "properties": {"level": "admin"},
            "confidence": 0.8,
            "verified": False,
        },
    )
    graph.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "asset-1",
            "target_id": "cred-1",
            "relationship": "leads_to",
            "confidence": 0.9,
            "technique_id": "T1078",
        },
    )
    graph.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "cred-1",
            "target_id": "access-1",
            "relationship": "enables",
            "confidence": 0.8,
            "technique_id": "T1552.001",
        },
    )
    return graph


def test_attack_flow_renders_valid_mermaid() -> None:
    """Proven-chain graph -> attack_flow_mermaid starts with 'graph LR' and is non-empty."""
    graph = _build_proven_chain_graph()
    omega = Omega(graph)
    report = omega.generate_report("executive")

    assert report.attack_flow_mermaid != ""
    assert report.attack_flow_mermaid.startswith("graph LR")


def test_attack_flow_matches_selected_critical_path() -> None:
    """The diagram's edges correspond 1:1 to report.critical_path steps (same from/to/technique)."""
    graph = _build_proven_chain_graph()
    omega = Omega(graph)
    report = omega.generate_report("executive")

    assert len(report.critical_path) > 0
    diagram = report.attack_flow_mermaid

    for step in report.critical_path:
        from_sanitized = _sanitize_mermaid_id(step.from_node)
        to_sanitized = _sanitize_mermaid_id(step.to_node)
        tech = step.edge_technique_id.strip() if step.edge_technique_id else ""

        if tech:
            expected_edge = f"{from_sanitized} -->|{tech}| {to_sanitized}"
        else:
            expected_edge = f"{from_sanitized} --> {to_sanitized}"

        assert expected_edge in diagram, f"Edge '{expected_edge}' missing from Mermaid diagram"


def test_attack_flow_node_count_matches_distinct_path_nodes() -> None:
    """Node count in diagram == distinct node ids in critical_path."""
    graph = _build_proven_chain_graph()
    omega = Omega(graph)
    report = omega.generate_report("executive")

    distinct_node_ids = set()
    for step in report.critical_path:
        distinct_node_ids.add(step.from_node)
        distinct_node_ids.add(step.to_node)

    lines = report.attack_flow_mermaid.splitlines()
    node_decl_lines = [line for line in lines if '["' in line and '"]' in line]

    assert len(node_decl_lines) == len(distinct_node_ids)


def test_attack_flow_deterministic() -> None:
    """Generate the report twice on the same graph -> identical attack_flow_mermaid string."""
    graph = _build_proven_chain_graph()
    omega = Omega(graph)
    report1 = omega.generate_report("executive")
    report2 = omega.generate_report("executive")

    assert report1.attack_flow_mermaid == report2.attack_flow_mermaid

    diagram1 = render_attack_flow(report1.critical_path)
    diagram2 = render_attack_flow(report1.critical_path)
    assert diagram1 == diagram2


def test_attack_flow_empty_graph_is_empty_string() -> None:
    """No critical path -> attack_flow_mermaid == ''."""
    graph = NetworkXGraphStore()
    omega = Omega(graph)
    report = omega.generate_report("executive")

    assert report.critical_path == ()
    assert report.attack_flow_mermaid == ""
    assert render_attack_flow(()) == ""


def test_attack_flow_no_secret_in_diagram() -> None:
    """Seed a known secret; assert it does NOT appear in attack_flow_mermaid."""
    secret = "SUPER_SECRET_TOKEN_9999_DO_NOT_LEAK"
    graph = NetworkXGraphStore()
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "asset-1",
            "type": "asset",
            "properties": {"host": "example.com", "ip": "1.2.3.4"},
            "confidence": 1.0,
            "verified": False,
            "proof_artifacts": [
                {
                    "artifact_id": "art-1",
                    "type": "config_backup",
                    "storage_ref": f"storage://{secret}",
                    "description": f"Leaked token {secret}",
                    "captured_at": "2026-07-21T00:00:00Z",
                    "agent": "alpha",
                }
            ],
        },
    )
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "access-1",
            "type": "access_level",
            "properties": {"level": "admin"},
            "confidence": 0.9,
            "verified": False,
        },
    )
    graph.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "asset-1",
            "target_id": "access-1",
            "relationship": "enables",
            "confidence": 0.9,
            "technique_id": "T1078",
        },
    )

    omega = Omega(graph)
    report = omega.generate_report("technical")

    assert secret not in report.attack_flow_mermaid
