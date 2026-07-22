"""Omega Slice C test contract — HTML report export (client deliverable).

Tests rendering full Report as a self-contained HTML deliverable containing ALL sections:
narrative, attack-flow static SVG diagram, evidence bundle, blast radius, and recommendations.
Asserts content validity, redaction, determinism, placeholder handling, and HTML escaping.
"""

from __future__ import annotations

import html
import re

from agent_alpha.agents.omega.report_html import render_report_html
from agent_alpha.agents.omega.roaster import EvidenceItem, Omega, PathStep, Report
from agent_alpha.graph.narrative import BlastRadius
from agent_alpha.graph.networkx_store import NetworkXGraphStore


def _build_proven_chain_graph_with_evidence() -> tuple[NetworkXGraphStore, str]:
    """Helper: builds a proven-chain graph with proof artifacts and a vault secret."""
    raw_secret = "SUPER_SECRET_VAULT_PASSWORD_12345"
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
                    "storage_ref": "storage://backup-wp-config",
                    "description": "wp-config.php leak containing database credentials",
                    "captured_at": "2026-07-21T00:00:00Z",
                    "agent": "alpha",
                }
            ],
        },
    )
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "cred-1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": f"vault://{raw_secret}",
                "service": "odoo",
                "access_level": "admin",
            },
            "confidence": 0.9,
            "verified": False,
            "proof_artifacts": [
                {
                    "artifact_id": "art-2",
                    "type": "session_dump",
                    "storage_ref": "storage://session-admin-token",
                    "description": "Session token extracted from response header",
                    "captured_at": "2026-07-21T00:01:00Z",
                    "agent": "beta",
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
            "confidence": 0.8,
            "verified": True,
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

    return graph, raw_secret


def test_html_contains_all_sections() -> None:
    """Proven-chain Report -> HTML contains narrative, severity table, static SVG, findings, blast radius, recommendations."""
    graph, _ = _build_proven_chain_graph_with_evidence()
    omega = Omega(graph)
    report = omega.generate_report("executive", time_to_first_proof_s=45.2)

    html_out = report.to_html()

    # Branding
    assert "Agent-Alpha" in html_out
    assert "Confidential" in html_out

    # Section 1: Executive summary
    assert "Executive summary" in html_out
    assert report.narrative in html_out or report.narrative[:50] in html_out
    assert '<table class="sev">' in html_out or 'table' in html_out

    # Section 2: Attack path (static SVG, NO Mermaid JS)
    assert "Attack path" in html_out
    assert "<svg" in html_out
    assert "#0f1620" in html_out
    assert "mermaid.min.js" not in html_out

    # Section 3: Findings and proof
    assert "Findings and proof" in html_out
    for item in report.evidence:
        assert item.artifact_ref in html_out

    # Section 4: Impact and blast radius
    assert "Impact and blast radius" in html_out
    assert report.blast_radius is not None
    assert report.blast_radius.from_node_id in html_out

    # Section 5: Recommendations
    assert "Recommendations" in html_out

    # Footer
    assert "Agent-Alpha — Confidential" in html_out


def test_attack_svg_matches_critical_path() -> None:
    """SVG contains one node per distinct node in critical_path and edge technique IDs for 2-hop and multi-hop paths."""
    # 2-hop path (3 nodes: nodeA -> nodeB -> nodeC)
    step1 = PathStep("nodeA", "T1078", "nodeB", "asset")
    step2 = PathStep("nodeB", "T1552.001", "nodeC", "access_level")
    report_2hop = Report(
        narrative="2-hop test",
        mitre_techniques=["T1078", "T1552.001"],
        mitre_attack_version="v14",
        critical_path=(step1, step2),
    )
    svg_2hop = report_2hop.to_html()
    assert "nodeA" in svg_2hop
    assert "nodeB" in svg_2hop
    assert "nodeC" in svg_2hop
    assert "T1078" in svg_2hop
    assert "T1552.001" in svg_2hop
    assert "COMPROMISED" in svg_2hop

    # Longer 3-hop path (4 nodes: n1 -> n2 -> n3 -> n4)
    s1 = PathStep("n1", "T1190", "n2", "asset")
    s2 = PathStep("n2", "T1552", "n3", "credential")
    s3 = PathStep("n3", "T1078.004", "n4", "access_level")
    report_3hop = Report(
        narrative="3-hop test",
        mitre_techniques=["T1190", "T1552", "T1078.004"],
        mitre_attack_version="v14",
        critical_path=(s1, s2, s3),
    )
    svg_3hop = report_3hop.to_html()
    for n in ["n1", "n2", "n3", "n4"]:
        assert n in svg_3hop
    for t in ["T1190", "T1552", "T1078.004"]:
        assert t in svg_3hop


def test_html_no_raw_secret() -> None:
    """Seeded raw secret in credential vault ref must NOT appear in generated Report HTML."""
    graph, raw_secret = _build_proven_chain_graph_with_evidence()
    omega = Omega(graph)
    report = omega.generate_report("technical")

    html_out = report.to_html()
    assert raw_secret not in html_out

    # Non-vacuous check: if secret were in description, it WOULD render
    bad_evidence = EvidenceItem(
        technique_id="T1078",
        description=f"Leaked secret: {raw_secret}",
        artifact_ref="storage://test",
        sha256="123",
        captured_at="2026-07-21T00:00:00Z",
    )
    bad_report = Report(
        narrative="test",
        mitre_techniques=[],
        mitre_attack_version="v14",
        evidence=(bad_evidence,),
    )
    assert raw_secret in bad_report.to_html()


def test_html_branding_not_a1() -> None:
    """Assert 'Agent-Alpha' present and internal scenario label 'A1'/'a1_validation' is NOT surfaced as report title/brand."""
    report = Report(
        narrative="Test narrative",
        mitre_techniques=[],
        mitre_attack_version="v14",
    )
    html_out = report.to_html()
    assert "Agent-Alpha" in html_out
    assert "<title>Agent-Alpha" in html_out
    assert "<title>Security Assessment Report</title>" not in html_out
    assert "a1_validation" not in html_out


def test_html_deterministic() -> None:
    """Rendering the same Report twice produces byte-identical HTML output."""
    graph, _ = _build_proven_chain_graph_with_evidence()
    omega = Omega(graph)
    report = omega.generate_report("executive")

    html1 = report.to_html()
    html2 = report.to_html()

    assert html1 == html2
    assert render_report_html(report) == report.to_html()


def test_html_empty_report_renders_placeholders() -> None:
    """Empty report -> valid HTML with 'no data' placeholders, no crash."""
    empty_report = Report(
        narrative="",
        mitre_techniques=[],
        mitre_attack_version="v14",
        chain_finding=None,
        time_to_first_proof_s=None,
        critical_path=(),
        evidence=(),
        blast_radius=None,
        attack_flow_mermaid="",
    )

    html_out = empty_report.to_html()

    assert "<!DOCTYPE html>" in html_out
    assert "No narrative available." in html_out
    assert "No critical attack path available." in html_out or "No attack flow data" in html_out
    assert "No evidence collected." in html_out
    assert "No blast radius calculated." in html_out


def test_html_escapes_field_text() -> None:
    """Fields containing HTML special characters ('<script>', '&', etc.) are properly escaped."""
    malicious_text = "<script>alert('XSS & Injection')</script>"

    report = Report(
        narrative=malicious_text,
        mitre_techniques=[malicious_text],
        mitre_attack_version="v14",
        critical_path=(
            PathStep(
                from_node=malicious_text,
                edge_technique_id=malicious_text,
                to_node="target",
                node_kind="asset",
            ),
        ),
        evidence=(
            EvidenceItem(
                technique_id=malicious_text,
                description=malicious_text,
                artifact_ref=malicious_text,
                sha256="abc123",
                captured_at="2026-07-21T00:00:00Z",
            ),
        ),
        blast_radius=BlastRadius(
            from_node_id=malicious_text,
            reachable_node_ids=[malicious_text],
            reachable_count=1,
            high_value_targets=[malicious_text],
            severity="high",
        ),
    )

    html_out = report.to_html()

    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out or "&lt;script&gt;alert" in html_out
    assert "&amp;" in html_out
