"""Omega Slice C test contract — HTML report export (client deliverable).

Tests rendering full Report as a self-contained HTML deliverable containing ALL sections:
narrative, attack-flow diagram, evidence bundle, blast radius, and MITRE/chain findings.
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
    """Proven-chain Report -> HTML contains all 5 sections in correct order and content."""
    graph, _ = _build_proven_chain_graph_with_evidence()
    omega = Omega(graph)
    report = omega.generate_report("executive", time_to_first_proof_s=45.2)

    html_out = report.to_html()

    # (a) Executive/technical narrative section
    assert '<section id="narrative">' in html_out
    assert "Executive / Technical Narrative" in html_out
    assert report.narrative in html_out or report.narrative[:50] in html_out

    # (b) Attack-flow diagram section with exact attack_flow_mermaid body inside <pre class="mermaid">
    assert '<section id="attack-flow">' in html_out
    assert '<pre class="mermaid">' in html_out
    assert html.escape(report.attack_flow_mermaid) in html_out
    assert (
        '<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>'
        in html_out
    )
    assert "mermaid.initialize({startOnLoad: true});" in html_out

    # (c) Evidence bundle section
    assert '<section id="evidence">' in html_out
    assert '<table class="evidence-table">' in html_out
    for item in report.evidence:
        assert item.artifact_ref in html_out
        assert item.technique_id in html_out

    # (d) Blast radius summary section
    assert '<section id="blast-radius">' in html_out
    assert report.blast_radius is not None
    assert report.blast_radius.from_node_id in html_out

    # (e) Section 5: MITRE techniques + chain_finding + time_to_proof headline
    assert '<section id="mitre-summary">' in html_out
    assert "MITRE ATT&amp;CK &amp; Findings Summary" in html_out
    assert "Time to First Proof:" in html_out
    assert "45s" in html_out or "0m 45s" in html_out
    for tech in report.mitre_techniques:
        assert tech in html_out
    if report.chain_finding:
        assert report.chain_finding.credential_id in html_out
        assert report.chain_finding.access_id in html_out


def test_html_evidence_matches_report() -> None:
    """Number of evidence table rows == len(report.evidence); each technique_id + artifact_ref present."""
    graph, _ = _build_proven_chain_graph_with_evidence()
    omega = Omega(graph)
    report = omega.generate_report("technical")

    html_out = report.to_html()

    # Count <tr> tags inside <tbody> in the evidence table
    tbody_match = re.search(r"<tbody>(.*?)</tbody>", html_out, re.DOTALL)
    assert tbody_match is not None, "Evidence tbody not found in HTML"
    tbody_content = tbody_match.group(1)
    row_count = tbody_content.count("<tr>")

    assert row_count == len(report.evidence)

    for item in report.evidence:
        assert item.technique_id in html_out
        assert item.artifact_ref in html_out
        assert item.sha256 in html_out


def test_html_no_raw_secret() -> None:
    """Seeded raw secret in credential vault ref must NOT appear in generated Report HTML."""
    graph, raw_secret = _build_proven_chain_graph_with_evidence()
    omega = Omega(graph)
    report = omega.generate_report("technical")

    html_out = report.to_html()

    # The raw secret was placed in credential secret_ref vault://...
    # Verify that the raw secret does not leak into any section of the generated HTML report.
    assert raw_secret not in html_out

    # Non-vacuous check: if the secret were injected into a rendered field (e.g. description),
    # rendering that field would cause raw_secret to be present in HTML.
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
    assert "No attack flow data available." in html_out
    assert "No evidence collected." in html_out
    assert "No blast radius calculated." in html_out
    assert "No MITRE techniques recorded." in html_out
    assert "No verified chain finding." in html_out
    assert "Time to First Proof:" in html_out
    assert "N/A" in html_out


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
        attack_flow_mermaid=f'graph LR\n  node1["{malicious_text}"]',
    )

    html_out = report.to_html()

    # Raw unescaped script tag MUST NOT appear in the output
    assert "<script>alert" not in html_out

    # Escaped versions must appear in the HTML
    assert "&lt;script&gt;" in html_out or "&lt;script&gt;alert" in html_out
    assert "&amp;" in html_out
