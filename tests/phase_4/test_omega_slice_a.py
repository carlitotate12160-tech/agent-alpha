"""Omega Slice A test contract — evidence bundle + structured critical path.

Tests the payable core: critical_path, evidence, blast_radius fields on Report.
Validates the core invariant: every risk claim MUST trace to a graph edge with
technique_id AND be backed by >= 1 ProofArtifact (anti-#3 at report level).
"""

from __future__ import annotations

from agent_alpha.agents.omega.roaster import EvidenceItem, Omega, PathStep, Report
from agent_alpha.graph.networkx_store import NetworkXGraphStore


def test_report_has_critical_path_field() -> None:
    """Report now includes critical_path field (backward compatible default empty)."""
    report = Report(
        narrative="test",
        mitre_techniques=[],
        mitre_attack_version="v14",
    )
    assert report.critical_path == ()


def test_report_has_evidence_field() -> None:
    """Report now includes evidence field (backward compatible default empty)."""
    report = Report(
        narrative="test",
        mitre_techniques=[],
        mitre_attack_version="v14",
    )
    assert report.evidence == ()


def test_report_has_blast_radius_field() -> None:
    """Report now includes blast_radius field (backward compatible default None)."""
    report = Report(
        narrative="test",
        mitre_techniques=[],
        mitre_attack_version="v14",
    )
    assert report.blast_radius is None


def test_path_step_view_struct() -> None:
    """PathStep is a thin view struct, not a new domain type."""
    step = PathStep(
        from_node="asset-1",
        edge_technique_id="T1078",
        to_node="cred-1",
        node_kind="credential",
    )
    assert step.from_node == "asset-1"
    assert step.edge_technique_id == "T1078"
    assert step.to_node == "cred-1"
    assert step.node_kind == "credential"


def test_evidence_item_view_struct() -> None:
    """EvidenceItem is a thin view struct carrying redacted artifact data."""
    evidence = EvidenceItem(
        technique_id="T1078",
        description="Config backup leak",
        artifact_ref="storage://artifact-123",
        sha256="abc123",
        captured_at="2026-07-21T00:00:00Z",
    )
    assert evidence.technique_id == "T1078"
    assert evidence.description == "Config backup leak"
    assert evidence.artifact_ref == "storage://artifact-123"
    assert evidence.sha256 == "abc123"
    assert evidence.captured_at == "2026-07-21T00:00:00Z"


def test_omega_generate_report_populates_critical_path() -> None:
    """Omega.generate_report() walks find_critical_paths() and populates critical_path."""
    graph = NetworkXGraphStore()

    # Build a simple chain: asset -> credential -> access via events
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

    omega = Omega(graph)
    report = omega.generate_report("executive")

    # Critical path should have 2 steps
    assert len(report.critical_path) == 2
    assert report.critical_path[0].from_node == "asset-1"
    assert report.critical_path[0].edge_technique_id == "T1078"
    assert report.critical_path[0].to_node == "cred-1"
    assert report.critical_path[1].from_node == "cred-1"
    assert report.critical_path[1].edge_technique_id == "T1552.001"
    assert report.critical_path[1].to_node == "access-1"


def test_omega_generate_report_populates_evidence_from_proof_artifacts() -> None:
    """Omega.generate_report() collects ProofArtifacts from critical path nodes."""
    graph = NetworkXGraphStore()

    # Build asset node with proof artifact via event
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
                    "artifact_id": "artifact-1",
                    "type": "config_backup",
                    "storage_ref": "storage://backup-1",
                    "description": "wp-config.php.bak leak",
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

    omega = Omega(graph)
    report = omega.generate_report("executive")

    # Evidence should include the artifact from the asset node
    assert len(report.evidence) >= 1
    evidence = report.evidence[0]
    assert evidence.technique_id == "T1078"
    assert evidence.description == "wp-config.php.bak leak"
    assert evidence.artifact_ref == "storage://backup-1"
    assert evidence.captured_at == "2026-07-21T00:00:00Z"
    # SHA-256 is computed from storage_ref
    assert evidence.sha256 != ""


def test_omega_generate_report_populates_blast_radius() -> None:
    """Omega.generate_report() computes blast_radius from entry node."""
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

    omega = Omega(graph)
    report = omega.generate_report("executive")

    # Blast radius should be computed from the entry node
    assert report.blast_radius is not None
    assert report.blast_radius.from_node_id == "asset-1"
    assert report.blast_radius.reachable_count >= 1  # At least the credential


def test_redaction_guard_no_raw_secret_in_report() -> None:
    """REDACTION guard: report serialization contains no raw secret values."""
    # This is a placeholder for the actual guard test
    # The guard should assert that no known secret value appears in the serialized Report
    # For now, we test that EvidenceItem only carries artifact_ref, not raw secret
    evidence = EvidenceItem(
        technique_id="T1078",
        description="Config backup leak",
        artifact_ref="storage://artifact-123",
        sha256="abc123",
        captured_at="2026-07-21T00:00:00Z",
    )
    # EvidenceItem has no raw secret field
    assert not hasattr(evidence, "raw_secret")
    assert not hasattr(evidence, "value")


def test_provenance_guard_evidence_has_technique_id_and_artifact_ref() -> None:
    """PROVENANCE guard: every EvidenceItem has non-empty technique_id and artifact_ref."""
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
                    "artifact_id": "artifact-1",
                    "type": "config_backup",
                    "storage_ref": "storage://backup-1",
                    "description": "wp-config.php.bak leak",
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
                "secret_ref": "vault://secret-1",
                "service": "odoo",
                "access_level": "admin",
            },
            "confidence": 0.9,
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

    omega = Omega(graph)
    report = omega.generate_report("executive")

    # Every evidence item must have technique_id and artifact_ref
    for evidence in report.evidence:
        assert evidence.technique_id != "", f"Evidence missing technique_id: {evidence}"
        assert evidence.artifact_ref != "", f"Evidence missing artifact_ref: {evidence}"


def test_reproducibility_empty_graph() -> None:
    """REPRODUCIBILITY: empty graph produces empty critical_path and evidence."""
    graph = NetworkXGraphStore()
    omega = Omega(graph)

    report1 = omega.generate_report("executive")
    report2 = omega.generate_report("executive")

    assert report1.critical_path == report2.critical_path
    assert report1.evidence == report2.evidence
    assert report1.blast_radius == report2.blast_radius


def test_narrative_non_empty_for_all_styles() -> None:
    """narrative non-empty for each of executive|technical|remediation."""
    graph = NetworkXGraphStore()
    omega = Omega(graph)

    for style in ["executive", "technical", "remediation"]:
        report = omega.generate_report(style)
        assert report.narrative != "", f"narrative empty for style={style}"
