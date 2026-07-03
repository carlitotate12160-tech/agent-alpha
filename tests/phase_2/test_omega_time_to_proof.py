"""RED tests for Omega time-to-proof headline feature.

Tests the format_duration formatter, Report.time_to_proof_headline method,
Omega.generate_report parameter threading, and PDF export headline rendering.
All fields default to None for zero regression.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_alpha.agents.omega.roaster import Omega, Report, format_duration
from agent_alpha.graph.networkx_store import NetworkXGraphStore


def test_format_duration() -> None:
    """Format seconds as human-readable duration (None-safe)."""
    assert format_duration(None) is None
    assert format_duration(45.3) == "0m 45s"
    assert format_duration(120.0) == "2m 00s"
    assert format_duration(3665.0) == "1h 01m 05s"


def test_report_time_to_proof_headline_uses_format_duration() -> None:
    """Report.time_to_proof_headline delegates to format_duration."""
    report = Report(
        narrative="test",
        mitre_techniques=[],
        mitre_attack_version="v14",
        time_to_first_proof_s=300.0,
    )
    assert report.time_to_proof_headline() == "5m 00s"


def test_report_time_to_proof_headline_none_when_no_metric() -> None:
    """Report with time_to_first_proof_s=None -> headline returns None."""
    report = Report(
        narrative="test",
        mitre_techniques=[],
        mitre_attack_version="v14",
        time_to_first_proof_s=None,
    )
    assert report.time_to_proof_headline() is None


def test_omega_generate_report_threads_time_to_proof() -> None:
    """Omega.generate_report accepts time_to_first_proof_s and passes to Report."""
    graph_store = NetworkXGraphStore()
    omega = Omega(graph_store)
    report = omega.generate_report("executive", time_to_first_proof_s=180.0)
    assert report.time_to_first_proof_s == 180.0


def test_omega_generate_report_defaults_to_none() -> None:
    """Omega.generate_report without time_to_first_proof_s -> field is None."""
    graph_store = NetworkXGraphStore()
    omega = Omega(graph_store)
    report = omega.generate_report("executive")
    assert report.time_to_first_proof_s is None


def test_pdf_export() -> None:
    """PDF export works with and without time-to-proof headline."""
    # With metric
    report = Report(
        narrative="Test narrative body.",
        mitre_techniques=[],
        mitre_attack_version="v14",
        time_to_first_proof_s=90.0,
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.pdf"
        report.export_pdf(path)
        assert path.exists()
        assert path.stat().st_size > 0

    # Without metric (None)
    report = Report(
        narrative="Test narrative body.",
        mitre_techniques=[],
        mitre_attack_version="v14",
        time_to_first_proof_s=None,
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.pdf"
        report.export_pdf(path)
        assert path.exists()
        assert path.stat().st_size > 0
