"""Omega consumes CoverageReport → honest Coverage & Methodology section (§12.45/§12.62)."""

from __future__ import annotations

from agent_alpha.agents.omega.roaster import Omega, render_coverage_section
from agent_alpha.coverage.coverage_ledger import CoverageCell, CoverageReport
from agent_alpha.graph.networkx_store import NetworkXGraphStore


def _cov() -> CoverageReport:
    return CoverageReport(
        cells=(
            CoverageCell("hub.x", "auth_surface", "cred_reuse", "tested"),
            CoverageCell("hub.x", "auth_surface", "spa_json_login", "blocked", "WAF"),
        ),
        not_assessed=("sqli_auth_bypass", "subdomain_takeover", "network_service_exposure"),
    )


def test_section_is_honest_and_carries_no_verdict() -> None:
    txt = render_coverage_section(_cov()).lower()
    assert "coverage & methodology" in txt
    assert "cred_reuse" in txt  # tested
    assert "blocked by target defenses" in txt  # blocked
    assert "sqli_auth_bypass" in txt and "subdomain_takeover" in txt  # NOT assessed
    assert "not a security verdict" in txt
    # never an AFFIRMATIVE safety verdict (the false-assurance failure mode)
    for bad in ("no vulnerabilities", "system is safe", "fully secure", "is not vulnerable"):
        assert bad not in txt


def test_none_coverage_renders_empty() -> None:
    assert render_coverage_section(None) == ""


def test_generate_report_attaches_coverage_to_narrative_and_field() -> None:
    report = Omega(NetworkXGraphStore()).generate_report(style="technical", coverage=_cov())
    assert report.coverage is not None
    assert "Coverage & Methodology" in report.narrative
    assert "sqli_auth_bypass" in report.narrative  # honest disclosure reaches the deliverable
    assert "not a security verdict" in report.narrative.lower()


def test_report_without_coverage_is_backward_compatible() -> None:
    report = Omega(NetworkXGraphStore()).generate_report(style="technical")
    assert report.coverage is None
    assert "Coverage & Methodology" not in report.narrative
