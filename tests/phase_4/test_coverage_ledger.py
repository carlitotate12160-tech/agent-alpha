"""Coverage ledger — engagement-scope coverage projection (§12.45 generalization)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_alpha.coverage.coverage_ledger import load_catalog, project_coverage


@dataclass
class _Ev:
    event_type: str
    payload: dict[str, Any]


def _node_ev(host: str, tech_stack: list[str] | None = None) -> _Ev:
    """Real NodeDiscovered event shape: properties nested under 'properties'."""
    props: dict[str, Any] = {"host": host}
    if tech_stack:
        props["tech_stack"] = tech_stack
    return _Ev("NodeDiscovered", {"type": "asset", "properties": props})


def _buckets(report: Any, surface_type: str) -> dict[str, str]:
    return {c.technique_id: c.bucket for c in report.cells if c.surface_type == surface_type}


def test_catalog_loads_and_is_single_source() -> None:
    cat = load_catalog()
    ids = {t.id for t in cat}
    assert {"cred_reuse", "spa_json_login", "sqli_auth_bypass"} <= ids
    # every non-capable technique carries a gap_ref (roadmap linkage, anti-#7)
    assert all(t.gap_ref for t in cat if not t.capability_present)


def test_auth_surface_tested_vs_capability_absent() -> None:
    events = [
        _node_ev("hub.x", ["login-form"]),
        _Ev("StrikeCandidateAttempted", {"host": "hub.x"}),
    ]
    b = _buckets(project_coverage(events), "auth_surface")
    assert b["cred_reuse"] == "tested"
    assert b["spa_json_login"] == "tested"
    assert b["sqli_auth_bypass"] == "capability_absent"  # honest "we do NOT test SQLi"
    assert b["mfa_challenge_honest"] == "capability_absent"
    assert b["http_basic_auth_strike"] == "capability_absent"


def test_not_run_is_runtime_wiring_gate() -> None:
    """Capable + applicable but no run event = not_run (catches dead-code at runtime)."""
    events = [_node_ev("hub.x", ["login-form"])]  # NO strike
    b = _buckets(project_coverage(events), "auth_surface")
    assert b["cred_reuse"] == "not_run"
    assert b["spa_json_login"] == "not_run"


def test_blocked_beats_tested_for_capable() -> None:
    events = [
        _node_ev("hub.x", ["login-form"]),
        _Ev("StrikeCandidateAttempted", {"host": "hub.x"}),
        _Ev("WafBlocked", {"host": "hub.x"}),
    ]
    b = _buckets(project_coverage(events), "auth_surface")
    assert b["cred_reuse"] == "blocked"
    # capability_absent is unaffected by a block (we still can't do it)
    assert b["sqli_auth_bypass"] == "capability_absent"


def test_out_of_scope_from_roe() -> None:
    events = [
        _node_ev("hub.x", ["login-form"]),
        _Ev("StrikeCandidateAttempted", {"host": "hub.x"}),
    ]
    b = _buckets(
        project_coverage(events, excluded_techniques=frozenset({"cred_reuse"})), "auth_surface"
    )
    assert b["cred_reuse"] == "out_of_scope"


def test_not_assessed_declaration_is_engagement_scope() -> None:
    """The honest 'not assessed by this tool' list is emitted regardless of surfaces found."""
    report = project_coverage([_node_ev("h")])
    assert "sqli_auth_bypass" in report.not_assessed
    assert "subdomain_takeover" in report.not_assessed
    assert "trust_path_vendor_portal" in report.not_assessed  # GAP-069 gap reported honestly
    assert "cred_reuse" not in report.not_assessed


def test_nested_node_discovered_payload() -> None:
    """Real NodeDiscovered events nest host/tech_stack under 'properties' (node_to_dict)."""
    events = [
        _node_ev("app.target.com", ["spa-login-form"]),
        _Ev("StrikeCandidateAttempted", {"host": "app.target.com"}),
    ]
    b = _buckets(project_coverage(events), "auth_surface")
    assert b["cred_reuse"] == "tested"
    assert b["spa_json_login"] == "tested"
