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


def _host_ev(host: str) -> _Ev:
    return _Ev("NodeDiscovered", {"type": "asset", "properties": {"host": host}})


def test_recon_attempt_marks_tested_by_identity() -> None:
    """§12.64 Step 0: a RECON_TECHNIQUE_ATTEMPTED event marks its OWN technique tested on
    the host — the fix for the permanent `not_run` of recon techniques with no run_event."""
    host = _host_ev("h.x")
    before = _buckets(project_coverage([host]), "host")
    assert (
        before["git_exposure_leak"] == "not_run"
    )  # the bug: permanent not_run w/o instrumentation

    attempt = _Ev("ReconTechniqueAttempted", {"host": "h.x", "technique_id": "git_exposure_leak"})
    after = _buckets(project_coverage([host, attempt]), "host")
    assert after["git_exposure_leak"] == "tested"


def test_recon_attempt_does_not_false_mark_sibling() -> None:
    """§12.64 Step 0 CARDINAL: attempting ONE technique must NOT mark a sibling tested on the
    same host — matched by IDENTITY (host, technique_id), never by a shared event type."""
    host = _host_ev("h.x")
    attempt = _Ev("ReconTechniqueAttempted", {"host": "h.x", "technique_id": "git_exposure_leak"})
    b = _buckets(project_coverage([host, attempt]), "host")
    assert b["git_exposure_leak"] == "tested"
    assert b["js_secret_leak"] == "not_run"
    assert b["wp_rest_user_enum"] == "not_run"


def test_tool_to_technique_is_catalog_derived() -> None:
    """§12.64: the tool→technique join is single-source (derived from techniques.yaml)."""
    from agent_alpha.coverage.coverage_ledger import tool_to_technique

    m = tool_to_technique()
    assert m["git_exposure_probe"] == "git_exposure_leak"
    assert m["js_secret_probe"] == "js_secret_leak"
    assert m["wp_rest_users"] == "wp_rest_user_enum"


def test_tool_to_technique_rejects_duplicate_tool() -> None:
    """§12.64 Step 0 (Greptile/Sourcery): two techniques sharing a tool must fail loud, not
    collapse to last-wins — a silent collapse drops a technique into permanent not_run."""
    import pytest

    from agent_alpha.coverage.coverage_ledger import Technique, tool_to_technique

    dup = (
        Technique(id="a", mitre="T1", surface="host", capability_present=True, tool="shared"),
        Technique(id="b", mitre="T2", surface="host", capability_present=True, tool="shared"),
    )
    with pytest.raises(ValueError, match="duplicate tool"):
        tool_to_technique(dup)


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


# ── GAP-074 slice 2b: mechanism-precise auth denominator ──────────────────────
#
# The host's auth MECHANISM (mech_* on tech_stack) narrows WHICH auth techniques are
# APPLICABLE, so the coverage denominator stops claiming "we did not test JSON-RPC
# login" on a form-only surface. Mechanism UNKNOWN => fail-open (unchanged). The catalog
# uses BARE tokens (json_rpc); tech_stack uses mech_* — reconciled by bare_mechanisms().


def test_form_post_surface_excludes_json_rpc_technique() -> None:
    """CARDINAL (RED before fix): a form_post surface counts form_post/agnostic techniques
    but NOT json_rpc-only ones — spa_json_login drops out of the denominator entirely."""
    events = [
        _node_ev("hub.x", ["login-form", "mech_form_post"]),
        _Ev("StrikeCandidateAttempted", {"host": "hub.x"}),
    ]
    b = _buckets(project_coverage(events), "auth_surface")
    assert b["cred_reuse"] == "tested"  # [form_post, http_basic] ∩ {form_post} ✓
    assert b["default_creds_login"] == "tested"  # mechanism-agnostic → always applies
    assert "spa_json_login" not in b  # [json_rpc] ∩ {form_post} = ∅ → NOT applicable
    assert "oauth_saml_jwt_forgery" not in b  # [jwt,saml,oauth] ∩ {form_post} = ∅


def test_json_rpc_surface_excludes_form_only_technique() -> None:
    """CARDINAL (RED before fix): a json_rpc surface counts spa_json_login but NOT the
    form/basic-only cred_reuse — the JSON-RPC login is a distinct mechanism."""
    events = [
        _node_ev("api.x", ["spa-login-form", "mech_json_rpc"]),
        _Ev("StrikeCandidateAttempted", {"host": "api.x"}),
    ]
    b = _buckets(project_coverage(events), "auth_surface")
    assert b["spa_json_login"] == "tested"  # [json_rpc] ∩ {json_rpc} ✓
    assert b["default_creds_login"] == "tested"  # agnostic
    assert b["sqli_auth_bypass"] == "capability_absent"  # [form_post, json_rpc] ∩ {json_rpc} ✓
    assert "cred_reuse" not in b  # [form_post, http_basic] ∩ {json_rpc} = ∅ → NOT applicable
    assert "http_basic_auth_strike" not in b  # [http_basic] ∩ {json_rpc} = ∅


def test_mechanism_unknown_keeps_all_auth_techniques_fail_open() -> None:
    """REGRESSION guard: a surface with NO mech_* label keeps every auth technique in its
    denominator (fail-open) — mechanism precision must never DROP coverage when unknown."""
    events = [_node_ev("hub.x", ["login-form"])]  # no mech label
    b = _buckets(project_coverage(events), "auth_surface")
    assert "cred_reuse" in b
    assert b["spa_json_login"] == "not_run"  # still applicable (unknown mechanism)
    assert b["sqli_auth_bypass"] == "capability_absent"
