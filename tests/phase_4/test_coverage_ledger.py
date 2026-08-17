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
    # 187b-1: wp_rest_user_enum is WP-only (applies_to_stack: [wp]) → EXCLUDED on this bare
    # host, so it is not a sibling here at all (see test_stack_specific_* below).
    assert "wp_rest_user_enum" not in b


def test_stack_specific_technique_excluded_on_non_matching_host() -> None:
    """187b-1 CARDINAL: a WP-only technique is EXCLUDED from a non-WP host's denominator
    (not 'not_run'), so §12.64's not_run gate never bricks a Java/Odoo engagement (§12.62
    honesty). Stack-agnostic techniques (git/js) still apply on any host."""
    bare = _buckets(project_coverage([_host_ev("java.x")]), "host")
    assert "wp_rest_user_enum" not in bare  # WP technique excluded on unconfirmed stack
    assert bare["git_exposure_leak"] == "not_run"  # stack-agnostic → still applies
    assert bare["js_secret_leak"] == "not_run"

    # A confirmed-WP host (tech_stack includes "wp") → the WP technique is applicable again.
    wp = _buckets(project_coverage([_node_ev("wp.x", ["wp"])]), "host")
    assert wp["wp_rest_user_enum"] == "not_run"


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


# ── Sourcery/Qodo: catalog YAML scalar/null hardening (anti-#3 silent drop) ────
#
# `applies_to_stack`/`auth_mechanism` are list fields. A null key parses to None
# (tuple(None) → TypeError) and a bare scalar parses to str (tuple("wp") → ("w","p"),
# a silent char-split that drops the technique from EVERY denominator — a false
# 'not tested', Lyndon #3). _as_tuple_str coerces both safely.


def test_as_tuple_str_normalizes_scalar_null_and_list() -> None:
    """Unit: the three YAML authoring shapes all normalize safely — the char-split
    (`tuple('wp') == ('w','p')`) that silently dropped a stack-specific technique is gone."""
    from agent_alpha.coverage.coverage_ledger import _as_tuple_str

    assert _as_tuple_str(None) == ()  # `applies_to_stack:` (null) → stack-agnostic, no TypeError
    assert _as_tuple_str("") == ()
    assert _as_tuple_str("wp") == ("wp",)  # bare scalar → ONE label, NOT ("w","p")
    assert _as_tuple_str(["wp", "tomcat"]) == ("wp", "tomcat")
    assert _as_tuple_str([1, 2]) == ("1", "2")  # non-str list coerced to str tokens


def test_catalog_scalar_stack_is_wired_through_load_catalog(tmp_path: Any) -> None:
    """Integration (real parse path, not presence-only): a scalar `applies_to_stack: wp`
    in ACTUAL YAML loads as ('wp',) so the WP gate still fires — proving the hardening is
    wired into load_catalog, not just the helper in isolation."""
    import pathlib

    from agent_alpha.coverage.coverage_ledger import load_catalog

    yaml_text = (
        "techniques:\n"
        "  - id: scalar_stack_probe\n"
        "    mitre: T9999\n"
        "    surface: host\n"
        "    capability_present: true\n"
        "    applies_to_stack: wp\n"  # bare scalar, NOT [wp]
        "  - id: null_stack_probe\n"
        "    mitre: T9998\n"
        "    surface: host\n"
        "    capability_present: true\n"
        "    applies_to_stack:\n"  # null key
    )
    p = pathlib.Path(tmp_path) / "scalar_catalog.yaml"
    p.write_text(yaml_text)
    cat = {t.id: t for t in load_catalog(p)}
    assert cat["scalar_stack_probe"].applies_to_stack == ("wp",)  # NOT ("w","p")
    assert cat["null_stack_probe"].applies_to_stack == ()  # null → stack-agnostic, no crash


# ── 187b-2: recon coverage gate — recon_not_run_gaps (feeds GAP-189 RUN_PARTIAL) ──
#
# A task-COMPLETE recon that left a dispatchable recon technique `not_run` on a discovered
# surface is honestly 'partial', not 'done' (anti-#3). The gate scopes to Alpha-owned
# surfaces (surface != auth_surface): auth_surface techniques are Beta's and are `not_run`
# by construction during recon, so counting them would mark EVERY engagement partial (noise).


def test_recon_gap_flags_unrun_host_technique() -> None:
    """A discovered host with NO recon attempt → the capable host techniques are `not_run`
    and surface as recon gaps (the honest 'we could have probed and didn't')."""
    from agent_alpha.coverage.coverage_ledger import recon_not_run_gaps

    gaps = recon_not_run_gaps(project_coverage([_host_ev("h.x")]))
    assert "git_exposure_leak" in gaps
    assert "js_secret_leak" in gaps


def test_recon_gap_excludes_auth_surface_strike_cardinal() -> None:
    """CARDINAL (anti-noise): an auth_surface with an unrun STRIKE technique (cred_reuse) is
    NOT a recon gap — it is Beta's, `not_run` by construction during recon. If this leaks,
    EVERY recon is falsely 'partial' and the honest signal is drowned (#3 creeps back)."""
    from agent_alpha.coverage.coverage_ledger import recon_not_run_gaps

    # login-form host → auth_surface projected with cred_reuse/spa_json_login `not_run`.
    report = project_coverage([_node_ev("hub.x", ["login-form"])])
    assert _buckets(report, "auth_surface")["cred_reuse"] == "not_run"  # precondition
    gaps = recon_not_run_gaps(report)
    assert "cred_reuse" not in gaps  # STRIKE not_run is NOT a recon gap
    assert "spa_json_login" not in gaps


def test_recon_gap_empty_when_all_recon_tested() -> None:
    """A host whose recon techniques were all dispatched (§12.64 attempts) → no recon gap →
    the engagement stays 'done', not falsely 'partial'."""
    from agent_alpha.coverage.coverage_ledger import recon_not_run_gaps

    host = _host_ev("h.x")
    attempts = [
        _Ev("ReconTechniqueAttempted", {"host": "h.x", "technique_id": tid})
        for tid in ("git_exposure_leak", "js_secret_leak")
    ]
    gaps = recon_not_run_gaps(project_coverage([host, *attempts]))
    assert gaps == ()  # every applicable Alpha-owned host technique ran


def test_recon_gap_gate_is_surface_ownership_not_tool_enumeration() -> None:
    """FORWARD-PROPERTY (function contract, not current projection): the gate keys on surface
    OWNERSHIP (any non-auth_surface not_run), NOT the §12.64 {git,js,wp} tool set. A
    fronted_host `not_run` (e.g. origin_exposure_bypass) is a gap the moment such a surface is
    projected — proving D auto-covers it without editing an enumerated list (unlike option A).
    NB: project_coverage does not emit fronted_host surfaces TODAY (separate slice); this tests
    recon_not_run_gaps' pure contract over a hand-built report, so the claim is honest."""
    from agent_alpha.coverage.coverage_ledger import (
        CoverageCell,
        CoverageReport,
        recon_not_run_gaps,
    )

    report = CoverageReport(
        cells=(
            CoverageCell("cf.x", "fronted_host", "origin_exposure_bypass", "not_run"),
            CoverageCell("hub.x", "auth_surface", "cred_reuse", "not_run"),  # excluded
        ),
        not_assessed=(),
    )
    assert recon_not_run_gaps(report) == ("origin_exposure_bypass",)
