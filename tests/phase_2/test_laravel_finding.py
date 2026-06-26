"""RED contract: Laravel debug/config-exposure finding template (ADR §12.16).

Authored by Claude (interface + contract only). The build()/verify() BODIES are
DeepSeek's lane; until they exist this suite FAILS by construction — anti-Lyndon #2
(no dead code as done) and #3 (no silent success). DeepSeek is "done" only when EVERY
test here is green on Oracle ARM64.

Run: .venv/bin/python3 -m pytest tests/phase_2/test_laravel_finding.py -v
"""

from __future__ import annotations

from agent_alpha.tools.contracts import TargetContext, Template, ToolResult
from agent_alpha.tools.templates.cms.laravel_finding import LaravelFindingTemplate


def _laravel_ctx() -> TargetContext:
    return TargetContext(
        engagement_id="eng_test",
        tenant_id="t1",
        target="https://lab.invalid/",
        tech_stack={"framework": "laravel", "version": "10.3.1"},
    )


def _exposed_response() -> dict:
    """A Laravel app with APP_DEBUG=true — public debug-page signatures
    (tools/playbooks/laravel_debug.yaml). DeepSeek may enrich with a real captured sample."""
    return {
        "url": "https://lab.invalid/",
        "status": 500,
        "headers": {"content-type": "text/html"},
        "body": (
            "<title>Whoops! There was an error.</title>"
            "Illuminate\\Database\\QueryException Laravel v10.3.1 "
            "stack trace leaking DB_PASSWORD and APP_KEY"
        ),
    }


def _hardened_response() -> dict:
    """Same stack, debug OFF — no signatures. MUST NOT produce a finding (no FP)."""
    return {
        "url": "https://lab.invalid/",
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": "<title>Welcome</title><h1>Home</h1>",
    }


# ── metadata + protocol conformance (Claude's contract — passes now) ──────────


def test_template_conforms_to_protocol() -> None:
    assert isinstance(LaravelFindingTemplate(), Template)


def test_metadata_is_recon_scoped_and_mitre_mapped() -> None:
    t = LaravelFindingTemplate()
    assert t.template_id == "laravel_debug_exposure"
    assert t.required_auth == "RECON_ONLY"
    assert t.mitre_technique == "T1592.002"


# ── behavioural contract (RED until DeepSeek fills build()/verify()) ──────────


def test_build_acts_only_on_the_in_scope_target() -> None:
    req = LaravelFindingTemplate().build(_laravel_ctx())
    assert isinstance(req, dict)
    # Must act on the screened ctx.target, never invent a host (anti-SSRF, CWE-918).
    assert any("lab.invalid" in str(v) for v in req.values())


def test_verify_exposed_returns_proof_bearing_success() -> None:
    result = LaravelFindingTemplate().verify(_exposed_response())
    assert isinstance(result, ToolResult)
    assert result.success is True
    assert result.findings  # non-empty
    assert result.proof_artifacts  # PROOF, not assumption
    assert result.confidence >= 0.7


def test_verify_hardened_is_not_a_false_positive() -> None:
    result = LaravelFindingTemplate().verify(_hardened_response())
    assert result.success is False
    assert result.findings == ()
    assert result.proof_artifacts == ()


def test_verify_empty_response_is_failure_not_crash() -> None:
    result = LaravelFindingTemplate().verify(
        {"url": "https://lab.invalid/", "status": 0, "headers": {}, "body": ""}
    )
    assert result.success is False


def test_verify_never_claims_success_without_proof() -> None:
    """Structural: any success path MUST carry a proof artifact (anti-Lyndon #3)."""
    result = LaravelFindingTemplate().verify(_exposed_response())
    if result.success:
        assert len(result.proof_artifacts) >= 1
