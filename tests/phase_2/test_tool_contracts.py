"""Contract: tool-layer foundation types/protocols (ADR §12.16).

These pin the NON-OFFENSIVE contract DeepSeek's templates/tools must satisfy. The
key invariant is structural: a ToolResult cannot claim success without a finding
(anti-Lyndon #3) — enforced at construction, so no offensive body can fake success.
"""

from __future__ import annotations

import pytest

from agent_alpha.config import constants
from agent_alpha.tools.contracts import (
    ResourceBudget,
    TargetContext,
    Template,
    Tool,
    ToolResult,
)


def _ctx() -> TargetContext:
    return TargetContext(
        engagement_id="e", tenant_id="t", target="https://lab.invalid",
        tech_stack={"framework": "laravel", "version": "10.3.1"},
    )


# ── ToolResult anti-false-success contract ────────────────────────────


def test_success_requires_a_finding() -> None:
    with pytest.raises(ValueError):
        ToolResult(tool="x", success=True, confidence=0.9, findings=())


def test_failure_must_not_carry_findings() -> None:
    with pytest.raises(ValueError):
        ToolResult(tool="x", success=False, confidence=0.1, findings=({"k": "v"},))


def test_confidence_must_be_bounded() -> None:
    for bad in (-0.1, 1.1):
        with pytest.raises(ValueError):
            ToolResult(tool="x", success=False, confidence=bad)


def test_valid_results_construct() -> None:
    ok = ToolResult(tool="x", success=True, confidence=0.8, findings=({"id": "f1"},),
                    proof_artifacts=("evt:123",))
    assert ok.success and ok.findings
    miss = ToolResult(tool="x", success=False, confidence=0.0)
    assert not miss.success and miss.findings == ()


# ── ResourceBudget ties to the single-source rps ──────────────────────


def test_budget_default_rps_is_single_source() -> None:
    b = ResourceBudget(max_requests=100, max_seconds=60, max_cost_usd=1.0)
    assert b.rate_limit_rps == constants.DEFAULT_RATE_LIMIT_RPS


# ── protocol conformance (what DeepSeek must implement) ───────────────


class _FakeTemplate:
    template_id = "laravel_config_exposure"
    mitre_technique = "T1190"
    required_auth = "RECON_ONLY"

    def build(self, ctx: TargetContext) -> dict:
        return {"url": ctx.target}

    def verify(self, response: dict) -> ToolResult:
        # proof-bearing success only when the response confirms exposure
        if response.get("exposed"):
            return ToolResult(tool=self.template_id, success=True, confidence=0.95,
                              findings=({"type": "config_exposure"},),
                              proof_artifacts=("evt:abc",))
        return ToolResult(tool=self.template_id, success=False, confidence=0.2)


class _FakeTool:
    name = "laravel_finder"
    phase = "recon"
    required_auth = "RECON_ONLY"

    def applies_to(self, ctx: TargetContext) -> float:
        return 1.0 if ctx.tech_stack.get("framework") == "laravel" else 0.0

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        return ToolResult(tool=self.name, success=False, confidence=0.0)


def test_fakes_satisfy_the_protocols() -> None:
    assert isinstance(_FakeTemplate(), Template)
    assert isinstance(_FakeTool(), Tool)


def test_applies_to_drives_relevance_not_a_hardcoded_ladder() -> None:
    tool = _FakeTool()
    assert tool.applies_to(_ctx()) == 1.0
    other = TargetContext(engagement_id="e", tenant_id="t", target="x",
                          tech_stack={"framework": "django"})
    assert tool.applies_to(other) == 0.0


def test_template_verify_is_proof_not_assumption() -> None:
    tpl = _FakeTemplate()
    assert tpl.verify({"exposed": True}).success is True
    assert tpl.verify({"exposed": False}).success is False   # mere presence != finding
