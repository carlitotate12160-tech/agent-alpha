"""Contract: LLMOrchestrator tier ladder (Opsi B core).

decide(observation):
  1. ask the playbook (RULE).  hit -> return, LLM never touched.
  2. miss -> SINGLE_LLM (one provider call).
  3. (CONSENSUS tier is exercised in Phase 3; not asserted here.)

The spy provider RAISES if invoked. So a green `test_*_skips_llm` is hard
proof that the deterministic path did not silently fall through to the model
— the exact discipline Opsi B is supposed to buy us.
"""

from __future__ import annotations

import pathlib

from agent_alpha.config import constants
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"


class _ExplodingProvider:
    """Any call is a contract violation for the RULE-hit path."""

    def complete(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("LLM must not be called when the playbook matched")


class _StubProvider:
    """Records that it was consulted exactly once on the novel path."""

    def __init__(self) -> None:
        self.calls = 0
        self.model = constants.LLM_REASONING_PROVIDER

    def complete(self, *args: object, **kwargs: object):
        self.calls += 1
        return type(
            "R",
            (),
            {
                "text": '{"tool": "generic_http_probe"}',
                "usage_cost_usd": 0.002,
                "model": constants.LLM_REASONING_PROVIDER,
            },
        )()


def _orchestrator(provider: object) -> LLMOrchestrator:
    return LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=provider,
    )


def test_rule_hit_skips_llm_entirely() -> None:
    orch = _orchestrator(_ExplodingProvider())
    decision = orch.decide({"body": "Whoops! ... Laravel v10.3.1", "headers": {}})
    assert decision.tool == "laravel_debug_probe"
    assert decision.tier == constants.LLM_TIER_RULE


def test_novel_observation_escalates_to_single_llm_once() -> None:
    provider = _StubProvider()
    orch = _orchestrator(provider)
    decision = orch.decide({"body": "Acme Bespoke Admin Panel", "headers": {}})
    assert provider.calls == 1
    assert decision.tier == constants.LLM_TIER_SINGLE
    assert decision.tool == "generic_http_probe"


# ---------------------------------------------------------------------------
# Bug #2/#6 — decide_excluding: once a rule's tool has already run this
# engagement, that rule must not keep pre-empting the LLM tier forever on
# every subsequent page that also matches it.
# ---------------------------------------------------------------------------


def test_decide_excluding_empty_set_matches_decide() -> None:
    """decide() is exactly decide_excluding(observation, exclude_tools=frozenset())
    — this is what makes decide() backward compatible for every caller that
    predates this fix."""
    orch = _orchestrator(_ExplodingProvider())
    obs = {"body": "Whoops! ... Laravel v10.3.1", "headers": {}}
    assert orch.decide(obs) == orch.decide_excluding(obs, exclude_tools=frozenset())


def test_decide_excluding_skips_already_run_tool_and_reaches_llm() -> None:
    """The actual Bug #2/#6 scenario: a second page with the SAME rule-matching
    fingerprint (e.g. a second Odoo page after odoo_dbmanager_probe already ran)
    must reach the LLM tier instead of being handed the same RULE decision
    again forever."""
    provider = _StubProvider()
    orch = _orchestrator(provider)
    obs = {"body": "Whoops! ... Laravel v10.3.1", "headers": {}}

    decision = orch.decide_excluding(obs, exclude_tools=frozenset({"laravel_debug_probe"}))

    assert provider.calls == 1, (
        "LLM tier was not reached once the matching rule's tool was excluded"
    )
    assert decision.tier == constants.LLM_TIER_SINGLE
    assert decision.tool == "generic_http_probe"


# ---------------------------------------------------------------------------
# Bug #21 — exclude_tools forwarded to SINGLE_LLM tier (prompt + post-filter)
# ---------------------------------------------------------------------------


def test_build_tool_select_messages_carries_exclude_tools() -> None:
    """T1: When exclude_tools is non-empty, the system message contains the
    excluded tool name inside a [HARD CONSTRAINT] block. The full catalog
    remains present (defense in depth: prompt-level instruction)."""
    obs = {"body": "Acme Bespoke Admin Panel", "headers": {}}
    messages = LLMOrchestrator._build_tool_select_messages(
        obs, exclude_tools=frozenset({"odoo_dbmanager_probe"})
    )
    system_msg = messages[0]["content"]
    assert "odoo_dbmanager_probe" in system_msg
    assert "HARD CONSTRAINT" in system_msg
    assert "PERMANENTLY OFF-LIMITS" in system_msg
    assert "MUST select a tool" in system_msg
    # Catalog still present
    from agent_alpha.config.constants import RECON_TOOL_CATALOG

    for tool in RECON_TOOL_CATALOG:
        assert tool in system_msg


class _StubProviderReturningExcluded:
    """Stub that returns a tool that is in the exclude set — tests post-filter."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        self.calls = 0
        self.model = constants.LLM_REASONING_PROVIDER

    def complete(self, *args: object, **kwargs: object):
        self.calls += 1
        return type(
            "R",
            (),
            {
                "text": f'{{"tool": "{self.tool}"}}',
                "usage_cost_usd": 0.002,
                "model": constants.LLM_REASONING_PROVIDER,
            },
        )()


def test_parse_tool_response_post_filters_excluded_tool() -> None:
    """T2: Even if the LLM returns an excluded tool (negative constraint ignored),
    the post-filter in _parse_tool_response coerces it to generic_http_probe
    (correctness guarantee via defense in depth)."""
    decision = LLMOrchestrator._parse_tool_response(
        '{"tool": "odoo_dbmanager_probe"}',
        exclude_tools=frozenset({"odoo_dbmanager_probe"}),
    )
    assert decision.tool == "generic_http_probe"
    assert decision.tier == constants.LLM_TIER_SINGLE


def test_decide_excluding_differential_closes_starvation() -> None:
    """T3: Differential test proving Bug #21 starvation is closed. Same Odoo-fingerprint
    observation: Call A with empty exclude → odoo_dbmanager_probe. Call B with
    exclude={"odoo_dbmanager_probe"} → result.tool NOT in exclude_tools. This proves
    a previously-run tool never returns from the LLM tier (starvation closed)."""
    # Use a novel observation (no RULE match) to force LLM tier
    obs = {"body": "Acme Bespoke Admin Panel", "headers": {}}

    # Call A: empty exclusion → LLM returns odoo_dbmanager_probe (simulated)
    provider_a = _StubProviderReturningExcluded("odoo_dbmanager_probe")
    orch_a = _orchestrator(provider_a)
    decision_a = orch_a.decide_excluding(obs, exclude_tools=frozenset())
    assert decision_a.tool == "odoo_dbmanager_probe"

    # Call B: exclude odoo_dbmanager_probe → post-filter coerces to generic_http_probe
    provider_b = _StubProviderReturningExcluded("odoo_dbmanager_probe")
    orch_b = _orchestrator(provider_b)
    decision_b = orch_b.decide_excluding(obs, exclude_tools=frozenset({"odoo_dbmanager_probe"}))
    assert decision_b.tool not in {"odoo_dbmanager_probe"}
    assert decision_b.tool == "generic_http_probe"  # post-filter coercion


def test_contract_guard_raises_when_safe_fallback_excluded() -> None:
    """T5: When generic_http_probe itself is in exclude_tools, the contract
    guard raises ValueError at parse level and OrientationError at the public
    boundary (decide_excluding).  Asserts the contract "return value is NEVER
    in exclude_tools" holds even when the safe no-op is excluded."""
    import pytest

    from agent_alpha.llm.orchestrator import OrientationError

    # Parse-level: ValueError — out-of-catalog tool coerced to generic_http_probe,
    # which is itself excluded -> guard fires
    with pytest.raises(ValueError, match="generic_http_probe"):
        LLMOrchestrator._parse_tool_response(
            '{"tool": "foobar"}',
            exclude_tools=frozenset({"generic_http_probe"}),
        )

    # Public boundary: OrientationError (wraps ValueError)
    provider = _StubProviderReturningExcluded("foobar")
    orch = _orchestrator(provider)
    obs = {"body": "Acme Bespoke Admin Panel", "headers": {}}
    with pytest.raises(OrientationError, match="cannot produce a non-excluded tool"):
        orch.decide_excluding(obs, exclude_tools=frozenset({"generic_http_probe"}))


def test_coercion_still_works_when_generic_not_excluded() -> None:
    """T6: When generic_http_probe is NOT in exclude_tools, an out-of-catalog
    tool name is still coerced to generic_http_probe (coercion path intact,
    no raise)."""
    decision = LLMOrchestrator._parse_tool_response(
        '{"tool": "foobar"}',
        exclude_tools=frozenset({"odoo_dbmanager_probe"}),
    )
    assert decision.tool == "generic_http_probe"
    assert decision.tier == constants.LLM_TIER_SINGLE
