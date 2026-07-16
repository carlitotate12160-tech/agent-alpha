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
