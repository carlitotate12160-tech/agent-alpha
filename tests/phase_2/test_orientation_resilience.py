# tests/phase_2/test_orientation_resilience.py
"""Contract: the cognitive loop degrades gracefully on an LLM/decision failure.

Mirrors network-resilience for the ORIENT step: an external dependency (the LLM)
WILL fail sometimes — truncation (reasoning model eats the token budget),
malformed output, or an API/network error. The engagement must treat the probe
as non-analyzable and report FAILED, never CRASH (anti-Lyndon #3).
"""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.llm.orchestrator import LLMOrchestrator, OrientationError
from agent_alpha.llm.providers.deepseek import CompletionTruncatedError
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"


def _handoff(msg: a2a_pb2.A2AMessage) -> a2a_pb2.HandoffPayload:
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    return payload


class _TruncatingProvider:
    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object):
        raise CompletionTruncatedError("reasoning model consumed the token budget")


class _TruncateOnceThenSucceedProvider:
    """Truncates on the FIRST complete() (primary budget), succeeds on the retry."""

    model = "deepseek-v4-pro"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, *a: object, **k: object):
        self.calls += 1
        if self.calls == 1:
            raise CompletionTruncatedError("first attempt: reasoning ate the token budget")
        return type(
            "R",
            (),
            {
                "text": '{"tool": "generic_http_probe"}',
                "usage_cost_usd": 0.0,
                "model": "deepseek-v4-pro",
                "reasoning": "",
            },
        )()


class _BadJsonProvider:
    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object):
        return type(
            "R",
            (),
            {
                "text": "not json at all",
                "usage_cost_usd": 0.0,
                "model": "deepseek-v4-pro",
                "reasoning": "",
            },
        )()


# ── orchestrator wraps provider/parse failures into OrientationError ──────────


def test_truncation_becomes_orientation_error() -> None:
    orch = LLMOrchestrator(PlaybookEngine.from_directory(PLAYBOOK_DIR), _TruncatingProvider())
    with pytest.raises(OrientationError):
        orch.decide({"body": "Acme novel page no playbook match", "headers": {}})


def test_malformed_llm_output_becomes_orientation_error() -> None:
    orch = LLMOrchestrator(PlaybookEngine.from_directory(PLAYBOOK_DIR), _BadJsonProvider())
    with pytest.raises(OrientationError):
        orch.decide({"body": "Acme novel page no playbook match", "headers": {}})


# ── Bug #35: a truncated FIRST attempt retries once instead of surrendering ────


def test_truncation_retries_once_then_succeeds() -> None:
    """Bug #35 CARDINAL: a reasoning model that truncated (thinking > budget) is NOT a
    give-up. decide() retries ONCE with a larger budget and returns a real decision
    instead of raising OrientationError (the old behaviour = a false give-up)."""
    provider = _TruncateOnceThenSucceedProvider()
    orch = LLMOrchestrator(PlaybookEngine.from_directory(PLAYBOOK_DIR), provider)

    decision = orch.decide({"body": "Acme novel page no playbook match", "headers": {}})

    assert decision.tool == "generic_http_probe"
    assert provider.calls == 2  # primary truncated → retried once → succeeded


def test_tool_select_budget_is_reasoning_sized() -> None:
    """Bug #35 regression guard: the orientation budget must be large enough for a
    reasoning model's thinking + JSON reply — 512 was the false-give-up trap. Locks the
    primary budget right-sized and the retry budget strictly larger (single source)."""
    from agent_alpha.config import constants

    assert constants.LLM_TOOL_SELECT_MAX_TOKENS >= 2048
    assert constants.LLM_TOOL_SELECT_MAX_TOKENS_RETRY > constants.LLM_TOOL_SELECT_MAX_TOKENS


# ── Alpha survives an LLM decision failure: FAILED, not a crash ───────────────


def test_alpha_survives_llm_failure_reports_failed(
    recon_engagement, graph_store, event_store, http_client, hardened_target_url
) -> None:
    auth, engagement_id = recon_engagement
    # hardened body misses the playbook -> SINGLE_LLM -> provider truncates.
    orch = LLMOrchestrator(PlaybookEngine.from_directory(PLAYBOOK_DIR), _TruncatingProvider())
    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orch,
        http_client=http_client,
    )

    msg = agent.run_recon(engagement_id, hardened_target_url)  # must NOT raise

    handoff = _handoff(msg)
    assert handoff.status == a2a_pb2.FAILED  # could not analyze -> FAILED, honest
    assert handoff.findings_count == 0
