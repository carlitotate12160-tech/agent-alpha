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
