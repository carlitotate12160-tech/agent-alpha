"""Contract: DeepSeekProvider.

Two tiers:
  - unit  : guards/config that need no network.
  - live  : real reachability + one inference round-trip from Oracle.

Confirmed 2026-06-19: api.deepseek.com reachable from Oracle ARM64
(HTTP/2 200, models deepseek-v4-pro + deepseek-v4-flash present).
This codifies that probe so a regression (egress blocked, key revoked,
model renamed) fails loudly instead of silently.
"""

from __future__ import annotations

import pytest

from agent_alpha.config import constants
from agent_alpha.llm.providers.deepseek import DeepSeekProvider


# ── unit ──────────────────────────────────────────────────────────────


def test_default_model_is_single_source_of_truth() -> None:
    """Model id must come from constants, never hardcoded (anti-Lyndon #7)."""
    provider = DeepSeekProvider(api_key="unit-test-noop")
    assert provider.model == constants.LLM_REASONING_PRIMARY == "deepseek-v4-pro"


def test_provider_rejects_forbidden_payload_models() -> None:
    """The hard guard: Claude/GPT/Opus must never be selectable here.
    DeepSeek is the payload/offensive provider; the reasoning-vs-payload
    split is enforced, not advisory (ADR LLM role split)."""
    for forbidden in constants.LLM_PAYLOAD_NEVER:
        with pytest.raises(ValueError):
            DeepSeekProvider(api_key="unit-test-noop", model=forbidden)


def test_http_timeout_is_single_source_of_truth() -> None:
    """HTTP timeout must come from a constant, never hardcoded (anti-Lyndon #7).
    deepseek.py previously inlined timeout=30.0 at two call sites."""
    assert constants.DEEPSEEK_HTTP_TIMEOUT_SEC == 30.0
    provider = DeepSeekProvider(api_key="unit-test-noop")
    assert provider.timeout == constants.DEEPSEEK_HTTP_TIMEOUT_SEC


def test_http_timeout_is_configurable() -> None:
    """The timeout is injectable, so a slow/fast deployment can tune it in one
    place rather than editing call sites."""
    provider = DeepSeekProvider(api_key="unit-test-noop", timeout=12.5)
    assert provider.timeout == 12.5


def test_complete_captures_reasoning_content() -> None:
    """Reasoning models return `reasoning_content` separately from `content`.
    It must be captured (it feeds the inner monologue), not discarded.
    Hermetic via an injected transport — no network."""
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": "ping",
                            "reasoning_content": "the user asked for the word ping",
                        },
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            },
        )

    provider = DeepSeekProvider(api_key="noop", transport=httpx.MockTransport(handler))
    result = provider.complete(messages=[{"role": "user", "content": "x"}], max_tokens=64)

    assert result.text == "ping"
    assert result.reasoning == "the user asked for the word ping"


# ── live ──────────────────────────────────────────────────────────────


@pytest.mark.live
def test_deepseek_reachable_from_oracle(deepseek_api_key: str) -> None:
    """Exit criterion: GET /v1/models returns 200 and the configured
    reasoning model is actually offered by the account."""
    provider = DeepSeekProvider(api_key=deepseek_api_key)
    models = provider.list_models()
    assert constants.LLM_REASONING_PRIMARY in models


@pytest.mark.live
def test_deepseek_inference_roundtrip(deepseek_api_key: str) -> None:
    """Exit criterion: a real /v1/chat/completions call returns a VALIDATED
    non-empty completion. Empty/whitespace response is a FAILURE, not a
    silent success (anti-Lyndon #3). Cost must be reported for budget gates."""
    provider = DeepSeekProvider(api_key=deepseek_api_key)
    # NOTE: deepseek-v4-pro is a reasoning model — it spends completion tokens
    # on `reasoning_content` before emitting the final `content`. max_tokens
    # must leave headroom for both, or `content` comes back empty with
    # finish_reason="length". 256 is ample for a one-word reply.
    result = provider.complete(
        messages=[{"role": "user", "content": "Reply with the single word: ping"}],
        max_tokens=256,
    )
    assert result.text.strip(), "completion text must be non-empty"
    assert result.usage_cost_usd >= 0.0
    assert result.model == constants.LLM_REASONING_PRIMARY
