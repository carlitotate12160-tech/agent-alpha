"""Contract: ClaudeProvider — hermetic tests via httpx.MockTransport.

No network calls. All responses are mocked.
"""

from __future__ import annotations

import httpx
import pytest

from agent_alpha.llm.providers.claude import ClaudeProvider
from agent_alpha.llm.providers.deepseek import CompletionTruncatedError


def test_claude_complete_hermetic() -> None:
    """ClaudeProvider.complete() via MockTransport — no network."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "pong"},
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )

    provider = ClaudeProvider(
        api_key="noop",
        model="claude-sonnet-4-20250514",
        transport=httpx.MockTransport(handler),
    )
    result = provider.complete(
        messages=[{"role": "user", "content": "Reply with: pong"}],
        max_tokens=128,
    )
    assert result.text == "pong"
    assert result.model == "claude-sonnet-4-20250514"
    assert result.usage_cost_usd >= 0.0


def test_claude_complete_captures_reasoning() -> None:
    """Claude thinking blocks are captured as reasoning."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "thinking", "thinking": "analyzing the request"},
                    {"type": "text", "text": "answer"},
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )

    provider = ClaudeProvider(
        api_key="noop",
        model="claude-sonnet-4-20250514",
        transport=httpx.MockTransport(handler),
    )
    result = provider.complete(messages=[{"role": "user", "content": "x"}], max_tokens=128)
    assert result.text == "answer"
    assert result.reasoning == "analyzing the request"


def test_claude_max_tokens_raises_truncated() -> None:
    """stop_reason=max_tokens raises CompletionTruncatedError even if partial
    text exists (Fix #8: check max_tokens BEFORE empty text)."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "partial answer"},
                ],
                "stop_reason": "max_tokens",
                "usage": {"input_tokens": 10, "output_tokens": 128},
            },
        )

    provider = ClaudeProvider(
        api_key="noop",
        model="claude-sonnet-4-20250514",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(CompletionTruncatedError):
        provider.complete(messages=[{"role": "user", "content": "x"}], max_tokens=128)


def test_claude_empty_text_raises() -> None:
    """Empty completion with non-max_tokens stop_reason raises RuntimeError."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "content": [],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 0},
            },
        )

    provider = ClaudeProvider(
        api_key="noop",
        model="claude-sonnet-4-20250514",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(RuntimeError, match="empty completion"):
        provider.complete(messages=[{"role": "user", "content": "x"}], max_tokens=128)


def test_claude_system_prompt_separated() -> None:
    """ClaudeProvider separates system prompt from user/assistant messages
    per Anthropic Messages API requirement."""
    captured_payload: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        captured_payload.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 2},
            },
        )

    provider = ClaudeProvider(
        api_key="noop",
        model="claude-sonnet-4-20250514",
        transport=httpx.MockTransport(handler),
    )
    provider.complete(
        messages=[
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hi"},
        ],
        max_tokens=64,
    )
    assert "system" in captured_payload
    assert captured_payload["system"] == "You are helpful."
    assert len(captured_payload["messages"]) == 1
    assert captured_payload["messages"][0]["role"] == "user"
