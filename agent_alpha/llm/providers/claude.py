from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from agent_alpha.config import constants

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompletionResult:
    text: str
    usage_cost_usd: float
    model: str
    reasoning: str = ""


class ClaudeProvider:
    """Anthropic Claude provider for reasoning and payload roles.

    Uses the Anthropic Messages API (https://api.anthropic.com/v1/messages).
    Compatible with the CompletionProvider protocol expected by routing.py.
    """

    def __init__(
        self,
        api_key: str,
        model: str = constants.LLM_REASONING_CONSENSUS,
        base_url: str = "https://api.anthropic.com",
        timeout: float = constants.DEEPSEEK_HTTP_TIMEOUT_SEC,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def list_models(self) -> list[str]:
        """Anthropic does not expose a /v1/models endpoint; return known models."""
        return [
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-haiku-3-5-20241022",
        ]

    def complete(self, messages: list[dict[str, Any]], max_tokens: int) -> CompletionResult:
        """Run a single inference round-trip via Anthropic Messages API."""
        url = f"{self.base_url}/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        # Anthropic requires separating system prompt from user/assistant messages.
        system_text = ""
        api_messages: list[dict[str, str]] = []
        for msg in messages:
            if msg["role"] == "system":
                system_text += msg["content"] + "\n"
            else:
                api_messages.append({"role": msg["role"], "content": msg["content"]})

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": api_messages,
        }
        if system_text.strip():
            payload["system"] = system_text.strip()

        with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        content_blocks = data.get("content", [])
        text_parts: list[str] = []
        reasoning_parts: list[str] = []
        for block in content_blocks:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "thinking":
                reasoning_parts.append(block.get("thinking", ""))

        text = " ".join(text_parts).strip()
        reasoning = " ".join(reasoning_parts).strip()

        if not text:
            stop_reason = data.get("stop_reason", "")
            if stop_reason == "max_tokens":
                raise RuntimeError(
                    "completion truncated; raise max_tokens (reasoning model consumed the token budget)"
                )
            raise RuntimeError("Provider returned empty completion text.")

        usage = data.get("usage", {})
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)

        pricing = CLAUDE_PRICING_USD_PER_1K.get(self.model, {"input": 0.0, "output": 0.0})
        cost = (prompt_tokens / 1000.0) * pricing["input"] + (completion_tokens / 1000.0) * pricing[
            "output"
        ]

        return CompletionResult(
            text=text, usage_cost_usd=cost, model=self.model, reasoning=reasoning
        )


CLAUDE_PRICING_USD_PER_1K: dict[str, dict[str, float]] = {
    "claude-sonnet-4-20250514": {"input": 0.003, "output": 0.015},
    "claude-opus-4-20250514": {"input": 0.015, "output": 0.075},
    "claude-haiku-3-5-20241022": {"input": 0.0008, "output": 0.004},
}
