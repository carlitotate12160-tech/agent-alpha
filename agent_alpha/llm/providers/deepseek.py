from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from agent_alpha.config import constants
from agent_alpha.config.constants import DEEPSEEK_PRICING_USD_PER_1K

logger = logging.getLogger(__name__)


class CompletionTruncatedError(RuntimeError):
    """Raised when max_tokens is too small for the reasoning model to output a final answer."""


@dataclass(frozen=True)
class CompletionResult:
    text: str
    usage_cost_usd: float
    model: str
    reasoning: str = ""


class DeepSeekProvider:
    def __init__(
        self,
        api_key: str,
        model: str = constants.LLM_REASONING_PROVIDER,
        base_url: str = "https://api.deepseek.com",
        timeout: float = constants.DEEPSEEK_HTTP_TIMEOUT_SEC,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Initialize the DeepSeek reasoning/payload LLM client."""
        # HARD GUARD: NEVER allow payload forbidden models (Claude/GPT/Opus/Sonnet)
        model_lower = model.lower()
        for forbidden in constants.LLM_PAYLOAD_NEVER:
            if forbidden in model_lower:
                raise ValueError(
                    f"Forbidden model '{model}': Contains blacklisted token '{forbidden}'."
                )

        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def list_models(self) -> list[str]:
        """Fetch available models from the provider."""
        url = f"{self.base_url}/v1/models"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        # Note: Do not log headers or api_key
        with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return [model_obj["id"] for model_obj in data.get("data", [])]

    def complete(self, messages: list[dict[str, Any]], max_tokens: int) -> CompletionResult:
        """Run a single inference round-trip."""
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError("Provider returned no choices in response.")

        finish_reason = choices[0].get("finish_reason")
        content = choices[0].get("message", {}).get("content", "")
        text = (content or "").strip()
        # Reasoning models return `reasoning_content` separate from `content`;
        # capture it for the inner monologue instead of discarding it.
        reasoning = (choices[0].get("message", {}).get("reasoning_content") or "").strip()

        if not text and finish_reason == "length":
            raise CompletionTruncatedError(
                "completion truncated; raise max_tokens (reasoning model consumed the token budget)"
            )
        if not text:
            raise RuntimeError("Provider returned empty completion text.")

        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        # Cost calculation
        if self.model not in DEEPSEEK_PRICING_USD_PER_1K:
            logger.warning("no pricing for model %s; cost under-reported", self.model)
            cost = 0.0
        else:
            pricing = DEEPSEEK_PRICING_USD_PER_1K[self.model]
            cost = (prompt_tokens / 1000.0) * pricing.get("input", 0.0) + (
                completion_tokens / 1000.0
            ) * pricing.get("output", 0.0)

        return CompletionResult(
            text=text, usage_cost_usd=cost, model=self.model, reasoning=reasoning
        )
