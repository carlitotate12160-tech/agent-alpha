from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

import httpx

from agent_alpha.config import constants


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompletionResult:
    text: str
    usage_cost_usd: float
    model: str


class DeepSeekProvider:
    def __init__(
        self,
        api_key: str,
        model: str = constants.LLM_REASONING_PRIMARY,
        base_url: str = "https://api.deepseek.com",
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

    def list_models(self) -> List[str]:
        """Fetch available models from the provider."""
        url = f"{self.base_url}/v1/models"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        # Note: Do not log headers or api_key
        with httpx.Client() as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return [model_obj["id"] for model_obj in data.get("data", [])]

    def complete(self, messages: List[Dict[str, Any]], max_tokens: int) -> CompletionResult:
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

        with httpx.Client() as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError("Provider returned no choices in response.")

        text = choices[0].get("message", {}).get("content", "")
        if text is not None:
            text = text.strip()
        else:
            text = ""

        # Anti-Lyndon #3: empty/whitespace response must raise an error
        if not text:
            raise RuntimeError("Provider returned empty completion text.")

        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        # Cost calculation
        pricing = getattr(constants, "DEEPSEEK_PRICING_USD_PER_1K", {}).get(self.model)
        if pricing and usage:
            cost = (prompt_tokens / 1000.0) * pricing.get("input", 0.0) + (
                completion_tokens / 1000.0
            ) * pricing.get("output", 0.0)
        else:
            cost = 0.0

        return CompletionResult(text=text, usage_cost_usd=cost, model=self.model)
