"""LLMOrchestrator — tier router (RULE → SINGLE_LLM).

Escalation ladder:
  1. Ask the PlaybookEngine (deterministic RULE tier).
     Hit → return immediately; the LLM provider is **never** invoked.
  2. Miss → escalate to SINGLE_LLM: one provider.complete() call,
     parse JSON, return PlaybookDecision.
  3. CONSENSUS tier (parallel MiMo) is deferred to Phase 3.
"""

from __future__ import annotations

import json
from typing import Any

from agent_alpha.config import constants
from agent_alpha.tools.playbook import PlaybookDecision, PlaybookEngine


class LLMOrchestrator:
    """Route observations through the Opsi-B tier ladder.

    The provider is injected (duck-typed: must expose ``complete(**kw)``
    returning an object with a ``.text`` attribute).  The orchestrator
    is intentionally provider-agnostic — no concrete import of
    DeepSeekProvider or any other backend.
    """

    def __init__(self, playbook: PlaybookEngine, provider: Any) -> None:
        self.playbook = playbook
        self.provider = provider

    # ── public API ──────────────────────────────────────────────

    def decide(self, observation: dict[str, Any]) -> PlaybookDecision:
        """Return a tool decision for *observation*.

        1. Deterministic playbook match → RULE tier (provider untouched).
        2. No match → SINGLE_LLM tier via provider.complete().

        Raises ``ValueError`` if the provider response is not valid JSON
        or lacks a ``"tool"`` key (anti-Lyndon #3: no silent fallback).
        """
        # ── RULE tier ───────────────────────────────────────────
        decision = self.playbook.match(observation)
        if decision is not None:
            return decision

        # ── SINGLE_LLM tier ─────────────────────────────────────
        messages = self._build_tool_select_messages(observation)
        result = self.provider.complete(
            messages=messages,
            max_tokens=constants.LLM_TOOL_SELECT_MAX_TOKENS,
        )
        return self._parse_tool_response(result.text)

    # ── internals ───────────────────────────────────────────────

    @staticmethod
    def _build_tool_select_messages(
        observation: dict[str, Any],
    ) -> list[dict[str, str]]:
        """Construct the chat messages for a single-LLM tool selection."""
        return [
            {
                "role": "system",
                "content": (
                    "You are a security-tool selector. Given an HTTP "
                    "observation, choose the single most appropriate tool "
                    "to investigate it. Reply with ONLY a JSON object: "
                    '{"tool": "<tool_name>"}. No explanation, no markdown.'
                ),
            },
            {
                "role": "user",
                "content": json.dumps(observation),
            },
        ]

    @staticmethod
    def _parse_tool_response(text: str) -> PlaybookDecision:
        """Parse the provider's JSON response into a PlaybookDecision.

        Raises ``ValueError`` on malformed JSON or missing ``"tool"`` key.
        """
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM response is not valid JSON: {text!r}") from exc

        if "tool" not in data:
            raise ValueError(f"LLM JSON response missing 'tool' key: {data!r}")

        return PlaybookDecision(
            tool=data["tool"],
            tier=constants.LLM_TIER_SINGLE,
            technique_id="",
        )
