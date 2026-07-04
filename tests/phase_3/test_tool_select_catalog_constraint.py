"""FROZEN contract (architect-authored — IDE implements; do NOT edit assertions).

The LLM tool-select (SINGLE_LLM tier, used only when the RULE tier does not match) is
UNCONSTRAINED: the system prompt asks for "the single most appropriate tool" without giving
the model the list of tools that actually exist, and the parser passes whatever string the
model returns straight through. On the live FP-run this produced invented tool names —
`laravel_session_tester`, `testssl.sh` — which only "worked" because Alpha's dispatch maps
unknown tools to the generic asset-only handler. That is luck, not correctness: noise, a
misleading "Running <fictional tool>" log line, and a latent misfire if a hallucinated name
ever collides with a real tool.

This is independent of WHICH model does tool-select (deepseek-chat vs v4-pro). The fix is a
CATALOG CONSTRAINT, not a model change:

  * A single-source tool catalog (constants.RECON_TOOL_CATALOG) = the tools Alpha can actually
    dispatch: {"laravel_debug_probe", "wp_config_probe", "js_secret_probe", "generic_http_probe"}.
  * The tool-select system prompt lists that catalog (constrain at the source).
  * The parser COERCES any out-of-catalog tool to the generic probe "generic_http_probe"
    (the safe no-op: asset-only, no fabricated finding) — never returns a fictional name.
  * A valid tool is returned unchanged (no over-coercion).

Authoritative run: Oracle ARM64.
"""

from __future__ import annotations

import json
from typing import Any

from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

GENERIC = "generic_http_probe"


class _StubProvider:
    """Returns a fixed {"tool": ...} JSON — stands in for the reasoning model's reply."""

    model = "deepseek-chat"

    def __init__(self, tool: str) -> None:
        self._tool = tool

    def complete(self, *, messages: list[dict[str, str]], max_tokens: int) -> Any:
        return type(
            "R",
            (),
            {
                "text": json.dumps({"tool": self._tool}),
                "usage_cost_usd": 0.0,
                "reasoning": "",
                "model": "deepseek-chat",
            },
        )()


def _decide_with_llm_returning(tool: str) -> str:
    """Force the SINGLE_LLM tier (empty playbook -> no RULE match) and return the chosen tool."""
    orchestrator = LLMOrchestrator(playbook=PlaybookEngine([]), provider=_StubProvider(tool))
    decision = orchestrator.decide({"body": "an unremarkable page", "headers": {}})
    return decision.tool


def test_fictional_tool_is_coerced_to_generic() -> None:
    """An out-of-catalog tool name must be coerced to the generic probe, not passed through."""
    assert _decide_with_llm_returning("laravel_session_tester") == GENERIC, (
        "LLM returned a tool not in the catalog; it must be coerced to the generic probe, "
        "not surfaced as a fictional tool that only works by falling through to generic."
    )


def test_second_fictional_tool_also_coerced() -> None:
    assert _decide_with_llm_returning("testssl.sh") == GENERIC


def test_valid_catalog_tool_passes_through_unchanged() -> None:
    """Guard against over-coercion: a real tool the LLM legitimately selects is kept."""
    assert _decide_with_llm_returning("wp_config_probe") == "wp_config_probe"


def test_explicit_generic_passes_through() -> None:
    assert _decide_with_llm_returning(GENERIC) == GENERIC
