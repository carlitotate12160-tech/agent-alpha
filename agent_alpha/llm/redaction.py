# agent_alpha/llm/redaction.py
"""Redaction + injection hardening before untrusted target content reaches an
external LLM (ADR §8l).

Two defense-in-depth controls — neither is a guarantee alone:

1. Secret redaction. Target responses can leak secrets (a Laravel debug page
   leaks DB_PASSWORD, an admin page leaks a Bearer token). Sending that raw to a
   third-party LLM would EXFILTRATE the client's secret. We mask key=value /
   JSON / Bearer secret formats using the single source of truth for secret
   patterns (LOG_SCRUB_PATTERNS via LogScrubber — anti-Lyndon #7, no duplicate
   patterns). Pattern-based redaction cannot catch every encoding (e.g. a secret
   split across separate HTML cells); it is ONE layer, not the whole defense.

2. Injection containment. Target content is UNTRUSTED and may carry prompt
   injection. Structural control: cap the body (bound token cost + injection
   surface) and have the caller fence it as data (the orchestrator system prompt
   declares the user message untrusted-data-not-instruction). The strongest
   control remains playbook-first routing — the RULE tier reaches no LLM at all,
   so most target content never leaves the process.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.config import constants
from agent_alpha.security.secrets import LogScrubber

_scrubber = LogScrubber()  # reuse LOG_SCRUB_PATTERNS — single source of truth


def redact_secrets(text: str) -> str:
    """Mask secret values (LOG_SCRUB_PATTERNS) so they never leave to an LLM."""
    return _scrubber.scrub(text)


def sanitize_observation(
    observation: dict[str, Any],
    *,
    max_body_chars: int = constants.LLM_MAX_UNTRUSTED_BODY_CHARS,
) -> dict[str, Any]:
    """Return an LLM-safe copy of *observation*: secrets masked, body bounded.

    Never mutates the input. The returned dict is safe to serialize into a
    provider request; the caller must still fence it as untrusted data.
    """
    body = str(observation.get("body", ""))
    headers = observation.get("headers", {}) or {}

    safe_body = redact_secrets(body)[:max_body_chars]
    safe_headers = {str(k): redact_secrets(str(v)) for k, v in dict(headers).items()}
    return {"body": safe_body, "headers": safe_headers}
