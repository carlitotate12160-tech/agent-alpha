"""browser_solve transport adapter (Phase 9c, DeepSeek lane).

This module provides a concrete :class:`BrowserSolveTransport` implementation
that delegates the actual Cloudflare/Turnstile solving work to an **external
DeepSeek-powered service** exposed over HTTP.

Architecture boundaries (from ADR §12.33 / slice-9c/9d):

* This adapter lives in the Python (Claude) lane and ONLY handles the
  **transport contract**:

    ``(url, engagement_id) -> ChallengeSolveResult``

  It never implements the challenge-bypass logic itself.
* The external service is responsible for driving a real browser (e.g.
  Playwright/camoufox) against a self-owned, lab-only target and returning the
  final response after any CF/Turnstile challenge has been solved.
* Lab-only guarantee is enforced by the harness via ``assert_lab_only_target``;
  this adapter assumes it is only called with such targets.

The :class:`DeepSeekBrowserSolve` class can be injected into
``run_a1_validation`` (slice-9d) via the ``browser_solve`` parameter or the
``--browser-solve`` CLI flag. When no solver is provided, the harness uses
``_NoopBrowserSolve`` and fails loud, so A1 never silently "passes" without a
real solver.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from agent_alpha.config import constants

# ── Environment variable names ────────────────────────────────────────────────

ENV_ENDPOINT = "A1_BROWSER_SOLVE_ENDPOINT"
ENV_API_KEY = "A1_BROWSER_SOLVE_API_KEY"


@dataclass(frozen=True)
class BrowserSolveResponse:
    """Concrete response type matching ``ChallengeSolveResult``.

    This is a plain data carrier; the protocol itself is defined in
    ``a1_validation_runner.py``. Structural typing means the dataclass does
    not need to inherit from the Protocol as long as attribute names match.
    """

    status_code: int
    body: str
    headers: dict[str, str]
    cleared_cookies: dict[str, str]
    challenge_encountered: bool
    challenge_solved: bool


class DeepSeekBrowserSolve:
    """HTTP adapter for a DeepSeek-backed browser_solve service (9c).

    The external service MUST expose an HTTP endpoint that accepts JSON:

        {"url": str, "engagement_id": str}

    and returns JSON with at least the following fields:

        {
          "status_code": int,
          "body": str,
          "headers": {str: str},
          "cleared_cookies": {str: str},
          "challenge_encountered": bool,
          "challenge_solved": bool,
        }

    On any transport or protocol error, this adapter raises ``RuntimeError`` so
    that the A1 harness fails loud instead of silently treating the run as a
    success.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str | None = None,
        timeout: float = constants.HTTP_REQUEST_TIMEOUT_SEC,
    ) -> None:
        if not endpoint:
            raise ValueError("DeepSeekBrowserSolve.endpoint must be non-empty")
        self._endpoint = endpoint
        self._api_key = api_key
        self._timeout = timeout

    @classmethod
    def from_env(cls, *, timeout: float = constants.HTTP_REQUEST_TIMEOUT_SEC) -> "DeepSeekBrowserSolve | None":
        """Build from environment variables.

        Reads ``A1_BROWSER_SOLVE_ENDPOINT`` (required) and
        ``A1_BROWSER_SOLVE_API_KEY`` (optional). Returns ``None`` when the
        endpoint env-var is unset or empty, so the caller can fall back to
        ``_NoopBrowserSolve`` (fail-loud).
        """
        endpoint = os.environ.get(ENV_ENDPOINT, "").strip()
        if not endpoint:
            return None
        api_key = os.environ.get(ENV_API_KEY, "").strip() or None
        return cls(endpoint=endpoint, api_key=api_key, timeout=timeout)

    def solve_and_fetch(self, url: str, *, engagement_id: str) -> BrowserSolveResponse:
        payload: dict[str, Any] = {"url": url, "engagement_id": engagement_id}
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            resp = httpx.post(
                self._endpoint,
                json=payload,
                headers=headers,
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:  # network / timeout / TLS
            raise RuntimeError(f"browser_solve request failed: {exc}") from exc

        if resp.status_code != 200:
            raise RuntimeError(
                f"browser_solve endpoint returned HTTP {resp.status_code} for {url!r}"
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError("browser_solve endpoint returned non-JSON response") from exc

        try:
            status_code = int(data["status_code"])
            body = str(data.get("body", ""))
            headers_raw = data.get("headers") or {}
            cookies_raw = data.get("cleared_cookies") or {}
            challenge_encountered = bool(data.get("challenge_encountered"))
            challenge_solved = bool(data.get("challenge_solved"))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(
                "browser_solve endpoint response missing required fields"
            ) from exc

        # Normalise headers/cookies to str→str mappings.
        norm_headers: dict[str, str] = {
            str(k).lower(): str(v) for k, v in getattr(headers_raw, "items", lambda: [])()
        }
        norm_cookies: dict[str, str] = {
            str(k): str(v) for k, v in getattr(cookies_raw, "items", lambda: [])()
        }

        return BrowserSolveResponse(
            status_code=status_code,
            body=body,
            headers=norm_headers,
            cleared_cookies=norm_cookies,
            challenge_encountered=challenge_encountered,
            challenge_solved=challenge_solved,
        )
