# tests/phase_2_5/test_browser_solve.py
"""Tests for DeepSeekBrowserSolve adapter (9c) — env-var + HTTP contract.

Run:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_browser_solve.py -v
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest

from agent_alpha.live_fire.browser_solve import (
    ENV_API_KEY,
    ENV_ENDPOINT,
    BrowserSolveResponse,
    DeepSeekBrowserSolve,
)

# ── from_env ──────────────────────────────────────────────────────────────────


def test_from_env_returns_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    assert DeepSeekBrowserSolve.from_env() is None


def test_from_env_returns_none_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "  ")
    assert DeepSeekBrowserSolve.from_env() is None


def test_from_env_builds_solver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "https://solver.internal/solve")
    monkeypatch.setenv(ENV_API_KEY, "secret-key-123")
    solver = DeepSeekBrowserSolve.from_env()
    assert solver is not None
    assert solver._endpoint == "https://solver.internal/solve"
    assert solver._api_key == "secret-key-123"


def test_from_env_no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "https://solver.internal/solve")
    monkeypatch.delenv(ENV_API_KEY, raising=False)
    solver = DeepSeekBrowserSolve.from_env()
    assert solver is not None
    assert solver._api_key is None


# ── solve_and_fetch — success ─────────────────────────────────────────────────


def _mock_response(
    status_code: int = 200,
    json_body: dict | None = None,
) -> httpx.Response:
    if json_body is None:
        json_body = {
            "status_code": 200,
            "body": "<html>ok</html>",
            "headers": {"cf-mitigated": "challenge", "Content-Type": "text/html"},
            "cleared_cookies": {"cf_clearance": "abc123"},
            "challenge_encountered": True,
            "challenge_solved": True,
        }
    return httpx.Response(
        status_code=status_code,
        content=json.dumps(json_body).encode(),
        headers={"content-type": "application/json"},
    )


@patch("agent_alpha.live_fire.browser_solve.httpx.post")
def test_solve_and_fetch_success(mock_post: any) -> None:
    mock_post.return_value = _mock_response()

    solver = DeepSeekBrowserSolve(endpoint="https://solver.internal/solve")
    result = solver.solve_and_fetch("https://alpha-ai.web.id/web", engagement_id="eng-1")

    assert isinstance(result, BrowserSolveResponse)
    assert result.status_code == 200
    assert result.body == "<html>ok</html>"
    assert result.challenge_encountered is True
    assert result.challenge_solved is True
    assert result.cleared_cookies == {"cf_clearance": "abc123"}
    assert result.headers["cf-mitigated"] == "challenge"

    # Verify the request was made with correct payload
    call_args = mock_post.call_args
    assert call_args.kwargs["json"] == {
        "url": "https://alpha-ai.web.id/web",
        "engagement_id": "eng-1",
    }


@patch("agent_alpha.live_fire.browser_solve.httpx.post")
def test_solve_and_fetch_with_api_key(mock_post: any) -> None:
    mock_post.return_value = _mock_response()

    solver = DeepSeekBrowserSolve(
        endpoint="https://solver.internal/solve",
        api_key="my-key",
    )
    solver.solve_and_fetch("https://alpha-ai.web.id/web", engagement_id="eng-1")

    call_args = mock_post.call_args
    assert call_args.kwargs["headers"]["Authorization"] == "Bearer my-key"


# ── solve_and_fetch — error cases ─────────────────────────────────────────────


@patch("agent_alpha.live_fire.browser_solve.httpx.post")
def test_solve_and_fetch_http_error_raises(mock_post: any) -> None:
    mock_post.side_effect = httpx.ConnectError("connection refused")

    solver = DeepSeekBrowserSolve(endpoint="https://solver.internal/solve")
    with pytest.raises(RuntimeError, match="browser_solve request failed"):
        solver.solve_and_fetch("https://alpha-ai.web.id/web", engagement_id="eng-1")


@patch("agent_alpha.live_fire.browser_solve.httpx.post")
def test_solve_and_fetch_non_200_raises(mock_post: any) -> None:
    mock_post.return_value = _mock_response(status_code=503)

    solver = DeepSeekBrowserSolve(endpoint="https://solver.internal/solve")
    with pytest.raises(RuntimeError, match="HTTP 503"):
        solver.solve_and_fetch("https://alpha-ai.web.id/web", engagement_id="eng-1")


@patch("agent_alpha.live_fire.browser_solve.httpx.post")
def test_solve_and_fetch_missing_fields_raises(mock_post: any) -> None:
    mock_post.return_value = _mock_response(
        json_body={"body": "<html></html>"},  # missing status_code (required field)
    )

    solver = DeepSeekBrowserSolve(endpoint="https://solver.internal/solve")
    with pytest.raises(RuntimeError, match="missing required fields"):
        solver.solve_and_fetch("https://alpha-ai.web.id/web", engagement_id="eng-1")


@patch("agent_alpha.live_fire.browser_solve.httpx.post")
def test_solve_and_fetch_non_json_raises(mock_post: any) -> None:
    mock_post.return_value = httpx.Response(
        status_code=200,
        content=b"not json at all",
        headers={"content-type": "text/plain"},
    )

    solver = DeepSeekBrowserSolve(endpoint="https://solver.internal/solve")
    with pytest.raises(RuntimeError, match="non-JSON"):
        solver.solve_and_fetch("https://alpha-ai.web.id/web", engagement_id="eng-1")


# ── constructor validation ────────────────────────────────────────────────────


def test_empty_endpoint_raises() -> None:
    with pytest.raises(ValueError, match="endpoint must be non-empty"):
        DeepSeekBrowserSolve(endpoint="")
