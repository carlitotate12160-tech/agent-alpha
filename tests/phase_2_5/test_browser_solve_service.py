# tests/phase_2_5/test_browser_solve_service.py
"""Tests for browser_solve_service (9c) — FastAPI + Camoufox solver.

Tests cover:
- API contract: /solve and /health endpoints
- Challenge detection logic
- Response model validation
- Error handling (camoufox not installed)

Camoufox/Playwright is mocked — no real browser is launched.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import agent_alpha.live_fire.browser_solve_service as browser_solve_service
from agent_alpha.live_fire.browser_solve_service import (
    SolveRequest,
    SolveResponse,
    _detect_challenge,
    _get_browser,
    _solve_and_fetch,
    _wait_for_challenge_clear,
    app,
)
from agent_alpha.live_fire.lab_guard import LabOnlyViolation

# ── Test client ───────────────────────────────────────────────────────────────


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ── /health ───────────────────────────────────────────────────────────────────


def test_health_endpoint(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "browser_solve"
    assert data["version"] == "9c"


# ── /solve — mocked Camoufox ──────────────────────────────────────────────────


def _mock_camoufox_response() -> dict:
    return {
        "status_code": 200,
        "body": "<html><body>Hello from lab</body></html>",
        "headers": {"content-type": "text/html", "cf-mitigated": "challenge"},
        "cleared_cookies": {"cf_clearance": "token-abc123", "session_id": "sess-xyz"},
        "challenge_encountered": True,
        "challenge_solved": True,
    }


@patch("agent_alpha.live_fire.browser_solve_service._solve_and_fetch")
def test_solve_endpoint_success(mock_solve: MagicMock, client: TestClient) -> None:
    mock_solve.return_value = SolveResponse(**_mock_camoufox_response())

    resp = client.post(
        "/solve",
        json={"url": "https://alpha-ai.web.id/web", "engagement_id": "eng-test-1"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status_code"] == 200
    assert "Hello from lab" in data["body"]
    assert data["challenge_encountered"] is True
    assert data["challenge_solved"] is True
    assert data["cleared_cookies"]["cf_clearance"] == "token-abc123"
    assert data["headers"]["cf-mitigated"] == "challenge"

    mock_solve.assert_called_once_with("https://alpha-ai.web.id/web", "eng-test-1")


@patch("agent_alpha.live_fire.browser_solve_service._solve_and_fetch")
def test_solve_endpoint_no_challenge(mock_solve: MagicMock, client: TestClient) -> None:
    mock_solve.return_value = SolveResponse(
        status_code=200,
        body="<html>pass-through</html>",
        headers={},
        cleared_cookies={},
        challenge_encountered=False,
        challenge_solved=False,
    )

    resp = client.post(
        "/solve",
        json={"url": "https://alpha-ai.web.id/web", "engagement_id": "eng-test-2"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["challenge_encountered"] is False
    assert data["challenge_solved"] is False


def test_solve_endpoint_missing_url(client: TestClient) -> None:
    resp = client.post("/solve", json={"engagement_id": "eng-test"})
    assert resp.status_code == 422  # Pydantic validation error


def test_solve_endpoint_missing_engagement_id(client: TestClient) -> None:
    resp = client.post("/solve", json={"url": "https://alpha-ai.web.id/web"})
    assert resp.status_code == 422


@patch("agent_alpha.live_fire.browser_solve_service._solve_and_fetch")
def test_solve_endpoint_returns_502_on_runtime_error(
    mock_solve: MagicMock, client: TestClient
) -> None:
    mock_solve.side_effect = RuntimeError("boom: lab guard refused")

    resp = client.post(
        "/solve",
        json={"url": "https://evil.example.com/x", "engagement_id": "eng-test"},
    )

    assert resp.status_code == 502
    assert resp.json()["detail"] == "boom: lab guard refused"


@patch("agent_alpha.live_fire.browser_solve_service._solve_and_fetch")
def test_solve_endpoint_returns_502_on_unexpected_exception(
    mock_solve: MagicMock, client: TestClient
) -> None:
    mock_solve.side_effect = ValueError("unexpected")

    resp = client.post(
        "/solve",
        json={"url": "https://alpha-ai.web.id/web", "engagement_id": "eng-test"},
    )

    assert resp.status_code == 502
    assert "browser_solve failed" in resp.json()["detail"]


# ── SolveRequest / SolveResponse models ───────────────────────────────────────


def test_solve_request_model() -> None:
    req = SolveRequest(url="https://alpha-ai.web.id/web", engagement_id="eng-1")
    assert req.url == "https://alpha-ai.web.id/web"
    assert req.engagement_id == "eng-1"


def test_solve_response_model() -> None:
    resp = SolveResponse(
        status_code=200,
        body="<html></html>",
        headers={"content-type": "text/html"},
        cleared_cookies={"cf_clearance": "abc"},
        challenge_encountered=True,
        challenge_solved=True,
    )
    assert resp.status_code == 200
    assert resp.challenge_encountered is True
    assert resp.challenge_solved is True


# ── _detect_challenge ─────────────────────────────────────────────────────────


def test_detect_challenge_found() -> None:
    page = MagicMock()
    page.query_selector = AsyncMock(return_value=MagicMock())

    result = asyncio.run(_detect_challenge(page))
    assert result is True


def test_detect_challenge_not_found() -> None:
    page = MagicMock()
    page.query_selector = AsyncMock(return_value=None)
    page.title = AsyncMock(return_value="Welcome to Alpha-AI")

    result = asyncio.run(_detect_challenge(page))
    assert result is False


def test_detect_challenge_by_title() -> None:
    page = MagicMock()
    page.query_selector = AsyncMock(return_value=None)
    page.title = AsyncMock(return_value="Just a moment...")

    result = asyncio.run(_detect_challenge(page))
    assert result is True


# ── _wait_for_challenge_clear ─────────────────────────────────────────────────


def test_wait_for_challenge_clear_success() -> None:
    page = MagicMock()
    page.wait_for_selector = AsyncMock()
    page.wait_for_function = AsyncMock()
    # frame_locator returns a mock that will fail to find checkbox/body
    # (no Turnstile iframe to click) — falls through to wait strategies
    mock_fl = MagicMock()
    mock_fl.locator.return_value.click = AsyncMock(side_effect=Exception("no iframe"))
    page.frame_locator = MagicMock(return_value=mock_fl)
    # query_selector: Turnstile iframe not found (None), then _detect_challenge
    # selectors also None = challenge cleared
    page.query_selector = AsyncMock(return_value=None)
    page.title = AsyncMock(return_value="Welcome to Alpha-AI")

    result = asyncio.run(_wait_for_challenge_clear(page))
    assert result is True


def test_wait_for_challenge_clear_timeout() -> None:
    page = MagicMock()
    page.wait_for_selector = AsyncMock(side_effect=TimeoutError("timeout"))
    page.wait_for_function = AsyncMock(side_effect=TimeoutError("timeout"))
    # frame_locator: clicking checkbox and body both fail
    mock_fl = MagicMock()
    mock_fl.locator.return_value.click = AsyncMock(side_effect=Exception("cross-origin"))
    page.frame_locator = MagicMock(return_value=mock_fl)
    # query_selector: first call returns mock iframe with bounding box,
    # later calls from _detect_challenge return mock (challenge still present)
    mock_iframe = MagicMock()
    mock_iframe.bounding_box = AsyncMock(
        return_value={"x": 100, "y": 200, "width": 300, "height": 65}
    )
    page.query_selector = AsyncMock(return_value=mock_iframe)
    page.mouse = MagicMock()
    page.mouse.click = AsyncMock()
    page.title = AsyncMock(return_value="Just a moment...")

    result = asyncio.run(_wait_for_challenge_clear(page))
    assert result is False


# ── lab-guard defense-in-depth (_solve_and_fetch) ──────────────────────────────


@patch("agent_alpha.live_fire.browser_solve_service._get_browser")
def test_solve_and_fetch_rejects_non_lab_target(mock_get_browser: MagicMock) -> None:
    """Refuses a non-lab URL BEFORE ever touching the browser (no egress)."""
    with pytest.raises(LabOnlyViolation):
        asyncio.run(_solve_and_fetch("https://evil.example.com/x", "eng-test"))

    mock_get_browser.assert_not_called()


@patch("agent_alpha.live_fire.browser_solve_service.AsyncNewContext", new_callable=AsyncMock)
@patch("agent_alpha.live_fire.browser_solve_service._get_browser")
def test_solve_and_fetch_allows_lab_target(
    mock_get_browser: MagicMock, mock_new_context: AsyncMock
) -> None:
    """A lab-allowlisted URL passes the guard and proceeds to the browser."""
    mock_browser = MagicMock()
    mock_context = AsyncMock()
    mock_page = AsyncMock()
    mock_response = MagicMock(status=200, headers={})

    mock_new_context.return_value = mock_context
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_context.cookies = AsyncMock(return_value=[])
    mock_context.close = AsyncMock()
    mock_page.goto = AsyncMock(return_value=mock_response)
    mock_page.content = AsyncMock(return_value="<html>ok</html>")
    mock_page.query_selector = AsyncMock(return_value=None)
    mock_page.title = AsyncMock(return_value="Welcome")

    async def _fake_get_browser() -> MagicMock:
        return mock_browser

    mock_get_browser.side_effect = _fake_get_browser

    result = asyncio.run(_solve_and_fetch("https://alpha-ai.web.id/web", "eng-test"))

    assert result.status_code == 200
    assert result.body == "<html>ok</html>"
    assert result.challenge_encountered is False
    mock_context.close.assert_awaited_once()


# ── persistent browser singleton (_get_browser) ─────────────────────────


@pytest.fixture(autouse=False)
def _reset_browser_state() -> None:
    browser_solve_service._browser_state["playwright"] = None
    browser_solve_service._browser_state["browser"] = None


def test_get_browser_raises_when_playwright_unavailable(
    _reset_browser_state: None,
) -> None:
    with (
        patch("agent_alpha.live_fire.browser_solve_service.async_playwright", None),
        patch("agent_alpha.live_fire.browser_solve_service.AsyncNewBrowser", None),
    ):
        with pytest.raises(RuntimeError, match="camoufox is not installed"):
            asyncio.run(_get_browser())


def test_get_browser_reuses_singleton(_reset_browser_state: None) -> None:
    mock_browser = AsyncMock()
    mock_pw_instance = AsyncMock()

    mock_pw_factory = MagicMock()
    mock_pw_factory.return_value.start = AsyncMock(return_value=mock_pw_instance)

    mock_new_browser = AsyncMock(return_value=mock_browser)

    with (
        patch("agent_alpha.live_fire.browser_solve_service.async_playwright", mock_pw_factory),
        patch("agent_alpha.live_fire.browser_solve_service.AsyncNewBrowser", mock_new_browser),
    ):
        browser1 = asyncio.run(_get_browser())
        browser2 = asyncio.run(_get_browser())

    assert browser1 is browser2
    mock_new_browser.assert_called_once()
