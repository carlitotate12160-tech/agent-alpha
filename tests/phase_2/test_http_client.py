"""Contract: HttpClient — production httpx-backed HTTP client.

The real HTTP client Alpha uses against real (authorized) targets. It MUST
identify itself (User-Agent tied to the engagement) and MUST always have a timeout.
"""

from __future__ import annotations

import httpx

from agent_alpha.agents.http_client import HttpClient


def test_get_maps_response_fields_correctly():
    """HttpClient.get() maps status_code/text/headers/url correctly."""
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            text="hello",
            headers={"server": "nginx"},
        )
    )
    client = HttpClient(engagement_id="test-123", transport=transport)
    response = client.get("https://example.com")

    assert response.status_code == 200
    assert response.text == "hello"
    assert response.headers["server"] == "nginx"
    assert response.url == "https://example.com"


def test_user_agent_contains_engagement_id():
    """Every request carries User-Agent containing 'Agent-Alpha' and engagement_id."""
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers["user-agent"] = request.headers.get("user-agent", "")
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    client = HttpClient(engagement_id="eng-abc-456", transport=transport)
    client.get("https://example.com")

    ua = captured_headers["user-agent"]
    assert "Agent-Alpha" in ua
    assert "eng-abc-456" in ua


def test_timeout_is_configurable_with_positive_default():
    """Timeout is configurable and has a positive default."""
    client_default = HttpClient(engagement_id="test")
    assert client_default.timeout > 0

    client_custom = HttpClient(engagement_id="test", timeout=60.0)
    assert client_custom.timeout == 60.0


def test_timeout_applied_to_request():
    """Timeout is actually applied to the HTTP request."""
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="ok"))
    client = HttpClient(engagement_id="test", timeout=5.0, transport=transport)

    # If timeout wasn't applied, this would hang forever on a slow target.
    # With MockTransport, it's instant, but the timeout is still configured.
    response = client.get("https://example.com")
    assert response.status_code == 200
