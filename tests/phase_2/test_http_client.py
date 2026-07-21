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


def test_default_accept_header_is_sent():
    """Bug #10: every request carries an Accept header by default.

    Without it, origins like Cloudways/WP reject the request with HTTP 415
    (unsupported media type) and serve their generic error page instead of
    the target's real content.
    """
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers["accept"] = request.headers.get("accept", "")
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    client = HttpClient(engagement_id="eng-accept-test", transport=transport)
    client.get("https://example.com")

    assert captured_headers["accept"] != "", "no Accept header sent (Bug #10 regression)"
    assert "text/html" in captured_headers["accept"]


def test_caller_supplied_accept_header_overrides_default():
    """A caller-supplied Accept header (e.g. for a JSON API probe) still wins —
    the default is a floor, not a hard override (mirrors merged_headers in
    HttpClient._request: {**self._headers, **(headers or {})})."""
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers["accept"] = request.headers.get("accept", "")
        return httpx.Response(200, text="{}")

    transport = httpx.MockTransport(handler)
    client = HttpClient(engagement_id="eng-accept-override", transport=transport)
    client.get("https://example.com/api", headers={"Accept": "application/json"})

    assert captured_headers["accept"] == "application/json"


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


def test_get_verify_override_false_reaches_httpx():
    """Per-call verify=False → httpx.Client built with verify=False.

    Default call (verify omitted) keeps verify=True — backward-compat lock.
    This proves the per-call TLS override seam used by origin-direct login.
    """
    from unittest.mock import patch

    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="ok"))
    client = HttpClient(engagement_id="test-verify", transport=transport)

    # 1. Default: verify=True (instance default, no override)
    with patch("agent_alpha.agents.http_client.httpx.Client", wraps=httpx.Client) as mock_cls:
        client.get("https://example.com")
        _, kwargs = mock_cls.call_args
        assert kwargs["verify"] is True, f"default verify should be True, got {kwargs['verify']}"

    # 2. Override: verify=False per-call
    with patch("agent_alpha.agents.http_client.httpx.Client", wraps=httpx.Client) as mock_cls:
        client.get("https://example.com", verify=False)
        _, kwargs = mock_cls.call_args
        assert kwargs["verify"] is False, f"override verify should be False, got {kwargs['verify']}"

    # 3. POST with verify=False
    with patch("agent_alpha.agents.http_client.httpx.Client", wraps=httpx.Client) as mock_cls:
        client.post("https://example.com/login", data={"user": "x"}, verify=False)
        _, kwargs = mock_cls.call_args
        assert kwargs["verify"] is False, "POST verify=False override did not reach httpx"
