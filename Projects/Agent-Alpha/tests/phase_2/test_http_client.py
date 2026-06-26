"""Contract: the real (httpx-backed) HttpClient used by Alpha in live-fire.

Hermetic — uses httpx.MockTransport, never touches the network, so it runs in
the unit tier. Two guarantees matter beyond field-mapping:

  1. Identified scanner: every request carries a clear User-Agent tying it to
     the engagement (responsible-disclosure norm — the client's blue team must
     be able to see this is authorised testing, not an anonymous attack).
  2. The response shape matches what Alpha consumes (.status_code/.text/
     .headers/.url) — the same contract the test FakeHttpClient mimics.
"""

from __future__ import annotations

import httpx

from agent_alpha.agents.http_client import HttpClient


def test_get_maps_response_fields() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="hello world", headers={"server": "nginx"}
        )

    client = HttpClient(
        engagement_id="eng_test", transport=httpx.MockTransport(handler)
    )
    resp = client.get("https://example.test/path")

    assert resp.status_code == 200
    assert resp.text == "hello world"
    assert resp.headers["server"] == "nginx"
    assert resp.url == "https://example.test/path"


def test_request_carries_engagement_scoped_user_agent() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["user_agent"] = request.headers.get("user-agent", "")
        return httpx.Response(200, text="ok", headers={})

    client = HttpClient(
        engagement_id="eng_abc123", transport=httpx.MockTransport(handler)
    )
    client.get("https://example.test/")

    # Identified scanner: UA must tie the request to the engagement.
    assert "Agent-Alpha" in seen["user_agent"]
    assert "eng_abc123" in seen["user_agent"]


def test_timeout_is_configurable() -> None:
    client = HttpClient(engagement_id="eng_test", timeout=12.5)
    assert client.timeout == 12.5


def test_default_timeout_is_set() -> None:
    # A hung target must not block forever — a default timeout is mandatory.
    client = HttpClient(engagement_id="eng_test")
    assert client.timeout > 0
