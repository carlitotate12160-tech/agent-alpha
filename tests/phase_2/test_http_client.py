"""Contract: HttpClient — production HTTP client."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest

import agent_alpha.agents.http_client as http_client_module
from agent_alpha.agents.http_client import HttpClient, HttpResponse
from agent_alpha.config import constants


def test_get_maps_response_fields_correctly():
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


def test_default_ua_is_not_self_identifying():
    captured: dict[str, Any] = {}

    def fetcher(
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        cookies: dict[str, str] | None,
        data: dict[str, Any] | None,
        json_body: dict[str, Any] | None,
        allow_redirects: bool,
        verify: bool,
    ) -> HttpResponse:
        captured.update(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "cookies": cookies,
                "data": data,
                "json_body": json_body,
                "allow_redirects": allow_redirects,
                "verify": verify,
            }
        )
        return HttpResponse(status_code=200, text="ok", headers={}, url=url)

    client = HttpClient(engagement_id="eng-abc-456", fetcher=fetcher)
    client.get("https://example.com")

    headers = captured["headers"]
    ua = headers["User-Agent"]
    assert "Agent-Alpha" not in ua
    assert "Recon" not in ua
    assert ua == constants.STEALTH_BROWSER["user_agent"]
    assert headers["Accept"] == constants.STEALTH_BROWSER["accept"]
    assert headers["Accept-Language"] == constants.STEALTH_BROWSER["accept_language"]
    assert headers["sec-ch-ua"] == constants.STEALTH_BROWSER["sec_ch_ua"]
    assert headers["sec-fetch-site"] == "none"
    assert headers["sec-fetch-mode"] == "navigate"
    assert headers["sec-fetch-user"] == "?1"
    assert headers["sec-fetch-dest"] == "document"


def test_ua_matches_impersonation_profile():
    client = HttpClient(engagement_id="eng-ssot")
    assert client._headers["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
    assert client._headers["sec-ch-ua"] == constants.STEALTH_BROWSER["sec_ch_ua"]
    assert client._impersonate == constants.STEALTH_BROWSER["impersonate"]


def test_impersonate_token_matches_ua_version() -> None:
    assert constants.STEALTH_BROWSER["impersonate"] == "chrome124"
    assert "124" in constants.STEALTH_BROWSER["impersonate"]
    assert "Chrome/124" in constants.STEALTH_BROWSER["user_agent"]


def test_default_transport_is_curl_cffi(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _FakeCurlRequests:
        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            captured.update({"method": method, "url": url, **kwargs})
            return SimpleNamespace(
                status_code=200,
                text="ok",
                headers={"server": "cloudflare"},
                url=url,
            )

    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("default fetch path should not instantiate httpx.Client")

    monkeypatch.setattr(http_client_module, "is_tls_impersonate_available", lambda: True)
    monkeypatch.setattr(http_client_module, "cffi_requests", _FakeCurlRequests())
    monkeypatch.setattr(http_client_module.httpx, "Client", _boom)

    client = HttpClient(engagement_id="eng-curl-default")
    response = client.get("https://example.com")

    assert response.status_code == 200
    assert captured["impersonate"] == constants.STEALTH_BROWSER["impersonate"]
    assert captured["headers"]["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
    assert captured["allow_redirects"] is True
    assert captured["verify"] is True


def test_curl_cffi_unavailable_warns_not_silent(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    captured: dict[str, Any] = {}

    class _FakeResponse:
        status_code = 200
        text = "ok"
        headers: dict[str, str] = {}
        url = "https://example.com"

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

        def request(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse()

    monkeypatch.setattr(http_client_module, "is_tls_impersonate_available", lambda: False)
    monkeypatch.setattr(http_client_module.httpx, "Client", _FakeClient)
    caplog.set_level("WARNING")

    client = HttpClient(engagement_id="eng-httpx-fallback", rate_limit_rps=1000.0)
    response = client.get("https://example.com")

    assert response.status_code == 200
    assert "STEALTH-DEGRADED" in caplog.text
    assert captured["verify"] is True


def test_default_accept_header_is_sent():
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers["accept"] = request.headers.get("accept", "")
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    client = HttpClient(engagement_id="eng-accept-test", transport=transport)
    client.get("https://example.com")

    assert captured_headers["accept"] != "", "no Accept header sent (Bug #10 regression)"
    assert captured_headers["accept"] == constants.STEALTH_BROWSER["accept"]


def test_caller_supplied_accept_header_overrides_default():
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers["accept"] = request.headers.get("accept", "")
        return httpx.Response(200, text="{}")

    transport = httpx.MockTransport(handler)
    client = HttpClient(engagement_id="eng-accept-override", transport=transport)
    client.get("https://example.com/api", headers={"Accept": "application/json"})

    assert captured_headers["accept"] == "application/json"


def test_timeout_is_configurable_with_positive_default():
    client_default = HttpClient(engagement_id="test")
    assert client_default.timeout > 0

    client_custom = HttpClient(engagement_id="test", timeout=60.0)
    assert client_custom.timeout == 60.0


def test_timeout_applied_to_request():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="ok"))
    client = HttpClient(engagement_id="test", timeout=5.0, transport=transport)

    response = client.get("https://example.com")
    assert response.status_code == 200


def test_rate_limiter_gates_every_request() -> None:
    calls: list[str] = []

    class _FakeRateLimiter:
        def acquire(self) -> None:
            calls.append("acquire")

    def fetcher(
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        cookies: dict[str, str] | None,
        data: dict[str, Any] | None,
        json_body: dict[str, Any] | None,
        allow_redirects: bool,
        verify: bool,
    ) -> HttpResponse:
        return HttpResponse(status_code=200, text=method, headers={}, url=url)

    client = HttpClient(
        engagement_id="eng-rate-limit",
        fetcher=fetcher,
        rate_limiter=_FakeRateLimiter(),
    )

    client.get("https://example.com")
    client.post("https://example.com/login", data={"user": "x"})

    assert calls == ["acquire", "acquire"]


def test_get_verify_override_false_reaches_httpx():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="ok"))
    client = HttpClient(engagement_id="test-verify", transport=transport)

    with patch("agent_alpha.agents.http_client.httpx.Client", wraps=httpx.Client) as mock_cls:
        client.get("https://example.com")
        _, kwargs = mock_cls.call_args
        assert kwargs["verify"] is True

    with patch("agent_alpha.agents.http_client.httpx.Client", wraps=httpx.Client) as mock_cls:
        client.get("https://example.com", verify=False)
        _, kwargs = mock_cls.call_args
        assert kwargs["verify"] is False

    with patch("agent_alpha.agents.http_client.httpx.Client", wraps=httpx.Client) as mock_cls:
        client.post("https://example.com/login", data={"user": "x"}, verify=False)
        _, kwargs = mock_cls.call_args
        assert kwargs["verify"] is False
