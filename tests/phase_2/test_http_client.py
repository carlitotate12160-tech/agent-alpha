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
    assert headers["Accept-Encoding"] == constants.STEALTH_BROWSER["accept_encoding"]
    assert headers["sec-ch-ua"] == constants.STEALTH_BROWSER["sec_ch_ua"]
    assert headers["sec-ch-ua-mobile"] == constants.STEALTH_BROWSER["sec_ch_ua_mobile"]
    assert headers["sec-ch-ua-platform"] == constants.STEALTH_BROWSER["sec_ch_ua_platform"]
    assert headers["upgrade-insecure-requests"] == "1"
    assert headers["sec-fetch-site"] == "none"
    assert headers["sec-fetch-mode"] == "navigate"
    assert headers["sec-fetch-user"] == "?1"
    assert headers["sec-fetch-dest"] == "document"


def test_ua_matches_impersonation_profile():
    client = HttpClient(engagement_id="eng-ssot")
    assert client._headers["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
    assert client._headers["sec-ch-ua"] == constants.STEALTH_BROWSER["sec_ch_ua"]
    assert client._headers["sec-ch-ua-platform"] == constants.STEALTH_BROWSER["sec_ch_ua_platform"]
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
        def acquire(self, url: str | None = None) -> None:  # noqa: ARG002
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


def test_pacer_notify_receives_response_status() -> None:
    """§12.50: HttpClient feeds each response status back to the pacer via the
    optional notify() hook (StealthPacer uses it for 429/503 backoff)."""
    import httpx

    from agent_alpha.agents.http_client import HttpClient

    transport = httpx.MockTransport(lambda req: httpx.Response(429, text="rate limited"))

    class _StubPacer:
        def __init__(self) -> None:
            self.acquired = 0
            self.notified: list[int] = []

        def acquire(self, url: str | None = None) -> None:  # noqa: ARG002
            self.acquired += 1

        def notify(self, status_code: int) -> None:
            self.notified.append(status_code)

    pacer = _StubPacer()
    client = HttpClient(engagement_id="eng-notify", transport=transport, rate_limiter=pacer)
    client.get("https://example.test/")

    assert pacer.acquired == 1, "pacer.acquire() not called at the egress chokepoint"
    assert pacer.notified == [429], "response status not fed back to the pacer (backoff hook)"


# ── Header consistency validation (anti-fingerprint-contradiction) ────────────


def test_default_headers_sec_ch_ua_platform_matches_ua_os() -> None:
    """Default STEALTH_BROWSER headers must have sec-ch-ua-platform matching
    the User-Agent OS — a mismatch is a bot fingerprint signal that WAF/CDN
    bot detection can flag."""
    client = HttpClient(engagement_id="eng-consistency")
    ua = client._headers["User-Agent"]
    platform = client._headers["sec-ch-ua-platform"]
    assert "Windows" in ua
    assert platform == '"Windows"'


def test_derive_platform_from_ua_windows() -> None:
    from agent_alpha.agents.http_client import _derive_platform_from_ua
    assert _derive_platform_from_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)") == '"Windows"'


def test_derive_platform_from_ua_macos() -> None:
    from agent_alpha.agents.http_client import _derive_platform_from_ua
    assert _derive_platform_from_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)") == '"macOS"'


def test_derive_platform_from_ua_linux() -> None:
    from agent_alpha.agents.http_client import _derive_platform_from_ua
    assert _derive_platform_from_ua("Mozilla/5.0 (X11; Linux x86_64)") == '"Linux"'


def test_derive_platform_from_ua_cros() -> None:
    from agent_alpha.agents.http_client import _derive_platform_from_ua
    assert _derive_platform_from_ua("Mozilla/5.0 (X11; CrOS x86_64)") == '"Chrome OS"'


def test_derive_platform_from_ua_ios() -> None:
    from agent_alpha.agents.http_client import _derive_platform_from_ua
    assert _derive_platform_from_ua("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)") == '"iOS"'


def test_derive_platform_from_ua_android() -> None:
    from agent_alpha.agents.http_client import _derive_platform_from_ua
    assert _derive_platform_from_ua("Mozilla/5.0 (Linux; Android 14)") == '"Android"'


def test_derive_platform_from_ua_unknown_returns_unknown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from agent_alpha.agents.http_client import _derive_platform_from_ua
    caplog.set_level("WARNING")
    result = _derive_platform_from_ua("Mozilla/5.0 (UnknownOS)")
    assert result == '"Unknown"'
    assert "DERIVE-PLATFORM-UNKNOWN" in caplog.text


def test_validate_header_consistency_no_mismatch() -> None:
    from agent_alpha.agents.http_client import _validate_header_consistency
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0)", "sec-ch-ua-platform": '"Windows"'}
    assert _validate_header_consistency(headers) == []


def test_validate_header_consistency_detects_mismatch() -> None:
    from agent_alpha.agents.http_client import _validate_header_consistency
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0)", "sec-ch-ua-platform": '"macOS"'}
    warnings = _validate_header_consistency(headers)
    assert len(warnings) == 1
    assert "contradicts" in warnings[0]


def test_opsec_ua_override_auto_derives_platform() -> None:
    """When opsec supplies a custom User-Agent, sec-ch-ua-platform must be
    auto-derived to match — preventing the UA=Windows / platform=macOS
    contradiction that was the original bug."""
    mac_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    client = HttpClient(
        engagement_id="eng-opsec-mac",
        opsec={"user_agent": mac_ua},
    )
    assert client._headers["User-Agent"] == mac_ua
    assert client._headers["sec-ch-ua-platform"] == '"macOS"'


def test_opsec_ua_override_windows_derives_windows_platform() -> None:
    win_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    client = HttpClient(
        engagement_id="eng-opsec-win",
        opsec={"user_agent": win_ua},
    )
    assert client._headers["User-Agent"] == win_ua
    assert client._headers["sec-ch-ua-platform"] == '"Windows"'


def test_opsec_explicit_platform_override_not_clobbered_by_ua() -> None:
    """If opsec explicitly sets sec-ch-ua-platform via headers dict, that
    explicit value wins over auto-derivation — the operator is taking
    responsibility for the override."""
    win_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    client = HttpClient(
        engagement_id="eng-opsec-explicit",
        opsec={
            "user_agent": win_ua,
            "headers": {"sec-ch-ua-platform": '"Linux"'},
        },
    )
    assert client._headers["sec-ch-ua-platform"] == '"Linux"'


def test_inconsistent_headers_logged_as_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If opsec creates an inconsistent header set (UA=Windows but
    sec-ch-ua-platform=Linux via explicit headers), a warning must be logged
    so the operator is alerted to the fingerprint contradiction."""
    caplog.set_level("WARNING")
    win_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    HttpClient(
        engagement_id="eng-inconsistent",
        opsec={
            "user_agent": win_ua,
            "headers": {"sec-ch-ua-platform": '"Linux"'},
        },
    )
    assert "HEADER-INCONSISTENCY" in caplog.text


def test_per_request_header_override_validates_consistency(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Per-call headers that introduce a UA/platform mismatch must be caught
    by the per-request validation in _request, not just construction-time
    validation in __init__."""
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="ok"))
    client = HttpClient(engagement_id="eng-per-call", transport=transport)
    caplog.set_level("WARNING")
    # Per-call override: set a macOS UA while the default sec-ch-ua-platform
    # is "Windows" — this creates a contradiction that per-request validation
    # must catch.
    client.get(
        "https://example.com",
        headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    )
    assert "HEADER-INCONSISTENCY" in caplog.text
