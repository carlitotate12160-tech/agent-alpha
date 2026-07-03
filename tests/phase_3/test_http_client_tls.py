"""Security test: HttpClient TLS verification.

Not coverage padding. ``verify`` controls httpx TLS certificate validation.
``verify=False`` = accept any cert = MITM-able recon/creds. The security-critical
invariant is: verification is ON by default, and whatever is configured is passed
through to httpx unchanged. A regression here silently downgrades every egress.
"""

from __future__ import annotations

from typing import Any

import httpx

from agent_alpha.agents.http_client import HttpClient


def test_verify_defaults_on() -> None:
    """Secure-by-default: no explicit arg -> TLS verification enabled."""
    client = HttpClient(engagement_id="eng_test")
    assert client._verify is True


def test_verify_explicit_off_is_honoured() -> None:
    client = HttpClient(engagement_id="eng_test", verify=False)
    assert client._verify is False


def test_verify_passthrough_to_httpx(monkeypatch: Any) -> None:
    """The configured verify flag reaches httpx.Client(verify=...) unchanged.

    Uses a fake httpx.Client so no network egress happens; captures the kwarg.
    """
    captured: dict[str, Any] = {}

    class _FakeResponse:
        status_code = 200
        text = ""
        headers: dict[str, str] = {}
        url = "https://lab.example-you-own.dev/"

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

        def request(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse()

    monkeypatch.setattr(httpx, "Client", _FakeClient)

    # high rps so the rate limiter does not sleep during the test
    client = HttpClient(engagement_id="eng_test", rate_limit_rps=1000.0, verify=False)
    client.get("https://lab.example-you-own.dev/")

    assert captured.get("verify") is False


def test_verify_true_passthrough_to_httpx(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _FakeResponse:
        status_code = 200
        text = ""
        headers: dict[str, str] = {}
        url = "https://lab.example-you-own.dev/"

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

        def request(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse()

    monkeypatch.setattr(httpx, "Client", _FakeClient)

    client = HttpClient(engagement_id="eng_test", rate_limit_rps=1000.0)  # default verify=True
    client.get("https://lab.example-you-own.dev/")

    assert captured.get("verify") is True


# Keep the httpx import referenced so linters do not flag it; it documents the
# dependency whose behaviour these tests pin.
_ = httpx
