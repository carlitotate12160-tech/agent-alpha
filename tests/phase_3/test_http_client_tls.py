"""Security test: HttpClient TLS verification.

Not coverage padding. ``verify`` controls transport TLS certificate validation.
The security-critical invariant is: verification is ON by default, and whatever
is configured is passed through to the active transport unchanged.
"""

from __future__ import annotations

from typing import Any

import httpx

from agent_alpha.agents.http_client import HttpClient


def test_verify_defaults_on() -> None:
    client = HttpClient(engagement_id="eng_test")
    assert client._verify is True


def test_verify_explicit_off_is_honoured() -> None:
    client = HttpClient(engagement_id="eng_test", verify=False)
    assert client._verify is False


def test_verify_passthrough_to_httpx(monkeypatch: Any) -> None:
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

    client = HttpClient(
        engagement_id="eng_test",
        rate_limit_rps=1000.0,
        verify=False,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text="ok")),
    )
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

    client = HttpClient(
        engagement_id="eng_test",
        rate_limit_rps=1000.0,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text="ok")),
    )
    client.get("https://lab.example-you-own.dev/")

    assert captured.get("verify") is True


_ = httpx
