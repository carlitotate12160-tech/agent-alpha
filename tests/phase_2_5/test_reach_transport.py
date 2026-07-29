# tests/phase_2_5/test_reach_transport.py
"""Contract: tls_impersonate_fetch — curl_cffi TLS-impersonation transport.

Proves:
  1. verify=True is passed to curl_cffi (never downgrade — front-door fetch
     through CF whose cert is valid for the domain).
  2. Returns OriginDirectResult with challenge_solved=False (front-door, no
     challenge interaction — setting True would be Lyndon #3).
  3. curl_cffi error → RuntimeError (fail-loud, anti-#3 — never synthetic 200).
  4. is_tls_impersonate_available() returns bool based on importability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_alpha.config import constants
from agent_alpha.recon.reach_transport import (
    OriginDirectResult,
    is_tls_impersonate_available,
    tls_impersonate_fetch,
)


# ---------------------------------------------------------------------------
# Stub for curl_cffi response
# ---------------------------------------------------------------------------


@dataclass
class _FakeCffiResponse:
    status_code: int = 200
    text: str = "<html>clean body</html>"
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {"content-type": "text/html"}


# ---------------------------------------------------------------------------
# T1: verify=True passed, timeout=REACH_TIMEOUT_S, result shape correct
# ---------------------------------------------------------------------------


class TestTlsImpersonateFetchVerify:
    def test_calls_with_verify_true_and_returns_origin_direct_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """curl_cffi.requests.get MUST be called with verify=True and
        timeout=constants.REACH_TIMEOUT_S (anti-#7: single source).
        Result reuses OriginDirectResult with challenge_solved=False."""
        captured: dict[str, Any] = {}

        def _fake_get(url: str, **kwargs: Any) -> _FakeCffiResponse:
            captured["url"] = url
            captured["kwargs"] = kwargs
            return _FakeCffiResponse()

        # Monkeypatch the cffi_requests alias used inside reach_transport
        from agent_alpha.recon import reach_transport

        monkeypatch.setattr(reach_transport, "cffi_requests", MagicMock(get=_fake_get))
        monkeypatch.setattr(reach_transport, "_CURL_CFFI_AVAILABLE", True)

        result = tls_impersonate_fetch("https://target.example.com/path")

        # verify=True — the invariant that prevents MITM downgrade
        assert captured["kwargs"]["verify"] is True
        # timeout from constants — anti-#7 single source
        assert captured["kwargs"]["timeout"] == constants.REACH_TIMEOUT_S
        # impersonate default
        assert captured["kwargs"]["impersonate"] == "chrome"

        # Result shape
        assert isinstance(result, OriginDirectResult)
        assert result.status_code == 200
        assert result.body == "<html>clean body</html>"
        assert result.challenge_encountered is False
        assert result.challenge_solved is False


# ---------------------------------------------------------------------------
# T2: curl_cffi error → RuntimeError (fail-loud, anti-#3)
# ---------------------------------------------------------------------------


class TestTlsImpersonateFetchError:
    def test_curl_cffi_error_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Any curl_cffi error must surface as RuntimeError — never a synthetic 200."""

        def _boom(url: str, **kwargs: Any) -> None:
            raise Exception("TLS handshake failed")

        from agent_alpha.recon import reach_transport

        monkeypatch.setattr(reach_transport, "cffi_requests", MagicMock(get=_boom))
        monkeypatch.setattr(reach_transport, "_CURL_CFFI_AVAILABLE", True)

        with pytest.raises(RuntimeError, match="tls_impersonate_fetch failed"):
            tls_impersonate_fetch("https://target.example.com")


# ---------------------------------------------------------------------------
# T3: is_tls_impersonate_available
# ---------------------------------------------------------------------------


class TestIsTlsImpersonateAvailable:
    def test_returns_bool(self) -> None:
        """is_tls_impersonate_available() returns a bool (True iff curl_cffi importable)."""
        result = is_tls_impersonate_available()
        assert isinstance(result, bool)
