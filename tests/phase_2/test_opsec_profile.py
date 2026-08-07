"""RED tests for OPSEC profile resolution and HttpClient header application."""

from __future__ import annotations

from typing import Any

import pytest

from agent_alpha.agents.http_client import HttpClient, HttpResponse
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.config import constants


@pytest.fixture()
def policy() -> PolicyEnforcer:
    return PolicyEnforcer()


def test_default_profile_is_stealth_browser_identity(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("stealth", evasion_authorized=False)
    hc = HttpClient(engagement_id="e", opsec=p)
    assert hc._headers["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
    assert hc._headers["sec-ch-ua"] == constants.STEALTH_BROWSER["sec_ch_ua"]
    assert "Agent-Alpha" not in hc._headers["User-Agent"]


def test_explicit_announced_profile_still_identifies_itself(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("announced", evasion_authorized=False)
    hc = HttpClient(engagement_id="e", opsec=p)
    assert hc._headers["User-Agent"] == "Agent-Alpha-Recon"


def test_evasion_profile_requires_authorization(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("blend", evasion_authorized=False)
    assert p == policy.get_opsec_profile(constants.DEFAULT_OPSEC_PROFILE)


def test_authorized_evasion_keeps_ssot_browser_identity(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("blend", evasion_authorized=True)
    hc = HttpClient(engagement_id="e", opsec=p)
    assert hc._headers["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
    assert hc._headers["sec-ch-ua"] == constants.STEALTH_BROWSER["sec_ch_ua"]


def test_ua_applied_to_every_request(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("stealth", evasion_authorized=False)
    captured_headers: list[dict[str, str]] = []

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
        captured_headers.append(dict(headers))
        return HttpResponse(status_code=200, text="ok", headers={}, url=url)

    hc = HttpClient(engagement_id="e", opsec=p, fetcher=fetcher)

    hc.get("https://example.com/")
    hc.post("https://example.com/login", data={"log": "x", "pwd": "y"})

    assert len(captured_headers) == 2
    for hdrs in captured_headers:
        assert hdrs["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
        assert "agent-alpha" not in hdrs["User-Agent"].lower()


def test_no_opsec_uses_stealth_defaults() -> None:
    hc = HttpClient(engagement_id="eng-123")
    assert hc._headers["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
