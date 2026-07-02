"""RED tests for OPSEC profile — per-engagement UA/headers with evasion gate.

The evasion profile ('blend') must NOT be selectable without SOW authorization.
Default ('announced') = honest identifying UA. Fail-closed.
"""

from __future__ import annotations

import httpx
import pytest

from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.policy import PolicyEnforcer


@pytest.fixture()
def policy() -> PolicyEnforcer:
    return PolicyEnforcer()


# ── T1: default profile is honest UA ──────────────────────────────────────────


def test_default_profile_is_honest_ua(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("announced", evasion_authorized=False)
    hc = HttpClient(engagement_id="e", opsec=p)
    assert "Agent-Alpha" in hc._headers["User-Agent"]


# ── T2: evasion profile requires authorization (the gate) ────────────────────


def test_evasion_profile_requires_authorization(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("blend", evasion_authorized=False)
    assert p.get("evasion") is False  # fell back to announced — NO spoofing unauthorized


# ── T3: authorized evasion applies profile UA and headers ────────────────────


def test_authorized_evasion_applies_profile_ua_and_headers(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("blend", evasion_authorized=True)
    hc = HttpClient(engagement_id="e", opsec=p)
    assert hc._headers["User-Agent"] == p["user_agent"]  # not the giveaway UA
    assert set(p.get("headers", {})).issubset(hc._headers)  # browser headers applied


# ── T4: UA applied to every request (single chokepoint, #7) ───────────────────


class _FakeTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.captured_headers: list[dict[str, str]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.captured_headers.append(dict(request.headers))
        return httpx.Response(200, text="ok", headers={}, request=request)


def test_ua_applied_to_every_request(policy: PolicyEnforcer) -> None:
    p = policy.resolve_opsec_profile("blend", evasion_authorized=True)
    transport = _FakeTransport()
    hc = HttpClient(engagement_id="e", opsec=p, transport=transport)

    hc.get("https://example.com/")
    hc.post("https://example.com/login", data={"log": "x", "pwd": "y"})

    assert len(transport.captured_headers) == 2
    for hdrs in transport.captured_headers:
        # httpx lowercases header keys
        assert hdrs["user-agent"] == p["user_agent"]
        assert "agent-alpha" not in hdrs["user-agent"].lower()


# ── T5: no opsec = backward compatible (honest UA with engagement_id) ────────


def test_no_opsec_backward_compatible() -> None:
    hc = HttpClient(engagement_id="eng-123")
    assert hc._headers["User-Agent"] == "Agent-Alpha-Recon/eng-123"
