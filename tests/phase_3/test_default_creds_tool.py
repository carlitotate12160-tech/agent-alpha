"""Contract: DefaultCredsTool — conformance, applies_to, and run smoke tests.

Phase 3. Tests tool protocol conformance, relevance scoring, and basic
run() behavior with test doubles. The offensive body author is GLM 5.2 High.

What is pinned here:
  A. Conforms to Tool protocol (name, phase, required_auth).
  B. applies_to() raises relevance for auth surfaces, lowers for existing creds.
  C. run() returns ToolResult on success (no longer NotImplementedError).
  D. run() returns ToolResult(success=False) when all defaults rejected.
  E. run() returns ToolResult(success=False) on identical responses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult
from agent_alpha.tools.internal.access.default_creds import DefaultCredsTool

ENTRY = "http://lab-target.invalid/login"


# ── Test doubles ────────────────────────────────────────────────


@dataclass
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ENTRY


class _AuthAwareHttpClient:
    """Routes by presence of auth context (headers/cookies/data)."""

    def __init__(self, *, unauth: _Resp, authed: _Resp) -> None:
        self._unauth = unauth
        self._authed = authed

    def _route(self, headers: Any, cookies: Any, data: Any) -> _Resp:
        return self._authed if (bool(headers) or bool(cookies) or bool(data)) else self._unauth

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _Resp:
        return self._route(headers, cookies, None)

    def post(
        self, url: str, *, data: Any = None, json_body: Any = None,
        headers: Any = None, cookies: Any = None,
    ) -> _Resp:
        return self._route(headers, cookies, data or json_body)


def _ctx(**overrides: Any) -> TargetContext:
    defaults: dict[str, Any] = {
        "engagement_id": "eng-1",
        "tenant_id": None,
        "target": ENTRY,
    }
    defaults.update(overrides)
    return TargetContext(**defaults)


def _budget() -> ResourceBudget:
    return ResourceBudget(max_requests=30, max_seconds=120.0, max_cost_usd=0.0)


# ── A. Protocol conformance ──────────────────────────────────────


def test_conforms_to_tool_protocol() -> None:
    tool = DefaultCredsTool()
    assert tool.name == "default_creds"
    assert tool.phase == "access"
    assert tool.required_auth == "ACTIVE_APPROVED"


# ── B. applies_to relevance scoring ─────────────────────────────


def test_applies_to_auth_surface() -> None:
    tool = DefaultCredsTool()
    ctx = _ctx(open_ports=(22, 80), tech_stack={"cms": "WordPress 6.5"})
    assert tool.applies_to(ctx) >= 0.7


def test_applies_to_existing_cred_lowers_score() -> None:
    tool = DefaultCredsTool()
    ctx = _ctx(prior_findings=("Credential leaked in debug page",))
    assert tool.applies_to(ctx) == 0.1


def test_applies_to_baseline() -> None:
    tool = DefaultCredsTool()
    ctx = _ctx()
    assert 0.0 <= tool.applies_to(ctx) <= 0.5  # no ports, no tech hints


# ── C. run() returns ToolResult on success ───────────────────────


def test_run_success_returns_finding_with_content() -> None:
    http = _AuthAwareHttpClient(
        unauth=_Resp(401, "<html>login required</html>"),
        authed=_Resp(200, "<html>admin dashboard — welcome administrator</html>",
                     headers={"set-cookie": "session=abc"}),
    )
    tool = DefaultCredsTool(http_client=http)
    result = tool.run(_ctx(), _budget())

    assert isinstance(result, ToolResult)
    assert result.success is True
    assert result.confidence > 0.0
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert "username" in finding
    assert "password" in finding
    assert finding["access_level"] == "admin"
    assert "proof_request" in finding
    assert "proof_response" in finding
    assert finding["session_cookie"] is not None


# ── D. run() returns failure when all defaults rejected ──────────


def test_run_no_access_returns_failure() -> None:
    http = _AuthAwareHttpClient(
        unauth=_Resp(401, "<html>login required</html>"),
        authed=_Resp(403, "<html>forbidden</html>"),
    )
    tool = DefaultCredsTool(http_client=http)
    result = tool.run(_ctx(), _budget())

    assert isinstance(result, ToolResult)
    assert result.success is False
    assert result.findings == ()


# ── E. run() rejects identical responses ─────────────────────────


def test_run_identical_response_is_not_access() -> None:
    same = "<html>same page either way</html>"
    http = _AuthAwareHttpClient(
        unauth=_Resp(200, same),
        authed=_Resp(200, same),
    )
    tool = DefaultCredsTool(http_client=http)
    result = tool.run(_ctx(), _budget())

    assert result.success is False
