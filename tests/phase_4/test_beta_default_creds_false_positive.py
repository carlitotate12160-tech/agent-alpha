from unittest.mock import Mock

from agent_alpha.tools.contracts import ResourceBudget, TargetContext
from agent_alpha.tools.internal.access.default_creds import (
    DefaultCredsTool,
    _has_positive_auth_signal,
)


def test_lang_cookie_on_400_is_not_auth():
    """400 + Set-Cookie: frontend_lang=en -> _has_positive_auth_signal False"""
    baseline = Mock(text='<input type="password">')
    auth_resp = Mock(
        status_code=400,
        headers={"set-cookie": "frontend_lang=en; Path=/"},
        text="bad request",
    )
    assert not _has_positive_auth_signal(auth_resp, baseline)


def test_400_with_session_cookie_still_rejected():
    """status gate beats a session cookie"""
    baseline = Mock(text='<input type="password">')
    auth_resp = Mock(
        status_code=400,
        headers={"set-cookie": "session_id=123; Path=/"},
        text="bad request",
    )
    assert not _has_positive_auth_signal(auth_resp, baseline)


def test_session_cookie_on_200_is_auth():
    """200 + session_id=... -> True"""
    baseline = Mock(text='<input type="password">')
    auth_resp = Mock(
        status_code=200,
        headers={"set-cookie": "session_id=123; Path=/"},
        text="welcome",
    )
    assert _has_positive_auth_signal(auth_resp, baseline)


def test_genuine_200_form_gone_success():
    """regression: a genuine 200 + form-gone success still succeeds"""
    baseline = Mock(text='<input type="password">')
    auth_resp = Mock(
        status_code=200,
        headers={},
        text="welcome admin",
    )
    assert _has_positive_auth_signal(auth_resp, baseline)


def test_default_creds_tool_quantum_false_positive():
    """Integration: ToolResult.success False -> NO cred/access node"""
    http_client = Mock()
    # Baseline
    http_client.get.return_value = Mock(status_code=200, text='<input type="password">', headers={})

    # Auth POST - returns 400 with frontend_lang
    auth_resp = Mock(
        status_code=400,
        headers={"set-cookie": "frontend_lang=en; Path=/"},
        text="admin login failed",  # Contains "admin" but shouldn't matter due to status gate
    )
    http_client.post.return_value = auth_resp

    tool = DefaultCredsTool(http_client=http_client)
    ctx = TargetContext(
        engagement_id="eng1",
        tenant_id=None,
        target="http://example.com/login",
        prior_findings=[],
        open_ports=[],
        tech_stack={"odoo": "odoo"},
    )
    budget = ResourceBudget(max_requests=10, max_seconds=10.0, max_cost_usd=0.0)

    result = tool.run(ctx, budget)

    assert not result.success
    assert "no default credential produced a positive auth signal" in result.error
