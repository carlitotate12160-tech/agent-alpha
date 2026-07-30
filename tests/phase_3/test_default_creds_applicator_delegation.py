# Field bug: solusibersama.co.id (2026-07-30) — Beta FAILED on a WP target
# that had 0 harvested credentials (cred_reuse correctly had nothing to
# reuse) AND a live wp-login.php surface (applicators count=4 in the run
# log, WpLoginApplicator@wp-login.php among them). DefaultCredsTool never
# consumed that roster: it POSTed {"username","password"} straight to
# ctx.target (the homepage), which has no login form at all. Even a naive
# "just fix the URL" patch would still fail — WordPress's login form fields
# are log/pwd, not username/password, and success is a 302→/wp-admin/
# redirect or a wordpress_logged_in_* cookie, never a body-diff.
#
# This file pins the INTEGRATION (DefaultCredsTool + the real applicator
# roster shape Beta builds via applicator_factory.beta_web_applicators() +
# _resolve_in_scope_targets) — WpLoginApplicator/HttpFormApplicator
# themselves already have their own unit tests (test_wp_login_applicator.py).
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_3/test_default_creds_applicator_delegation.py -v

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.conductor.applicator_factory import BoundApplicator
from agent_alpha.config import constants
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator, WpLoginApplicator
from agent_alpha.tools.internal.access.default_creds import DefaultCredsTool

HOST = "solusibersama.example"
HOMEPAGE = f"https://{HOST}/"
WP_LOGIN = f"https://{HOST}/wp-login.php"


@dataclass
class _R:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class _WpTarget:
    """Homepage has no login form. wp-login.php accepts admin/admin via the
    real WP field names (log/pwd) and signals success the real WP way (302
    -> /wp-admin/ + wordpress_logged_in_* cookie) — never a body-diff."""

    def __init__(self) -> None:
        self.posted: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _R:
        if url.rstrip("/") == HOMEPAGE.rstrip("/"):
            return _R(200, "<html>Welcome to Solusi Bersama</html>")
        return _R(200, "<html><input type='password' name='pwd'>login</html>")

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        d = dict(data or {})
        self.posted.append((url, d))
        if url != WP_LOGIN:
            # Homepage has no login endpoint — a real WP site just re-renders it.
            return _R(200, "<html>Welcome to Solusi Bersama</html>")
        if d.get("log") == "admin" and d.get("pwd") == "admin":
            return _R(
                302,
                "",
                {
                    "location": f"https://{HOST}/wp-admin/",
                    "set-cookie": "wordpress_logged_in_abc=xyz; Path=/; HttpOnly",
                },
            )
        return _R(200, "<html><input type='password' name='pwd'>login failed</html>")


def _budget() -> ResourceBudget:
    return ResourceBudget(max_requests=60, max_seconds=60.0, max_cost_usd=0.0)


def _real_roster(http: Any) -> list[BoundApplicator]:
    """Reconstructs the exact 4-entry shape Beta receives from
    applicator_factory in production for a WP host (2 applicators x
    2 targets, WP-specific before generic — beta_web_applicators() order)."""
    return [
        BoundApplicator(WpLoginApplicator(http_client=http), HOMEPAGE),
        BoundApplicator(WpLoginApplicator(http_client=http), WP_LOGIN),
        BoundApplicator(HttpFormApplicator(http_client=http), HOMEPAGE),
        BoundApplicator(HttpFormApplicator(http_client=http), WP_LOGIN),
    ]


def _ctx() -> TargetContext:
    return TargetContext(
        engagement_id="eng-1",
        tenant_id=None,
        target=HOMEPAGE,  # entry_point is the homepage, same as the field bug
        tech_stack={"cms": constants.STACK_WP},
    )


# ── The fix: WP field names + wp-login.php target now actually reached ────


def test_admin_admin_succeeds_via_wp_login_applicator_when_roster_injected() -> None:
    http = _WpTarget()
    tool = DefaultCredsTool(applicators=_real_roster(http), http_client=http)

    result = tool.run(_ctx(), _budget())

    assert isinstance(result, ToolResult)
    assert result.success is True, "admin/admin against wp-login.php must succeed via WpLoginApplicator"
    assert result.findings[0]["access_level"] == "admin"
    assert result.findings[0]["username"] == "admin"

    # The WP-correct fields (log/pwd) were sent to wp-login.php — never a
    # generic username/password POST to the homepage.
    wp_login_posts = [d for url, d in http.posted if url == WP_LOGIN]
    assert wp_login_posts, "wp-login.php was never POSTed to (still targeting ctx.target?)"
    assert wp_login_posts[0].get("log") == "admin"
    assert wp_login_posts[0].get("pwd") == "admin"
    assert "username" not in wp_login_posts[0], "generic field names must not be used against WP"


def test_homepage_alone_is_never_reported_as_a_login_success() -> None:
    """The homepage has no login form; POSTing default creds to it must never
    be mistaken for access — pins the ORIGINAL bug's exact failure shape."""
    http = _WpTarget()
    tool = DefaultCredsTool(applicators=_real_roster(http), http_client=http)

    result = tool.run(_ctx(), _budget())

    # The roster tries WpLoginApplicator@wp-login.php before ever reaching
    # HttpFormApplicator@homepage (roster order + per-credential short-circuit
    # on first success) — homepage is correctly never even attempted once WP
    # login succeeds. The only invariant this test pins: whatever the winning
    # attempt was, it was never the homepage.
    assert result.success is True
    assert result.findings[0]["proof_request"]["url"] != HOMEPAGE


# ── Regression: no injected roster keeps prior (imperfect) behaviour ──────


def test_no_applicators_injected_falls_back_to_ctx_target_generic_post() -> None:
    """Standalone construction (no roster injected) must keep the old
    behaviour byte-for-byte — this is what test_default_creds_tool.py pins;
    this test only confirms the WP case specifically stays a miss without
    the roster (proving the roster, not luck, is what fixes it)."""
    http = _WpTarget()
    tool = DefaultCredsTool(http_client=http)  # no applicators=

    result = tool.run(_ctx(), _budget())

    assert result.success is False, (
        "without an injected roster the tool only knows ctx.target (homepage) — "
        "it must NOT find the wp-login.php surface on its own"
    )
    assert all(url == HOMEPAGE for url, _d in http.posted), (
        "fallback path must only ever POST to ctx.target, never discover wp-login.php itself"
    )
