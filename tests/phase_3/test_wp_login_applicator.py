"""RED tests for WpLoginApplicator — WordPress-aware login reuse.

Success = 302→/wp-admin/ redirect OR wordpress_logged_in_* cookie.
NOT body-diff (#3). Secret NEVER in AuthResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.applicator import WpLoginApplicator

B = ResourceBudget(max_requests=5, max_seconds=10, max_cost_usd=0.0)
TARGET = "https://h/wp-login.php"


@dataclass
class _R:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""


class Fake:
    """Returns 302→/wp-admin/ + wordpress_logged_in cookie for correct (log, pwd)."""

    def __init__(self, *, right_pwd: str = "RIGHT") -> None:
        self._right = right_pwd

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _R:
        return _R(200, "<html>login form</html>", {}, url)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        d = data or {}
        if d.get("log") and d.get("pwd") == self._right:
            return _R(
                302,
                "",
                {
                    "location": "https://h/wp-admin/",
                    "set-cookie": "wordpress_logged_in_abc123=xyz; Path=/; HttpOnly",
                },
                url,
            )
        return _R(200, "<html>login form — try again</html>", {}, url)


class FakeRecordingFields:
    """Records POST data keys to assert WP field names (log/pwd, not username/password)."""

    posted_data: dict[str, Any] = field(default_factory=dict)

    def __init__(self) -> None:
        self.posted_data = {}

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _R:
        return _R(200, "<html>login form</html>", {}, url)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        self.posted_data = dict(data or {})
        return _R(302, "", {"location": "https://h/wp-admin/"}, url)


class Fake200NoRedirect:
    """Always returns 200 form re-render — no redirect, no cookie (anti-#3)."""

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _R:
        return _R(200, "<html>login form</html>", {}, url)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        return _R(200, "<html>login form — try again</html>", {}, url)


class FakeCountingPosts:
    """Counts POST calls — for empty-username guard test."""

    def __init__(self) -> None:
        self.post_calls = 0

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _R:
        return _R(200, "<html>login form</html>", {}, url)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        self.post_calls += 1
        return _R(302, "", {"location": "https://h/wp-admin/"}, url)


# ── T1: applies_to — wp-login target only ────────────────────────────────────


def test_applies_to_wp_login_only() -> None:
    a = WpLoginApplicator(http_client=Fake())
    assert a.applies_to("database", "https://h/wp-login.php") is True
    assert a.applies_to("database", "https://h/") is False


# ── T2: POSTs WP field names (log/pwd), NOT generic (username/password) ──────


def test_posts_wp_field_names_not_generic() -> None:
    fake = FakeRecordingFields()
    WpLoginApplicator(http_client=fake).apply(
        username="wpvuln", secret="pw", target=TARGET, budget=B
    )
    assert {"log", "pwd", "wp-submit"} <= set(fake.posted_data.keys())
    assert "username" not in fake.posted_data
    assert "password" not in fake.posted_data


# ── T3: success on wp-admin redirect ─────────────────────────────────────────


def test_success_on_wp_admin_redirect() -> None:
    res = WpLoginApplicator(http_client=Fake(right_pwd="RIGHT")).apply(
        username="wpvuln", secret="RIGHT", target=TARGET, budget=B
    )
    assert res.success is True
    assert res.access_level == "admin"


# ── T4: wrong password is failure ────────────────────────────────────────────


def test_wrong_password_is_failure() -> None:
    res = WpLoginApplicator(http_client=Fake(right_pwd="RIGHT")).apply(
        username="wpvuln", secret="WRONG", target=TARGET, budget=B
    )
    assert res.success is False


# ── T5: 200 form re-render is NOT success (anti-#3) ───────────────────────────


def test_200_form_rerender_is_not_success() -> None:
    res = WpLoginApplicator(http_client=Fake200NoRedirect()).apply(
        username="x", secret="y", target=TARGET, budget=B
    )
    assert res.success is False


# ── T6: empty username never posts ───────────────────────────────────────────


def test_empty_username_never_posts() -> None:
    fake = FakeCountingPosts()
    res = WpLoginApplicator(http_client=fake).apply(
        username="", secret="pw", target=TARGET, budget=B
    )
    assert res.success is False
    assert fake.post_calls == 0


# ── T7: secret never in result ───────────────────────────────────────────────


def test_secret_never_in_result() -> None:
    res = WpLoginApplicator(http_client=Fake(right_pwd="S3cr3tPW")).apply(
        username="wpvuln", secret="S3cr3tPW", target=TARGET, budget=B
    )
    assert "S3cr3tPW" not in str(res)
