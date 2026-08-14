"""Slice-B: SpaLoginApplicator — cross-verified JSON-API login reuse (hardened)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.tools.contracts import ResourceBudget

_BUDGET = ResourceBudget(max_requests=20, max_seconds=30.0, max_cost_usd=0.0)
from agent_alpha.tools.internal.access.spa_login_applicator import SpaLoginApplicator

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-DEF_123"
_LOGIN = "https://app.example.com/api/auth/login"
_PROT = "https://app.example.com/api/me"


@dataclass
class _Resp:
    status_code: int
    text: str = ""
    _json: dict[str, Any] | None = None

    def json(self) -> dict[str, Any]:
        if self._json is None:
            raise ValueError("no json")
        return self._json


@dataclass
class _Http:
    """Fake: GET returns scripted per-URL(+auth); POST returns a scripted login resp."""

    login_resp: _Resp
    baseline: _Resp = field(default_factory=lambda: _Resp(200, "PUBLIC"))
    authed: _Resp = field(default_factory=lambda: _Resp(200, "welcome user profile"))
    posts: list[dict[str, Any]] = field(default_factory=list)

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> _Resp:
        return self.authed if headers and "Authorization" in headers else self.baseline

    def post(
        self, url: str, *, json: dict[str, Any] | None = None, data: dict[str, Any] | None = None
    ) -> _Resp:
        self.posts.append(json or data or {})
        return self.login_resp


def _apply(http: _Http, username: str = "u@x.com", secret: str = "pw") -> Any:
    app = SpaLoginApplicator(http_client=http, login_url=_LOGIN, protected_url=_PROT)
    return app.apply(username=username, secret=secret, target=_LOGIN, budget=_BUDGET)


def test_t1_cross_verified_success() -> None:
    http = _Http(login_resp=_Resp(200, _json={"access_token": _JWT}))
    r = _apply(http)
    assert r.success is True and r.access_level in ("user", "admin")


def test_t2_token_but_replay_401_is_failure() -> None:
    """ANTI-#3 CARDINAL: valid JWT but protected replay 401 -> success=False."""
    http = _Http(login_resp=_Resp(200, _json={"access_token": _JWT}), authed=_Resp(401, "nope"))
    assert _apply(http).success is False


def test_t2b_replay_non_2xx_is_failure() -> None:
    """CodeRabbit #4: 404/302/500 on replay is NOT access even though != 401/403."""
    for st in (404, 302, 500):
        http = _Http(login_resp=_Resp(200, _json={"access_token": _JWT}), authed=_Resp(st, "x"))
        assert _apply(http).success is False


def test_t3_no_token_is_failure() -> None:
    http = _Http(login_resp=_Resp(200, _json={"message": "unauthorized"}))
    assert _apply(http).success is False


def test_authed_body_equals_baseline_is_failure() -> None:
    http = _Http(
        login_resp=_Resp(200, _json={"access_token": _JWT}),
        baseline=_Resp(200, "same"),
        authed=_Resp(200, "same"),
    )
    assert _apply(http).success is False


def test_t3b_single_login_post_no_lockout_doubling() -> None:
    """CodeRabbit #3: exactly ONE login POST per apply (not two body shapes)."""
    http = _Http(login_resp=_Resp(200, _json={"access_token": _JWT}))
    _apply(http, username="alice", secret="pw")  # no '@' -> username shape
    assert len(http.posts) == 1
    assert "username" in http.posts[0] and "email" not in http.posts[0]


def test_email_username_uses_email_shape() -> None:
    http = _Http(login_resp=_Resp(200, _json={"access_token": _JWT}))
    _apply(http, username="a@b.com", secret="pw")
    assert "email" in http.posts[0]


def test_t5_no_raw_secret_or_token_in_result() -> None:
    http = _Http(
        login_resp=_Resp(200, _json={"access_token": _JWT}), authed=_Resp(200, f"welcome {_JWT}")
    )  # body reflects token
    r = _apply(http, secret="SUPER_SECRET_PW")
    blob = repr(r.proof_request) + repr(r.proof_response)
    assert _JWT not in blob  # redacted excerpt + no token field
    assert "SUPER_SECRET_PW" not in blob


def test_t6_required_auth_active_approved() -> None:
    assert (
        SpaLoginApplicator(http_client=_Http(login_resp=_Resp(200)), login_url=_LOGIN).required_auth
        == "ACTIVE_APPROVED"
    )


def test_https_only_refuses_http_login_url() -> None:
    """CodeRabbit #2: an http login_url must never receive credentials."""
    app = SpaLoginApplicator(
        http_client=_Http(login_resp=_Resp(200, _json={"access_token": _JWT})),
        login_url="http://app.example.com/api/auth/login",
    )
    r = app.apply(username="u", secret="pw", target="x", budget=_BUDGET)
    assert r.success is False and "https" in r.error


def test_t7_spa_login_form_is_strikable() -> None:
    from agent_alpha.recon.auth_surface import SPA_LOGIN_FORM, STRIKABLE_AUTH_LABELS

    assert SPA_LOGIN_FORM in STRIKABLE_AUTH_LABELS
