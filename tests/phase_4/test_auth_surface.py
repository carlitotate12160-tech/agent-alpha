"""Universal auth-surface recognizer - technology-agnostic, no per-target logic.

Proves ANY client's login/auth surface is recognized from universal HTTP signals
(password input / auth-challenge header) - never a framework catalog. Synthetic
hosts only; ZERO reference to any specific client.
"""

from __future__ import annotations

from agent_alpha.recon.auth_surface import detect_auth_surface_labels


def test_form_login_password_input_any_stack() -> None:
    body = '<html><form><input name="user"><input type="password" name="pw"></form></html>'
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_single_quoted_password_input() -> None:
    body = "<input type='password'>"
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_http_basic_auth_via_401() -> None:
    assert detect_auth_surface_labels(status_code=401, headers={}, body="") == ["http_basic_auth"]


def test_http_basic_auth_via_header_case_insensitive() -> None:
    hdr = {"WWW-Authenticate": 'Basic realm="x"'}
    assert detect_auth_surface_labels(status_code=200, headers=hdr, body="") == ["http_basic_auth"]


def test_both_signals() -> None:
    hdr = {"www-authenticate": "Basic"}
    body = "<input type=password>"
    assert detect_auth_surface_labels(status_code=401, headers=hdr, body=body) == [
        "http_basic_auth",
        "login-form",
    ]


def test_no_auth_surface() -> None:
    body = "<html><body>welcome, nothing to log into</body></html>"
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == []


def test_none_body_no_crash() -> None:
    assert detect_auth_surface_labels(status_code=200, headers={}, body=None) == []  # type: ignore[arg-type]


def test_password_word_boundary_not_false_positive() -> None:
    """type='passwordxyz' must NOT match (word boundary after 'password')."""
    body = "<input type='passwordxyz'>"
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == []


def test_labels_are_router_auth_surface_labels() -> None:
    # The labels MUST be ones the router's has_web_auth_surface() recognizes.
    from agent_alpha.conductor.router import _AUTH_SURFACE_LABELS

    assert {"login-form", "http_basic_auth"} <= _AUTH_SURFACE_LABELS
