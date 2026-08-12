"""Universal auth-surface recognizer - technology-agnostic, no per-target logic.

Proves ANY client's login/auth surface is recognized from universal HTTP signals
(password input / auth-challenge header) - never a framework catalog. Synthetic
hosts only; ZERO reference to any specific client.
"""

from __future__ import annotations

from agent_alpha.recon.auth_surface import detect_auth_surface_labels, scan_js_for_login_surface


def test_form_login_password_input_any_stack() -> None:
    body = '<html><form><input name="user"><input type="password" name="pw"></form></html>'
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_single_quoted_password_input() -> None:
    body = "<input type='password'>"
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_bare_401_no_challenge_is_unknown_auth() -> None:
    """GAP-030 (deliberate contract change): a bare 401 WITHOUT a WWW-Authenticate
    challenge is NO LONGER assumed http_basic_auth (that false positive would route a
    basic-auth strike at a token/api surface). Tradeoff: a real basic-auth host whose
    header was stripped by a proxy/CDN is now unknown_auth (false-negative) — accepted
    per the classify-precisely decision. Only an actual Basic challenge -> http_basic_auth."""
    assert detect_auth_surface_labels(status_code=401, headers={}, body="") == ["unknown_auth"]


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


def test_vue_bound_password_input_detected() -> None:
    """Vue.js dynamic binding :type="..." with name="password" must be detected."""
    body = "<input :type=\"showPassword ? 'text' : 'password'\" name=\"password\">"
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_autocomplete_current_password_detected() -> None:
    """WHATWG standard autocomplete attribute (SPA-proof)."""
    body = '<input autocomplete="current-password">'
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_autocomplete_new_password_detected() -> None:
    """New-password autocomplete (change password forms)."""
    body = '<input autocomplete="new-password">'
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_name_password_detected() -> None:
    """name="password" attribute (any framework)."""
    body = '<input name="password">'
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_id_password_detected() -> None:
    """id="password" attribute (any framework)."""
    body = '<input id="password">'
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_static_type_password_still_detected() -> None:
    """Regression: existing static type="password" detection still works."""
    body = '<input type="password">'
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == ["login-form"]


def test_no_password_no_label() -> None:
    """No password signal → no login-form label (no false positive)."""
    body = "<html><body>welcome, no login here</body></html>"
    assert detect_auth_surface_labels(status_code=200, headers={}, body=body) == []


def test_basic_auth_requires_basic_challenge() -> None:
    """Regression: http_basic_auth requires an actual WWW-Authenticate: Basic challenge."""
    hdr = {"WWW-Authenticate": 'Basic realm="x"'}
    assert detect_auth_surface_labels(status_code=401, headers=hdr, body="") == ["http_basic_auth"]


# ── GAP-030 expanded: WWW-Authenticate scheme discrimination ────────────────────


def test_401_multiple_challenges_bearer_then_basic() -> None:
    """Server advertises both Bearer and Basic in one header — BOTH labels emitted."""
    hdr = {"WWW-Authenticate": 'Bearer, Basic realm="restricted"'}
    labels = detect_auth_surface_labels(status_code=401, headers=hdr, body="")
    assert "token_auth" in labels
    assert "http_basic_auth" in labels


def test_401_comma_in_realm_not_split() -> None:
    """realm="x,y" — comma inside quoted string must NOT split schemes."""
    hdr = {"WWW-Authenticate": 'Basic realm="x,y"'}
    labels = detect_auth_surface_labels(status_code=401, headers=hdr, body="")
    assert labels == ["http_basic_auth"]


def test_401_bearer_is_token_auth_not_basic() -> None:
    hdr = {"WWW-Authenticate": "Bearer"}
    assert detect_auth_surface_labels(status_code=401, headers=hdr, body="") == ["token_auth"]


def test_401_digest_is_digest_auth_not_basic() -> None:
    hdr = {"WWW-Authenticate": 'Digest realm="x", nonce="y"'}
    assert detect_auth_surface_labels(status_code=401, headers=hdr, body="") == ["http_digest_auth"]


def test_401_json_no_header_is_api_auth() -> None:
    hdr = {"Content-Type": "application/json"}
    assert detect_auth_surface_labels(
        status_code=401, headers=hdr, body='{"error":"unauthorized"}'
    ) == ["api_auth"]


def test_401_json_body_without_content_type_is_api_auth() -> None:
    assert detect_auth_surface_labels(status_code=401, headers={}, body='{"detail":"nope"}') == [
        "api_auth"
    ]


def test_unknown_scheme_is_unknown_auth() -> None:
    hdr = {"WWW-Authenticate": "Negotiate"}
    assert detect_auth_surface_labels(status_code=401, headers=hdr, body="") == ["unknown_auth"]


def test_non_strikable_auth_types_excluded_from_router_candidates() -> None:
    """Contract #9: token_auth / api_auth / http_digest_auth / unknown_auth are NOT
    strike candidates (kept out of the router's strikable set)."""
    from agent_alpha.conductor.router import _AUTH_SURFACE_LABELS

    for non_strikable in ("token_auth", "api_auth", "http_digest_auth", "unknown_auth"):
        assert non_strikable not in _AUTH_SURFACE_LABELS
    # strikable ones remain
    assert {"http_basic_auth", "login-form"} <= _AUTH_SURFACE_LABELS


def test_401_login_page_still_strikable_via_login_form() -> None:
    """A 401 that serves an HTML login form is still strikable (login-form present),
    even though the 401-with-no-basic-challenge also yields unknown_auth."""
    body = '<form><input type="password" name="pw"></form>'
    labels = detect_auth_surface_labels(status_code=401, headers={}, body=body)
    assert "login-form" in labels


# ── GAP-030 Slice 1b: SPA login-surface scan of JS bundle bodies ────────────────


def test_js_scan_detects_type_password() -> None:
    assert scan_js_for_login_surface('h("input",{type:"password"})') is True


def test_js_scan_detects_autocomplete_password() -> None:
    assert scan_js_for_login_surface('{autocomplete:"current-password"}') is True
    assert scan_js_for_login_surface('{autocomplete:"new-password"}') is True


def test_js_scan_detects_name_or_id_password() -> None:
    assert scan_js_for_login_surface('createElement("input",{name:"password"})') is True
    assert scan_js_for_login_surface("el.id = 'password'") is True


def test_js_scan_detects_template_input_password() -> None:
    assert scan_js_for_login_surface('render(`<input type="password">`)') is True


def test_js_scan_detects_backtick_quoted_password() -> None:
    """Vite/esbuild minified bundles use backtick template-literal quotes."""
    assert scan_js_for_login_surface('jsx("input",{type:`password`})') is True
    assert scan_js_for_login_surface('{name:`password`}') is True
    assert scan_js_for_login_surface('{autocomplete:`current-password`}') is True


def test_js_scan_rejects_mixed_quote_delimiters() -> None:
    """Mismatched open/close delimiters (type:'password") must NOT trigger."""
    assert scan_js_for_login_surface("type:'password\"") is False
    assert scan_js_for_login_surface('type:"password`') is False
    assert scan_js_for_login_surface('name:`password\'') is False


def test_js_scan_bare_password_word_not_false_positive() -> None:
    """The bare word 'password' (e.g. a reset-email string) must NOT trigger."""
    assert scan_js_for_login_surface('const msg = "check your password reset email"') is False


def test_js_scan_empty_or_no_login() -> None:
    assert scan_js_for_login_surface("") is False
    assert scan_js_for_login_surface("export const sum=(a,b)=>a+b") is False
