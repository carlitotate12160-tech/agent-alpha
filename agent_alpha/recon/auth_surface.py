# agent_alpha/recon/auth_surface.py
"""Universal auth-surface recognition - technology-agnostic.

A reachable login / authentication surface is a first-class objective for the
access phase (Beta), independent of any framework-specific vuln probe. This
recognizer keys ONLY on universal HTTP signals (auth-challenge header, a
password input) - NEVER a per-target or per-framework catalog (anti-Lyndon #11:
no hardcoded per-client behaviour). Labels are drawn from the same semantic set
the router's has_web_auth_surface() consumes.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

# Fallback 1: static type="password" (existing)
_PASSWORD_INPUT = re.compile(r"<input[^>]*type\s*=\s*['\"]?password\b['\"]?", re.IGNORECASE)

# Fallback 2: autocomplete attribute (WHATWG standard — strongest, SPA-proof)
_AUTOCOMPLETE_PASSWORD = re.compile(
    r'autocomplete\s*=\s*["\'](?:current-password|new-password)["\']', re.IGNORECASE
)

# Fallback 3: name="password" or id="password" within <input ...> tag (any framework)
_NAME_ID_PASSWORD = re.compile(r'<input[^>]*(?:name|id)\s*=\s*["\']?password["\']?', re.IGNORECASE)


# ── Auth-type label vocabulary (SINGLE source, anti-#7) ─────────────────────────
# Beta can bind a credential applicator to STRIKABLE labels NOW. The others are
# classified-but-not-attacked (GAP-030): token/digest/api need Gamma-tier tools
# (JWT confusion, API abuse) or no applicator exists — labelling them precisely
# stops false ``http_basic_auth`` from routing a strike at a non-basic surface.
HTTP_BASIC_AUTH = "http_basic_auth"
HTTP_DIGEST_AUTH = "http_digest_auth"
TOKEN_AUTH = "token_auth"
API_AUTH = "api_auth"
UNKNOWN_AUTH = "unknown_auth"
LOGIN_FORM = "login-form"

# WWW-Authenticate scheme (RFC 7235 token, case-insensitive) -> auth-type label.
_WWW_AUTH_SCHEME: dict[str, str] = {
    "basic": HTTP_BASIC_AUTH,
    "digest": HTTP_DIGEST_AUTH,
    "bearer": TOKEN_AUTH,
}

# The subset Beta may actually strike this phase (auth-type only; the router adds
# tech-stack fingerprints like wp/odoo that also imply a strikable login surface).
STRIKABLE_AUTH_LABELS: frozenset[str] = frozenset({HTTP_BASIC_AUTH, LOGIN_FORM})


def _body_is_json(headers: Mapping[str, str], body: str) -> bool:
    for k, v in headers.items():
        if k.lower() == "content-type" and "json" in v.lower():
            return True
    stripped = (body or "").lstrip()
    return stripped[:1] in ("{", "[")


def _parse_www_authenticate_schemes(headers: Mapping[str, str]) -> list[str]:
    """Extract all WWW-Authenticate scheme tokens from response headers.

    Handles comma-joined single-header form (legacy). Comma inside quoted strings
    (realm="x,y") is NOT split. Mapping[str, str] already flattens separate headers.
    """
    raw_values = [v for k, v in headers.items() if k.lower() == "www-authenticate"]
    schemes: list[str] = []
    for raw in raw_values:
        parts: list[str] = []
        current = ""
        in_quote = False
        for ch in raw:
            if ch in ('"', "'"):
                in_quote = not in_quote
            if ch == "," and not in_quote:
                parts.append(current.strip())
                current = ""
            else:
                current += ch
        if current.strip():
            parts.append(current.strip())
        for part in parts:
            scheme = part.split(None, 1)[0].lower() if part else ""
            # Skip parts that are parameters of the previous challenge (e.g.
            # nonce="y" after Digest realm="x",). A valid scheme token is a
            # bare word that is NOT a key=value pair.
            if scheme and "=" not in part.split(None, 1)[0]:
                schemes.append(scheme)
    return schemes


def detect_auth_surface_labels(
    *, status_code: int, headers: Mapping[str, str], body: str
) -> list[str]:
    """Return auth-surface labels for a fetched response (order-stable, deduped).

    * HTTP auth challenge (401 or WWW-Authenticate header) -> "http_basic_auth"
    * a password input anywhere in the body                -> "login-form"

    Password input detection (universal, framework-agnostic):
      1. <input type="password"> (static)
      2. autocomplete="current-password" | "new-password" (WHATWG standard)
      3. <input name="password"> | <input id="password"> (any framework)

    Empty list = no auth surface observed. Pure + deterministic; no I/O; works
    for ANY stack (Laravel, WP, custom, Tomcat, Vue, React) because it keys on
    universal HTML attributes, not framework-specific patterns.
    """
    labels: list[str] = []
    # ── Auth-challenge classification (GAP-030): discriminate by WWW-Authenticate
    #    scheme. A bare 401 without a Basic challenge is NOT assumed basic-auth —
    #    that false positive would route a basic-auth strike at a token/api surface.
    #    Multiple WWW-Authenticate challenges (RFC 7235) are ALL parsed — a server
    #    may advertise "Bearer, Basic" and both labels are emitted.
    www_auth_schemes = _parse_www_authenticate_schemes(headers)
    if www_auth_schemes:
        for scheme in www_auth_schemes:
            labels.append(_WWW_AUTH_SCHEME.get(scheme, UNKNOWN_AUTH))
    elif status_code == 401:
        # 401 with no challenge header: JSON body => api_auth, else unknown_auth.
        labels.append(API_AUTH if _body_is_json(headers, body) else UNKNOWN_AUTH)
    if body:
        # Check all three fallbacks; any match = login-form
        has_password_input = (
            _PASSWORD_INPUT.search(body) is not None
            or _AUTOCOMPLETE_PASSWORD.search(body) is not None
            or _NAME_ID_PASSWORD.search(body) is not None
        )
        if has_password_input:
            labels.append(LOGIN_FORM)
    # Dedup while preserving order (first occurrence wins)
    seen: set[str] = set()
    deduped: list[str] = []
    for label in labels:
        if label not in seen:
            seen.add(label)
            deduped.append(label)
    return deduped
