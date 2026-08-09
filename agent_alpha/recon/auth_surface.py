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
    has_www_auth = any(k.lower() == "www-authenticate" for k in headers)
    if status_code == 401 or has_www_auth:
        labels.append("http_basic_auth")
    if body:
        # Check all three fallbacks; any match = login-form
        has_password_input = (
            _PASSWORD_INPUT.search(body) is not None
            or _AUTOCOMPLETE_PASSWORD.search(body) is not None
            or _NAME_ID_PASSWORD.search(body) is not None
        )
        if has_password_input:
            labels.append("login-form")
    # Dedup while preserving order (first occurrence wins)
    seen: set[str] = set()
    deduped: list[str] = []
    for label in labels:
        if label not in seen:
            seen.add(label)
            deduped.append(label)
    return deduped
