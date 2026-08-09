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

_PASSWORD_INPUT = re.compile(r"<input[^>]*type\s*=\s*['\"]?password\b['\"]?", re.IGNORECASE)


def detect_auth_surface_labels(
    *, status_code: int, headers: Mapping[str, str], body: str
) -> list[str]:
    """Return auth-surface labels for a fetched response (order-stable, deduped).

    * HTTP auth challenge (401 or WWW-Authenticate header) -> "http_basic_auth"
    * a password input anywhere in the body                -> "login-form"

    Empty list = no auth surface observed. Pure + deterministic; no I/O; works
    for ANY stack (Laravel, WP, custom, Tomcat) because it keys on the surface,
    not the framework.
    """
    labels: list[str] = []
    has_www_auth = any(k.lower() == "www-authenticate" for k in headers)
    if status_code == 401 or has_www_auth:
        labels.append("http_basic_auth")
    if body and _PASSWORD_INPUT.search(body):
        labels.append("login-form")
    return labels
