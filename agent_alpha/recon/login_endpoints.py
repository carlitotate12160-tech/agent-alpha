"""Slice-B read-model: resolve login API endpoints from harvested recon intel.

Pure projection over the event store (Claude lane — like GAP-034 unreachable_hosts;
NO I/O, NO offensive body). ``verify_js_secret_leak`` harvests API paths from JS
bundles as ``NODE_DISCOVERED{type:"api_endpoint", host, endpoint}`` events. This
read-model filters those to LOGIN-candidate endpoints so the factory can bind a
SpaLoginApplicator to a concrete URL (host-level ``spa-login-form`` does not say WHICH
path authenticates — the label->path binding gap).

HTTPS-ONLY (CodeRabbit #2): every returned URL is https. An http:// harvested endpoint
is upgraded to https — credentials/tokens must NEVER traverse cleartext; a cleartext-only
origin then fails the https strike (fail-closed) instead of leaking creds.

Deterministic (anti-GAP-036: RULE, never LLM). Fail-closed: no login endpoint -> ().
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from agent_alpha.events.event_types import EventType

_LOGIN_PATH = re.compile(
    r"/(?:auth/|api/(?:[^/]+/)*)?(?:login|log-in|signin|sign-in|"
    r"session|sessions|authenticate|token)/?$",
    re.IGNORECASE,
)


def _https_url(host: str, endpoint: str) -> str | None:
    """Return an https URL for *endpoint* on *host*, or None if cross-host."""
    parsed = urlparse(endpoint)
    if parsed.scheme:
        if parsed.hostname != host:
            return None  # never cross-scope
        return parsed._replace(scheme="https").geturl()  # upgrade http -> https
    path = endpoint if endpoint.startswith("/") else "/" + endpoint
    return f"https://{host}{path}"


def login_endpoint_candidates(events: Iterable[Any], host: str) -> tuple[str, ...]:
    """Login API endpoint https-URLs for *host*, best-first (most specific), deduped."""
    scored: list[tuple[int, str]] = []
    seen: set[str] = set()
    for event in events:
        if getattr(event, "event_type", None) != EventType.NODE_DISCOVERED:
            continue
        payload = getattr(event, "payload", None) or {}
        if payload.get("type") != "api_endpoint" or payload.get("host") != host:
            continue
        endpoint = str(payload.get("endpoint") or "")
        if not endpoint:
            continue
        parsed = urlparse(endpoint)
        path = parsed.path if parsed.scheme else endpoint
        if not _LOGIN_PATH.search(path):
            continue
        url = _https_url(host, endpoint)
        if url is None or url in seen:
            continue
        seen.add(url)
        scored.append((-path.count("/"), url))
    scored.sort()
    return tuple(url for _, url in scored)


def first_non_login_api_endpoint(events: Iterable[Any], host: str) -> str | None:
    """First non-login https api_endpoint URL for *host* (SpaLogin cross-verify oracle)."""
    for event in events:
        if getattr(event, "event_type", None) != EventType.NODE_DISCOVERED:
            continue
        payload = getattr(event, "payload", None) or {}
        if payload.get("type") != "api_endpoint" or payload.get("host") != host:
            continue
        endpoint = str(payload.get("endpoint") or "")
        if not endpoint:
            continue
        parsed = urlparse(endpoint)
        path = parsed.path if parsed.scheme else endpoint
        if not path.startswith("/"):
            path = "/" + path
        if _LOGIN_PATH.search(path):
            continue
        url = _https_url(host, endpoint)
        if url is not None:
            return url
    return None
