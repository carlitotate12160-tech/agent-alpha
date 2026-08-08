# agent_alpha/agents/origin_aware_client.py
"""OriginAwareHttpClient - §12.46 Slice 2 (Beta reach parity).

Wraps a (stealth-configured) HttpClient so agent HTTP transparently goes
origin-direct when the fronted host has a proven-bound origin, gated by the
§12.46 composed authorization gate. REUSES HttpClient GET/POST machinery +
assert_origin_authorized_or_bound + proven_origins. Does NOT re-bind, NOT
duplicate POST transport, does NOT touch origin_direct_fetch (sealed recon GET).

Operator posture:
  * Offensive request to a proven-bound host MUST pass the composed gate first
    (reuse Slice-1 per-host ORIGIN_BINDING_PROVEN).
  * Fronted host with NO binding => REFUSED (fail-closed), never a naked hit on
    the CDN edge (that burns the technique at the WAF).
  * verify=False on the direct leg is intentional (cert matches domain not IP
    literal, ADR §12.33) - scoping, not a downgrade.

Carries NO opsec of its own: the CALLER must hand it a stealth-configured client.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

from agent_alpha.agents.http_client import HttpResponse
from agent_alpha.conductor.engagement_profile import (
    assert_origin_authorized_or_bound,
    proven_origins,
)


class OriginUnreachableError(RuntimeError):
    """Offensive request to a host with no authorized/proven-bound origin while
    the engagement expects CDN-fronted origins (allow_origin_discovery).
    Fail-closed: refuse the naked CDN-edge hit rather than burn the technique."""


class OriginAwareHttpClient:
    """HttpClientProtocol-compatible wrapper adding gated origin-direct reach.

    The wrapped ``inner`` provides the real transport (and its opsec posture);
    this class only decides WHERE a request goes and enforces the §12.46 gate
    before rewriting to an origin IP.
    """

    def __init__(
        self,
        inner: Any,
        *,
        profile: Any | None,
        event_store: Any,
        engagement_id: str,
    ) -> None:
        self._inner = inner
        self._profile = profile
        self._event_store = event_store
        self._engagement_id = engagement_id

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
        verify: bool | None = None,
    ) -> HttpResponse:
        target_url, host, is_direct = self._route(url)
        resp = self._inner.get(
            target_url,
            headers=self._merge_host(headers, host) if is_direct else headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=False if is_direct else verify,
        )
        return cast(HttpResponse, resp)

    def post(
        self,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
        verify: bool | None = None,
    ) -> HttpResponse:
        target_url, host, is_direct = self._route(url)
        resp = self._inner.post(
            target_url,
            data=data,
            json_body=json_body,
            headers=self._merge_host(headers, host) if is_direct else headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=False if is_direct else verify,
        )
        return cast(HttpResponse, resp)

    def _route(self, url: str) -> tuple[str, str, bool]:
        """Return (target_url, fronted_host, is_origin_direct)."""
        parts = urlsplit(url)
        host = parts.hostname or ""
        if self._profile is None or not host:
            return url, host, False

        bound = proven_origins(self._event_store, self._engagement_id, host)
        signed = set(getattr(self._profile, "authorized_origins", frozenset()) or ())
        candidates = bound | signed

        if not candidates:
            if getattr(self._profile, "allow_origin_discovery", False):
                raise OriginUnreachableError(
                    f"no proven/authorized origin for {host!r} - refusing naked reach "
                    f"(fail-closed; would hit the CDN edge and burn the technique)"
                )
            return url, host, False

        origin_ip = sorted(candidates)[0]
        assert_origin_authorized_or_bound(
            origin_ip,
            host,
            self._profile,
            self._event_store,
            self._engagement_id,
        )
        rewritten = urlunsplit(
            (parts.scheme or "https", origin_ip, parts.path, parts.query, parts.fragment)
        )
        return rewritten, host, True

    @staticmethod
    def _merge_host(headers: dict[str, str] | None, host: str) -> dict[str, str]:
        merged = dict(headers or {})
        merged["Host"] = host
        return merged
