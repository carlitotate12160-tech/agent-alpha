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

from agent_alpha.agents.http_client import HttpClientError, HttpResponse
from agent_alpha.conductor.engagement_profile import (
    assert_origin_authorized_or_bound,
    proven_origins,
)


class OriginUnreachableError(HttpClientError):
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
        self._fronted_cache: frozenset[str] | None = None

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
            # verify=False on origin-direct: cert matches domain not IP literal (ADR §12.33).
            # lgtm[py/request-without-cert-validation]
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
            # verify=False on origin-direct: cert matches domain not IP literal (ADR §12.33).
            # lgtm[py/request-without-cert-validation]
            verify=False if is_direct else verify,
        )
        return cast(HttpResponse, resp)

    def _route(self, url: str) -> tuple[str, str, bool]:
        """Return (target_url, fronted_host, is_origin_direct)."""
        parts = urlsplit(url)
        host = parts.hostname or ""
        if self._profile is None or not host:
            return url, host, False

        # Bindings - fail-open on any store error (CodeRabbit): a store failure here
        # must degrade to "no known binding", never crash the strike (symmetric with
        # the _fronted_hosts fail-open below - both store reads now fail-open).
        try:
            bound = proven_origins(self._event_store, self._engagement_id, host)
        except Exception:  # noqa: BLE001 - store boundary; no binding evidence => none
            bound = frozenset()
        signed = set(getattr(self._profile, "authorized_origins", frozenset()) or ())
        candidates = bound | signed

        if not candidates:
            # Fail-closed ONLY for hosts recon CONFIRMED are CF-fronted (WAF_BLOCKED
            # event). A host recon reached directly (e.g. a 401 basic-auth subdomain)
            # has NO WAF_BLOCKED event -> plain passthrough (do NOT over-refuse a
            # reachable host). OriginUnreachableError IS an HttpClientError -> the
            # caller (Beta) skips the target gracefully. Independent of the discovery
            # flag: a WAF-confirmed host is never naked-hit regardless.
            if self._host_is_fronted(host):
                raise OriginUnreachableError(
                    f"{host!r} is CF-fronted (WAF_BLOCKED) with no proven origin - "
                    f"skipping target (fail-closed; won't naked-hit the CDN edge)"
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

    def _fronted_hosts(self) -> frozenset[str]:
        """Set of hosts recon CONFIRMED are CF-fronted (a WAF_BLOCKED event exists).
        Computed ONCE per wrapper (Beta run) and cached: Alpha's recon is complete
        before Beta runs, so this set is static during the strike - #6 perf (one
        scan, not per-_route). Fail-open on any store error (empty set -> nothing
        refused -> never crash)."""
        if self._fronted_cache is not None:
            return self._fronted_cache
        from agent_alpha.events.event_types import EventType

        fronted: set[str] = set()
        try:
            events = self._event_store.get_events(self._engagement_id)
        except Exception:  # noqa: BLE001 - store boundary; no evidence => reachable
            events = []
        for e in events:
            if getattr(e, "event_type", None) == EventType.WAF_BLOCKED:
                blocked_host = (getattr(e, "payload", None) or {}).get("host")
                if blocked_host:
                    fronted.add(blocked_host)
        self._fronted_cache = frozenset(fronted)
        return self._fronted_cache

    def _host_is_fronted(self, host: str) -> bool:
        """Per-host (cross-host isolation): a block for host A NEVER refuses host B."""
        return host in self._fronted_hosts()

    @staticmethod
    def _merge_host(headers: dict[str, str] | None, host: str) -> dict[str, str]:
        merged = dict(headers or {})
        merged["Host"] = host
        return merged
