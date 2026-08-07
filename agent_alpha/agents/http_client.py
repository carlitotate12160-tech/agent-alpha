"""Production HTTP client for agent egress.

Phase 2: GET-only for Alpha recon. Phase 3: an AUTHENTICATED request surface so
Beta (STRIKE) can actually apply a credential — without it, "initial access" is
structurally impossible and any "verification" is theatre (anti-Lyndon #3). The
new ``headers``/``cookies`` kwargs and ``post()`` are additive: ``get(url)`` keeps
working unchanged for Alpha (#10 — no behavioural change to the existing path).
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Protocol, cast, runtime_checkable

import httpx

from agent_alpha.agents.rate_limiter import Pacer, RateLimiter
from agent_alpha.config import constants
from agent_alpha.recon.reach_transport import cffi_requests, is_tls_impersonate_available

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    """HTTP response shape consumed by agents. ``headers`` carries set-cookie, so
    a session token is observable without widening this contract yet."""

    status_code: int
    text: str
    headers: dict[str, str]
    url: str


class HttpClientError(Exception):
    """Transport-level failure (host unreachable, DNS, connect/read timeout).

    The production client raises this instead of leaking an ``httpx``
    exception, so agents handle network failure without importing httpx
    (one domain contract per concept). It deliberately does NOT subclass
    any ``httpx`` type.
    """


@runtime_checkable
class HttpFetcher(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        cookies: dict[str, str] | None,
        data: dict[str, Any] | None,
        json_body: dict[str, Any] | None,
        allow_redirects: bool,
        verify: bool,
    ) -> HttpResponse: ...


@runtime_checkable
class HttpClientProtocol(Protocol):
    """Minimal HTTP client interface for recon GET requests.

    ONE canonical definition (anti-#6): the recon probes import this instead of each
    hand-rolling an identical Protocol. The concrete ``HttpClient`` below satisfies it.
    """

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
        verify: bool | None = None,
    ) -> Any: ...

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
    ) -> Any: ...


class HttpClient:
    """Production HTTP client for agent requests."""

    def __init__(
        self,
        engagement_id: str,
        timeout: float = constants.HTTP_REQUEST_TIMEOUT_SEC,
        transport: httpx.BaseTransport | None = None,
        rate_limit_rps: float = constants.DEFAULT_RATE_LIMIT_RPS,
        rate_limiter: Pacer | None = None,
        opsec: dict[str, Any] | None = None,
        verify: bool = True,
        fetcher: HttpFetcher | None = None,
    ) -> None:
        self.timeout = timeout
        self._verify = verify
        self._impersonate = str(constants.STEALTH_BROWSER["impersonate"])
        self._headers = self._default_headers()
        if opsec is not None:
            ua = opsec.get("user_agent")
            if isinstance(ua, str) and ua:
                self._headers["User-Agent"] = ua
            extra = opsec.get("headers", {})
            if isinstance(extra, dict):
                self._headers.update({str(k): str(v) for k, v in extra.items()})
            rps = float(opsec.get("rate_limit_rps", rate_limit_rps))
        else:
            rps = rate_limit_rps
        self._transport = transport
        self._rate_limiter = rate_limiter or RateLimiter(rps)
        if fetcher is not None:
            self._fetcher = fetcher
        elif transport is not None:
            self._fetcher = self._build_httpx_fetcher(transport)
        elif is_tls_impersonate_available() and cffi_requests is not None:
            self._fetcher = self._curl_cffi_fetch
        else:
            logger.warning(
                "STEALTH-DEGRADED: curl_cffi unavailable; falling back to httpx transport"
            )
            self._fetcher = self._build_httpx_fetcher(None)

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
        verify: bool | None = None,
    ) -> HttpResponse:
        """Issue a GET. ``headers``/``cookies`` (default None) let Beta apply a
        credential's auth context; omitting them reproduces the Phase-2 recon GET
        exactly. ``allow_redirects=False`` is used by the A1 mitigation probe to
        classify 3xx responses before auto-following to an off-scope destination.
        ``verify`` overrides TLS certificate verification per-call (None → fall
        back to the instance default, typically True).
        Transport failures raise :class:`HttpClientError`; httpx never
        escapes this method."""
        return self._request(
            "GET",
            url,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
        )

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
        """Issue a POST (e.g. a login form submission). Exactly one of ``data``
        (form-encoded) or ``json_body`` should be set. Same error contract as
        :meth:`get`."""
        return self._request(
            "POST",
            url,
            headers=headers,
            cookies=cookies,
            data=data,
            json_body=json_body,
            allow_redirects=allow_redirects,
            verify=verify,
        )

    def _default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": str(constants.STEALTH_BROWSER["user_agent"]),
            "Accept": str(constants.STEALTH_BROWSER["accept"]),
            "Accept-Language": str(constants.STEALTH_BROWSER["accept_language"]),
            "sec-ch-ua": str(constants.STEALTH_BROWSER["sec_ch_ua"]),
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
        }

    def _build_httpx_fetcher(self, transport: httpx.BaseTransport | None) -> HttpFetcher:
        def fetch(
            method: str,
            url: str,
            *,
            headers: dict[str, str],
            cookies: dict[str, str] | None,
            data: dict[str, Any] | None,
            json_body: dict[str, Any] | None,
            allow_redirects: bool,
            verify: bool,
        ) -> HttpResponse:
            try:
                with httpx.Client(
                    timeout=self.timeout,
                    transport=transport,
                    # codeql[py/request-without-cert-validation] — intentional for lab origin-direct (ADR §12.33)
                    verify=verify,
                    follow_redirects=allow_redirects,
                ) as client:
                    # lgtm[py/request-without-cert-validation]
                    response = client.request(
                        method,
                        url,
                        headers=headers,
                        cookies=cookies,
                        data=data,
                        json=json_body,
                    )
            except httpx.TransportError as exc:
                raise HttpClientError(f"{method} {url} failed: {exc}") from exc
            return HttpResponse(
                status_code=response.status_code,
                text=response.text,
                headers={k.lower(): v for k, v in response.headers.items()},
                url=str(response.url),
            )

        return fetch

    def _curl_cffi_fetch(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        cookies: dict[str, str] | None,
        data: dict[str, Any] | None,
        json_body: dict[str, Any] | None,
        allow_redirects: bool,
        verify: bool,
    ) -> HttpResponse:
        if cffi_requests is None:
            raise HttpClientError(f"{method} {url} failed: curl_cffi unavailable")
        try:
            response = cffi_requests.request(
                cast("Any", method),
                url,
                headers=headers,
                cookies=cookies,
                data=data,
                json=json_body,
                allow_redirects=allow_redirects,
                verify=verify,
                timeout=self.timeout,
                impersonate=cast("Any", self._impersonate),
            )
        except Exception as exc:
            raise HttpClientError(f"{method} {url} failed: {exc}") from exc
        return HttpResponse(
            status_code=response.status_code,
            text=response.text,
            headers={str(k).lower(): str(v) for k, v in response.headers.items()},
            url=str(response.url),
        )

    # ── internal ────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        allow_redirects: bool = True,
        verify: bool | None = None,
    ) -> HttpResponse:
        # RoE: block to honour the engagement rate limit before egress. Delays,
        # never drops (anti-Lyndon #3). Single chokepoint for every method (#7).
        self._rate_limiter.acquire()
        merged_headers = {**self._headers, **(headers or {})}
        # Per-call verify override: None → fall back to instance default (self._verify).
        effective_verify = self._verify if verify is None else verify
        response = self._fetcher(
            method,
            url,
            headers=merged_headers,
            cookies=cookies,
            data=data,
            json_body=json_body,
            allow_redirects=allow_redirects,
            verify=effective_verify,
        )
        # §12.50 adaptive backoff: feed the response status back to the pacer if
        # it supports it (StealthPacer does; RateLimiter does not). Duck-typed.
        notify = getattr(self._rate_limiter, "notify", None)
        if notify is not None:
            notify(response.status_code)
        return response
