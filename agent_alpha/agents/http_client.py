"""Production HTTP client for agent egress.

Phase 2: GET-only for Alpha recon. Phase 3: an AUTHENTICATED request surface so
Beta (STRIKE) can actually apply a credential — without it, "initial access" is
structurally impossible and any "verification" is theatre (anti-Lyndon #3). The
new ``headers``/``cookies`` kwargs and ``post()`` are additive: ``get(url)`` keeps
working unchanged for Alpha (#10 — no behavioural change to the existing path).
"""

from __future__ import annotations

import dataclasses
from typing import Any, Protocol, runtime_checkable

import httpx

from agent_alpha.agents.rate_limiter import RateLimiter
from agent_alpha.config import constants


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
    ) -> Any: ...


class HttpClient:
    """httpx-backed HTTP client for production use."""

    def __init__(
        self,
        engagement_id: str,
        timeout: float = constants.HTTP_REQUEST_TIMEOUT_SEC,
        transport: httpx.BaseTransport | None = None,
        rate_limit_rps: float = constants.DEFAULT_RATE_LIMIT_RPS,
        rate_limiter: RateLimiter | None = None,
        opsec: dict[str, Any] | None = None,
        verify: bool = True,
    ) -> None:
        self.timeout = timeout
        self._verify = verify
        if opsec is not None:
            ua = opsec.get("user_agent", f"Agent-Alpha-Recon/{engagement_id}")
            self._headers: dict[str, str] = {
                "User-Agent": ua,
                "Accept": constants.HTTP_DEFAULT_ACCEPT_HEADER,
            }
            extra = opsec.get("headers", {})
            if isinstance(extra, dict):
                self._headers.update(extra)
            rps = opsec.get("rate_limit_rps", rate_limit_rps)
        else:
            self._headers = {
                "User-Agent": f"Agent-Alpha-Recon/{engagement_id}",
                "Accept": constants.HTTP_DEFAULT_ACCEPT_HEADER,
            }
            rps = rate_limit_rps
        self._transport = transport
        self._rate_limiter = rate_limiter or RateLimiter(rps)

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Issue a GET. ``headers``/``cookies`` (default None) let Beta apply a
        credential's auth context; omitting them reproduces the Phase-2 recon GET
        exactly. Transport failures raise :class:`HttpClientError`; httpx never
        escapes this method."""
        return self._request("GET", url, headers=headers, cookies=cookies)

    def post(
        self,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Issue a POST (e.g. a login form submission). Exactly one of ``data``
        (form-encoded) or ``json_body`` should be set. Same error contract as
        :meth:`get`."""
        return self._request(
            "POST", url, headers=headers, cookies=cookies, data=data, json_body=json_body
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
    ) -> HttpResponse:
        # RoE: block to honour the engagement rate limit before egress. Delays,
        # never drops (anti-Lyndon #3). Single chokepoint for every method (#7).
        self._rate_limiter.acquire()
        merged_headers = {**self._headers, **(headers or {})}
        try:
            with httpx.Client(
                timeout=self.timeout,
                transport=self._transport,
                verify=self._verify,
                follow_redirects=True,
            ) as client:
                response = client.request(
                    method,
                    url,
                    headers=merged_headers,
                    cookies=cookies,
                    data=data,
                    json=json_body,
                )
                return HttpResponse(
                    status_code=response.status_code,
                    text=response.text,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    url=str(response.url),
                )
        except httpx.TransportError as exc:
            # httpx.TimeoutException is itself a TransportError, so this
            # single band covers connect/read/timeout failures.
            raise HttpClientError(f"{method} {url} failed: {exc}") from exc
