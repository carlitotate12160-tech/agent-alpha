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


# ── Browser-identity consistency (anti-fingerprint-contradiction) ────────────
# curl_cffi's impersonate preset sends its own sec-ch-ua-platform (e.g. "macOS"
# for chrome124). If we override User-Agent to Windows but leave
# sec-ch-ua-platform at the curl_cffi default, a WAF/CDN sees a contradiction
# (UA=Windows, platform=macOS) and can flag the request as bot. These helpers
# ensure every header override stays internally consistent.


def _derive_platform_from_ua(ua: str) -> str:
    """Derive the ``sec-ch-ua-platform`` value that matches a User-Agent string.

    Chrome sends ``sec-ch-ua-platform`` as a quoted value (e.g. ``"Windows"``).
    This function inspects the UA OS token and returns the matching quoted
    platform so the two headers never contradict each other.

    Order matters: CrOS and iOS are checked before the broader Macintosh/Linux
    tokens because those substrings can appear in edge-case UAs.
    """
    if "Windows" in ua:
        return '"Windows"'
    if "CrOS" in ua:
        return '"Chrome OS"'
    if "Android" in ua:
        return '"Android"'
    if "iPhone" in ua or "iPad" in ua or "iOS" in ua:
        return '"iOS"'
    if "Macintosh" in ua or "Mac OS X" in ua:
        return '"macOS"'
    if "Linux" in ua:
        return '"Linux"'
    # Unknown platform — log so the operator is alerted, and return a neutral
    # value rather than silently falling back to STEALTH_BROWSER's platform
    # (which could itself contradict the UA).
    logger.warning(
        "DERIVE-PLATFORM-UNKNOWN: could not infer sec-ch-ua-platform from UA='%s' "
        "— returning '\"Unknown\"'; set sec-ch-ua-platform explicitly via opsec",
        ua[:80],
    )
    return '"Unknown"'


def _validate_header_consistency(headers: dict[str, str]) -> list[str]:
    """Return a list of inconsistency warning strings (empty if consistent).

    Checks that ``sec-ch-ua-platform`` matches the OS implied by the
    ``User-Agent`` header. A mismatch is a fingerprint contradiction that
    WAF/CDN bot detection can flag.
    """
    warnings: list[str] = []
    ua = headers.get("User-Agent", "")
    platform = headers.get("sec-ch-ua-platform", "")
    if ua and platform:
        expected = _derive_platform_from_ua(ua)
        if platform != expected:
            warnings.append(
                f"sec-ch-ua-platform={platform} contradicts User-Agent OS "
                f"(expected {expected} from UA)"
            )
    return warnings


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    """HTTP response shape consumed by agents. ``headers`` carries set-cookie, so
    a session token is observable without widening this contract yet."""

    status_code: int
    text: str
    headers: dict[str, str]
    url: str
    # GAP-116-C: the FULL response cookie jar (name->value). ``headers`` collapses multiple
    # Set-Cookie headers into one string, so a multi-cookie session (WordPress issues
    # wordpress_logged_in_* AND wordpress_sec_*) is unrecoverable from ``headers`` alone. This
    # is populated from the transport's cookie jar (httpx/curl_cffi both parse every Set-Cookie),
    # so an applicator can hand the COMPLETE won session to the 116-B authenticated crawl.
    # Defaults to {} so existing constructions/fakes are unaffected (additive, back-compatible).
    cookies: dict[str, str] = dataclasses.field(default_factory=dict)


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
                # Auto-derive sec-ch-ua-platform to match the overridden UA.
                # Without this, curl_cffi's preset platform (e.g. "macOS")
                # would contradict a Windows UA — a bot fingerprint signal.
                self._headers["sec-ch-ua-platform"] = _derive_platform_from_ua(ua)
            extra = opsec.get("headers", {})
            if isinstance(extra, dict):
                self._headers.update({str(k): str(v) for k, v in extra.items()})
            rps = float(opsec.get("rate_limit_rps", rate_limit_rps))
        else:
            rps = rate_limit_rps
        # Validate header consistency (anti-fingerprint-contradiction).
        # Log warnings for any UA/platform mismatch — does not block construction
        # so that degraded configs still function, but surfaces the risk loudly.
        for w in _validate_header_consistency(self._headers):
            logger.warning("HEADER-INCONSISTENCY: %s — WAF may detect bot fingerprint", w)
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
            "Accept-Encoding": str(constants.STEALTH_BROWSER["accept_encoding"]),
            "sec-ch-ua": str(constants.STEALTH_BROWSER["sec_ch_ua"]),
            "sec-ch-ua-mobile": str(constants.STEALTH_BROWSER["sec_ch_ua_mobile"]),
            "sec-ch-ua-platform": str(constants.STEALTH_BROWSER["sec_ch_ua_platform"]),
            "upgrade-insecure-requests": str(
                constants.STEALTH_BROWSER["upgrade_insecure_requests"]
            ),
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
                # GAP-116-C: full multi-cookie jar (getattr-guarded for transport test doubles).
                cookies=dict(getattr(response, "cookies", {}) or {}),
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
            # GAP-116-C: full multi-cookie jar (getattr-guarded for transport test doubles).
            cookies={
                str(k): str(v) for k, v in dict(getattr(response, "cookies", {}) or {}).items()
            },
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
        self._rate_limiter.acquire(url)
        merged_headers = {**self._headers, **(headers or {})}
        # Validate header consistency on the FINAL merged headers — per-call
        # overrides (e.g. custom Accept, custom UA) could introduce a mismatch
        # between User-Agent and sec-ch-ua-platform. Log warnings so the operator
        # is alerted to fingerprint contradictions before egress.
        for w in _validate_header_consistency(merged_headers):
            logger.warning("HEADER-INCONSISTENCY: %s — WAF may detect bot fingerprint", w)
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
