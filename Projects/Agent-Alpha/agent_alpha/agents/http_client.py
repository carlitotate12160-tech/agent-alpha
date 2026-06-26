"""Production HTTP client for Alpha reconnaissance."""

from __future__ import annotations

import dataclasses

import httpx

from agent_alpha.config import constants


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    """HTTP response shape consumed by Alpha."""

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


class HttpClient:
    """httpx-backed HTTP client for production use."""

    def __init__(
        self,
        engagement_id: str,
        timeout: float = constants.HTTP_REQUEST_TIMEOUT_SEC,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.timeout = timeout
        self._headers = {
            "User-Agent": f"Agent-Alpha-Recon/{engagement_id}",
        }
        self._transport = transport

    def get(self, url: str) -> HttpResponse:
        """Issue a GET request with configured timeout and headers.

        Transport failures (connection refused, DNS error, connect/read
        timeout) are re-raised as :class:`HttpClientError`. ``httpx``
        never escapes this method.
        """
        try:
            with httpx.Client(
                timeout=self.timeout,
                transport=self._transport,
            ) as client:
                response = client.get(url, headers=self._headers)
                return HttpResponse(
                    status_code=response.status_code,
                    text=response.text,
                    headers=dict(response.headers),
                    url=str(response.url),
                )
        except httpx.TransportError as exc:
            # httpx.TimeoutException is itself a TransportError, so this
            # single band covers connect/read/timeout failures.
            raise HttpClientError(f"GET {url} failed: {exc}") from exc
