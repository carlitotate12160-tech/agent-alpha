import dataclasses
from typing import Any

from agent_alpha.config import constants

__all__ = [
    "OriginDirectResult",
    "origin_direct_fetch",
    "is_tls_impersonate_available",
    "tls_impersonate_fetch",
    "cffi_requests",
]


@dataclasses.dataclass(frozen=True)
class OriginDirectResult:
    """Result from an origin-direct fetch. Satisfies ChallengeSolveResult.

    challenge_encountered and challenge_solved are ALWAYS False: origin-direct
    bypasses the CDN front door — the challenge is never encountered, never
    solved. Setting either to True would be Lyndon #3 (false success).
    """

    status_code: int
    body: str
    headers: dict[str, str]
    cleared_cookies: dict[str, str] = dataclasses.field(default_factory=dict)
    challenge_encountered: bool = False
    challenge_solved: bool = False

    def __post_init__(self) -> None:
        # Invariant (anti-#7): header keys are ALWAYS lowercase, regardless of the
        # producing transport. httpx (origin_direct_fetch) lowercases via its Headers
        # type; curl_cffi (tls_impersonate_fetch) preserves the server's original
        # casing. Every consumer reads headers.get("server"/"x-powered-by") with a
        # lowercase literal (service_fingerprint.get_merged_service_nodes,
        # origin_reach.is_edge_fronted_host, origin_resolver._is_origin) — a title-case
        # "Server" silently misses. Normalize ONCE here so producers AND consumers are
        # transport-agnostic. frozen=True -> object.__setattr__.
        object.__setattr__(
            self,
            "headers",
            {str(k).lower(): str(v) for k, v in self.headers.items()},
        )


def origin_direct_fetch(
    host: str,
    origin_ip: str,
    path: str = "/",
    *,
    verify_tls: bool = False,
) -> OriginDirectResult:
    """Fetch via origin IP with Host header, bypassing CDN.

    TLS verify=False for lab slice: origin cert matches *host* domain, NOT the
    origin IP literal → naive verify=True always fails. Production origin-direct
    against clients MUST use SNI-override domain-cert verification (anti-MITM)
    — see ADR §12.33 verify-posture doctrine.

    This is SCOPING (hitting the real server), NOT a security downgrade.
    """
    import httpx

    url = f"https://{origin_ip}{path}"
    try:
        # lab: verify_tls=False is intentional — origin cert matches domain, not IP literal.
        # Production MUST use SNI-override domain-cert verification (ADR §12.33).
        # CodeQL: this is scoping, not a security downgrade.
        _client_opts: dict[str, Any] = {"verify": verify_tls, "timeout": constants.REACH_TIMEOUT_S}
        with httpx.Client(**_client_opts) as client:
            resp = client.get(url, headers={"Host": host})
    except httpx.HTTPError as exc:
        raise RuntimeError(f"origin_direct_fetch failed for {host} via {origin_ip}: {exc}") from exc
    return OriginDirectResult(
        status_code=resp.status_code,
        body=resp.text,
        headers=dict(resp.headers),
    )


# ── TLS impersonation transport (§12.33 — FINGERPRINT class) ─────────────────

# Lazy import: curl_cffi may not be installed in every environment. The
# is_tls_impersonate_available() gate lets the scout degrade to honest-block
# when the dep is absent, rather than crashing at import time.
try:
    from curl_cffi import requests as cffi_requests

    _CURL_CFFI_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dependency
    cffi_requests = None  # type: ignore[assignment, unused-ignore]
    _CURL_CFFI_AVAILABLE = False


def is_tls_impersonate_available() -> bool:
    """True iff curl_cffi is importable (the TLS-impersonation transport is usable).

    The scout uses this gate so FINGERPRINT reach degrades to honest-block
    (DIRECT) when the dependency is absent — no crash, no silent cheat.
    """
    return _CURL_CFFI_AVAILABLE


def tls_impersonate_fetch(
    url: str,
    *,
    impersonate: str = "chrome131",
    verify_tls: bool = True,
) -> OriginDirectResult:
    """Front-door fetch with a real browser TLS/JA4 fingerprint (curl_cffi)
    so a CF/WAF FINGERPRINT block (403/503) is bypassed WITHOUT the origin
    IP and WITHOUT a browser — datacenter-viable (unlike browser_solve).
    Reuses OriginDirectResult (anti-#6).

    verify_tls=True: this hits the REAL domain through CF whose cert is valid
    for the domain — NEVER downgrade to False (that is origin_direct_fetch's
    IP-literal case, ADR §12.33). challenge flags stay False: no challenge is
    interacted with (anti-#3).
    """
    if not _CURL_CFFI_AVAILABLE:
        raise RuntimeError(
            "tls_impersonate_fetch requires curl_cffi — install it or gate via "
            "is_tls_impersonate_available()"
        )
    try:
        resp = cffi_requests.get(
            url,
            impersonate=impersonate,  # type: ignore[arg-type, unused-ignore]
            verify=verify_tls,
            timeout=constants.REACH_TIMEOUT_S,
        )
    except Exception as exc:
        # Fail-loud (anti-#3): any curl_cffi error surfaces as RuntimeError.
        # The scout catches this and records an honest block — never a synthetic 200.
        raise RuntimeError(f"tls_impersonate_fetch failed for {url}: {exc}") from exc
    return OriginDirectResult(
        status_code=resp.status_code,
        body=resp.text,
        headers={str(k): str(v) for k, v in resp.headers.items()},
    )
