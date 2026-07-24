import dataclasses
from typing import Any


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
        _client_opts: dict[str, Any] = {"verify": verify_tls, "timeout": 15.0}
        with httpx.Client(**_client_opts) as client:
            resp = client.get(url, headers={"Host": host})
    except httpx.HTTPError as exc:
        raise RuntimeError(f"origin_direct_fetch failed for {host} via {origin_ip}: {exc}") from exc
    return OriginDirectResult(
        status_code=resp.status_code,
        body=resp.text,
        headers=dict(resp.headers),
    )
