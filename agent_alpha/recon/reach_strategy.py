"""Reach-strategy selection — A1 Slice B.

Decides HOW to reach a target given its mitigation posture.
ORIGIN_DIRECT is scoping (not an EvasionTechnique) — keep the concepts
separate (§12.33).  No network I/O lives here; pure decision logic.
"""

import enum
import ipaddress

from agent_alpha.config.constants import CF_IP_RANGES
from agent_alpha.recon.transport_resilience import MitigationClass

# Cache parsed networks once at module load (not per-call).
_CF_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(r) for r in CF_IP_RANGES
)


def is_cloudflare_ip(ip: str) -> bool:
    """True iff *ip* belongs to a Cloudflare published IPv4 range.

    Used to filter CF edge IPs from origin candidates: hitting a CF
    edge with a Host header is NOT origin-direct — it still hits the
    WAF. Only non-CF IPs qualify as valid origin candidates.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False  # IPv6 or malformed — not in our CF list
    return any(addr in net for net in _CF_NETWORKS)


class ReachStrategy(enum.StrEnum):
    """Which reach path the planner should use for a given target."""

    DIRECT = "direct"  # normal front-door
    EVASION = "evasion"  # transport_resilience (9a/9b/9c) — residential only
    ORIGIN_DIRECT = "origin_direct"  # scoping: hit authorized origin, bypass CDN
    TLS_IMPERSONATE = "tls_impersonate"  # curl_cffi front-door with browser JA3


def choose_reach(
    mitigation: MitigationClass | None,
    *,
    browser_solve_viable: bool,
    authorized_origin: str | None,
    tls_impersonate_viable: bool = False,
) -> ReachStrategy:
    """Select a reach strategy based on the mitigation class.

    Decision table (differential — class drives strategy, anti-#11):
    * No mitigation              → DIRECT
    * CHALLENGE + viable solve   → EVASION
    * Authorized origin present  → ORIGIN_DIRECT (origin beats CF front-door)
    * FINGERPRINT + impersonate  → TLS_IMPERSONATE (datacenter-viable CF bypass)
    * Otherwise                  → DIRECT (honest block — never a silent cheat).

    Ordering is deliberate: ORIGIN_DIRECT (hitting the real origin) is preferred
    over impersonating the CF front door when an authorized origin exists.
    """
    if mitigation is None:
        return ReachStrategy.DIRECT
    if mitigation is MitigationClass.CHALLENGE and browser_solve_viable:
        return ReachStrategy.EVASION
    if authorized_origin is not None:
        return ReachStrategy.ORIGIN_DIRECT
    if mitigation is MitigationClass.FINGERPRINT and tls_impersonate_viable:
        return ReachStrategy.TLS_IMPERSONATE
    return ReachStrategy.DIRECT
