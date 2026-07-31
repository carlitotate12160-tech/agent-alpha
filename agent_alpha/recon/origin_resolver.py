"""Origin IP resolver — find real server IPs behind a CDN front-door.

Pipeline: crt.sh subdomains → DNS resolve → CF filter → host probe.
Reuses existing building blocks (parse_crtsh_names, is_cloudflare_ip,
origin_direct_fetch) — no re-implementation (anti-#6).

Limitation: only discovers IPs exposed via CT subdomains. Sites with no
CT-discoverable subdomains (e.g. single-subdomain CF setups) return [].
"""

from __future__ import annotations

import logging
import socket
from typing import Any

from agent_alpha.recon.passive_discovery import CRTSH_URL_TEMPLATE, parse_crtsh_names
from agent_alpha.recon.reach_strategy import is_cloudflare_ip
from agent_alpha.recon.reach_transport import origin_direct_fetch

_log = logging.getLogger(__name__)

# Probe path — root is safest (redirect is fine, auth-wall is fine,
# what we want to detect is: does this IP serve the domain at all?)
_PROBE_PATH: str = "/"

# Status codes that confirm the IP is serving the domain
# (any non-error response that isn't a CF WAF 403)
_CONFIRMING_STATUSES: frozenset[int] = frozenset({200, 301, 302, 401, 404})
# 401 = origin exists and has auth; 404 = origin exists, path absent
# Both confirm the IP is the real origin.
# 403 = likely WAF block; 5xx = server error (inconclusive)


def _resolve_ipv4(hostname: str) -> list[str]:
    """DNS resolve hostname → deduplicated list of IPv4 addresses.
    Returns [] on any failure (NXDOMAIN, timeout, etc).
    """
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        seen: set[str] = set()
        result: list[str] = []
        for info in infos:
            ip = str(info[4][0])  # cast to str for mypy
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
        return result
    except OSError:
        return []


def _probe_as_origin(ip: str, host: str) -> bool:
    """True iff ip responds to Host:host with a non-WAF-403 status.

    Uses origin_direct_fetch (verify_tls=False: origin cert covers the
    domain name, not the IP literal — same rationale as origin_direct_fetch
    docstring). A confirming status code + no 'server: cloudflare' header
    = real origin confirmed.
    """
    try:
        result = origin_direct_fetch(host, ip, _PROBE_PATH, verify_tls=False)
    except RuntimeError:
        return False  # transport failure = not provably an origin
    if result.status_code not in _CONFIRMING_STATUSES:
        return False
    server = result.headers.get("server", "").lower()
    return "cloudflare" not in server


def discover_origin_ips(
    domain: str,
    http_client: Any,
    *,
    crtsh_url_template: str = CRTSH_URL_TEMPLATE,
    max_probe_candidates: int = 10,
) -> list[str]:
    """Discover real origin IPs for *domain* behind a CDN front-door.

    Pipeline:
      1. Fetch crt.sh subdomain list for *domain*
      2. DNS-resolve each subdomain → IPv4 addresses
      3. Filter out Cloudflare edge IPs (is_cloudflare_ip)
      4. Probe each candidate with Host:domain header
      5. Return confirmed origin IPs (up to max_probe_candidates checked)

    Returns [] if crt.sh returns no subdomains or all IPs are CF/unresponsive.
    Caller must add returned IPs to EngagementProfile.authorized_origins before
    origin_direct_fetch will use them (auth gate — anti-bypass).
    """
    # Step 1: fetch crt.sh
    url = crtsh_url_template.format(domain=domain)
    try:
        resp = http_client.get(url)
        subdomains = parse_crtsh_names(resp.text, domain)
    except OSError:  # network errors, DNS failures, etc.
        _log.warning("origin_resolver: crt.sh fetch failed for %s", domain)
        return []

    _log.info("origin_resolver: %d subdomains from CT for %s", len(subdomains), domain)

    # Step 2+3: resolve and filter
    candidates: set[str] = set()
    for subdomain in subdomains:
        for ip in _resolve_ipv4(subdomain):
            if not is_cloudflare_ip(ip):
                candidates.add(ip)

    _log.info("origin_resolver: %d non-CF candidate IPs for %s", len(candidates), domain)

    # Step 4: probe (bounded — anti-#5 unbounded probe)
    confirmed: list[str] = []
    for ip in list(candidates)[:max_probe_candidates]:
        if _probe_as_origin(ip, domain):
            _log.info("origin_resolver: confirmed origin IP %s for %s", ip, domain)
            confirmed.append(ip)

    return confirmed
