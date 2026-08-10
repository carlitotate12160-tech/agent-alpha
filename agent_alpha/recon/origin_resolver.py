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
from collections.abc import Sequence
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
_CONFIRMING_STATUSES: frozenset[int] = frozenset({200, 301, 302, 303, 307, 308, 401, 404})
# 3xx = origin alive + serving (redirect, incl. 303 See Other — Odoo /web backends);
# 401 = origin exists behind auth; 404 = origin exists, path absent. All confirm.
# 403 = likely WAF/CF block (never confirm); 5xx = server error (inconclusive).


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


def probe_as_origin(ip: str, host: str) -> bool:
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
    engagement_id: str,
    domain: str,
    http_client: Any,
    authorization: Any,
    *,
    seed_hosts: Sequence[str] = (),
    crtsh_url_template: str = CRTSH_URL_TEMPLATE,
    max_probe_candidates: int = 10,
    crtsh_timeout: float = 60.0,
) -> list[str]:
    """Discover real origin IPs for *domain* behind a CDN front-door.

    Pipeline:
      1. Fetch crt.sh subdomain list for *domain*
      2. DNS-resolve each subdomain → IPv4 addresses
      3. Filter out Cloudflare edge IPs (is_cloudflare_ip)
      4. Probe each candidate with Host:domain header
      5. Return confirmed origin IPs (up to max_probe_candidates checked)

    Candidates come from crt.sh subdomains AND *seed_hosts* (in-scope authorized
    target hostnames) — a grey-cloud subdomain CT never logged is still found.
    Returns [] if no candidate resolves to a confirmed non-CF origin.
    Caller must add returned IPs to EngagementProfile.authorized_origins before
    origin_direct_fetch will use them (auth gate — anti-bypass).
    """
    # Fail-closed gate BEFORE any network I/O (anti-bypass).
    if max_probe_candidates < 0:
        return []
    from agent_alpha.a2a import a2a_pb2

    if not authorization.can_agent_proceed(a2a_pb2.ALPHA, engagement_id):
        return []
    if not authorization.is_in_scope(engagement_id, domain):
        return []

    # Step 1: fetch crt.sh (best-effort — a CT miss must NOT abort; the in-scope
    # seed_hosts are an independent origin-candidate source, §12.44).
    url = crtsh_url_template.format(domain=domain)
    subdomains: list[str] = []
    try:
        from agent_alpha.agents.http_client import HttpClientError

        resp = http_client.get(url)
        subdomains = parse_crtsh_names(resp.text, domain)
    except (HttpClientError, OSError):  # network errors, DNS failures, etc.
        _log.warning(
            "origin_resolver: crt.sh fetch failed for %s (seed_hosts may still yield)", domain
        )

    # Origin candidates = crt.sh subdomains ∪ in-scope seed hosts (authorized target
    # subdomains). A grey-cloud subdomain (non-CF) that CT never logged — e.g. under a
    # wildcard / CF Universal-SSL cert — is the #1 real origin leak. Resolving a KNOWN
    # authorized host is discovery (the IP comes from DNS), NOT a hand-fed origin.
    candidate_hosts: set[str] = set(subdomains)
    for raw in seed_hosts:
        host = (raw or "").strip().lower()
        if host and authorization.is_in_scope(engagement_id, host):
            candidate_hosts.add(host)

    _log.info(
        "origin_resolver: %d CT subdomain(s) + %d seed → %d candidate host(s) for %s",
        len(subdomains),
        len(tuple(seed_hosts)),
        len(candidate_hosts),
        domain,
    )

    # Step 2+3: resolve and filter — keep ALL in-scope hostnames per IP so the probe
    # can try each Host header. Multiple vhosts often share one origin IP and respond
    # differently (odoo → 303 to /web, wp → 200); the first hostname alone is not
    # enough (RC3). Sorted iteration = deterministic, no hash-order dependence (RC1).
    ip_to_hosts: dict[str, list[str]] = {}
    for hostname in sorted(candidate_hosts):
        for ip in _resolve_ipv4(hostname):
            if is_cloudflare_ip(ip):
                continue
            hosts = ip_to_hosts.setdefault(ip, [])
            if hostname not in hosts:
                hosts.append(hostname)

    _log.info("origin_resolver: %d non-CF candidate IP(s) for %s", len(ip_to_hosts), domain)

    # Step 4: probe each candidate IP with EACH of its hostnames until one confirms
    # (bounded to max_probe_candidates IPs — anti-#5 unbounded probe).
    confirmed: list[str] = []
    for ip in sorted(ip_to_hosts)[:max_probe_candidates]:
        for probe_host in ip_to_hosts[ip]:
            if probe_as_origin(ip, probe_host):
                _log.info(
                    "origin_resolver: confirmed origin IP %s for %s (via %s)",
                    ip,
                    domain,
                    probe_host,
                )
                confirmed.append(ip)
                break  # one confirming Host is enough for this IP

    return confirmed


class LiveOriginDiscovery:
    """§12.46 Slice B — production ``OriginDiscovery``: real CT/DNS origin
    resolution via :func:`discover_origin_ips`.

    Constructed on the Conductor path when the signed profile consents to
    ``allow_origin_discovery`` (the alternative to the cooperative
    ``StaticOriginDiscovery`` fed from pre-signed ``authorized_origins``).

    ``candidates()`` delegates to :func:`discover_origin_ips`, which has its OWN
    fail-closed auth gate (``can_agent_proceed`` + ``is_in_scope``) BEFORE any
    network I/O — and a returned candidate is still only ACTED on after the
    §12.46 binding proof + composed gate. The HTTP client is the stealth
    ``HttpClient`` (built lazily so construction stays import-cheap); an explicit
    client may be injected for hermetic tests.
    """

    def __init__(
        self,
        engagement_id: str,
        authorization: Any,
        *,
        http_client: Any = None,
    ) -> None:
        self._engagement_id = engagement_id
        self._authorization = authorization
        self._http_client = http_client

    def candidates(self, fronted_host: str) -> list[str]:
        http = self._http_client
        if http is None:
            from agent_alpha.agents.http_client import HttpClient

            http = HttpClient(engagement_id=self._engagement_id)
            # Cache so the same client + its RateLimiter (pacing state) is reused
            # across candidates() calls within this engagement (CodeRabbit #351-B).
            self._http_client = http
        return discover_origin_ips(
            self._engagement_id,
            fronted_host,
            http,
            self._authorization,
            seed_hosts=self._scope_seed_hosts(),
        )

    def _scope_seed_hosts(self) -> tuple[str, ...]:
        """The engagement's in-scope authorized domains, used as origin-candidate
        seeds (GAP-018). discover_origin_ips re-filters each through is_in_scope,
        so this is defense-in-depth, never a scope bypass. Without these, origin
        discovery yields NOTHING whenever crt.sh is down (crt.sh flaky = common) —
        the T4 CF-bypass MOAT becomes unprovable. Read from the auth state machine
        (which owns the Scope from enable_recon) — LiveOriginDiscovery already holds
        auth, so no caller (main.py) needs to spoon-feed derivable scope. Fail-open
        to () if the record/scope is unavailable."""
        try:
            record = self._authorization.get_record(self._engagement_id)
        except Exception:  # noqa: BLE001 — scope read must never crash discovery
            return ()
        scope = getattr(record, "scope", None)
        return tuple(scope.domains) if scope is not None else ()
