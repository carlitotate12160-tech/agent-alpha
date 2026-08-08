# agent_alpha/recon/osint_sources.py
# Phase 4 — §12.48 slice-2: keyless OSINT source functions.
#
# Passive, zero-target-contact subdomain sources OTHER than crt.sh (which lives in
# passive_discovery.py). Each source is a pure fetch+parse pair: fail-open (returns
# [] on any error, never raises), single GET, no auth logic (the caller applies the
# fail-closed gate + is_in_scope partition). All network I/O goes through the SAME
# stealth ``HttpClient`` the recon path uses — NEVER urllib with a self-identifying
# User-Agent (that is the §12.49 / PR#346 regression this slice retires).
#
# Slice-2 ships ONE source: HackerTarget host-search (no API key), the crt.sh
# fallback. OTX / VirusTotal / RapidDNS / DNSDumpster are later source slices.

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

# HackerTarget host-search API — plaintext CSV "hostname,ip" per line, no key.
HACKERTARGET_URL_TEMPLATE: str = "https://api.hackertarget.com/hostsearch/?q={domain}"

# Sentinel bodies HackerTarget returns instead of rows when it has nothing / is
# rate-limited. Treated as "no data" (fail-open), never parsed as a hostname.
_HACKERTARGET_ERROR_MARKERS: tuple[str, ...] = (
    "error",
    "api count exceeded",
    "no records",
)


def parse_hackertarget_hosts(body: str, domain: str) -> list[str]:
    """Parse a HackerTarget host-search CSV body → sorted, deduped, domain-filtered
    hostnames.

    Each line is ``hostname,ip``; only the hostname is taken, lowercased, and kept
    iff it is exactly ``domain`` or ends with ``.{domain}``. Never raises.
    """
    domain_lower = domain.strip().lower()
    if not domain_lower:
        return []
    suffix = "." + domain_lower

    # HackerTarget signals errors as the FIRST line (e.g. "error invalid host",
    # "API count exceeded"), never inline in a CSV data row. Scope the marker check
    # to the first line only — a whole-body substring scan would drop valid
    # hostnames that merely CONTAIN a marker (e.g. "error.ex.com"). CodeRabbit #349.
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines:
        return []
    first_line = lines[0].lower()
    if any(
        first_line == marker
        or first_line.startswith(f"{marker} ")
        or first_line.startswith(f"{marker}:")
        for marker in _HACKERTARGET_ERROR_MARKERS
    ):
        return []

    seen: set[str] = set()
    for line in body.splitlines():
        host = line.split(",", 1)[0].strip().lower()
        if not host or "*" in host:
            continue
        if host == domain_lower or host.endswith(suffix):
            seen.add(host)
    return sorted(seen)


def fetch_hackertarget_subdomains(domain: str, *, http_client: Any) -> list[str]:
    """Single GET to HackerTarget → parsed, domain-filtered hostnames. Fail-open.

    ``http_client`` is the stealth ``HttpClient`` (curl_cffi impersonate + stealth
    UA) — no self-identifying fingerprint. Any transport/parse error → ``[]``.
    """
    url = HACKERTARGET_URL_TEMPLATE.format(domain=domain)
    try:
        resp = http_client.get(url)
    except Exception:  # noqa: BLE001 — OSINT source boundary; any error = no data (fail-open)
        _log.warning("HackerTarget fetch failed for %s — fail-open", domain, exc_info=True)
        return []
    return parse_hackertarget_hosts(getattr(resp, "text", "") or "", domain)


# ── CertSpotter (SSLMate CT search) — CT-log source, sibling of crt.sh ─────────
# More reliable / complete than crt.sh in the field. Keyless works (rate-limited);
# an optional Bearer key raises the limit. include_subdomains=true + expand=dns_names
# returns every issuance's SAN list. Same fail-open contract as the other sources.
CERTSPOTTER_URL_TEMPLATE: str = (
    "https://api.certspotter.com/v1/issuances?domain={domain}"
    "&include_subdomains=true&expand=dns_names"
)


def parse_certspotter_names(body: str, domain: str) -> list[str]:
    """Parse a CertSpotter issuances JSON body → sorted, deduped, domain-filtered
    hostnames (from each issuance's ``dns_names``). Never raises.

    Guards non-list payloads (CertSpotter returns an error OBJECT, not an array,
    on a bad request / rate-limit) → treated as no data (fail-open)."""
    try:
        entries = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(entries, list):
        return []

    domain_lower = domain.strip().lower()
    if not domain_lower:
        return []
    suffix = "." + domain_lower

    seen: set[str] = set()
    for obj in entries:
        if not isinstance(obj, dict):
            continue
        for name in obj.get("dns_names", []) or []:
            host = str(name).strip().lower()
            if host.startswith("*."):
                host = host[2:]
            if host and "*" not in host and (host == domain_lower or host.endswith(suffix)):
                seen.add(host)
    return sorted(seen)


def fetch_certspotter_subdomains(
    domain: str, *, http_client: Any, api_key: str | None = None
) -> list[str]:
    """Single GET to CertSpotter → parsed, domain-filtered hostnames. Fail-open.

    ``http_client`` is the stealth ``HttpClient``. ``api_key`` (optional) is sent as
    a Bearer token for higher limits; absent = keyless. Any transport/parse error → [].
    """
    url = CERTSPOTTER_URL_TEMPLATE.format(domain=domain)
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
    try:
        resp = http_client.get(url, headers=headers)
    except Exception:  # noqa: BLE001 — OSINT source boundary; any error = no data (fail-open)
        _log.warning("CertSpotter fetch failed for %s — fail-open", domain, exc_info=True)
        return []
    return parse_certspotter_names(getattr(resp, "text", "") or "", domain)


# ── OTX (AlienVault / LevelBlue OTX) — passive-DNS + URL history ───────────────
# UNIQUE value vs the CT sources: resolved IPs (passive_dns.address) and URL-scan
# origin IPs (url_list[].result.urlworker.ip) = ORIGIN CANDIDATES for CF-bypass,
# plus historical PATHS (url_list[].url). Key-gated (X-OTX-API-KEY); keyless is not
# used (we don't spam unauth). Every field is a HINT/candidate — origin IPs MUST
# pass verify_origin_binding downstream, never become hand-fed authorized_origins.
OTX_PASSIVE_DNS_URL_TEMPLATE: str = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
)
OTX_URL_LIST_URL_TEMPLATE: str = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
)


def _is_public_ipv4(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global  # routable origin candidate only


def parse_otx_origin_ips(passive_dns_body: str, url_list_body: str) -> list[str]:
    """Extract public origin-IP CANDIDATES from OTX passive_dns + url_list bodies.

    passive_dns[].address and url_list[].result.urlworker.ip; public IPv4 only,
    deduped, sorted. Never raises (fail-open → []). These are CANDIDATES: the
    origin-binding gate confirms them, this parser never authorises anything.
    """
    ips: set[str] = set()
    try:
        pdns = json.loads(passive_dns_body)
        for row in pdns.get("passive_dns", []) if isinstance(pdns, dict) else []:
            if isinstance(row, dict) and _is_public_ipv4(str(row.get("address", ""))):
                ips.add(str(row["address"]).strip())
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    try:
        ul = json.loads(url_list_body)
        for row in ul.get("url_list", []) if isinstance(ul, dict) else []:
            worker = (
                (row.get("result", {}) or {}).get("urlworker", {}) if isinstance(row, dict) else {}
            )
            ip = str(worker.get("ip", "")) if isinstance(worker, dict) else ""
            if _is_public_ipv4(ip):
                ips.add(ip.strip())
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return sorted(ips)


def parse_otx_historical_paths(url_list_body: str) -> list[str]:
    """Extract historical URL PATHS from an OTX url_list body (deduped, sorted).

    Only the path component (no host/query) — feeds a later Bug #26 probe-selection
    consumer. Never raises (fail-open → [])."""
    paths: set[str] = set()
    try:
        ul = json.loads(url_list_body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    for row in ul.get("url_list", []) if isinstance(ul, dict) else []:
        if not isinstance(row, dict):
            continue
        path = urlparse(str(row.get("url", ""))).path
        if path and path != "/":
            paths.add(path)
    return sorted(paths)


class OtxClient:
    """OTX source seam: two key-gated GETs → (origin_ip_candidates, historical_paths).

    Fail-open: any transport/parse error on either endpoint yields empties for that
    endpoint, never raises. ``api_key`` sent as X-OTX-API-KEY."""

    def __init__(self, http_client: Any, api_key: str) -> None:
        self._http = http_client
        self._headers = {"X-OTX-API-KEY": api_key}

    def _get(self, url: str) -> str:
        try:
            resp = self._http.get(url, headers=self._headers)
        except Exception:  # noqa: BLE001 — OSINT boundary; any error = no data (fail-open)
            _log.warning("OTX fetch failed for %s — fail-open", url, exc_info=True)
            return ""
        return getattr(resp, "text", "") or ""

    def origin_ips_and_paths(self, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        pdns = self._get(OTX_PASSIVE_DNS_URL_TEMPLATE.format(domain=domain))
        ul = self._get(OTX_URL_LIST_URL_TEMPLATE.format(domain=domain))
        return tuple(parse_otx_origin_ips(pdns, ul)), tuple(parse_otx_historical_paths(ul))
