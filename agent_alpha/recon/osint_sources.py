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


# ── §12.48 slice-2 (VT): VirusTotal v3 passive DNS + subdomain source ─────────

VT_DOMAIN_URL_TEMPLATE: str = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_RESOLUTIONS_URL_TEMPLATE: str = "https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
VT_SUBDOMAINS_URL_TEMPLATE: str = (
    "https://www.virustotal.com/api/v3/domains/{domain}/relationships/subdomains?limit=40"
)


def parse_vt_origin_ips(resolutions_body: str) -> list[str]:
    """Extract origin IP candidates from a VT v3 resolutions body (deduped, sorted).

    VT v3 returns ``{"data": [{"id": "<ip><host>", "attributes": {"date": ...}}, ...]}``.
    The ``id`` is a concatenation of IP + hostname — we extract the IP portion (the
    leading numeric part before the hostname). Fail-open → [] on any parse error.
    """
    ips: set[str] = set()
    try:
        data = json.loads(resolutions_body)
        for row in data.get("data", []) if isinstance(data, dict) else []:
            if not isinstance(row, dict):
                continue
            # VT v3 id format: "<ip><hostname>" — extract IP from attributes or id
            attrs = row.get("attributes", {}) or {}
            ip = str(attrs.get("ip_address", "") or attrs.get("host_name", "") or "")
            # If id is "<ip><host>", try to extract leading IP
            if not ip:
                raw_id = str(row.get("id", ""))
                # Leading IPv4 pattern
                parts = raw_id.split(".")
                if len(parts) >= 4:
                    candidate = ".".join(parts[:4])
                    # Strip trailing non-digit chars
                    cleaned = ""
                    for ch in candidate:
                        if ch.isdigit() or ch == ".":
                            cleaned += ch
                        else:
                            break
                    if _is_public_ipv4(cleaned):
                        ips.add(cleaned.strip())
            elif _is_public_ipv4(ip):
                ips.add(ip.strip())
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return sorted(ips)


def parse_vt_subdomains(subdomains_body: str, base_domain: str) -> list[str]:
    """Extract subdomains from a VT v3 subdomains relationship body (deduped, sorted).

    VT v3 returns ``{"data": [{"id": "<subdomain>", "type": "subdomain"}, ...]}``.
    Filters to subdomains of *base_domain* (anti-cross-domain contamination).
    Fail-open → [] on any parse error.
    """
    names: set[str] = set()
    base = base_domain.strip().lower().rstrip(".")
    try:
        data = json.loads(subdomains_body)
        for row in data.get("data", []) if isinstance(data, dict) else []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("id", "")).strip().lower().rstrip(".")
            if not name:
                continue
            # Accept exact match or subdomain of base_domain
            if name == base or name.endswith("." + base):
                names.add(name)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return sorted(names)


class VirusTotalClient:
    """VirusTotal v3 source seam: key-gated GETs → origin IPs + subdomains.

    Fail-open: any transport/parse error on either endpoint yields empties for that
    endpoint, never raises. ``api_key`` sent as ``x-apikey`` header (VT v3 convention).

    Two endpoints queried:
      - ``/domains/{domain}/resolutions`` → historical IP resolutions (origin candidates)
      - ``/domains/{domain}/relationships/subdomains`` → VT-discovered subdomains

    Subdomains are NOT a subdomain source for crt.sh's pipeline (CT already covers that)
    — they are returned separately so the caller can DNS-resolve them as additional
    origin-candidate hosts (grey-cloud subdomains that CT never logged, like
    ``qs.quantum-laboratories.com`` → origin IP directly).
    """

    def __init__(self, http_client: Any, api_key: str) -> None:
        self._http = http_client
        self._headers = {"x-apikey": api_key}

    def _get(self, url: str) -> str:
        try:
            resp = self._http.get(url, headers=self._headers)
        except Exception:  # noqa: BLE001 — OSINT boundary; any error = no data (fail-open)
            _log.warning("VirusTotal fetch failed for %s — fail-open", url, exc_info=True)
            return ""
        return getattr(resp, "text", "") or ""

    def origin_ips_and_subdomains(
        self, domain: str
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Return (origin_ip_candidates, vt_subdomains) for *domain*.

        Origin IPs come from the resolutions endpoint (historical DNS).
        Subdomains come from the relationships/subdomains endpoint — these may
        resolve to non-CF IPs (grey-cloud), unlike crt.sh which only sees CT-logged
        certs. Both are candidates, NOT authorized — the binding gate confirms them.
        """
        resols = self._get(VT_RESOLUTIONS_URL_TEMPLATE.format(domain=domain))
        subs = self._get(VT_SUBDOMAINS_URL_TEMPLATE.format(domain=domain))
        return tuple(parse_vt_origin_ips(resols)), tuple(parse_vt_subdomains(subs, domain))
