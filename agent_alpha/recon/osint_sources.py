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

import logging
from typing import Any

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
