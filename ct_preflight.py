#!/usr/bin/env python3
"""Layer V-B CT preflight — confirm REAL crt.sh has indexed the lab subdomains
BEFORE running the seal, so a failed run fails for a REAL reason (chain logic),
never because CT indexing simply had not caught up yet (anti false-negative).

Reuses agent_alpha.recon.passive_discovery.parse_crtsh_names (single source of
truth) — no duplicate parser (anti-Lyndon #6/#7).

Usage:
    .venv312/bin/python3 ct_preflight.py <apex> <expected_host> [<expected_host> ...]
Example:
    .venv312/bin/python3 ct_preflight.py agentalpha.duckdns.org vuln.agentalpha.duckdns.org

Exit 0 = all expected hosts present in CT (safe to run V-B); 1 = missing (wait/retry).
"""
from __future__ import annotations

import sys
import urllib.request

from agent_alpha.recon.passive_discovery import CRTSH_URL_TEMPLATE, parse_crtsh_names


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: ct_preflight.py <apex> <expected_host> [<expected_host> ...]")
        return 2
    apex, expected = argv[0], argv[1:]
    url = CRTSH_URL_TEMPLATE.format(domain=apex)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — preflight must report, not crash
        print(f"crt.sh query failed: {exc!r} — retry shortly.")
        return 1

    found = set(parse_crtsh_names(body, apex))
    print(f"crt.sh({apex}): {len(found)} names indexed")
    missing = []
    for host in expected:
        h = host.strip().lower()
        ok = h in found
        print(f"  {'OK  ' if ok else 'MISS'} {host}")
        if not ok:
            missing.append(host)

    if missing:
        print(f"NOT READY — missing {missing}. CT can lag minutes–hours; wait and retry.")
        return 1
    print("READY — all expected hosts indexed in CT. Safe to run Layer V-B.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
