#!/usr/bin/env python3
"""Scan multiple domains for Laravel debug mode

Usage:
    python3 scan_laravel_debug.py domains.txt

domains.txt format (one domain per line):
    example.com
    test-site.org
    another-domain.net
"""

import sys
sys.path.insert(0, '/home/ubuntu/agent-alpha')

from agent_alpha.agents.http_client import HttpClient
import re

def check_laravel_debug(body: str) -> tuple[bool, list[str]]:
    """Check if body contains Laravel DEBUG signatures."""
    signals = []
    
    if "Whoops" in body:
        signals.append("Whoops")
    if "Illuminate\\" in body:
        signals.append("Illuminate\\")
    if re.search(r"Laravel v[0-9]", body):
        signals.append("Laravel version pattern")
    if "SQLSTATE" in body:
        signals.append("SQLSTATE (database error)")
    
    return len(signals) > 0, signals

def scan_domain(domain: str) -> dict:
    """Scan a single domain for Laravel debug mode."""
    client = HttpClient(engagement_id="scan-engagement", timeout=10.0)
    
    # Try both HTTP and HTTPS
    results = {}
    for protocol in ["http", "https"]:
        url = f"{protocol}://{domain}"
        try:
            resp = client.get(url)
            is_debug, signals = check_laravel_debug(resp.text)
            results[url] = {
                "status": resp.status_code,
                "is_debug": is_debug,
                "signals": signals,
            }
        except Exception as e:
            results[url] = {
                "error": str(e),
            }
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scan_laravel_debug.py domains.txt")
        sys.exit(1)
    
    domains_file = sys.argv[1]
    
    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    print(f"Scanning {len(domains)} domains for Laravel debug mode...")
    print("=" * 60)
    
    debug_found = []
    
    for domain in domains:
        print(f"\nScanning: {domain}")
        results = scan_domain(domain)
        
        for url, result in results.items():
            if "error" in result:
                print(f"  {url}: ❌ {result['error']}")
            elif result["is_debug"]:
                print(f"  {url}: ✅ LARAVEL DEBUG - Signals: {result['signals']}")
                debug_found.append(url)
            else:
                print(f"  {url}: ❌ No debug signatures")
    
    print("\n" + "=" * 60)
    print(f"Summary: {len(debug_found)} Laravel debug sites found")
    if debug_found:
        print("Debug sites:")
        for url in debug_found:
            print(f"  - {url}")
