#!/usr/bin/env python3
"""Quick check if a URL is built with Laravel."""

import sys
sys.path.insert(0, '/home/ubuntu/agent-alpha')

from agent_alpha.agents.http_client import HttpClient
import re

def check_laravel_signatures(body: str) -> tuple[bool, list[str]]:
    """Check if body contains Laravel debug signatures."""
    signals = []
    
    if "Whoops" in body:
        signals.append("Whoops")
    if "Illuminate\\" in body:
        signals.append("Illuminate\\")
    if re.search(r"Laravel v[0-9]", body):
        signals.append("Laravel version pattern")
    if "laravel" in body.lower():
        signals.append("laravel (case-insensitive)")
    
    return len(signals) > 0, signals

def test_target(url: str) -> None:
    """Test a single URL for Laravel signatures."""
    print(f"\nTesting: {url}")
    print("=" * 60)
    
    client = HttpClient(timeout=30.0)
    
    try:
        resp = client.get(url)
        print(f"Status: {resp.status_code}")
        print(f"Content-Length: {len(resp.text)} bytes")
        
        # Check headers
        server = resp.headers.get("server", "N/A")
        powered_by = resp.headers.get("x-powered-by", "N/A")
        print(f"Server: {server}")
        print(f"X-Powered-By: {powered_by}")
        
        # Check Laravel signatures
        is_laravel, signals = check_laravel_signatures(resp.text)
        
        if is_laravel:
            print(f"✅ LARAVEL DETECTED - Signals: {signals}")
        else:
            print(f"❌ No Laravel signatures found")
            
        # Show first 500 chars of body for context
        print(f"\nFirst 500 chars of body:")
        print("-" * 60)
        print(resp.text[:500])
        print("-" * 60)
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_laravel.py <url>")
        sys.exit(1)
    
    test_target(sys.argv[1])
