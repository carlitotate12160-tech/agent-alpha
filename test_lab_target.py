#!/usr/bin/env python3
"""Test Laravel lab target for C6 testing

Run this on the Oracle ARM64 box:
    python3 test_lab_target.py
"""

import sys

sys.path.insert(0, "/home/ubuntu/agent-alpha")

import re

from agent_alpha.agents.http_client import HttpClient


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
    if "Illuminate\\Foundation\\Http\\Kernel" in body:
        signals.append("Laravel stack trace")

    return len(signals) > 0, signals


def test_target(url: str) -> None:
    """Test a single URL for Laravel debug signatures."""
    print(f"\nTesting: {url}")
    print("=" * 60)

    client = HttpClient(engagement_id="test-engagement", timeout=30.0)

    try:
        resp = client.get(url)
        print(f"Status: {resp.status_code}")
        print(f"Content-Length: {len(resp.text)} bytes")

        # Check headers
        server = resp.headers.get("server", "N/A")
        powered_by = resp.headers.get("x-powered-by", "N/A")
        print(f"Server: {server}")
        print(f"X-Powered-By: {powered_by}")

        # Check Laravel debug signatures
        is_debug, signals = check_laravel_debug(resp.text)

        if is_debug:
            print(f"✅ LARAVEL DEBUG DETECTED - Signals: {signals}")
        else:
            print("❌ No Laravel debug signatures found")

        # Show first 500 chars of body for context
        print("\nFirst 500 chars of body:")
        print("-" * 60)
        print(resp.text[:500])
        print("-" * 60)

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    targets = [
        "http://localhost:9090/trigger-error",
    ]

    for target in targets:
        test_target(target)
