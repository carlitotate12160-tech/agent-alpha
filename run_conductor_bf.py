#!/usr/bin/env python3
"""Run bernofarm.com engagement via Conductor API."""
from __future__ import annotations

import json
import os
import time

import jwt
import urllib.request

BASE = "http://localhost:8000"
JWT_SECRET = os.environ.get("AGENT_ALPHA_JWT_SECRET", "u4nIY9hCMpSVA0mkDHvlvAPXkc8ziSwgQCPYjBQ61EM")

token = jwt.encode(
    {"sub": "operator", "tenant_id": "default", "exp": int(time.time()) + 3600},
    JWT_SECRET,
    algorithm="HS256",
)

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def post(path: str, body: dict | None = None) -> dict:
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else b""
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


# Step 1: Create engagement
print("=== CREATE ENGAGEMENT ===")
resp = post("/engagements", {"client_id": "bernofarm", "target": "bernofarm.com"})
print(json.dumps(resp, indent=2))
eid = resp.get("engagement_id", "")
print(f"Engagement ID: {eid}")

# Step 2: Ownership challenge (required before authorize)
print("\n=== OWNERSHIP CHALLENGE ===")
resp = post(f"/engagements/{eid}/ownership/challenge", {"domain": "bernofarm.com"})
print(json.dumps(resp, indent=2))

# Step 3: Authorize (skip_domain_verification via env var on server)
print("\n=== AUTHORIZE ===")
resp = post(f"/engagements/{eid}/authorize", {
    "domains": ["bernofarm.com"],
    "consent_items": ["recon_only", "evasion"],
    "allow_evasion": True,
    "signed_by": "operator",
    "signed_at": "2026-07-31T00:00:00Z",
})
print(json.dumps(resp, indent=2))

# Step 4: Enable recon (empty body — scope derived from signed profile)
print("\n=== ENABLE RECON ===")
resp = post(f"/engagements/{eid}/recon", {})
print(json.dumps(resp, indent=2))

# Step 5: Run
print("\n=== RUN ===")
resp = post(f"/engagements/{eid}/run")
print(json.dumps(resp, indent=2))

print(f"\n=== ENGAGEMENT ID: {eid} ===")
print(f"Monitor: curl -s http://localhost:8000/engagements/{eid}/run-status -H 'Authorization: Bearer {token}'")
