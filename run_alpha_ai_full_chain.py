#!/usr/bin/env python3
"""Run Agent Alpha full chain with all new capabilities to alpha-ai.web.id (Tier 2 Integration Test).

Tests all merged capabilities:
- GAP-115: Wayback CDX Historical Recon
- GAP-051: Engagement-Level Wall Verdict
- Bug #34: Engagement-Scoped State Reset
- Bug #35: LLM Orientation Budget & Retry Resilience
- GAP-074: Odoo JSON-RPC Fallback

Usage (on Oracle ARM64):
    cd ~/Agent-Alpha
    AGENT_ALPHA_LIVE_FIRE=1 .venv312/bin/python3 run_alpha_ai_full_chain.py
"""
from __future__ import annotations

import os
import sys
import pathlib as _p

sys.path.insert(0, ".")

# Load env vars for DeepSeek
if not os.environ.get("DEEPSEEK_API_KEY") or not os.environ.get("PROFILE_SIGNING_KEY"):
    for _fname in (".env.runtime", ".env"):
        env_file = _p.Path(__file__).parent / _fname
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if k in ("DEEPSEEK_API_KEY", "PROFILE_SIGNING_KEY"):
                        os.environ.setdefault(k, v)
            break

from agent_alpha.conductor import main as m
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope, authorize_engagement
from agent_alpha.conductor.engagement_profile import dump_signed_profile
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import PostgresEventStore
from agent_alpha.live_fire.lab_guard import assert_lab_only_target
from agent_alpha.security.secrets import get_profile_signing_key

# Config - alpha-ai.web.id full chain test
_TARGETS = [
    "alpha-ai.web.id",          # apex (CF-fronted)
    "wp.alpha-ai.web.id",       # CF-fronted (origin-binding MOAT)
    "laravel.alpha-ai.web.id",  # self-owned sibling (CT surface)
    "odoo.alpha-ai.web.id",     # self-owned sibling (CT surface)
    "direct.alpha-ai.web.id",   # self-owned non-CF sibling (CT surface)
]
_RECON_URL = "https://wp.alpha-ai.web.id/"  # Start with WP for cred-reuse chain
_TENANT_ID = "tenant_alpha_ai_full_chain"

# Ownership tokens from alpha_ai_integrated.example.yaml
_OWNERSHIP_TOKENS = {
    "alpha-ai.web.id": "2bc860d964b4719a759743cdd8f46105ed9f6dbd8023e7ee5874e985e5a908ef",
    "wp.alpha-ai.web.id": "5fd127953896afcb6bc19b0cfc434786",
    "odoo.alpha-ai.web.id": "5fd127953896afcb6bc19b0cfc434786",
    "laravel.alpha-ai.web.id": "5fd127953896afcb6bc19b0cfc434786",
    "direct.alpha-ai.web.id": "5fd127953896afcb6bc19b0cfc434786",
}

# Lab guard (fail-closed)
for target in _TARGETS:
    assert_lab_only_target(f"https://{target}/")

# Celery eager (synchronous task execution)
from agent_alpha.conductor.main import celery_app
celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True

# Setup engagement + auth with PostgreSQL store
from agent_alpha.events.store import PostgresEventStore
import os

# Get DSN from env
dsn = os.environ.get("AGENT_ALPHA_PG_DSN")
if not dsn:
    for _fname in (".env.runtime", ".env"):
        env_file = _p.Path(__file__).parent / _fname
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if k == "AGENT_ALPHA_PG_DSN":
                        dsn = v
                        break
            break

store = PostgresEventStore(dsn=dsn, tenant_id=_TENANT_ID)
auth = AuthorizationStateMachine(event_store=store)
rec = auth.create_engagement("alpha-ai-full-chain", _RECON_URL, tenant_id=_TENANT_ID)
auth.enable_recon(
    rec.engagement_id,
    Scope(ip_ranges=[], domains=_TARGETS, exclusions=[], allow_subdomains=True),
)
auth.enable_active(rec.engagement_id)  # Upgrade to ACTIVE_APPROVED for Beta/Omega chain

# Route the worker's tenant store
m.store_provider._stores[_TENANT_ID] = store

# Execute Conductor
if __name__ == "__main__":
    print(f"[*] Starting Full Chain Conductor run against alpha-ai.web.id stack...")
    print(f"[*] Targets: {_TARGETS}")
    print(f"[*] Features: StealthPacer (GAP-026), Origin Direct Evasion (§12.46), Wayback CDX (GAP-115), Full Chain Dispatched")
    signing_key = get_profile_signing_key()
    
    profile = authorize_engagement(
        engagement_id=rec.engagement_id,
        client_id="alpha-ai-lab",
        targets=_TARGETS,
        scope_mode="multi",
        authorized_origins=frozenset({"168.110.192.62"}),
        allow_origin_discovery=True,
        allow_subdomain_enum=True,
        allow_evasion=True,
        opsec_stealth=True,
        authorization_level="ACTIVE_APPROVED",
        consent_items=frozenset({
            "authorized_recon",
            "origin_discovery",
            "origin_direct",
            "subdomain_enum",
            "active",
            "active_approved",
            "stealth",
            "evasion",
            "scope_confirmed",
        }),
        signed_by="system",
        signed_at="2026-08-15T00:00:00Z",
        ownership_tokens=_OWNERSHIP_TOKENS,
        skip_domain_verification=True,
        verification_mode="cooperative",
        event_store=store,
        key=signing_key,
    )
    envelope = dump_signed_profile(profile, key=signing_key)
    store.append(
        event_type=EventType.ENGAGEMENT_PROFILE_SIGNED,
        engagement_id=rec.engagement_id,
        agent="CONDUCTOR",
        payload=envelope,
    )
    
    # Trigger the full engagement pipeline via Conductor Celery task
    from agent_alpha.conductor.main import run_engagement_task
    
    print("[*] Dispatching to Celery (Eager mode)...")
    run_engagement_task.delay(
        engagement_id=rec.engagement_id,
        tenant_id=_TENANT_ID,
    )
    
    print("\n" + "=" * 60)
    print("[*] Full Chain Run Completed. Event Store Telemetry:")
    print("=" * 60)
    event_count = store.count(rec.engagement_id)
    print(f"[*] Total events recorded: {event_count}")
    
    events = store.get_events(rec.engagement_id)
    event_types: dict[str, int] = {}
    for e in events:
        ename = e.event_type.name if hasattr(e.event_type, "name") else str(e.event_type)
        event_types[ename] = event_types.get(ename, 0) + 1
        
    print("\n[*] Event Breakdown:")
    for ename, count in sorted(event_types.items(), key=lambda x: -x[1]):
        print(f"  - {ename}: {count}")
    
    origin_bindings = [e for e in events if "ORIGIN_BINDING_PROVEN" in str(e.event_type)]
    creds = [e for e in events if "CREDENTIAL_HARVESTED" in str(e.event_type) or "SECRET" in str(e.event_type)]
    access = [e for e in events if "ACCESS_GRANTED" in str(e.event_type)]
    
    print(f"\n[*] Key Milestones:")
    print(f"  - Origin Bindings Proven: {len(origin_bindings)}")
    print(f"  - Secrets/Credentials Harvested: {len(creds)}")
    print(f"  - Access Granted Events: {len(access)}")
    print(f"\n[*] Engagement ID: {rec.engagement_id}")
    print("[*] Full Chain Autonomous Test Completed.")
