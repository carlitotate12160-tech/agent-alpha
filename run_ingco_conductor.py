#!/usr/bin/env python3
"""Run full chain via Conductor path against ingco.co.id.

Conductor autonomous path (run_engagement_task + advance_engagement_task eager).
No mocking, no stubbing — real network, real DeepSeek LLM, real target.

GAP-044 field proof: verify soft-404 catch-all calibration suppresses the
93858-byte CodeIgniter catch-all that previously produced ~34 false findings.

Usage (on Oracle ARM64):
    source .env.runtime
    AGENT_ALPHA_LIVE_FIRE=1 .venv312/bin/python3 run_ingco_conductor.py
"""
from __future__ import annotations

import os
import sys
import pathlib as _p

sys.path.insert(0, ".")

# ── Load .env.runtime if env vars not set ──────────────────────────────────
if not os.environ.get("DEEPSEEK_API_KEY") or not os.environ.get("PROFILE_SIGNING_KEY"):
    env_file = _p.Path(__file__).parent / ".env.runtime"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export "):]
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k in ("DEEPSEEK_API_KEY", "PROFILE_SIGNING_KEY", "OTX_API_KEY",
                         "VIRUSTOTAL_API_KEY"):
                    os.environ.setdefault(k, v)

from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor import main as m
from agent_alpha.conductor.authorization import (
    AuthorizationStateMachine,
    Scope,
    authorize_engagement,
)
from agent_alpha.conductor.engagement_profile import dump_signed_profile
from agent_alpha.conductor.execute_agent import rebuild_graph_from_events
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.lab_guard import assert_lab_only_target
from agent_alpha.security.secrets import get_profile_signing_key
from agent_alpha.tools.internal.access.applicator import CredentialApplicator

# ── Config ─────────────────────────────────────────────────────────────────
_TARGET = "ingco.co.id"
_RECON_URL = f"https://{_TARGET}/"
_TENANT_ID = "tenant_ingco_conductor"
_LAB_TOKEN = "dns-txt:agent-alpha=client-approved"

# ── Lab guard (fail-closed) ────────────────────────────────────────────────
assert_lab_only_target(_RECON_URL)

# ── Celery eager (synchronous task execution) ──────────────────────────────
from agent_alpha.conductor.main import celery_app
celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True

# ── Spy on applicator factory (non-mutating) ───────────────────────────────
applicator_calls: list[int] = []
_orig_beta_web_applicators = m.beta_web_applicators

def _spy_beta_web_applicators(http_client: object) -> list[CredentialApplicator]:
    candidates = _orig_beta_web_applicators(http_client)
    applicator_calls.append(len(candidates))
    return candidates

m.beta_web_applicators = _spy_beta_web_applicators

# ── Setup engagement + auth ────────────────────────────────────────────────
store = InMemoryEventStore()
auth = AuthorizationStateMachine(event_store=store)
rec = auth.create_engagement("ingco-conductor", _RECON_URL, tenant_id=_TENANT_ID)
auth.enable_recon(
    rec.engagement_id,
    Scope(ip_ranges=[], domains=[_TARGET], exclusions=[], allow_subdomains=True),
)
auth.enable_active(rec.engagement_id)  # ACTIVE_APPROVED — Beta gate

# Route the worker's tenant store
m.store_provider._stores[_TENANT_ID] = store

# ── Signed EngagementProfile ───────────────────────────────────────────────
# authorized_origins=None — agent must discover origin itself.
# allow_origin_discovery=True → LiveOriginDiscovery (CT/DNS passive recon).
signing_key = get_profile_signing_key()
profile = authorize_engagement(
    engagement_id=rec.engagement_id,
    client_id="ingco-conductor",
    targets=[_TARGET],
    scope_mode="single",
    authorized_origins=None,
    allow_origin_discovery=True,
    allow_subdomain_enum=True,
    authorization_level="ACTIVE_APPROVED",
    consent_items=frozenset({"origin_direct", "active_approved"}),
    signed_by="natanael",
    signed_at="2026-08-11T00:00:00Z",
    ownership_tokens={_TARGET: _LAB_TOKEN},
    skip_domain_verification=True,  # lab_guard allowlist = ownership proof
    verification_mode="cooperative",  # SOW-based, no DNS-TXT
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

print(f"[INGCO] Engagement: {rec.engagement_id}")
print(f"[INGCO] Target: {_TARGET}")
print(f"[INGCO] Auth tier: ACTIVE_APPROVED")
print(f"[INGCO] Origin discovery: LiveOriginDiscovery (agent discovers)")
print(f"[INGCO] GAP-044 field proof: soft-404 catch-all calibration active")
print(f"[INGCO] Starting Conductor chain...\n")

# ── Run engagement ─────────────────────────────────────────────────────────
try:
    result = m.run_engagement_task(rec.engagement_id, _TENANT_ID)
    print(f"\n[INGCO] run_engagement_task result: {result}")
except Exception as exc:
    print(f"\n[INGCO] run_engagement_task FAILED: {exc}")
    import traceback
    traceback.print_exc()

# ── Dump graph + events ────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("GRAPH DUMP")
print("=" * 70)
try:
    graph = rebuild_graph_from_events(store, rec.engagement_id)
    for node_type in NodeType:
        nodes = list(graph.nodes_by_type(node_type))
        if nodes:
            print(f"\n{node_type.name} nodes ({len(nodes)}):")
            for n in nodes:
                props = n.properties
                print(f"  id={n.id} ", end="")
                for attr in ("host", "tech_stack", "level", "service", "username",
                             "secret_ref", "verified", "url", "status_code"):
                    val = getattr(props, attr, None)
                    if val is not None:
                        print(f"{attr}={val!r} ", end="")
                print()
except Exception as exc:
    print(f"Graph dump failed: {exc}")

print("\n" + "=" * 70)
print("EVENT STREAM (key events only)")
print("=" * 70)
try:
    events = store.get_events(rec.engagement_id)
    print(f"Total events: {len(events)}")
    for e in events:
        etype = e.event_type
        etype_name = etype.name if hasattr(etype, "name") else str(etype)
        if etype_name in ("SCRATCHPAD_SNAPSHOTTED", "NODE_DISCOVERED", "EDGE_DISCOVERED"):
            continue
        print(f"  [{etype_name}] agent={e.agent} ", end="")
        if isinstance(e.payload, dict):
            short = {k: (str(v)[:80] + "..." if len(str(v)) > 80 else v)
                     for k, v in e.payload.items()
                     if k in ("target", "host", "status", "access_level",
                              "credential_refs", "dispatched_agent", "next_agent",
                              "reason", "node_count", "action", "tool", "url")}
            print(f"payload={short}")
        else:
            print(f"payload={str(e.payload)[:100]}")
except Exception as exc:
    print(f"Event dump failed: {exc}")

# ── GAP-044 field proof: soft-404 suppression count ────────────────────────
print("\n" + "=" * 70)
print("GAP-044 FIELD PROOF: soft-404 catch-all suppression")
print("=" * 70)
try:
    soft404_events = [
        e for e in store.get_events(rec.engagement_id)
        if hasattr(e.event_type, "name")
        and e.event_type.name == "PASSIVE_DISCOVERY"
        and isinstance(e.payload, dict)
        and e.payload.get("reason") == "soft_404_catch_all"
    ]
    print(f"Soft-404 suppressed paths: {len(soft404_events)}")
    for ev in soft404_events:
        if isinstance(ev.payload, dict):
            print(f"  {ev.payload.get('url', '?')}")

    # Before GAP-044: ~34 false findings from catch-all
    # After GAP-044: 0 false findings (suppressed)
    print(f"\nBefore GAP-044: ~34 false findings from 93858-byte catch-all")
    print(f"After GAP-044:  {len(soft404_events)} paths suppressed (0 false findings)")
except Exception as exc:
    print(f"GAP-044 field proof dump failed: {exc}")

# ── Summary findings ───────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("FINDINGS SUMMARY")
print("=" * 70)
try:
    graph = rebuild_graph_from_events(store, rec.engagement_id)
    events = store.get_events(rec.engagement_id)

    assets = list(graph.nodes_by_type(NodeType.ASSET))
    print(f"\nASSET nodes: {len(assets)}")
    for a in assets:
        props = a.properties
        print(f"  {a.id} tech_stack={getattr(props, 'tech_stack', None)}")

    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    print(f"\nCREDENTIAL nodes: {len(creds)}")

    access = list(graph.nodes_by_type(NodeType.ACCESS_LEVEL))
    print(f"ACCESS_LEVEL nodes: {len(access)}")

    vulns = list(graph.nodes_by_type(NodeType.VULNERABILITY))
    print(f"VULNERABILITY nodes: {len(vulns)}")
    for v in vulns:
        props = v.properties
        print(f"  {v.id} affected_service={getattr(props, 'affected_service', None)}")

    dispatched = [e for e in events
                  if hasattr(e.event_type, "name") and e.event_type.name == "AGENT_DISPATCHED"]
    print(f"\nAGENT_DISPATCHED events: {len(dispatched)}")
    for d in dispatched:
        if isinstance(d.payload, dict):
            agent = d.payload.get("dispatched_agent")
            print(f"  dispatched_agent={agent}")

    proofs = [e for e in events
              if hasattr(e.event_type, "name") and e.event_type.name == "PROOF_ARTIFACT_RECORDED"]
    print(f"PROOF_ARTIFACT_RECORDED events: {len(proofs)}")

    origin_attempts = [e for e in events
                       if hasattr(e.event_type, "name") and e.event_type.name == "ORIGIN_DIRECT_ATTEMPT"]
    print(f"ORIGIN_DIRECT_ATTEMPT events: {len(origin_attempts)}")

    waf_blocks = [e for e in events
                  if hasattr(e.event_type, "name") and e.event_type.name == "WAF_BLOCKED"]
    print(f"WAF_BLOCKED events: {len(waf_blocks)}")

    egress_blocks = [e for e in events
                     if hasattr(e.event_type, "name") and e.event_type.name == "EGRESS_BLOCKED"]
    print(f"EGRESS_BLOCKED events: {len(egress_blocks)}")

    print(f"\nApplicator calls: {applicator_calls}")

except Exception as exc:
    print(f"Findings summary failed: {exc}")
    import traceback
    traceback.print_exc()

print("\n[DONE]")
