#!/usr/bin/env python3
"""Synchronous engagement runner for external targets.

Bypasses Celery — calls run_recon_for_engagement directly.
Requires DEEPSEEK_API_KEY in environment.
"""

from __future__ import annotations

import os
import sys
import time

# Load .env manually (no python-dotenv dependency)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    for line in open(_env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

if not os.environ.get("DEEPSEEK_API_KEY"):
    print("ERROR: DEEPSEEK_API_KEY not set in environment or .env")
    sys.exit(1)

from agent_alpha.conductor.authorization import (  # noqa: E402
    AuthorizationStateMachine,
    authorize_engagement,
)
from agent_alpha.conductor.recon_runner import run_recon_for_engagement  # noqa: E402
from agent_alpha.events.store import InMemoryEventStore  # noqa: E402
from agent_alpha.graph.networkx_store import NetworkXGraphStore  # noqa: E402
from agent_alpha.security.secrets import SecretsManager  # noqa: E402

TARGET = "bernofarm.com"
CLIENT_ID = "bernofarm"

os.environ.setdefault("AGENT_ALPHA_SKIP_DOMAIN_VERIFICATION", "1")
os.environ.setdefault("PROFILE_SIGNING_KEY", "test_key_that_is_at_least_32_bytes_long_1234")
os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")


def main() -> int:
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    secrets_manager = SecretsManager()

    # 1. Create engagement
    record = auth.create_engagement(client_id=CLIENT_ID, target=TARGET)
    eid = record.engagement_id
    print(f"[ENGAGEMENT] {eid} — target: {TARGET}")

    # 2. Authorize (skip DNS-TXT verification for external targets)
    print("[AUTH] Authorizing (skip_domain_verification=True)...")
    signing_key = os.environ["PROFILE_SIGNING_KEY"].encode()
    profile = authorize_engagement(
        engagement_id=eid,
        client_id=CLIENT_ID,
        targets=[TARGET],
        ownership_tokens={},
        dns_resolver=None,
        skip_domain_verification=True,
        consent_items=frozenset({"recon_only", "evasion"}),
        allow_evasion=True,
        signed_by="operator",
        signed_at="2026-07-28T00:00:00Z",
        event_store=event_store,
        key=signing_key,
    )
    print(f"[AUTH] Signed profile: {sorted(profile.scope_targets)}")

    # 3. Enable recon
    from agent_alpha.conductor.models import Scope

    scope = Scope(
        ip_ranges=[],
        domains=sorted(profile.scope_targets),
        exclusions=[],
    )
    auth.enable_recon(eid, scope)
    print("[AUTH] RECON_ONLY enabled")

    # 3.5. Wire browser_solve if profile allows evasion
    from agent_alpha.live_fire.browser_solve import DeepSeekBrowserSolve

    browser_solve = None
    browser_solve_viable = False
    if getattr(profile, "allow_evasion", False):
        browser_solve = DeepSeekBrowserSolve.from_env()
        browser_solve_viable = browser_solve is not None
        if browser_solve_viable:
            print(f"[BROWSER_SOLVE] Viable — endpoint={os.environ.get('A1_BROWSER_SOLVE_ENDPOINT', 'not set')}")
        else:
            print("[BROWSER_SOLVE] Not viable — A1_BROWSER_SOLVE_ENDPOINT not set")
    else:
        print("[BROWSER_SOLVE] Skipped — profile does not allow evasion")

    # 4. Run recon synchronously
    print("[RECON] Starting...")
    t0 = time.time()
    result = run_recon_for_engagement(
        engagement_id=eid,
        tenant_id=None,
        auth=auth,
        store=event_store,
        record=auth.get_record(eid),
        secrets_manager=secrets_manager,
        engagement_profile=profile,
        browser_solve=browser_solve,
        browser_solve_viable=browser_solve_viable,
    )
    elapsed = time.time() - t0

    # 5. Print results
    print(f"\n{'=' * 60}")
    print(f"Engagement: {eid}")
    print(f"Target:     {TARGET}")
    print(f"Duration:   {elapsed:.1f}s")
    print(f"Nodes:      {result.node_count}")
    print(f"Targets:    {result.targets_scanned}")
    if result.enumerated_hosts:
        print(f"Enumerated: {result.enumerated_hosts}")
    print(f"{'=' * 60}")

    # 6. Print report
    report = result.report
    print(f"\nReport:\n{report.narrative}")

    # 7. Print graph nodes
    graph = NetworkXGraphStore()
    from agent_alpha.graph.store import rebuild_from_events

    rebuild_from_events(graph, event_store.get_events(eid))
    print(f"\nGraph nodes ({graph.node_count()}):")
    for node in graph.all_nodes():
        print(f"  [{node.type}] {node.id} (confidence={node.confidence})")

    # 8. Print findings
    from agent_alpha.graph.nodes import NodeType
    findings = [n for n in graph.all_nodes() if n.type == NodeType.VULNERABILITY]
    print(f"\nFindings: {len(findings)}")
    for n in findings:
        props = n.properties if hasattr(n, "properties") else None
        cve = getattr(props, "cve_id", "?") if props else "?"
        print(f"  {n.id} (cve={cve}, confidence={n.confidence})")

    print(f"\n{'=' * 60}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
