#!/usr/bin/env python3
"""Synchronous engagement runner — bypasses Celery, calls run_recon_for_engagement directly."""

from __future__ import annotations

import os
import time

_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    for line in open(_env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

os.environ.setdefault("AGENT_ALPHA_SKIP_DOMAIN_VERIFICATION", "1")

# Allow forcing InMemoryEventStore (e.g. local run without PostgreSQL)
if os.environ.get("AGENT_ALPHA_USE_MEMORY_STORE", "").strip().lower() in ("1", "true", "yes"):
    os.environ.pop("AGENT_ALPHA_PG_DSN", None)
if not os.environ.get("A1_BROWSER_SOLVE_ENDPOINT", "").strip():
    os.environ["A1_BROWSER_SOLVE_ENDPOINT"] = "http://127.0.0.1:8080/solve"

from agent_alpha.a2a import a2a_pb2  # noqa: E402
from agent_alpha.agents.beta.strike import Beta  # noqa: E402
from agent_alpha.agents.http_client import HttpClient  # noqa: E402
from agent_alpha.conductor.applicator_factory import (  # noqa: E402
    beta_web_applicators,
    build_applicators_for_engagement,
)
from agent_alpha.conductor.authorization import (  # noqa: E402
    AuthorizationStateMachine,
    authorize_engagement,
)
from agent_alpha.conductor.execute_agent import rebuild_graph_from_events  # noqa: E402
from agent_alpha.conductor.recon_runner import run_recon_for_engagement  # noqa: E402
from agent_alpha.conductor.reporting import build_engagement_report  # noqa: E402
from agent_alpha.events.store import PostgresEventStore  # noqa: E402
from agent_alpha.graph.nodes import NodeType  # noqa: E402
from agent_alpha.llm.orchestrator import LLMOrchestrator  # noqa: E402
from agent_alpha.llm.routing import resolve_reasoning_provider  # noqa: E402
from agent_alpha.security.secrets import SecretsManager  # noqa: E402
from agent_alpha.tools.playbook import PlaybookEngine  # noqa: E402

CLIENT_ID = os.environ.get("SYNC_CLIENT_ID", "unibis")

# Targets to scan — main domain + any subdomains in SOW
_sync_env = os.environ.get("SYNC_TARGETS", "")
SYNC_TARGETS = [t.strip() for t in _sync_env.split(",") if t.strip()] or ["unibis.co.id"]

_PLAYBOOK_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "agent_alpha",
    "tools",
    "playbooks",
)


def run_one_target(target: str, event_store, auth, secrets_manager) -> None:
    import pathlib
    print(f"\n{'#' * 70}")
    print(f"# TARGET: {target}")
    print(f"{'#' * 70}")

    # ── 1. Create engagement ──────────────────────────────────
    record = auth.create_engagement(client_id=CLIENT_ID, target=target)
    eid = record.engagement_id
    print(f"\n[ENGAGEMENT] {eid} — target: {target}")

    # ── 2. Authorize (pre-discovery, no origins yet) ───────────
    signing_key = os.environ["PROFILE_SIGNING_KEY"].encode()
    profile = authorize_engagement(
        engagement_id=eid,
        client_id=CLIENT_ID,
        targets=[target],
        ownership_tokens={},
        dns_resolver=None,
        skip_domain_verification=True,
        consent_items=frozenset({"recon_only", "evasion"}),
        allow_evasion=True,
        signed_by="operator",
        signed_at="2026-07-29T00:00:00Z",
        authorized_origins=None,
        event_store=event_store,
        key=signing_key,
    )
    print(f"[AUTH] Signed profile: {sorted(profile.scope_targets)}")

    from agent_alpha.conductor.models import Scope

    scope = Scope(ip_ranges=[], domains=[target], exclusions=[])
    auth.enable_recon(eid, scope)
    print("[AUTH] RECON_ONLY enabled")

    # ── 2b. Discover origin IPs (bypass CF) ─────────────────────
    from agent_alpha.recon.origin_resolver import discover_origin_ips
    from agent_alpha.agents.http_client import HttpClient

    http_client = HttpClient(engagement_id=eid, timeout=60.0)
    origin_ips = discover_origin_ips(eid, target, http_client, auth)
    print(f"[AUTH] Origin IPs: {sorted(origin_ips) if origin_ips else 'none (all CF or unresponsive)'}")

    # Re-authorize with discovered origins if found
    if origin_ips:
        profile = authorize_engagement(
            engagement_id=eid,
            client_id=CLIENT_ID,
            targets=[target],
            ownership_tokens={},
            dns_resolver=None,
            skip_domain_verification=True,
            consent_items=frozenset({"recon_only", "evasion"}),
            allow_evasion=True,
            signed_by="operator",
            signed_at="2026-07-29T00:00:00Z",
            authorized_origins=frozenset(origin_ips),
            event_store=event_store,
            key=signing_key,
        )
        print(f"[AUTH] Re-signed profile with {len(origin_ips)} origin IPs")

    # ── 3. Wire browser_solve + origin_discovery ───────────────
    from agent_alpha.live_fire.browser_solve import DeepSeekBrowserSolve

    browser_solve = None
    browser_solve_viable = False
    if getattr(profile, "allow_evasion", False):
        browser_solve = DeepSeekBrowserSolve.from_env()
        browser_solve_viable = browser_solve is not None
        if browser_solve_viable:
            print(f"[BROWSER_SOLVE] Viable — endpoint={os.environ.get('A1_BROWSER_SOLVE_ENDPOINT')}")
        else:
            print("[BROWSER_SOLVE] Not viable")
    else:
        print("[BROWSER_SOLVE] Skipped — no evasion consent")

    from agent_alpha.recon.origin_discovery import StaticOriginDiscovery

    origin_discovery = None
    if profile.authorized_origins:
        origin_discovery = StaticOriginDiscovery(list(profile.authorized_origins))
        print(f"[ORIGIN_DIRECT] Wired — origins={sorted(profile.authorized_origins)}")
    else:
        print("[ORIGIN_DIRECT] No authorized origins (CF blocked all candidates)")

    # ── 4. Run Alpha recon ────────────────────────────────────
    print(f"\n{'─' * 70}")
    print(f"[ALPHA] Starting recon on {target}...")
    t0 = time.time()
    result = run_recon_for_engagement(
        engagement_id=eid,
        tenant_id="default",
        auth=auth,
        store=event_store,
        record=auth.get_record(eid),
        secrets_manager=secrets_manager,
        engagement_profile=profile,
        browser_solve=browser_solve,
        browser_solve_viable=browser_solve_viable,
        origin_discovery=origin_discovery,
    )
    alpha_elapsed = time.time() - t0
    print(f"[ALPHA] Done in {alpha_elapsed:.1f}s — nodes: {result.node_count}, targets: {result.targets_scanned}")
    if result.enumerated_hosts:
        print(f"[ALPHA] Enumerated: {result.enumerated_hosts}")

    # ── 5. Rebuild graph + count findings ─────────────────────
    graph_store = rebuild_graph_from_events(event_store, eid)
    print(f"[GRAPH] Rebuilt — {graph_store.node_count()} nodes")

    vuln_count = 0
    cred_count = 0
    for node in graph_store.nodes_by_type(NodeType.VULNERABILITY):
        vuln_count += 1
        print(f"  [FINDING] vuln: {node.id} — {getattr(node.properties, 'affected_service', '')}")
    for node in graph_store.nodes_by_type(NodeType.CREDENTIAL):
        cred_count += 1
        print(f"  [FINDING] cred: {node.id} — {getattr(node.properties, 'service', '')}")
    alpha_findings = vuln_count + cred_count
    print(f"[ALPHA] Findings: {alpha_findings} ({vuln_count} vuln, {cred_count} cred)")

    # ── 6. Beta (only if Alpha found findings) ────────────────
    if alpha_findings == 0:
        print(f"\n{'─' * 70}")
        print("[BETA] SKIPPED — Alpha found 0 findings, no attack surface")
    else:
        print(f"\n{'─' * 70}")
        print(f"[BETA] Alpha found {alpha_findings} finding(s) — enabling ACTIVE_APPROVED...")
        auth.enable_active(eid)
        print("[BETA] ACTIVE_APPROVED enabled")

        http_client = HttpClient(engagement_id=eid)
        provider = resolve_reasoning_provider(api_key=os.environ["DEEPSEEK_API_KEY"])
        orchestrator = LLMOrchestrator(
            PlaybookEngine.from_directory(pathlib.Path(_PLAYBOOK_DIR), phase="access"),
            provider,
        )

        candidates = beta_web_applicators(http_client)
        applicators = build_applicators_for_engagement(
            engagement_id=eid,
            auth=auth,
            graph_store=graph_store,
            web_target=target,
            candidates=candidates,
        )

        beta = Beta(
            authorization=auth,
            graph_store=graph_store,
            event_store=event_store,
            orchestrator=orchestrator,
            http_client=http_client,
            secrets_manager=secrets_manager,
            cred_applicators=applicators,
        )

        print(f"[BETA] Starting strike on {target}...")
        t0 = time.time()
        try:
            entry_point = f"https://{target}" if not target.startswith(("http://", "https://")) else target
            msg = beta.run_strike(eid, entry_point)
            beta_elapsed = time.time() - t0
            payload = a2a_pb2.HandoffPayload()
            payload.ParseFromString(msg.payload)
            status_name = a2a_pb2.PhaseStatus.Name(payload.status)
            print(f"[BETA] Done in {beta_elapsed:.1f}s — status: {status_name}, proofs: {len(payload.proof_artifacts)}")
        except Exception as exc:
            beta_elapsed = time.time() - t0
            print(f"[BETA] Failed in {beta_elapsed:.1f}s — {exc}")

        graph_store = rebuild_graph_from_events(event_store, eid)
        print(f"[GRAPH] Rebuilt after Beta — {graph_store.node_count()} nodes")

    # ── 7. Omega report ───────────────────────────────────────
    print(f"\n{'─' * 70}")
    print(f"[OMEGA] Generating report for {target}...")
    report = build_engagement_report(graph_store, event_store, eid, style="technical")
    print("[OMEGA] Report generated")
    print(f"\n{'=' * 70}")
    print(f"REPORT: {target}")
    print(f"{'=' * 70}")
    print(report.narrative)
    if report.mitre_techniques:
        print(f"\nMITRE ATT&CK techniques: {', '.join(report.mitre_techniques)}")
    if report.blocked_hosts:
        print(f"\nBlocked hosts: {', '.join(report.blocked_hosts)}")
    print(f"{'=' * 70}\n")

    # ── 8. Print events ───────────────────────────────────────
    events = event_store.get_events(eid)
    print(f"Events ({len(events)}):")
    for e in events:
        print(f"  {e.event_type}: {e.payload}")
    print()


def main() -> int:
    dsn = os.environ.get("AGENT_ALPHA_PG_DSN", "")
    if dsn:
        event_store = PostgresEventStore(dsn=dsn, tenant_id="default")
        print(f"[PG] Connected: {dsn[:40]}...")
    else:
        from agent_alpha.events.store import InMemoryEventStore
        event_store = InMemoryEventStore()
        print("[PG] No DSN — using InMemoryEventStore")

    auth = AuthorizationStateMachine(event_store=event_store)
    secrets_manager = SecretsManager()

    for target in SYNC_TARGETS:
        try:
            run_one_target(target, event_store, auth, secrets_manager)
        except Exception as exc:
            print(f"\n[ERROR] Target {target} failed: {exc}")
            import traceback
            traceback.print_exc()
            continue

    print(f"\n{'#' * 70}")
    print(f"# ALL TARGETS COMPLETE: {', '.join(SYNC_TARGETS)}")
    print(f"{'#' * 70}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
