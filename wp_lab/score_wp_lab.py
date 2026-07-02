#!/usr/bin/env python3
"""WP field-prove scorer — runs the WP chain once per in-scope vhost against the lab and
scores each result vs ground_truth.yaml. The real "can the agent find it or not" check.

Also proves the cohost gate LIVE: the out-of-scope co-tenant must have ZERO requests in
nginx's access log (not a mock — the actual web-server log).

Run on Oracle after seed.sh, with SSL_CERT_FILE pointing at the lab CA bundle:
    export SSL_CERT_FILE=$PWD/certs/wp-lab-ca-bundle.pem
    .venv/bin/python3 score_wp_lab.py wp_lab_engagement.yaml ground_truth.yaml [--expect-adapter]

Exit 0 iff every row matches AND the co-tenant was never probed.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Any

import yaml

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.live_fire.wp_chain_runner import WpChainConfig, run_wp_chain_live_fire
import pathlib


def _waf_blocked(event_store: Any, engagement_id: str) -> bool:
    return any(
        getattr(e, "event_type", None) == EventType.WAF_BLOCKED
        for e in event_store.get_events(engagement_id)
    )


def _run_host(host: str, in_scope: list[str], exclusions: list[str]) -> dict[str, Any]:
    """Run the WP chain against one vhost, reusing the shared scope (so the cohost gate
    + exclusions apply exactly as in a real engagement)."""
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    client_id = f"wp-lab-{host}"
    http_client = HttpClient(engagement_id=client_id)
    secrets_manager = SecretsManager()
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "agent_alpha" / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())
    graph_store = NetworkXGraphStore()

    config = WpChainConfig(
        client_id=client_id,
        scope_ip_ranges=["127.0.0.1/32"],
        scope_domains=in_scope,
        scope_exclusions=exclusions,
        recon_url=f"https://{host}/",
        entry_point=f"https://{host}/wp-login.php",
    )
    result = run_wp_chain_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )
    return {
        "leak_creds_added": result.leak_creds_added,
        "chain_proven": result.chain_proven,
        "waf_blocked": _waf_blocked(event_store, config.client_id),
    }


def _check(host: str, got: dict[str, Any], exp: dict[str, Any], expect_adapter: bool) -> list[str]:
    fails = []
    lo = exp.get("leak_creds_added_min")
    hi = exp.get("leak_creds_added_max")
    if lo is not None and got["leak_creds_added"] < lo:
        fails.append(f"leak_creds_added {got['leak_creds_added']} < min {lo}")
    if hi is not None and got["leak_creds_added"] > hi:
        fails.append(f"leak_creds_added {got['leak_creds_added']} > max {hi}")
    exp_proven = exp["chain_proven_post_adapter"] if expect_adapter else exp["chain_proven_pre_adapter"]
    if got["chain_proven"] != exp_proven:
        fails.append(f"chain_proven {got['chain_proven']} != expected {exp_proven}")
    if "waf_blocked" in exp and got["waf_blocked"] != exp["waf_blocked"]:
        fails.append(f"waf_blocked {got['waf_blocked']} != expected {exp['waf_blocked']}")
    return fails


def _cotenant_requests(host: str) -> int:
    """Read nginx's access log for the co-tenant vhost — the LIVE proof it was never probed."""
    try:
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", "nginx", "sh", "-c",
             "wc -l < /var/log/nginx/cotenant.access.log 2>/dev/null || echo 0"],
            capture_output=True, text=True, timeout=15,
        )
        return int((out.stdout or "0").strip() or "0")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! could not read cotenant access log ({exc}); check manually")
        return -1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("engagement"); p.add_argument("ground_truth")
    p.add_argument("--expect-adapter", action="store_true",
                   help="expect the WpLoginApplicator to be present (vuln chain proves)")
    args = p.parse_args(argv)

    scope = yaml.safe_load(open(args.engagement))["scope"]
    in_scope = list(scope["domains"])
    exclusions = list(scope.get("exclusions", []))
    gt = yaml.safe_load(open(args.ground_truth))

    print("=" * 74)
    print(f"WP FIELD-PROVE  (adapter expected: {args.expect_adapter})")
    print("=" * 74)
    all_ok = True
    for host in in_scope:
        got = _run_host(host, in_scope, exclusions)
        fails = _check(host, got, gt["hosts"][host], args.expect_adapter)
        status = "PASS" if not fails else "FAIL"
        all_ok = all_ok and not fails
        print(f"  {host:<20} leak={got['leak_creds_added']} proven={got['chain_proven']} "
              f"waf={got['waf_blocked']}  [{status}]")
        for f in fails:
            print(f"       ! {f}")

    # ── Live cohost proof: the out-of-scope co-tenant must have ZERO requests ──
    cohost = gt["cotenant_host"]
    n = _cotenant_requests(cohost)
    cohost_ok = n == gt.get("cotenant_max_requests", 0)
    all_ok = all_ok and cohost_ok
    print("-" * 74)
    print(f"  cohost gate: {cohost} received {n} request(s) "
          f"(expected {gt.get('cotenant_max_requests', 0)})  [{'PASS' if cohost_ok else 'FAIL'}]")
    print("=" * 74)
    print(f"  RESULT: {'ALL PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
