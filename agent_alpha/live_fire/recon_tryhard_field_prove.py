"""Recon try-hard field-prove harness (D2-b).

Validates the Alpha Try-Harder recovery against a late-discovered host leak.
Two-run differential: greedy misses a sibling's leak, planner finds it.

Lab-only (assert_lab_only_target). Run:
    python -m agent_alpha.live_fire.recon_tryhard_field_prove <engagement.yaml>
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any

import yaml

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.base import BoundedAutonomy, run_cognitive_loop
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.field_prove_common import credential_vaulted
from agent_alpha.live_fire.lab_guard import assert_lab_only_target
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine


class _DeterministicStubProvider:
    """Deterministic stub provider — mirrors the offline CI test.

    Returns ``generic_http_probe`` for every orient call so boring roots
    mint ASSET nodes → graph has hosts → try_harder seeds well-known paths.
    The field-prove is rule-tier (backup_file leak), not LLM-quality.
    """

    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object) -> Any:
        return type(
            "R",
            (),
            {
                "text": '{"tool": "generic_http_probe", "reasoning": "stub"}',
                "usage_cost_usd": 0.0,
                "model": "deepseek-v4-pro",
            },
        )()


@dataclasses.dataclass(frozen=True)
class ReconTryHardConfig:
    """Configuration for the Try-Harder recon live-fire test."""

    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str
    seed_hosts: list[str]


def load_recon_tryhard_config(path: str | pathlib.Path) -> ReconTryHardConfig:
    """Load and validate the recon try-harder configuration from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("recon tryhard config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url", "seed_hosts"):
        if key not in data:
            raise ValueError(f"recon tryhard config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"recon tryhard config scope missing required key: {key!r}")
    return ReconTryHardConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope["exclusions"]),
        recon_url=data["recon_url"],
        seed_hosts=list(data["seed_hosts"]),
    )


def run_recon_tryhard_field_prove(
    config: ReconTryHardConfig,
    orchestrator: Any,
) -> bool:
    """Alpha recon try-harder differential (Run A vs Run B)."""

    def _run_pass(try_harder_enabled: bool) -> tuple[int, bool, Any, Any, str]:
        """Run Alpha with the given try_harder_enabled flag, isolated state."""
        event_store = InMemoryEventStore()
        auth = AuthorizationStateMachine(event_store=event_store)
        secrets_manager = SecretsManager()
        graph_store = NetworkXGraphStore()
        http_client = HttpClient(engagement_id=config.client_id)

        rec = auth.create_engagement(client_id=config.client_id, target=config.recon_url)
        auth.enable_recon(
            rec.engagement_id,
            Scope(
                ip_ranges=config.scope_ip_ranges,
                domains=config.scope_domains,
                exclusions=config.scope_exclusions,
            ),
        )

        alpha = Alpha(
            authorization=auth,
            graph_store=graph_store,
            event_store=event_store,
            orchestrator=orchestrator,
            http_client=http_client,
            secrets_manager=secrets_manager,
            try_harder_enabled=try_harder_enabled,
        )

        # Drive the loop manually for seed injection (layer_v_runner pattern).
        # We DO NOT call run_recon() as that restricts initial seeds to target_url.
        alpha._engagement_id = rec.engagement_id
        alpha._work_queue = []
        alpha._probed = set()
        alpha._findings = 0
        alpha._analyzable_probes = 0
        alpha._ran_campaigns = set()
        alpha._body_hashes = set()
        alpha._current_objective = None
        alpha._try_harder_fired = False

        for host_url in config.seed_hosts:
            alpha.enqueue_discovered_url(host_url)

        policy = BoundedAutonomy(no_progress_threshold=constants.ALPHA_RECON_NO_PROGRESS_ITERS)
        run_cognitive_loop(
            alpha,
            policy,
            event_store=event_store,
            engagement_id=rec.engagement_id,
        )

        cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
        # Filter for late.recon.lab credentials
        late_creds = [
            n
            for n in cred_nodes
            if "late.recon.lab" in str(n.id)
            or "late.recon.lab" in getattr(n.properties, "host", "")
        ]
        creds_added = len(late_creds)

        is_vaulted = credential_vaulted(graph_store, secrets_manager)

        return creds_added, is_vaulted, graph_store, event_store, rec.engagement_id

    print("Running Run A (try_harder_enabled=False)...")
    a_creds, _, _, a_event_store, _ = _run_pass(try_harder_enabled=False)

    print("Running Run B (try_harder_enabled=True)...")
    b_creds, b_vaulted, b_graph_store, b_event_store, b_engagement_id = _run_pass(
        try_harder_enabled=True
    )

    print("=" * 64)
    print("RECON TRY-HARDER LIVE-FIRE RESULTS")
    print("=" * 64)

    a_missed = a_creds == 0
    b_found = b_creds > 0
    proven = a_missed and b_found and b_vaulted

    print(f"Run A (Greedy)  - missed credential? : {a_missed} (found {a_creds})")
    print(f"Run B (Planner) - found credential?  : {b_found} (found {b_creds})")
    print(f"Run B (Planner) - credential vaulted?: {b_vaulted}")

    # Check decoys, waffs, dead, hardened in Run B graph/events
    b_all_creds = list(b_graph_store.nodes_by_type(NodeType.CREDENTIAL))
    decoy_creds = len(
        [
            n
            for n in b_all_creds
            if "decoy.recon.lab" in str(n.id)
            or "decoy.recon.lab" in getattr(n.properties, "host", "")
        ]
    )
    hardened_creds = len(
        [
            n
            for n in b_all_creds
            if "hardened.recon.lab" in str(n.id)
            or "hardened.recon.lab" in getattr(n.properties, "host", "")
        ]
    )
    dead_creds = len(
        [
            n
            for n in b_all_creds
            if "dead.recon.lab" in str(n.id)
            or "dead.recon.lab" in getattr(n.properties, "host", "")
        ]
    )

    b_events = b_event_store.get_events(b_engagement_id)

    # waf.recon.lab should be CHALLENGE
    waf_events = [
        e
        for e in b_events
        if e.event_type == EventType.WAF_BLOCKED and e.payload.get("host") == "waf.recon.lab"
    ]
    waf_challenge_proven = any(e.payload.get("signal") == "cf_challenge" for e in waf_events)

    # dead.recon.lab should be BLOCKED (503)
    dead_events = [
        e
        for e in b_events
        if e.event_type == EventType.WAF_BLOCKED and e.payload.get("host") == "dead.recon.lab"
    ]
    dead_blocked_proven = len(dead_events) > 0

    print(f"Decoy 0 credentials?                 : {decoy_creds == 0}")
    print(f"WAF classified CHALLENGE?            : {waf_challenge_proven}")
    print(f"Dead non-analyzable (no crash)?      : {dead_blocked_proven and dead_creds == 0}")
    print(f"Hardened 0 credentials?              : {hardened_creds == 0}")

    overall_proven = (
        proven
        and decoy_creds == 0
        and waf_challenge_proven
        and dead_blocked_proven
        and dead_creds == 0
        and hardened_creds == 0
    )

    print("-" * 64)
    print(f"GREEDY-FAILS/PLANNER-WINS PROVEN: {overall_proven}")
    print("=" * 64)

    return overall_proven


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for the try-harder field prove."""
    parser = argparse.ArgumentParser(description="Agent-Alpha Recon Try-Harder field-prove")
    parser.add_argument("config", help="Path to recon try-harder engagement YAML config")
    args = parser.parse_args(argv)

    config = load_recon_tryhard_config(args.config)

    for domain in config.scope_domains:
        assert_lab_only_target(domain)

    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(
        PlaybookEngine.from_directory(playbook_dir), _DeterministicStubProvider()
    )

    overall_proven = run_recon_tryhard_field_prove(
        config,
        orchestrator=orchestrator,
    )

    return 0 if overall_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
