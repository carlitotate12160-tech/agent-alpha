"""CodeIgniter config-leak field-prove harness (Phase 4 slice-1c-1).

Validates the Alpha CodeIgniter config-leak vector end-to-end on a self-owned
lab, through the SAME full live path as backup_file / git_exposure / spa_secret:
Alpha.run_recon → fingerprint 'codeigniter' → derive /application/config/
database.php → dispatch codeigniter_config_probe → parse DB credentials →
extract → vault → mint.

RUNNER-SEAL, NOT AUTONOMOUS-WIRED: this proves the vector via Alpha.run_recon
(the Alpha recon path). It self-authorizes and BYPASSES the Conductor — legitimate
ONLY for a self-owned lab (assert_lab_only_target). The Conductor autonomous seal
is a separate proof (verify_access_nodes at conductor/main.py); track that gap in
tests/governance/test_wiring_gate.py, do not claim it from this runner.

Lab-only (assert_lab_only_target, fail-closed). Run on Oracle ARM64:
    python -m agent_alpha.live_fire.codeigniter_field_prove <engagement.yaml>
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any
from urllib.parse import urlparse

import yaml

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config.stores import build_event_store
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.live_fire.field_prove_common import credential_vaulted
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

# Leak VULNERABILITY node id substring for the CI config-leak vector (matches
# the id minted by the codeigniter_config probe path).
_CI_LEAK_NODE_MARKER = "ci_config"


@dataclasses.dataclass(frozen=True)
class CodeIgniterConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str


@dataclasses.dataclass(frozen=True)
class CodeIgniterResult:
    creds_added: int
    credential_vaulted: bool
    leak_detected: bool

    @property
    def chain_proven(self) -> bool:
        # Every clause REQUIRED (anti-#3): a leak node without a resolvable
        # vaulted credential is presence, not a payable finding.
        return self.creds_added > 0 and self.credential_vaulted and self.leak_detected


def load_codeigniter_config(path: str | pathlib.Path) -> CodeIgniterConfig:
    # skipcq: PTC-W6004 — live-fire CLI loads an operator-supplied YAML config from argv,
    # same pattern as all sibling live_fire/load_*_config helpers (lab_guard validates the domain).
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("codeigniter field-prove config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url"):
        if key not in data:
            raise ValueError(f"codeigniter field-prove config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"codeigniter field-prove config scope missing required key: {key!r}")
    return CodeIgniterConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope["exclusions"]),
        recon_url=data["recon_url"],
    )


def run_codeigniter_field_prove(
    config: CodeIgniterConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
) -> dict[str, CodeIgniterResult]:
    """Alpha recon (CI config-leak vector) on each target domain, via run_recon."""
    results: dict[str, CodeIgniterResult] = {}

    for target in config.scope_domains:
        rec = auth.create_engagement(client_id=config.client_id, target=target)
        auth.enable_recon(
            rec.engagement_id,
            Scope(
                ip_ranges=config.scope_ip_ranges,
                domains=[target],
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
        )

        # Derive per-target recon URL — same scheme/port as config.recon_url,
        # but hostname from the iteration target. The codeigniter lab runs
        # vuln + hardened as Host-header vhosts on the same IP:port (127.0.0.1:8444);
        # a fixed recon_url would fetch the WRONG vhost for the 2nd target.
        parsed = urlparse(config.recon_url)
        port_suffix = f":{parsed.port}" if parsed.port else ""
        target_url = f"{parsed.scheme}://{target}{port_suffix}/"
        alpha.run_recon(rec.engagement_id, target_url)

        creds_added = len(graph_store.nodes_by_type(NodeType.CREDENTIAL))
        leak_nodes = [
            n
            for n in graph_store.nodes_by_type(NodeType.VULNERABILITY)
            if _CI_LEAK_NODE_MARKER in getattr(n, "id", "")
        ]
        results[target] = CodeIgniterResult(
            creds_added=creds_added,
            credential_vaulted=credential_vaulted(graph_store, secrets_manager),
            leak_detected=len(leak_nodes) > 0,
        )

        # Isolate per-target graph state (public API, not private _graph).
        graph_store.clear()

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha CodeIgniter config-leak field-prove")
    parser.add_argument("config", help="Path to codeigniter engagement YAML config")
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip TLS verification (for self-signed lab certs)",
    )
    args = parser.parse_args(argv)

    config = load_codeigniter_config(args.config)

    from agent_alpha.live_fire.lab_guard import assert_lab_only_target

    for domain in config.scope_domains:
        assert_lab_only_target(domain)

    event_store = build_event_store()
    auth = AuthorizationStateMachine(event_store=event_store)
    # TLS verification is opt-out ONLY for self-owned lab_guard targets with self-signed certs;
    # production recon uses the secure default (verify=True).
    http_client = HttpClient(engagement_id=config.client_id, verify=not args.no_verify)
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())

    results = run_codeigniter_field_prove(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    print("=" * 64)
    print("CODEIGNITER CONFIG-LEAK LIVE-FIRE RESULTS")
    print("=" * 64)

    all_proven = True
    for target, result in results.items():
        print(f"TARGET: {target}")
        print(f"  Leak creds added       : {result.creds_added}")
        print(f"  Credential vaulted     : {result.credential_vaulted}")
        print(f"  Leak detected          : {result.leak_detected}")
        if "vuln" in target:
            proven = result.chain_proven
            print(f"  EXPECTED POSITIVE PROVEN: {proven}")
            if not proven:
                all_proven = False
        elif "hardened" in target:
            proven = (
                result.creds_added == 0
                and not result.credential_vaulted
                and not result.leak_detected
            )
            print(f"  EXPECTED NEGATIVE PROVEN: {proven}")
            if not proven:
                all_proven = False
        else:
            # A target that is neither a known vuln nor hardened label would be
            # SILENTLY skipped, leaving all_proven=True — a false pass. Fail loud.
            raise ValueError(f"unknown field-prove target label: {target!r}")
        print("-" * 64)

    print(f"OVERALL CHAIN PROVEN: {all_proven}")
    print("=" * 64)
    return 0 if all_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
