"""Backup-file exposure field-prove harness (Phase 4 slice-1c).

Validates the Alpha backup-file leak vector (verify_backup_file) end-to-end on a
self-owned lab, through the SAME full live path Layer V and git_exposure set:
Alpha.run_recon → seed backup paths (WELL_KNOWN_LEAK_PATHS) → playbook rule →
dispatch → _handle_backup_file → verify_backup_file → extract → vault → mint.

DIRECT (no dumper): unlike git_exposure there is no GitDumper reconstruction — a
200 on a backup path IS the recovered content. So this runner threads no dumper.

Lab-only (assert_lab_only_target). Run on Oracle ARM64:
    python -m agent_alpha.live_fire.backup_file_field_prove <engagement.yaml>
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any

import yaml

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.live_fire.field_prove_common import credential_vaulted
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine


@dataclasses.dataclass(frozen=True)
class BackupFileConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str


@dataclasses.dataclass(frozen=True)
class BackupFileResult:
    creds_added: int
    credential_vaulted: bool
    leak_detected: bool

    @property
    def chain_proven(self) -> bool:
        # Every clause REQUIRED (anti-#3): a leak node without a resolvable vaulted
        # credential is presence, not a payable finding.
        return self.creds_added > 0 and self.credential_vaulted and self.leak_detected


def load_backup_file_config(path: str | pathlib.Path) -> BackupFileConfig:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("backup file config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url"):
        if key not in data:
            raise ValueError(f"backup file config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"backup file config scope missing required key: {key!r}")
    return BackupFileConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope["exclusions"]),
        recon_url=data["recon_url"],
    )


def run_backup_file_field_prove(
    config: BackupFileConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
) -> dict[str, BackupFileResult]:
    """Alpha recon (backup-file leak vector) on each target domain, via run_recon."""
    results: dict[str, BackupFileResult] = {}

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

        # FULL live path — OBSERVE root → seed backup paths → rule → dispatch →
        # _handle_backup_file → verify_backup_file → mint. No dumper (DIRECT).
        alpha.run_recon(rec.engagement_id, config.recon_url)

        creds_added = len(graph_store.nodes_by_type(NodeType.CREDENTIAL))
        leak_nodes = [
            n
            for n in graph_store.nodes_by_type(NodeType.VULNERABILITY)
            if "backup_file" in getattr(n, "id", "")
        ]
        results[target] = BackupFileResult(
            creds_added=creds_added,
            credential_vaulted=credential_vaulted(graph_store, secrets_manager),
            leak_detected=len(leak_nodes) > 0,
        )

        # Isolate per-target graph state (public API, not private _graph).
        graph_store.clear()

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha backup-file field-prove")
    parser.add_argument("config", help="Path to backup-file engagement YAML config")
    args = parser.parse_args(argv)

    config = load_backup_file_config(args.config)

    from agent_alpha.live_fire.lab_guard import assert_lab_only_target

    for domain in config.scope_domains:
        assert_lab_only_target(domain)

    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id)
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())

    results = run_backup_file_field_prove(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    print("=" * 64)
    print("BACKUP FILE LIVE-FIRE RESULTS")
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
