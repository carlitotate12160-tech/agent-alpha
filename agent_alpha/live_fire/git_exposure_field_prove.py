"""Git exposure field-prove harness (Phase 4 slice-1c-ii).

Validates the Alpha GitDumper integration and credential extraction logic
on a self-owned lab.

Lab-only (assert_lab_only_target). Run:
    python -m agent_alpha.live_fire.git_exposure_field_prove <engagement.yaml>
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any

import yaml

from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.git_exposure_probe import GitDumper, verify_git_exposure
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine


@dataclasses.dataclass(frozen=True)
class GitExposureConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str


@dataclasses.dataclass(frozen=True)
class GitExposureResult:
    creds_added: int
    credential_vaulted: bool
    exposure_detected: bool

    @property
    def chain_proven(self) -> bool:
        return self.creds_added > 0 and self.credential_vaulted and self.exposure_detected


def load_git_exposure_config(path: str | pathlib.Path) -> GitExposureConfig:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("git exposure config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url"):
        if key not in data:
            raise ValueError(f"git exposure config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"git exposure config scope missing required key: {key!r}")
    return GitExposureConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope["exclusions"]),
        recon_url=data["recon_url"],
    )


def _credential_vaulted(graph_store: Any, secrets_manager: Any) -> bool:
    """True iff a CREDENTIAL node has a resolvable vault pointer (secret_ref)."""
    cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
    for node in cred_nodes:
        ref = getattr(node.properties, "secret_ref", "")
        if not ref.startswith("secret_"):
            continue
        try:
            secrets_manager.retrieve(ref)
            return True
        except Exception:
            continue
    return False


def run_git_exposure_live_fire(
    config: GitExposureConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
    dumper: Any = None,
) -> dict[str, GitExposureResult]:
    """Alpha recon (git exposure probe) on each target domain."""
    results: dict[str, GitExposureResult] = {}

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

        creds_added = verify_git_exposure(
            engagement_id=rec.engagement_id,
            auth=auth,
            http_client=http_client,
            scope_hosts=[target],
            graph_store=graph_store,
            event_store=event_store,
            secrets_manager=secrets_manager,
            dumper=dumper or GitDumper(),
        )

        # Check exposure detected by verifying VULNERABILITY nodes exist
        vuln_nodes = [
            n
            for n in graph_store.nodes_by_type(NodeType.VULNERABILITY)
            if "git_exposure" in getattr(n, "id", "")
        ]
        exposure_detected = len(vuln_nodes) > 0

        results[target] = GitExposureResult(
            creds_added=creds_added,
            credential_vaulted=_credential_vaulted(graph_store, secrets_manager),
            exposure_detected=exposure_detected,
        )

        # Clear graph for the next iteration to isolate per target
        if hasattr(graph_store, "_graph"):
            graph_store._graph.clear()
        elif hasattr(graph_store, "graph"):
            graph_store.graph.clear()

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha Git exposure field-prove")
    parser.add_argument("config", help="Path to git exposure engagement YAML config")
    args = parser.parse_args(argv)

    config = load_git_exposure_config(args.config)

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

    results = run_git_exposure_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    print("=" * 64)
    print("GIT EXPOSURE LIVE-FIRE RESULTS")
    print("=" * 64)

    all_proven = True

    for target, result in results.items():
        print(f"TARGET: {target}")
        print(f"  Leak creds added       : {result.creds_added}")
        print(f"  Credential vaulted     : {result.credential_vaulted}")
        print(f"  Exposure detected      : {result.exposure_detected}")

        if "vuln" in target:
            proven = result.chain_proven
            print(f"  EXPECTED POSITIVE PROVEN: {proven}")
            if not proven:
                all_proven = False
        elif "hardened" in target:
            proven = (
                result.creds_added == 0
                and not result.credential_vaulted
                and not result.exposure_detected
            )
            print(f"  EXPECTED NEGATIVE PROVEN: {proven}")
            if not proven:
                all_proven = False
        print("-" * 64)

    print(f"OVERALL CHAIN PROVEN: {all_proven}")
    print("=" * 64)

    return 0 if all_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
