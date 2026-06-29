"""Cred-reuse CHAIN live-fire — single process, Alpha → Beta, one SecretsManager.

Proves the multi-hop a scanner can't assemble, end-to-end against a real server:
  Alpha recon leaks a credential (e.g. DB_PASSWORD via a Laravel debug page) →
  VAULTS it → writes a CREDENTIAL node → Beta cred_reuse RETRIEVES the vaulted
  secret and reuses it on the login → access → credential→access ENABLES edge.

This is a PASSWORD-REUSE finding (leaked DB password also works on the web admin
login) — a real, payable pattern, not just wiring.

SINGLE-PROCESS by design: SecretsManager is in-memory + per-instance key, so Alpha
and Beta MUST share one instance (multi-worker needs a persistent shared vault —
later). No DeepSeek key needed: the Laravel + login playbooks keep both agents
rule-tier (_NoLLMProvider raises if the LLM is ever reached).
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any

import yaml

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.applicator_factory import build_applicators_for_engagement
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.live_fire.beta_runner import _NoLLMProvider, _scan_leak
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine


@dataclasses.dataclass(frozen=True)
class ChainConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    recon_url: str  # where Alpha harvests the leaked credential
    login_url: str  # where Beta reuses it


@dataclasses.dataclass(frozen=True)
class ChainResult:
    status: int
    gained_access: bool
    edge_from_harvested_cred: bool  # the chain is REAL (edge source = Alpha's vaulted node)
    leak_suspected: bool

    @property
    def chain_proven(self) -> bool:
        return self.gained_access and self.edge_from_harvested_cred and not self.leak_suspected


def load_chain_config(path: str | pathlib.Path) -> ChainConfig:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("chain config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url", "login_url"):
        if key not in data:
            raise ValueError(f"chain config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains"):
        if key not in scope:
            raise ValueError(f"chain config scope missing required key: {key!r}")
    return ChainConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        recon_url=data["recon_url"],
        login_url=data["login_url"],
    )


def _edge_from_harvested_cred(graph_store: Any, secrets_manager: Any) -> bool:
    """True iff an ENABLES edge to an ACCESS_LEVEL node originates from an Alpha
    HARVESTED+VAULTED credential (its secret_ref is a vault id that resolves) —
    NOT a Beta-minted default node. This is the real-vs-fake chain check."""
    access_ids = {n.id for n in graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)}
    cred_by_id = {n.id: n for n in graph_store.nodes_by_type(NodeType.CREDENTIAL)}
    for edge in graph_store.edges_by_relationship(RelationshipType.ENABLES):
        if edge.target_id not in access_ids or edge.source_id not in cred_by_id:
            continue
        ref = getattr(cred_by_id[edge.source_id].properties, "secret_ref", "")
        if not ref.startswith("secret_"):  # vault id format → Alpha harvested
            continue
        try:
            secrets_manager.retrieve(ref)  # resolves → genuinely vaulted
            return True
        except Exception:
            continue
    return False


def run_chain_live_fire(
    config: ChainConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
) -> ChainResult:
    """Alpha recon (vault) → Beta cred_reuse (retrieve+reuse) in ONE engagement."""
    rec = auth.create_engagement(client_id=config.client_id, target=config.scope_domains[0])
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=config.scope_ip_ranges, domains=config.scope_domains, exclusions=[]),
    )

    # ── Alpha: recon harvests + VAULTS the leaked credential ──
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    alpha.run_recon(rec.engagement_id, config.recon_url)

    # ── Escalate, then Beta reuses the vaulted credential ──
    auth.enable_active(rec.engagement_id)
    candidates = [HttpFormApplicator(http_client=http_client)]
    applicators = build_applicators_for_engagement(
        engagement_id=rec.engagement_id,
        auth=auth,
        graph_store=graph_store,
        web_target=config.login_url,
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
    msg = beta.run_strike(rec.engagement_id, config.login_url)
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)

    return ChainResult(
        status=payload.status,
        gained_access=payload.status == a2a_pb2.COMPLETE,
        edge_from_harvested_cred=_edge_from_harvested_cred(graph_store, secrets_manager),
        leak_suspected=_scan_leak(event_store, rec.engagement_id),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha cred-reuse chain live-fire")
    parser.add_argument("config", help="Path to chain engagement YAML config")
    args = parser.parse_args(argv)

    config = load_chain_config(args.config)

    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id)
    secrets_manager = SecretsManager()  # ONE shared instance (single-process)
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())
    graph_store = NetworkXGraphStore()

    result = run_chain_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    print("=" * 64)
    print("CRED-REUSE CHAIN LIVE-FIRE SCORECARD")
    print("=" * 64)
    print(f"  Recon (harvest+vault) : {config.recon_url}")
    print(f"  Reuse (login)         : {config.login_url}")
    print(f"  Access gained         : {result.gained_access}")
    print(f"  Edge from Alpha cred  : {result.edge_from_harvested_cred}  (real chain, not fake)")
    print(f"  Leak suspected        : {result.leak_suspected}")
    print("-" * 64)
    print(f"  Verdict: {'CHAIN PROVEN' if result.chain_proven else 'FAIL'}")
    print("=" * 64)

    from agent_alpha.agents.omega.roaster import Omega

    report = Omega(graph_store).generate_report("technical")
    cf = report.chain_finding
    print()
    print("OMEGA REPORT (chain finding)")
    print("-" * 64)
    if cf is None:
        print("  No cred-reuse chain finding produced.")
    else:
        print(f"  Severity        : {cf.severity.upper()}")
        print(f"  Credential      : {cf.credential_id}")
        print(f"  Access          : {cf.access_id}  (level={cf.access_level})")
        print(f"  Downstream mapped: {cf.downstream_mapped}")
        print(f"  Rationale       : {cf.rationale}")
        print(f"  MITRE           : {', '.join(report.mitre_techniques)}")
    print("=" * 64)

    return 0 if result.chain_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
