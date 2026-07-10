"""Odoo cross-service cred-reuse CHAIN live-fire — Alpha recon → wp-config leak →
Beta (ranked → odoo_access) XML-RPC reuse.

Mirrors wp_chain_runner, but the ACCESS vector is OdooAccessTool (XML-RPC
``authenticate``), now reachable in the live path because Beta projects the recon
tech_stack into the ranking context (see _project_target_context). No cred_applicators
are passed: the web-form cred_reuse path is inert, so the XML-RPC tool is the access
mechanism.

Honest chain (the 1d bar):
  * ``db_enumerated`` — the db name came from XML-RPC ``db.list()``, NOT a host-label
    guess. A guessed db that authenticates is NOT a proven chain (db_source decision).
  * ``edge_from_harvested_cred`` — the ENABLES edge into the ACCESS_LEVEL node
    originates from Alpha's VAULTED credential (secret_ref resolves). This is the
    graph-level proof the access came from a REUSED harvested credential, not a
    built-in default (default-cred nodes carry no vault secret_ref).

Lab-only (assert_lab_only_target). Run:
    python -m agent_alpha.live_fire.odoo_chain_runner <engagement.yaml>
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any

import yaml

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.live_fire.beta_runner import _NoLLMProvider, _scan_leak
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.wp_config_probe import verify_wp_config_leak
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine


@dataclasses.dataclass(frozen=True)
class OdooChainConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str  # odoo host root — Alpha fingerprints odoo + harvests the config leak
    entry_point: str  # odoo base URL — OdooAccessTool posts XML-RPC here


@dataclasses.dataclass(frozen=True)
class OdooChainResult:
    leak_creds_added: int
    web_access_level: str  # "" | "user" | "admin" (from the ACCESS_LEVEL node)
    edge_from_harvested_cred: bool  # ENABLES edge source = Alpha's vaulted cred (=reused)
    db_enumerated: bool  # odoo_access proof shows db.list() enumeration, not a guess
    leak_suspected: bool

    @property
    def chain_proven(self) -> bool:
        return (
            self.leak_creds_added > 0
            and self.web_access_level in ("user", "admin")
            and self.edge_from_harvested_cred
            and self.db_enumerated
            and not self.leak_suspected
        )


def load_odoo_chain_config(path: str | pathlib.Path) -> OdooChainConfig:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("odoo chain config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url", "entry_point"):
        if key not in data:
            raise ValueError(f"odoo chain config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"odoo chain config scope missing required key: {key!r}")
    return OdooChainConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope["exclusions"]),
        recon_url=data["recon_url"],
        entry_point=data["entry_point"],
    )


def _web_access_level(graph_store: Any) -> str:
    nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)
    if not nodes:
        return ""
    return getattr(nodes[0].properties, "level", "")


def _edge_from_harvested_cred(graph_store: Any, secrets_manager: Any) -> bool:
    """True iff an ENABLES edge to an ACCESS_LEVEL node originates from an
    Alpha-harvested+vaulted credential (vault id resolves). This is the graph-level
    proof the access used a REUSED credential, not a built-in default."""
    access_ids = {n.id for n in graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)}
    cred_by_id = {n.id: n for n in graph_store.nodes_by_type(NodeType.CREDENTIAL)}
    for edge in graph_store.edges_by_relationship(RelationshipType.ENABLES):
        if edge.target_id not in access_ids or edge.source_id not in cred_by_id:
            continue
        ref = getattr(cred_by_id[edge.source_id].properties, "secret_ref", "")
        if not ref.startswith("secret_"):
            continue
        try:
            secrets_manager.retrieve(ref)
            return True
        except Exception:
            continue
    return False


def _db_enumerated(event_store: Any, engagement_id: str) -> bool:
    """True iff the odoo_access authenticate proof shows db_source=='enumerated'
    (db.list() returned the name), never a host-label guess. The 1d gate: a guessed
    db that authenticates is NOT a proven chain."""
    for e in event_store.get_events(engagement_id):
        payload = getattr(e, "payload", None)
        if not isinstance(payload, dict):
            continue
        pr = payload.get("proof_request")
        if isinstance(pr, dict) and pr.get("method") == "authenticate":
            if pr.get("database_source") == "enumerated":
                return True
    return False


def run_odoo_chain_live_fire(
    config: OdooChainConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
) -> OdooChainResult:
    """Alpha recon (odoo fingerprint + config leak) → Beta ranked→odoo_access XML-RPC reuse."""
    rec = auth.create_engagement(client_id=config.client_id, target=config.scope_domains[0])
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=config.scope_exclusions,
        ),
    )

    # 1) Alpha generic recon — fingerprints odoo (writes ASSET tech_stack=['odoo'])
    Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    ).run_recon(rec.engagement_id, config.recon_url)

    # 2) wp-config leak recon — harvests the reused admin/<pw> login credential (vaulted)
    creds_added = verify_wp_config_leak(
        engagement_id=rec.engagement_id,
        auth=auth,
        http_client=http_client,
        scope_hosts=config.scope_domains,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    # 3) Escalate to ACTIVE for XML-RPC access
    auth.enable_active(rec.engagement_id)

    # 4) Beta — NO cred_applicators: fingerprint routing picks odoo_access (XML-RPC),
    #    which reuses the vaulted credential itself.
    Beta(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    ).run_strike(rec.engagement_id, config.entry_point)

    return OdooChainResult(
        leak_creds_added=creds_added,
        web_access_level=_web_access_level(graph_store),
        edge_from_harvested_cred=_edge_from_harvested_cred(graph_store, secrets_manager),
        db_enumerated=_db_enumerated(event_store, rec.engagement_id),
        leak_suspected=_scan_leak(event_store, rec.engagement_id),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha Odoo cred-reuse chain live-fire")
    parser.add_argument("config", help="Path to odoo chain engagement YAML config")
    args = parser.parse_args(argv)

    config = load_odoo_chain_config(args.config)

    from agent_alpha.live_fire.lab_guard import assert_lab_only_target

    assert_lab_only_target(config.recon_url)
    assert_lab_only_target(config.entry_point)

    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id)
    secrets_manager = SecretsManager()
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())
    graph_store = NetworkXGraphStore()

    result = run_odoo_chain_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    print("=" * 64)
    print("ODOO CROSS-SERVICE CRED-REUSE CHAIN LIVE-FIRE")
    print("=" * 64)
    print(f"  Client ID              : {config.client_id}")
    print(f"  Recon (root)           : {config.recon_url}")
    print(f"  Odoo entry (XML-RPC)   : {config.entry_point}")
    print(f"  Leak creds added       : {result.leak_creds_added}")
    print(f"  Web/app access level   : {result.web_access_level or '(none)'}")
    print(f"  Edge from harvested cred (=reused) : {result.edge_from_harvested_cred}")
    print(f"  DB enumerated (not guessed)        : {result.db_enumerated}")
    print(f"  Leak suspected          : {result.leak_suspected}")
    print("-" * 64)
    print(f"  CHAIN PROVEN: {result.chain_proven}")
    print("=" * 64)
    return 0 if result.chain_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
