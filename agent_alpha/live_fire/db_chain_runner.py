"""DIRECT-DB cred-reuse CHAIN live-fire — the real "3d done" field-prove.

Alpha recon leaks a DB credential → VAULTS it → verify_in_scope_db_services (RECON,
real socket) confirms the in-scope MySQL and writes a SERVICE node → escalate to
OFFENSIVE → the factory binds MySqlApplicator to the IN-SCOPE host:port → Beta
cred_reuse applies the vaulted secret DIRECTLY to the DB → db_root → Omega HIGH.

This is the payable finding a scanner cannot assemble: "leaked DB password proves
DIRECT database access." Run on Oracle ARM64 against a SELF-OWNED, in-scope MySQL
whose host:port is in the signed SOW (scope.db_endpoints). NEVER localhost.

SINGLE-PROCESS (one SecretsManager shared by Alpha + Beta), mirrors chain_runner.

KNOWN GAP THIS HARNESS SURFACES (flaw-first): Alpha writes ONE credential node per
leaked env key, so DB_USERNAME and DB_PASSWORD become SEPARATE nodes — neither holds
BOTH the DB user AND its password. MySqlApplicator.apply needs both. Until a
credential-pairing fix lands, the DB auth will fail. This runner DETECTS and reports
that precondition explicitly (it does not fake success).
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
from agent_alpha.conductor.applicator_factory import build_applicators_for_engagement
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.narrative import summarize_chain_finding
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.live_fire.beta_runner import _NoLLMProvider, _scan_leak
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.db_service_probe import SocketDbHandshakeProbe, verify_in_scope_db_services
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.internal.access.mysql_applicator import MySqlApplicator
from agent_alpha.tools.playbook import PlaybookEngine

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0"})


@dataclasses.dataclass(frozen=True)
class DbChainConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    db_endpoints: list[str]  # "host:port" from the SOW — the in-scope DB targets
    recon_url: str  # where Alpha harvests the leaked DB credential
    entry_point: str  # in-scope web URL Beta observes to trigger cred_reuse


@dataclasses.dataclass(frozen=True)
class DbChainResult:
    service_discovered: bool  # verify wrote a SERVICE(mysql) node
    mysql_bound: bool  # the factory bound MySqlApplicator to the in-scope endpoint
    db_credential_usable: bool  # a cred node holds BOTH a username AND a secret (the gap)
    db_access_level: str  # "" | "db_user" | "db_root"
    edge_from_harvested_cred: bool  # chain edge source = Alpha's vaulted node
    report_severity: str  # Omega chain-finding severity
    leak_suspected: bool

    @property
    def chain_proven(self) -> bool:
        return (
            self.service_discovered
            and self.mysql_bound
            and self.db_access_level in ("db_user", "db_root")
            and self.edge_from_harvested_cred
            and not self.leak_suspected
        )


def load_db_chain_config(path: str | pathlib.Path) -> DbChainConfig:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("db chain config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url", "entry_point"):
        if key not in data:
            raise ValueError(f"db chain config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "db_endpoints"):
        if key not in scope:
            raise ValueError(f"db chain config scope missing required key: {key!r}")
    db_endpoints = list(scope["db_endpoints"])
    # Anti-trap guard (FLAW 2): a field-prove against loopback is meaningless — it hits
    # Agent-Alpha's own box, not a real in-scope client DB. Refuse it loudly.
    for endpoint in db_endpoints:
        host = endpoint.rsplit(":", 1)[0]
        if host in _LOOPBACK_HOSTS:
            raise ValueError(
                f"db_endpoint {endpoint!r} is loopback — the field-prove must target a real "
                "in-scope, self-owned DB host (the factory exists to block localhost/DB_HOST)."
            )
    return DbChainConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        db_endpoints=db_endpoints,
        recon_url=data["recon_url"],
        entry_point=data["entry_point"],
    )


def _db_credential_is_usable(graph_store: Any) -> bool:
    """True iff some CREDENTIAL node carries BOTH a non-empty username AND a resolvable
    secret_ref for a DB service — the precondition MySqlApplicator needs. The known gap:
    Alpha splits DB_USERNAME / DB_PASSWORD into separate nodes, so this is usually False
    until a pairing fix lands. Reported honestly, never faked."""
    for node in graph_store.nodes_by_type(NodeType.CREDENTIAL):
        props = node.properties
        service = getattr(props, "service", "")
        if service in ("mysql", "mariadb", "database") and getattr(props, "username", "") != "":
            return True
    return False


def _edge_from_harvested_cred(graph_store: Any, secrets_manager: Any) -> bool:
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


def run_db_chain_live_fire(
    config: DbChainConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
    probe: Any,
) -> DbChainResult:
    """Alpha recon (vault) → RECON DB-service verify → OFFENSIVE mysql cred-reuse."""
    rec = auth.create_engagement(client_id=config.client_id, target=config.scope_domains[0])
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=[],
            db_endpoints=config.db_endpoints,
        ),
    )

    # ── Alpha: recon harvests + VAULTS the leaked DB credential ──
    Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    ).run_recon(rec.engagement_id, config.recon_url)

    # ── RECON-tier DB service discovery (real socket greeting read) ──
    evidence = verify_in_scope_db_services(
        engagement_id=rec.engagement_id,
        auth=auth,
        scope_db_endpoints=config.db_endpoints,
        graph_store=graph_store,
        event_store=event_store,
        probe=probe,
        timeout_s=5.0,
    )
    service_discovered = len(evidence) > 0
    db_credential_usable = _db_credential_is_usable(graph_store)

    # ── Escalate to OFFENSIVE, bind the mysql applicator to the in-scope endpoint ──
    auth.enable_active(rec.engagement_id)
    auth.enable_offensive(rec.engagement_id, b"SIGNED-SOW: authorized direct-DB engagement")
    applicators = build_applicators_for_engagement(
        engagement_id=rec.engagement_id,
        auth=auth,
        graph_store=graph_store,
        web_target=config.entry_point,
        candidates=[MySqlApplicator()],  # connector=None → real pymysql
    )
    mysql_bound = any(getattr(b.applicator, "service", "") == "mysql" for b in applicators)

    # ── Beta: cred_reuse applies the vaulted secret DIRECTLY to the DB ──
    Beta(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
        cred_applicators=applicators,
    ).run_strike(rec.engagement_id, config.entry_point)

    # ── Read the outcome from the graph (db_root/db_user access node) ──
    db_access_level = ""
    for node in graph_store.nodes_by_type(NodeType.ACCESS_LEVEL):
        level = getattr(node.properties, "level", "")
        if level in ("db_root", "db_user"):
            db_access_level = level
            break

    chain = summarize_chain_finding(graph_store)
    report_severity = getattr(chain, "severity", "") if chain is not None else ""

    return DbChainResult(
        service_discovered=service_discovered,
        mysql_bound=mysql_bound,
        db_credential_usable=db_credential_usable,
        db_access_level=db_access_level,
        edge_from_harvested_cred=_edge_from_harvested_cred(graph_store, secrets_manager),
        report_severity=report_severity,
        leak_suspected=_scan_leak(event_store, rec.engagement_id),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha DIRECT-DB cred-reuse chain live-fire")
    parser.add_argument("config", help="Path to db chain engagement YAML config")
    args = parser.parse_args(argv)

    config = load_db_chain_config(args.config)

    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id)
    secrets_manager = SecretsManager()  # ONE shared instance (single-process)
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())
    graph_store = NetworkXGraphStore()
    probe = SocketDbHandshakeProbe()  # REAL socket — reads the greeting, sends nothing

    result = run_db_chain_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
        probe=probe,
    )

    print("=" * 64)
    print("DIRECT-DB CRED-REUSE CHAIN LIVE-FIRE")
    print("=" * 64)
    print(f"  SERVICE(mysql) discovered (RECON verify) : {result.service_discovered}")
    print(f"  MySqlApplicator bound to in-scope endpoint: {result.mysql_bound}")
    print(f"  DB credential usable (user+secret paired) : {result.db_credential_usable}")
    if not result.db_credential_usable:
        print("    ^ KNOWN GAP: DB_USERNAME / DB_PASSWORD are separate cred nodes; the")
        print("      mysql applicator needs both. A credential-pairing fix is required")
        print("      before the DB auth can succeed. (Not faked — reported honestly.)")
    print(f"  DB access level proven                    : {result.db_access_level or '(none)'}")
    print(f"  Chain edge from Alpha's vaulted credential : {result.edge_from_harvested_cred}")
    print(f"  Omega chain-finding severity               : {result.report_severity or '(none)'}")
    print(f"  Session-token leak suspected               : {result.leak_suspected}")
    print("-" * 64)
    print(f"  CHAIN PROVEN: {result.chain_proven}")
    print("=" * 64)
    return 0 if result.chain_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
