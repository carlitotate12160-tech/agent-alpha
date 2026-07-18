"""Layer V (the seal) runner — end-to-end verification.

Proves the Odoo chain without hand-feeding recon_url or entry_point.
Relies entirely on passive discovery and frontier expansion from a root domain.
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
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.live_fire.odoo_chain_runner import (
    OdooChainConfig,
    run_odoo_chain_live_fire,
)
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.memory.engagement import EngagementMemoryProjector
from agent_alpha.recon.passive_discovery import (
    CRTSH_URL_TEMPLATE,
    PassiveDiscovery,
    seed_frontier_from_passive,
)
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine


@dataclasses.dataclass(frozen=True)
class LayerVConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    root_domain: str
    # LAB-ONLY: a crt.sh-shaped CT SOURCE url template (has a {domain} slot). This
    # is a data SOURCE, never a target host — the exploited host still emerges from
    # parsing CT output. Omit in production; real crt.sh is used by default.
    passive_source_template: str | None = None


@dataclasses.dataclass(frozen=True)
class LayerVResult:
    engagement_id: str
    leak_creds_added: int
    web_access_level: str
    edge_from_harvested_cred: bool
    db_enumerated: bool
    leak_suspected: bool
    host_discovery_sourced: bool

    @property
    def chain_proven(self) -> bool:
        return (
            self.leak_creds_added > 0
            and self.web_access_level in ("user", "admin")
            and self.edge_from_harvested_cred
            and self.db_enumerated
            and not self.leak_suspected
            and self.host_discovery_sourced
        )


def load_layer_v_config(path: str | pathlib.Path) -> LayerVConfig:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("layer v config must be a YAML mapping")

    if "recon_url" in data or "entry_point" in data:
        raise ValueError("LayerVConfig forbids hand-fed recon_url or entry_point")

    for key in ("client_id", "scope", "root_domain"):
        if key not in data:
            raise ValueError(f"layer v config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"layer v config scope missing required key: {key!r}")
    return LayerVConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope["exclusions"]),
        root_domain=data["root_domain"],
        passive_source_template=data.get("passive_source_template"),
    )


def _host_discovery_sourced(event_store: Any, engagement_id: str, host: str) -> bool:
    """True iff the exploited odoo host's ASSET node traces to a passive_discovery OR
    frontier event in the event store (NOT to a config field)."""
    for e in event_store.get_events(engagement_id):
        event_type = getattr(e, "event_type", None)
        payload = getattr(e, "payload", {})
        if not isinstance(payload, dict):
            continue

        if event_type == EventType.PASSIVE_DISCOVERY:
            if host in payload.get("discovered", []):
                return True
        elif event_type == EventType.NODE_DISCOVERED:
            node_type = payload.get("type")
            properties = payload.get("properties", {})
            if node_type == "asset" and properties.get("host") == host:
                return True
    return False


def _authorize_apex_subdomains(
    auth: Any,
    engagement_id: str,
    config: LayerVConfig,
    result: Any,
) -> list[str]:
    """Promote CT-discovered apex-subdomains to scope via Conductor (audited).

    A host is authorized iff it is the apex OR a strict subdomain of it AND is not
    excluded. The apex bound is enforced HERE (belt-and-suspenders on top of
    parse_crtsh_names' suffix filter) so no discovery source can widen scope beyond
    the authorized registrable domain. Iterates result.discovered (the parsed CT
    surface), NOT the audit-only `enumerated` field. Default-DENY preserved.
    """
    apex = config.root_domain.strip().lower()
    suffix = "." + apex
    excluded = {e.strip().lower() for e in config.scope_exclusions}

    authorized: list[str] = []
    for host in result.discovered:
        h = host.strip().lower()
        if h in excluded:
            continue
        if h == apex or h.endswith(suffix):
            authorized.append(h)

    if authorized:
        extended = sorted(set(config.scope_domains) | set(authorized))
        auth.enable_recon(
            engagement_id,
            Scope(
                ip_ranges=config.scope_ip_ranges,
                domains=extended,
                exclusions=config.scope_exclusions,
            ),
        )
    return authorized


def run_layer_v_live_fire(
    config: LayerVConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
) -> LayerVResult:
    # 2a. Conductor create_engagement + enable_recon (RECON_ONLY) on root_domain
    rec = auth.create_engagement(client_id=config.client_id, target=config.root_domain)
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=config.scope_exclusions,
        ),
    )

    # 2b. R2 passive discovery from root_domain. The subdomain hosts EMERGE from
    #     parsing a CT source (public crt.sh, or a lab-local CT stand-in when
    #     passive_source_template is set) — never from this config. This exercises
    #     the SEALED R2 parse/partition/seed path on the live path (anti-Lyndon #2).
    pd = PassiveDiscovery(
        http_client=http_client,
        authorization=auth,
        event_store=event_store,
        crtsh_url_template=(config.passive_source_template or CRTSH_URL_TEMPLATE),
    )
    result = pd.discover(rec.engagement_id, config.root_domain)

    # 2b-bis. Authorize discovered apex-subdomains through Conductor (audited scope
    #         extension). Named + apex-bounded so this is a first-class authorization
    #         step, not an abuse of the audit-only `enumerated` field.
    authorized_hosts = _authorize_apex_subdomains(auth, rec.engagement_id, config, result)

    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    alpha._engagement_id = rec.engagement_id
    alpha._work_queue = []
    alpha._probed = set()
    alpha._findings = 0
    alpha._analyzable_probes = 0
    alpha._ran_campaigns = set()

    # Seed frontier: in-scope passive hosts + the just-authorized apex-subdomains.
    # Each authorized host is now its OWN in-scope origin; Alpha fingerprints it
    # same-origin. No cross-origin crawl is required or performed.
    seed_frontier_from_passive(alpha, result)
    for host in authorized_hosts:
        alpha.enqueue_discovered_url(f"https://{host}/")
    alpha.enqueue_discovered_url(f"https://{config.root_domain}/")

    # Alpha recon consumes the frontier and fingerprints hosts
    policy = BoundedAutonomy(no_progress_threshold=constants.ALPHA_RECON_NO_PROGRESS_ITERS)
    run_cognitive_loop(alpha, policy)

    # 2c. Select the odoo host from the DISCOVERED ASSET nodes
    odoo_host = None
    for node in graph_store.nodes_by_type(NodeType.ASSET):
        if "odoo" in node.properties.tech_stack:
            odoo_host = node.properties.host
            break

    if not odoo_host:
        raise ValueError("No odoo host discovered via passive frontier")

    derived_url = f"https://{odoo_host}/"

    # 2d. Delegate to the SEALED run_odoo_chain_live_fire
    # The delegated chain creates its OWN engagement; its scope MUST include the
    # discovered odoo host or the chain's own recon on it would be scope-blocked.
    odoo_config = OdooChainConfig(
        client_id=config.client_id,
        scope_ip_ranges=config.scope_ip_ranges,
        scope_domains=sorted(set(config.scope_domains) | {odoo_host}),
        scope_exclusions=config.scope_exclusions,
        recon_url=derived_url,
        entry_point=derived_url,
    )

    odoo_result = run_odoo_chain_live_fire(
        odoo_config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    is_sourced = _host_discovery_sourced(event_store, rec.engagement_id, odoo_host)

    return LayerVResult(
        engagement_id=rec.engagement_id,
        leak_creds_added=odoo_result.leak_creds_added,
        web_access_level=odoo_result.web_access_level,
        edge_from_harvested_cred=odoo_result.edge_from_harvested_cred,
        db_enumerated=odoo_result.db_enumerated,
        leak_suspected=odoo_result.leak_suspected,
        host_discovery_sourced=is_sourced,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha Layer V live-fire")
    parser.add_argument("config", help="Path to layer v chain engagement YAML config")
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip TLS verification (for self-signed Caddy internal CA lab)",
    )
    args = parser.parse_args(argv)

    config = load_layer_v_config(args.config)

    from agent_alpha.live_fire.lab_guard import assert_lab_only_target

    assert_lab_only_target(f"https://{config.root_domain}/")

    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    # TLS verification is opt-out ONLY for self-owned lab_guard targets with self-signed certs;
    # production recon uses the secure default (verify=True).
    http_client = HttpClient(engagement_id=config.client_id, verify=not args.no_verify)
    secrets_manager = SecretsManager()
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())
    graph_store = NetworkXGraphStore()

    result = run_layer_v_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    print("=" * 64)
    print("LAYER V ROOT-ONLY CHAIN LIVE-FIRE")
    print("=" * 64)
    print(f"  Client ID              : {config.client_id}")
    print(f"  Root domain            : {config.root_domain}")
    print(f"  Leak creds added       : {result.leak_creds_added}")
    print(f"  Web/app access level   : {result.web_access_level or '(none)'}")
    print(f"  Edge from harvested cred (=reused) : {result.edge_from_harvested_cred}")
    print(f"  DB enumerated (not guessed)        : {result.db_enumerated}")
    print(f"  Leak suspected          : {result.leak_suspected}")
    print(f"  Host discovery sourced  : {result.host_discovery_sourced}")
    print("-" * 64)
    print(f"  CHAIN PROVEN: {result.chain_proven}")
    print("=" * 64)

    from agent_alpha.memory.engagement import InMemoryEngagementMemoryStore

    mem = EngagementMemoryProjector(event_store, InMemoryEngagementMemoryStore()).project(
        result.engagement_id
    )
    print(f"  Blocked Hosts (CF)      : {mem.blocked_hosts}")

    return 0 if result.chain_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
