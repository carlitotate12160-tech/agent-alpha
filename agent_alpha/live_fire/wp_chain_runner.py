"""WP cred-reuse CHAIN live-fire — Alpha recon → WP config-backup leak → Beta cred-reuse.

Mirrors ``chain_runner.py`` (Laravel) but swaps the leak vector: instead of a
Laravel Whoops debug page, Alpha probes ``wp-config.php`` backup paths.  The
harvested DB credential is vaulted, then Beta reuses it on the WP login page.

Single-process by design (shared in-memory SecretsManager).  No DeepSeek key
needed: playbooks keep both agents rule-tier.

Run with:
    python -m agent_alpha.live_fire.wp_chain_runner <engagement.yaml>
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
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.live_fire.beta_runner import _NoLLMProvider, _scan_leak
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.js_secret_probe import verify_js_secret_leak
from agent_alpha.recon.wp_config_probe import verify_wp_config_leak
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator, WpLoginApplicator
from agent_alpha.tools.playbook import PlaybookEngine


@dataclasses.dataclass(frozen=True)
class WpChainConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str  # where Alpha does generic recon (root page)
    entry_point: str  # WP login URL (wp-login.php)
    evasion_authorized: bool = False  # SOW must explicitly authorize WAF-evasion


@dataclasses.dataclass(frozen=True)
class WpChainResult:
    leak_creds_added: int
    web_access_level: str
    edge_from_harvested_cred: bool
    leak_suspected: bool
    waf_blocked: bool  # recon di-blok WAF di run ini (≠ "clean")

    @property
    def chain_proven(self) -> bool:
        return (
            self.leak_creds_added > 0
            and self.web_access_level in ("user", "admin")
            and self.edge_from_harvested_cred
            and not self.leak_suspected
        )


def load_wp_chain_config(path: str | pathlib.Path) -> WpChainConfig:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("wp chain config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url", "entry_point"):
        if key not in data:
            raise ValueError(f"wp chain config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"wp chain config scope missing required key: {key!r}")
    return WpChainConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope["exclusions"]),
        recon_url=data["recon_url"],
        entry_point=data["entry_point"],
        evasion_authorized=bool(data.get("evasion_authorized", False)),
    )


def _edge_from_harvested_cred(graph_store: Any, secrets_manager: Any) -> bool:
    """True iff an ENABLES edge to an ACCESS_LEVEL node originates from an
    Alpha-harvested+vaulted credential (vault id resolves)."""
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


def _web_access_level(graph_store: Any) -> str:
    """Read the access level from the most recent ACCESS_LEVEL node."""
    nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)
    if not nodes:
        return ""
    # Return the first node's level (single engagement, single target).
    props = nodes[0].properties
    return getattr(props, "level", "")


def run_wp_chain_live_fire(
    config: WpChainConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
) -> WpChainResult:
    """Alpha recon → WP config-backup leak → Beta cred-reuse in ONE engagement."""
    rec = auth.create_engagement(client_id=config.client_id, target=config.scope_domains[0])
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=config.scope_exclusions,
        ),
    )

    # 1) Alpha generic recon on the root (unchanged, proven path)
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    alpha.run_recon(rec.engagement_id, config.recon_url)

    # 2) WP config-backup leak recon — THE WIRING (RECON-tier, scope-gated)
    creds_added = verify_wp_config_leak(
        engagement_id=rec.engagement_id,
        auth=auth,
        http_client=http_client,
        scope_hosts=config.scope_domains,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    # 2b) JS-bundle secret leak recon — generic, works for WP or SPA targets
    js_creds_added = verify_js_secret_leak(
        engagement_id=rec.engagement_id,
        auth=auth,
        http_client=http_client,
        scope_targets=config.scope_domains,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )
    creds_added += js_creds_added

    # 3) Escalate to ACTIVE for web cred-reuse (SOW-gated in real runs)
    auth.enable_active(rec.engagement_id)

    # 4) Bind the web applicator to the wp-login entry_point via the factory.
    #    entry_point MUST pass assert_offensive_web_target (owned domain, not bare IP).
    candidates = [
        HttpFormApplicator(http_client=http_client),
        WpLoginApplicator(http_client=http_client),
    ]
    applicators = build_applicators_for_engagement(
        engagement_id=rec.engagement_id,
        auth=auth,
        graph_store=graph_store,
        web_target=config.entry_point,
        candidates=candidates,
    )

    # 5) Beta web cred-reuse with the vaulted leaked credential
    beta = Beta(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
        cred_applicators=applicators,
    )
    beta.run_strike(rec.engagement_id, config.entry_point)

    # 6) Read results → WpChainResult
    waf_blocked = any(
        getattr(e, "event_type", None) == EventType.WAF_BLOCKED
        for e in event_store.get_events(rec.engagement_id)
    )
    return WpChainResult(
        leak_creds_added=creds_added,
        web_access_level=_web_access_level(graph_store),
        edge_from_harvested_cred=_edge_from_harvested_cred(graph_store, secrets_manager),
        leak_suspected=_scan_leak(event_store, rec.engagement_id),
        waf_blocked=waf_blocked,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha WP cred-reuse chain live-fire")
    parser.add_argument("config", help="Path to WP chain engagement YAML config")
    parser.add_argument(
        "--recon-only",
        action="store_true",
        help="Run only the RECON leg (leak discovery). Do NOT escalate to ACTIVE cred-reuse.",
    )
    parser.add_argument(
        "--report-pdf",
        type=str,
        default=None,
        help="Path to export PDF report (default: ./report.pdf)",
    )
    parser.add_argument(
        "--opsec-profile",
        type=str,
        default=None,
        help="OPSEC profile name (e.g. 'blend' for covert UA). Evasion gate: falls back to 'announced' without SOW authorization.",
    )
    args = parser.parse_args(argv)

    config = load_wp_chain_config(args.config)

    # ── Resolve OPSEC profile (evasion gate: fail-closed without SOW authorization) ──
    from agent_alpha.conductor.policy import PolicyEnforcer

    policy_enforcer = PolicyEnforcer()
    profile_name = args.opsec_profile or "announced"
    opsec = policy_enforcer.resolve_opsec_profile(
        profile_name, evasion_authorized=config.evasion_authorized
    )

    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id, opsec=opsec)
    secrets_manager = SecretsManager()
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), _NoLLMProvider())
    graph_store = NetworkXGraphStore()

    if args.recon_only:
        # ── RECON-only leg: leak discovery without ACTIVE escalation ────────
        rec = auth.create_engagement(client_id=config.client_id, target=config.scope_domains[0])
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
        )
        alpha.run_recon(rec.engagement_id, config.recon_url)
        creds_added = verify_wp_config_leak(
            engagement_id=rec.engagement_id,
            auth=auth,
            http_client=http_client,
            scope_hosts=config.scope_domains,
            graph_store=graph_store,
            event_store=event_store,
            secrets_manager=secrets_manager,
        )
        js_creds_added = verify_js_secret_leak(
            engagement_id=rec.engagement_id,
            auth=auth,
            http_client=http_client,
            scope_targets=config.scope_domains,
            graph_store=graph_store,
            event_store=event_store,
            secrets_manager=secrets_manager,
        )
        creds_added += js_creds_added
        waf_blocked = any(
            getattr(e, "event_type", None) == EventType.WAF_BLOCKED
            for e in event_store.get_events(rec.engagement_id)
        )
        result = WpChainResult(
            leak_creds_added=creds_added,
            web_access_level="",
            edge_from_harvested_cred=False,
            leak_suspected=False,
            waf_blocked=waf_blocked,
        )
    else:
        result = run_wp_chain_live_fire(
            config,
            auth=auth,
            http_client=http_client,
            orchestrator=orchestrator,
            graph_store=graph_store,
            event_store=event_store,
            secrets_manager=secrets_manager,
        )

    mode = "RECON-ONLY" if args.recon_only else "FULL CHAIN"
    print("=" * 64)
    print(f"WP CRED-REUSE CHAIN LIVE-FIRE  [{mode}]")
    print("=" * 64)
    print(f"  Client ID             : {config.client_id}")
    print(f"  Recon (root)          : {config.recon_url}")
    if not args.recon_only:
        print(f"  WP login (entry_point): {config.entry_point}")
    print(f"  Leak creds added      : {result.leak_creds_added}")
    if not args.recon_only:
        print(f"  Web access level      : {result.web_access_level or '(none)'}")
        print(
            f"  Edge from harvested   : {result.edge_from_harvested_cred}  (real chain, not fake)"
        )
        print(f"  Leak suspected        : {result.leak_suspected}")
    print(f"  WAF blocked           : {result.waf_blocked}")
    if result.waf_blocked:
        print("    ⚠  Recon blocked by WAF — INCONCLUSIVE, not 'clean'.")
        print("    Recommend retest with authenticated session.")
    print("-" * 64)
    if args.recon_only:
        if result.leak_creds_added > 0:
            print("  Verdict: LEAK FOUND — escalate to ACTIVE with SOW tier confirmation.")
        elif result.waf_blocked:
            print("  Verdict: WAF BLOCKED — inconclusive, recommend retest.")
        else:
            print("  Verdict: NO LEAK — target appears clean (valid result, not failure).")
    else:
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
    if result.waf_blocked:
        print()
        print("  WAF NOTE: One or more hosts returned 403 on backup path probes.")
        print("  These hosts are INCONCLUSIVE — recon was blocked by WAF/bot-protection.")
        print("  They are NOT reported as 'clean'. Recommend authenticated retest.")
    print("=" * 64)

    # ── PDF export ──────────────────────────────────────────────────────
    report_path = pathlib.Path(args.report_pdf or "./report.pdf")
    try:
        report.export_pdf(report_path)
        print(f"  PDF report exported: {report_path.resolve()}")
    except Exception as exc:
        print(f"  ! PDF export failed ({exc}) — console output above is the report.")
    print("=" * 64)

    return 0 if (result.chain_proven if not args.recon_only else result.leak_creds_added > 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
