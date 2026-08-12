"""GAP-015 field-prove — the Alpha→Beta predictable-credential moat, end-to-end.

Chain (autonomous path, NOT a tool-island):
  crt.sh passive discovery → origin_resolver finds a non-CF origin-sibling IP →
  origin-direct bypasses the CDN edge → Alpha.run_recon enumerates WP usernames
  (wp_rest_users → USER nodes) → Beta.run_strike ranks UserDerivedCredsTool →
  derive_login_candidates → verified admin via a PREDICTABLE credential →
  vuln:{host}:predictable_credential (accurate class, §cred_finding_catalog).

Reuses the proven wp_chain_runner + runner.py origin patterns (anti-#6). Origin IPs
are DISCOVERED (crt.sh), never hand-fed — authorized via the signed EngagementProfile
(§12.38). Lab-only (assert_lab_only_target). Operational runner (not unit-tested), run
on Oracle ARM64.

Run:
    python -m agent_alpha.live_fire.gap015_field_prove <engagement.yaml>
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
from typing import Any
from urllib.parse import urlparse

import yaml

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.applicator_factory import (
    beta_web_applicators,
    build_applicators_for_engagement,
)
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.engagement_profile import EngagementProfile
from agent_alpha.config.stores import build_event_store
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.origin_resolver import discover_origin_ips
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine


@dataclasses.dataclass(frozen=True)
class Gap015Config:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str  # WP root (wp_fingerprint → wp_rest_users battery)
    entry_point: str  # WP login URL (wp-login.php)


@dataclasses.dataclass(frozen=True)
class Gap015Result:
    origin_ips: list[str]
    users_enumerated: int
    web_access_level: str
    predictable_credential_proven: bool

    @property
    def chain_proven(self) -> bool:
        """Payable GAP-015 chain: usernames enumerated + admin/user access reached
        AND attributed to a PREDICTABLE (derived) credential — not a default or reuse."""
        return (
            self.users_enumerated > 0
            and self.web_access_level in ("user", "admin")
            and self.predictable_credential_proven
        )


def load_config(path: str | pathlib.Path) -> Gap015Config:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("gap015 config must be a YAML mapping")
    scope = data.get("scope", {}) or {}
    return Gap015Config(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope.get("ip_ranges", [])),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope.get("exclusions", [])),
        recon_url=data["recon_url"],
        entry_point=data["entry_point"],
    )


def _predictable_credential_proven(graph_store: Any) -> bool:
    """True iff a vuln node of the predictable-credential class was minted (§3a) —
    the report-accurate signal that the win came from a DERIVED guess, not a default."""
    for node in graph_store.nodes_by_type(NodeType.VULNERABILITY):
        if str(node.id).endswith(":predictable_credential"):
            return True
    return False


def _web_access_level(graph_store: Any) -> str:
    nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)
    return getattr(nodes[0].properties, "level", "") if nodes else ""


def run_gap015_field_prove(
    config: Gap015Config,
    *,
    engagement_id: str,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any,
    engagement_profile: Any,
) -> Gap015Result:
    """Alpha WP user-enum recon → Beta predictable-credential strike.

    The CALLER owns create+authorize (§one-engagement refactor — the profile, origin
    discovery, and this run share ONE engagement_id; a second engagement here would
    bind the profile to eng_A while recon ran under eng_B → scope/origin checks fail).
    """
    # 1) Alpha recon on the WP root — wp_fingerprint auto-seeds the wp_rest_users
    #    battery → USER nodes (the Alpha→Beta seam). Reach to the CF-proxied host
    #    goes origin-direct via the EngagementProfile.authorized_origins (discovered).
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
        engagement_profile=engagement_profile,
    )
    alpha.run_recon(engagement_id, config.recon_url)

    # 2) Escalate to ACTIVE for the web credential attempt (SOW-gated in real runs).
    auth.enable_active(engagement_id)

    # 3) Governed applicator roster (GovernedApplicator seam → per-account lockout).
    applicators = build_applicators_for_engagement(
        engagement_id=engagement_id,
        auth=auth,
        graph_store=graph_store,
        web_target=config.entry_point,
        candidates=beta_web_applicators(http_client),  # WpLogin BEFORE HttpForm (#7, opsec)
    )
    # 4) Beta strike — registry ranks UserDerivedCredsTool (USER nodes present) →
    #    derive → verified access → predictable_credential node (§3a).
    beta = Beta(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
        cred_applicators=applicators,
    )
    beta.run_strike(engagement_id, config.entry_point)

    return Gap015Result(
        origin_ips=list(getattr(engagement_profile, "authorized_origins", []) or []),
        users_enumerated=len(graph_store.nodes_by_type(NodeType.USER)),
        web_access_level=_web_access_level(graph_store),
        predictable_credential_proven=_predictable_credential_proven(graph_store),
    )


def main(argv: list[str] | None = None) -> int:
    from agent_alpha.live_fire.lab_guard import assert_lab_only_target
    from agent_alpha.llm.routing import resolve_reasoning_provider

    parser = argparse.ArgumentParser(
        description="Agent-Alpha GAP-015 predictable-credential field-prove"
    )
    parser.add_argument("config", help="engagement YAML")
    args = parser.parse_args(argv)
    config = load_config(args.config)

    # Lab-only guard — refuse client/prod domains.
    assert_lab_only_target(config.recon_url)
    assert_lab_only_target(config.entry_point)

    event_store = build_event_store()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id)
    rec_domain = config.scope_domains[0]

    # ONE engagement, owned by the caller (no double-engagement).
    rec = auth.create_engagement(client_id=config.client_id, target=rec_domain)
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=config.scope_exclusions,
        ),
    )

    # Origin discovery (crt.sh) under THIS engagement — DISCOVERED, never hand-fed
    # (§12.38). [] is honest (no CT origin-sibling → origin-direct impossible → reach
    # may be IP-gated; that is a valid finding, not a failure).
    origin_ips = discover_origin_ips(
        rec.engagement_id,
        rec_domain,
        http_client,
        auth,
        seed_hosts=config.scope_domains,
    )
    print(f"[origin] discovered {len(origin_ips)} non-CF origin IP(s): {origin_ips}")

    provider = resolve_reasoning_provider(api_key=os.environ["DEEPSEEK_API_KEY"])
    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), provider)
    graph_store = NetworkXGraphStore()
    secrets_manager = SecretsManager()

    lab_profile = EngagementProfile(
        engagement_id=rec.engagement_id,
        client_id=config.client_id,
        targets=frozenset([urlparse(config.recon_url).hostname or rec_domain]),
        authorized_origins=frozenset(origin_ips),
        authorization_level="RECON_ONLY",
        allow_evasion=True,  # lab consent — field-prove only
    )
    result = run_gap015_field_prove(
        config,
        engagement_id=rec.engagement_id,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
        engagement_profile=lab_profile,
    )

    print("=" * 60)
    print("GAP-015 FIELD-PROVE SCORECARD")
    print("=" * 60)
    print(f"  origin IPs discovered : {result.origin_ips}")
    print(f"  usernames enumerated  : {result.users_enumerated}")
    print(f"  web access level      : {result.web_access_level!r}")
    print(f"  predictable-cred node : {result.predictable_credential_proven}")
    print(f"  CHAIN PROVEN          : {result.chain_proven}")
    print("=" * 60)
    return 0 if result.chain_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
