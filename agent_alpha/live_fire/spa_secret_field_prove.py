"""SPA JS-secret field-prove runner — real HTTP against a self-owned lab.

Closes anti-Lyndon-#2 on ``js_secret_probe.py``: unit-green with a fake HTTP
client only. This runner field-proves ``verify_js_secret_leak`` against a **real,
served, self-owned** SPA with **known ground truth** (``expected.local.json``).

Mirrors the wiring in ``wp_chain_runner.py`` (AuthorizationStateMachine + Scope,
HttpClient, InMemoryEventStore, NetworkXGraphStore, SecretsManager) but
RECON-ONLY and with NO WP login step.

Reads ``js_lab_engagement.yaml`` + ``expected.local.json`` (both in js_lab/).

Usage:
    python -m agent_alpha.live_fire.spa_secret_field_prove <engagement.yaml> [--expected <path>]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import pathlib

import yaml

from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.recon.js_secret_probe import _mask, verify_js_secret_leak
from agent_alpha.security.secrets import SecretsManager

_log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class SpaLabConfig:
    """Parsed from js_lab_engagement.yaml."""

    client_id: str
    scope_domains: list[str]
    scope_ip_ranges: list[str]
    scope_exclusions: list[str]
    recon_url: str


@dataclasses.dataclass(frozen=True)
class ExpectedGroundTruth:
    """Parsed from expected.local.json (produced by generate_bundle.py)."""

    bundle_path: str
    expected_creds_added: int
    expected_secret_kind: str
    expected_secret_service: str
    expected_secret_preview: str
    rejected_decoys: list[str]
    expected_api_endpoints: list[str]


@dataclasses.dataclass(frozen=True)
class SpaSecretFieldProveResult:
    """Frozen result of the field-prove run. ``.proven`` implements all 8 clauses."""

    creds_added: int
    clause_1_return_value: bool
    clause_2_graph_state: bool
    clause_3_vault_preview: bool
    clause_4_decoys_absent: bool
    clause_5_intel_endpoints: bool
    clause_6_no_false_waf: bool
    clause_7_determinism: bool
    clause_8_environment: bool
    detail: str

    @property
    def proven(self) -> bool:
        return (
            self.clause_1_return_value
            and self.clause_2_graph_state
            and self.clause_3_vault_preview
            and self.clause_4_decoys_absent
            and self.clause_5_intel_endpoints
            and self.clause_6_no_false_waf
            and self.clause_7_determinism
            and self.clause_8_environment
        )


def load_spa_config(path: str | pathlib.Path) -> SpaLabConfig:
    """Parse client_id, scope.domains, scope.ip_ranges, scope.exclusions, recon_url from YAML."""
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("SPA lab config must be a YAML mapping")
    for key in ("client_id", "scope", "recon_url"):
        if key not in data:
            raise ValueError(f"SPA lab config missing required key: {key!r}")
    scope = data["scope"]
    for key in ("ip_ranges", "domains", "exclusions"):
        if key not in scope:
            raise ValueError(f"SPA lab config scope missing required key: {key!r}")
    return SpaLabConfig(
        client_id=data["client_id"],
        scope_domains=list(scope["domains"]),
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_exclusions=list(scope["exclusions"]),
        recon_url=data["recon_url"],
    )


def _load_expected(path: str | pathlib.Path) -> ExpectedGroundTruth:
    with open(path) as f:
        data = json.load(f)
    return ExpectedGroundTruth(
        bundle_path=data["bundle_path"],
        expected_creds_added=data["expected_creds_added"],
        expected_secret_kind=data["expected_secret_kind"],
        expected_secret_service=data["expected_secret_service"],
        expected_secret_preview=data["expected_secret_preview"],
        rejected_decoys=data["rejected_decoys"],
        expected_api_endpoints=data["expected_api_endpoints"],
    )


def _check_clause_2(
    graph_store: NetworkXGraphStore,
    target: str,
    expected: ExpectedGroundTruth,
) -> bool:
    """Graph state matches expected ground truth.

    TP (expected_creds_added > 0): vuln node + exactly one CREDENTIAL node + LEADS_TO edge.
    TN (expected_creds_added == 0): zero CREDENTIAL nodes, zero vuln nodes.
    """
    if expected.expected_creds_added == 0:
        cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
        vuln_nodes = graph_store.nodes_by_type(NodeType.VULNERABILITY)
        return len(cred_nodes) == 0 and len(vuln_nodes) == 0

    vuln_id = f"vuln:{target}:js_secret_leak"
    cred_id = f"cred:{target}:{expected.expected_secret_kind}"

    vuln_node = graph_store.get_node(vuln_id)
    if vuln_node is None or vuln_node.type != NodeType.VULNERABILITY:
        return False

    cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
    if len(cred_nodes) != 1:
        return False

    cred = cred_nodes[0]
    if cred.id != cred_id:
        return False

    props = cred.properties
    if not hasattr(props, "service") or props.service != expected.expected_secret_service:
        return False
    if not hasattr(props, "access_level") or props.access_level != "unverified":
        return False

    edge = graph_store.get_edge(vuln_id, cred_id)
    if edge is None or edge.relationship != RelationshipType.LEADS_TO:
        return False

    return True


def _check_clause_3(
    graph_store: NetworkXGraphStore,
    secrets_manager: SecretsManager,
    target: str,
    expected: ExpectedGroundTruth,
) -> bool:
    """Vault: retrieve stored secret, mask it, compare to expected preview.

    TP: vault has secret, masked preview matches.
    TN: vault has no secrets for this engagement.
    """
    if expected.expected_creds_added == 0:
        return len(secrets_manager.list_labels(target)) == 0

    cred_id = f"cred:{target}:{expected.expected_secret_kind}"
    cred = graph_store.get_node(cred_id)
    if cred is None:
        return False
    props = cred.properties
    if not hasattr(props, "secret_ref"):
        return False
    try:
        raw = secrets_manager.retrieve(props.secret_ref)
    except Exception:
        return False
    return _mask(raw) == expected.expected_secret_preview


def _check_clause_4(
    graph_store: NetworkXGraphStore,
    secrets_manager: SecretsManager,
    expected: ExpectedGroundTruth,
) -> bool:
    """No CREDENTIAL node whose vaulted value maps to either decoy."""
    cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
    for cred in cred_nodes:
        props = cred.properties
        if not hasattr(props, "secret_ref"):
            continue
        try:
            raw = secrets_manager.retrieve(props.secret_ref)
        except Exception:
            continue
        if raw in expected.rejected_decoys:
            return False
    return True


def _check_clause_5(
    event_store: InMemoryEventStore,
    engagement_id: str,
    expected: ExpectedGroundTruth,
) -> bool:
    """NODE_DISCOVERED events with type=api_endpoint exist for every expected endpoint."""
    events = event_store.get_events(engagement_id)
    found_endpoints: set[str] = set()
    for e in events:
        if getattr(e, "event_type", None) == EventType.NODE_DISCOVERED:
            payload = e.payload if hasattr(e, "payload") else {}
            if isinstance(payload, dict) and payload.get("type") == "api_endpoint":
                ep = payload.get("endpoint")
                if isinstance(ep, str):
                    found_endpoints.add(ep)
    return all(ep in found_endpoints for ep in expected.expected_api_endpoints)


def _check_clause_6(
    event_store: InMemoryEventStore,
    engagement_id: str,
) -> bool:
    """Zero WAF_BLOCKED events for this run."""
    events = event_store.get_events(engagement_id)
    return not any(getattr(e, "event_type", None) == EventType.WAF_BLOCKED for e in events)


def _check_clause_7(
    event_store: InMemoryEventStore,
    graph_store: NetworkXGraphStore,
    engagement_id: str,
) -> bool:
    """Replay event stream into a fresh NetworkXGraphStore → node/edge counts identical."""
    fresh = NetworkXGraphStore()
    events = event_store.get_events(engagement_id)
    for e in events:
        etype = getattr(e, "event_type", None)
        payload = e.payload if hasattr(e, "payload") else {}
        if etype in (EventType.NODE_DISCOVERED, EventType.EDGE_DISCOVERED):
            event_name = (
                "NodeDiscovered" if etype == EventType.NODE_DISCOVERED else "EdgeDiscovered"
            )
            # Skip intel events (e.g. api_endpoint) that are not valid NodeType
            if event_name == "NodeDiscovered":
                raw_type = payload.get("type", "")
                if raw_type not in {t.value for t in NodeType}:
                    continue
            fresh.apply_event(event_name, payload)
    original_nodes = len(graph_store.all_nodes())
    original_edges = len(graph_store.all_edges())
    fresh_nodes = len(fresh.all_nodes())
    fresh_edges = len(fresh.all_edges())
    return original_nodes == fresh_nodes and original_edges == fresh_edges


def _check_clause_8() -> bool:
    """Environment: must be Linux ARM64 (Oracle). Windows/local results not valid.

    On Windows this returns False. On Linux ARM64 it returns True. On other Linux
    architectures it returns False (the contract specifies Oracle ARM64).
    """
    import platform

    if platform.system() != "Linux":
        return False
    machine = platform.machine().lower()
    return machine in ("aarch64", "arm64")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Field-prove verify_js_secret_leak against a live self-owned SPA lab."
    )
    parser.add_argument(
        "config",
        help="Path to js_lab_engagement.yaml",
    )
    parser.add_argument(
        "--expected",
        default=None,
        help="Path to expected.local.json (default: same dir as config)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip TLS verification (for self-signed Caddy internal CA lab)",
    )
    args = parser.parse_args(argv)

    config = load_spa_config(args.config)

    expected_path = args.expected
    if expected_path is None:
        expected_path = str(pathlib.Path(args.config).resolve().parent / "expected.local.json")

    expected = _load_expected(expected_path)

    # ── Build infrastructure (mirrors wp_chain_runner recon-only leg) ──────────
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id, verify=not args.no_verify)
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()

    # ── Create engagement + enable RECON_ONLY ──────────────────────────────────
    target = config.scope_domains[0]
    rec = auth.create_engagement(client_id=config.client_id, target=target)
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=config.scope_exclusions,
        ),
    )

    # ── Call verify_js_secret_leak ─────────────────────────────────────────────
    try:
        creds_added = verify_js_secret_leak(
            engagement_id=rec.engagement_id,
            auth=auth,
            http_client=http_client,
            scope_targets=config.scope_domains,
            graph_store=graph_store,
            event_store=event_store,
            secrets_manager=secrets_manager,
        )
    except Exception as exc:
        # Network-resilience: ConnectError → FAIL, not crash
        creds_added = 0
        detail = f"verify_js_secret_leak raised: {exc}"
    else:
        detail = ""

    # ── Evaluate all 8 acceptance predicate clauses ────────────────────────────
    clause_1 = creds_added == expected.expected_creds_added
    clause_2 = _check_clause_2(graph_store, target, expected)
    clause_3 = _check_clause_3(graph_store, secrets_manager, target, expected)
    clause_4 = _check_clause_4(graph_store, secrets_manager, expected)
    clause_5 = _check_clause_5(event_store, rec.engagement_id, expected)
    clause_6 = _check_clause_6(event_store, rec.engagement_id)
    clause_7 = _check_clause_7(event_store, graph_store, rec.engagement_id)
    clause_8 = _check_clause_8()

    result = SpaSecretFieldProveResult(
        creds_added=creds_added,
        clause_1_return_value=clause_1,
        clause_2_graph_state=clause_2,
        clause_3_vault_preview=clause_3,
        clause_4_decoys_absent=clause_4,
        clause_5_intel_endpoints=clause_5,
        clause_6_no_false_waf=clause_6,
        clause_7_determinism=clause_7,
        clause_8_environment=clause_8,
        detail=detail,
    )

    # ── Print verdict ───────────────────────────────────────────────────────────
    print("=" * 64)
    print("SPA JS-SECRET FIELD-PROVE")
    print("=" * 64)
    print(f"  Client ID           : {config.client_id}")
    print(f"  Target              : {target}")
    print(f"  Creds added         : {creds_added}")
    print(f"  Expected creds      : {expected.expected_creds_added}")
    print("-" * 64)
    print(f"  Clause 1 (return)   : {'PASS' if clause_1 else 'FAIL'}")
    print(f"  Clause 2 (graph)    : {'PASS' if clause_2 else 'FAIL'}")
    print(f"  Clause 3 (vault)    : {'PASS' if clause_3 else 'FAIL'}")
    print(f"  Clause 4 (decoys)   : {'PASS' if clause_4 else 'FAIL'}")
    print(f"  Clause 5 (intel)    : {'PASS' if clause_5 else 'FAIL'}")
    print(f"  Clause 6 (no WAF)   : {'PASS' if clause_6 else 'FAIL'}")
    print(f"  Clause 7 (replay)   : {'PASS' if clause_7 else 'FAIL'}")
    print(f"  Clause 8 (env)      : {'PASS' if clause_8 else 'FAIL'}")
    if result.detail:
        print(f"  Detail              : {result.detail}")
    print("-" * 64)
    verdict = "PROVEN" if result.proven else "FAIL"
    print(f"  Verdict: {verdict}")
    print("=" * 64)

    return 0 if result.proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
