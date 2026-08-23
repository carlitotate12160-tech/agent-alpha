"""Class-C CoverageLedger diagnostic — read-only funnel projection over the event stream.

Produces one structured-English JSON verdict per target, deriving the
earliest_failed_transition mechanically from real events.  No production code
is modified; this is a diagnostic-only live-fire runner.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import platform
import sys
from collections.abc import Iterable
from typing import Any

import yaml

from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.domain_verification import DnspythonResolver
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.config.stores import build_event_store
from agent_alpha.coverage.coverage_ledger import (
    CoverageCell,
    CoverageReport,
    Technique,
    load_catalog,
    project_coverage,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent, InMemoryEventStore
from agent_alpha.live_fire.lab_guard import assert_lab_only_target
from agent_alpha.live_fire.recon_integrated_field_prove import (
    IntegratedConfig,
)
from agent_alpha.live_fire.recon_integrated_field_prove import (
    build_signed_profile as _build_signed_profile,
)
from agent_alpha.recon.origin_discovery import CompositeOriginDiscovery
from agent_alpha.recon.origin_resolver import LiveOriginDiscovery
from agent_alpha.security.secrets import SecretsManager


@dataclasses.dataclass(frozen=True)
class DiagnosticConfig:
    engagement_ids: tuple[str, ...] = ()
    targets: tuple[IntegratedConfig, ...] = ()
    excluded_techniques: frozenset[str] = frozenset()


@dataclasses.dataclass(frozen=True)
class FunnelStage:
    stage: str
    passed: bool
    evidence: list[str]


_STAGE_ORDER = (
    "S1_AUTHORIZED_ROOT_SEED",
    "S2_PASSIVE_SURFACE",
    "S3_REACH",
    "S4_STACK_AUTH_CLASSIFICATION",
    "S5_APPLICABLE_CAPABILITY",
    "S6_DISPATCH",
    "S7_TARGET_SIGNAL",
    "S8_HYPOTHESIS_EVIDENCE",
    "S9_INDEPENDENT_ORACLE",
    "S10_CROSS_VERIFIED_EDGE",
    "S11_CHAIN",
    "S12_OMEGA",
)

_ROOT_EVENTS = frozenset(
    {
        str(EventType.ENGAGEMENT_CREATED),
        str(EventType.ENGAGEMENT_AUTHORIZED),
        str(EventType.ENGAGEMENT_PROFILE_SIGNED),
        str(EventType.STATE_TRANSITIONED),
    }
)

_PASSIVE_EVENTS = frozenset(
    {
        str(EventType.PASSIVE_DISCOVERY),
        str(EventType.PASSIVE_INTEL_GATHERED),
    }
)

_SIGNAL_PRODUCES: dict[str, tuple[str, ...]] = {
    "git_exposure_leak": ("credential",),
    "js_secret_leak": ("credential",),
    "wp_rest_user_enum": ("user_enumerated",),
    "origin_exposure_bypass": ("fronted_host",),
    "cred_reuse": ("access:user", "enables_cred_access"),
    "spa_json_login": ("access:user", "enables_cred_access"),
    "default_creds_login": ("access:user", "enables_cred_access"),
    "http_basic_auth_strike": ("access:user", "enables_cred_access"),
    "sqli_auth_bypass": ("access:user", "enables_cred_access"),
    "mfa_challenge_honest": ("access:user",),
    "breach_credential_reuse": ("access:user", "enables_cred_access"),
    "oauth_saml_jwt_forgery": ("access:user", "enables_cred_access"),
}


def _event_host(payload: dict[str, Any]) -> str:
    """Best-effort host extraction from an event payload."""
    props = payload.get("properties")
    if isinstance(props, dict):
        host = props.get("host") or props.get("fronted_host")
        if host:
            return str(host)
    host = payload.get("host") or payload.get("fronted_host") or ""
    if host:
        return str(host)
    node_id = payload.get("id") or ""
    if node_id:
        parts = node_id.split(":")
        if len(parts) >= 3 and parts[0] in {
            "user",
            "cred",
            "vuln",
            "service",
            "data",
            "access",
        }:
            return parts[1]
    return ""


def _node_type(payload: dict[str, Any]) -> str:
    return str(payload.get("type", ""))


def _is_non_asset_node(payload: dict[str, Any]) -> bool:
    return _node_type(payload) not in ("", "asset")


def _passive_hosts(events: Iterable[AgentEvent]) -> set[str]:
    hosts: set[str] = set()
    for e in events:
        if e.event_type not in _PASSIVE_EVENTS:
            continue
        p = e.payload
        for key in ("in_scope", "discovered", "enumerated", "in_scope_subdomains"):
            vals = p.get(key)
            if isinstance(vals, list):
                hosts.update(str(v) for v in vals if v)
    return hosts


def _asset_hosts(events: Iterable[AgentEvent]) -> set[str]:
    hosts: set[str] = set()
    for e in events:
        if e.event_type == str(EventType.NODE_DISCOVERED):
            host = _event_host(e.payload)
            if host and _node_type(e.payload) in ("", "asset"):
                hosts.add(host)
    return hosts


def _blocked_hosts(events: Iterable[AgentEvent]) -> set[str]:
    blocked: set[str] = set()
    for e in events:
        if e.event_type in (str(EventType.WAF_BLOCKED), str(EventType.HOST_ABANDONED)):
            host = e.payload.get("host")
            if host:
                blocked.add(str(host))
    return blocked


def _stacks_confirmed(events: Iterable[AgentEvent]) -> list[str]:
    stacks: set[str] = set()
    for e in events:
        if e.event_type != str(EventType.NODE_DISCOVERED):
            continue
        if _node_type(e.payload) not in ("", "asset"):
            continue
        props = e.payload.get("properties") or {}
        tech_stack = props.get("tech_stack") or []
        if isinstance(tech_stack, list):
            stacks.update(str(s) for s in tech_stack)
    return sorted(stacks)


def _bucket_counts(report: CoverageReport) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in report.cells:
        counts[c.bucket] = counts.get(c.bucket, 0) + 1
    return counts


def _applicable_cells(report: CoverageReport) -> list[CoverageCell]:
    return [c for c in report.cells if c.bucket != "out_of_scope"]


def _tested_cells(report: CoverageReport) -> list[CoverageCell]:
    return [c for c in report.cells if c.bucket == "tested"]


def _capability_absent_all_applicable(report: CoverageReport) -> tuple[bool, list[str]]:
    applicable = _applicable_cells(report)
    if not applicable:
        return False, []
    absent = [c.technique_id for c in applicable if c.bucket == "capability_absent"]
    return len(absent) == len(applicable), absent


def _technique_signal(
    technique: Technique,
    surface_id: str,
    events: Iterable[AgentEvent],
) -> tuple[bool, str]:
    produces = _SIGNAL_PRODUCES.get(technique.id)
    if not produces:
        return False, "instrumentation_absent"
    if technique.id == "origin_exposure_bypass":
        for e in events:
            if e.event_type == str(EventType.ORIGIN_BINDING_PROVEN):
                if e.payload.get("fronted_host") == surface_id:
                    return True, "ORIGIN_BINDING_PROVEN"
        return False, "no_origin_binding"

    has_credential = "credential" in produces
    has_user = "user_enumerated" in produces
    has_access = "access:user" in produces or "enables_cred_access" in produces

    for e in events:
        if e.event_type != str(EventType.NODE_DISCOVERED):
            continue
        host = _event_host(e.payload)
        if host != surface_id:
            continue
        node_type = _node_type(e.payload)
        if has_credential and node_type in ("credential",):
            return True, f"NodeDiscovered:{node_type}"
        if has_user and node_type == "user":
            return True, f"NodeDiscovered:{node_type}"
        if has_access and node_type in ("access_level", "service"):
            return True, f"NodeDiscovered:{node_type}"
    if has_access:
        for e in events:
            if e.event_type == str(EventType.AUTHENTICATED_SURFACE_DISCOVERED):
                if e.payload.get("host") == surface_id:
                    return True, "AuthenticatedSurfaceDiscovered"
    return False, "no_signal"


def _cross_verified_nodes(events: Iterable[AgentEvent]) -> set[str]:
    verified: set[str] = set()
    for e in events:
        if e.event_type == str(EventType.NODE_VERIFIED):
            node_id = e.payload.get("node_id")
            if node_id:
                verified.add(str(node_id))
        if e.event_type == str(EventType.NODE_DISCOVERED):
            node_id = e.payload.get("id")
            verification = e.payload.get("verification")
            if node_id and verification == "cross_verified":
                verified.add(str(node_id))
    return verified


def _has_payable_chain(events: Iterable[AgentEvent], verified: set[str]) -> bool:
    for e in events:
        if e.event_type != str(EventType.EDGE_DISCOVERED):
            continue
        rel = e.payload.get("relationship")
        if rel not in ("enables", "leads_to"):
            continue
        src = e.payload.get("source_id")
        tgt = e.payload.get("target_id")
        if src and tgt and src in verified and tgt in verified:
            return True
    return False


def _compute_funnel(
    events: list[AgentEvent],
    report: CoverageReport,
    catalog: tuple[Technique, ...],
) -> tuple[list[FunnelStage], str, str]:
    """Compute the ordered funnel and the earliest failing stage."""
    by_type: dict[str, list[AgentEvent]] = {}
    for e in events:
        by_type.setdefault(e.event_type, []).append(e)

    stages: list[FunnelStage] = []

    # S1
    root_events = [e for t in _ROOT_EVENTS for e in by_type.get(t, [])]
    s1_pass = bool(root_events)
    stages.append(
        FunnelStage(
            "S1_AUTHORIZED_ROOT_SEED",
            s1_pass,
            [f"{t} x{len(by_type.get(t, []))}" for t in _ROOT_EVENTS],
        )
    )

    # S2
    passive_hosts = _passive_hosts(events)
    passive_surface_nodes = [
        e
        for e in by_type.get(str(EventType.NODE_DISCOVERED), [])
        if _event_host(e.payload) in passive_hosts and _node_type(e.payload) in ("", "asset")
    ]
    s2_pass = bool(passive_hosts) and bool(passive_surface_nodes)
    stages.append(
        FunnelStage(
            "S2_PASSIVE_SURFACE",
            s2_pass,
            [
                f"passive_hosts={sorted(passive_hosts)}",
                f"NodeDiscovered(passive) x{len(passive_surface_nodes)}",
            ],
        )
    )

    # S3
    assets = _asset_hosts(events)
    blocked = _blocked_hosts(events)
    reachable = assets - blocked
    s3_pass = bool(reachable)
    stages.append(
        FunnelStage(
            "S3_REACH",
            s3_pass,
            [
                f"asset_hosts={sorted(assets)}",
                f"blocked_hosts={sorted(blocked)}",
                f"reachable_hosts={sorted(reachable)}",
            ],
        )
    )

    # S4
    stacks = _stacks_confirmed(events)
    s4_pass = bool(stacks)
    stages.append(
        FunnelStage(
            "S4_STACK_AUTH_CLASSIFICATION",
            s4_pass,
            [f"stacks_confirmed={stacks}"],
        )
    )

    # S5
    all_absent, absent_ids = _capability_absent_all_applicable(report)
    s5_pass = not all_absent and bool(_applicable_cells(report))
    stages.append(
        FunnelStage(
            "S5_APPLICABLE_CAPABILITY",
            s5_pass,
            [
                f"applicable_cells={len(_applicable_cells(report))}",
                f"capability_absent={len(absent_ids)}",
            ],
        )
    )

    # S6
    tested = _tested_cells(report)
    s6_pass = bool(tested)
    stages.append(
        FunnelStage(
            "S6_DISPATCH",
            s6_pass,
            [
                f"tested_cells={len(tested)}",
                f"tested={[(c.surface_id, c.technique_id) for c in tested]}",
            ],
        )
    )

    # S7
    catalog_by_id = {t.id: t for t in catalog}
    tested_with_signal: list[str] = []
    tested_without_signal: list[str] = []
    for c in tested:
        tech = catalog_by_id.get(c.technique_id)
        if not tech:
            tested_without_signal.append(f"{c.surface_id}/{c.technique_id}: unknown_technique")
            continue
        ok, detail = _technique_signal(tech, c.surface_id, events)
        if ok:
            tested_with_signal.append(f"{c.surface_id}/{c.technique_id}: {detail}")
        else:
            tested_without_signal.append(f"{c.surface_id}/{c.technique_id}: {detail}")
    s7_pass = bool(tested_with_signal)
    stages.append(
        FunnelStage(
            "S7_TARGET_SIGNAL",
            s7_pass,
            [
                f"with_signal x{len(tested_with_signal)}",
                f"without_signal x{len(tested_without_signal)}",
            ],
        )
    )

    # S8
    finding_nodes = [
        e for e in by_type.get(str(EventType.NODE_DISCOVERED), []) if _is_non_asset_node(e.payload)
    ]
    s8_pass = bool(finding_nodes)
    stages.append(
        FunnelStage(
            "S8_HYPOTHESIS_EVIDENCE",
            s8_pass,
            [f"finding/credential/non-asset NodeDiscovered x{len(finding_nodes)}"],
        )
    )

    # S9
    oracle_events = [
        e
        for t in (str(EventType.NODE_VERIFIED), str(EventType.PROOF_ARTIFACT_RECORDED))
        for e in by_type.get(t, [])
    ]
    s9_pass = bool(oracle_events)
    stages.append(
        FunnelStage(
            "S9_INDEPENDENT_ORACLE",
            s9_pass,
            [f"{e.event_type} x{len(by_type.get(e.event_type, []))}" for e in oracle_events[:3]],
        )
    )

    # S10
    verified = _cross_verified_nodes(events)
    s10_pass = bool(verified)
    stages.append(
        FunnelStage(
            "S10_CROSS_VERIFIED_EDGE",
            s10_pass,
            [f"cross_verified_nodes={sorted(verified)}"],
        )
    )

    # S11
    s11_pass = _has_payable_chain(events, verified)
    stages.append(
        FunnelStage(
            "S11_CHAIN",
            s11_pass,
            ["payable_chain present" if s11_pass else "no payable chain"],
        )
    )

    # S12
    proof_backed_findings = [
        e
        for e in by_type.get(str(EventType.NODE_DISCOVERED), [])
        if _is_non_asset_node(e.payload) and e.payload.get("proof_artifacts")
    ]
    s12_pass = bool(proof_backed_findings) or bool(
        by_type.get(str(EventType.PROOF_ARTIFACT_RECORDED), [])
    )
    stages.append(
        FunnelStage(
            "S12_OMEGA",
            s12_pass,
            [f"proof-backed findings x{len(proof_backed_findings)}"],
        )
    )

    earliest = ""
    detail = ""
    for s in stages:
        if not s.passed:
            earliest = s.stage
            detail = _stage_failure_detail(
                s, report, catalog, tested_without_signal, absent_ids, blocked
            )
            break
    if not earliest:
        earliest = "S12_OMEGA"
        detail = "funnel complete through S12"

    return stages, earliest, detail


def _stage_failure_detail(
    stage: FunnelStage,
    report: CoverageReport,
    catalog: tuple[Technique, ...],
    tested_without_signal: list[str],
    absent_ids: list[str],
    blocked: set[str],
) -> str:
    if stage.stage == "S1_AUTHORIZED_ROOT_SEED":
        return "no engagement binding/profile events for engagement_id"
    if stage.stage == "S2_PASSIVE_SURFACE":
        return "no PASSIVE_DISCOVERY/PASSIVE_INTEL_GATHERED with in-scope surface"
    if stage.stage == "S3_REACH":
        return f"all discovered hosts are blocked/abandoned: blocked={sorted(blocked)}; surface not exhausted"
    if stage.stage == "S4_STACK_AUTH_CLASSIFICATION":
        return "no surface has a confirmed tech_stack or auth mechanism"
    if stage.stage == "S5_APPLICABLE_CAPABILITY":
        return f"every applicable cell is capability_absent: {absent_ids}"
    if stage.stage == "S6_DISPATCH":
        not_run = sorted({c.technique_id for c in report.cells if c.bucket == "not_run"})
        return f"no technique reached bucket 'tested'; not_run={not_run}"
    if stage.stage == "S7_TARGET_SIGNAL":
        return f"tested techniques produced no non-404/non-junk signal: {tested_without_signal}"
    if stage.stage in (
        "S8_HYPOTHESIS_EVIDENCE",
        "S9_INDEPENDENT_ORACLE",
        "S10_CROSS_VERIFIED_EDGE",
        "S11_CHAIN",
        "S12_OMEGA",
    ):
        return f"{stage.stage} not satisfied"
    return ""


def _next_slice_for_stage(
    stage: str,
    report: CoverageReport,
    catalog: tuple[Technique, ...],
    tested_without_signal: list[str],
    absent_ids: list[str],
) -> str:
    mapping = {
        "S1_AUTHORIZED_ROOT_SEED": "conductor/authorization — engagement creation and profile signing",
        "S2_PASSIVE_SURFACE": "§12.48 passive OSINT chain (CertSpotter/crt.sh/HackerTarget/OTX/VT)",
        "S3_REACH": "GAP-196/197 transport-dead reach + edge-fronted classification",
        "S4_STACK_AUTH_CLASSIFICATION": "GAP-169 fingerprint-first + auth_surface detection",
        "S5_APPLICABLE_CAPABILITY": _pick_capability_slice(report, catalog, absent_ids),
        "S6_DISPATCH": "§12.64 Step 0 — RECON_TECHNIQUE_ATTEMPTED instrumentation",
        "S7_TARGET_SIGNAL": _pick_signal_slice(tested_without_signal),
        "S8_HYPOTHESIS_EVIDENCE": "leak extraction / username harvest (GAP-047/GAP-030)",
        "S9_INDEPENDENT_ORACLE": "§12.43 independent per-edge oracle (P1)",
        "S10_CROSS_VERIFIED_EDGE": "GAP-118 attestor provenance / cross_verified tier",
        "S11_CHAIN": "ChainOracle MIN-composition",
        "S12_OMEGA": "Omega report / proof-artifact emission",
    }
    return mapping.get(stage, "unknown")


def _pick_capability_slice(
    report: CoverageReport, catalog: tuple[Technique, ...], absent_ids: list[str]
) -> str:
    by_id = {t.id: t for t in catalog}
    for c in report.cells:
        if c.bucket == "capability_absent" and c.technique_id in absent_ids:
            tech = by_id.get(c.technique_id)
            if tech and tech.gap_ref:
                return f"{tech.gap_ref} — build {c.technique_id} on {c.surface_type}:{c.surface_id}"
    if absent_ids:
        return f"build capability {absent_ids[0]}"
    return "build first not_assessed capability"


def _pick_signal_slice(tested_without_signal: list[str]) -> str:
    if tested_without_signal:
        return f"per-technique signal instrumentation / GAP-028 generic signal validation — {tested_without_signal[0]}"
    return "GAP-028 generic homepage/catch-all signal validation"


def _owner_for_stage(stage: str) -> str:
    mapping = {
        "S1_AUTHORIZED_ROOT_SEED": "conductor.authorization",
        "S2_PASSIVE_SURFACE": "conductor.recon_runner / recon.passive_intel",
        "S3_REACH": "recon.origin_reach / scout",
        "S4_STACK_AUTH_CLASSIFICATION": "recon.fingerprint / recon.auth_surface",
        "S5_APPLICABLE_CAPABILITY": "coverage.techniques (capability_absent catalog)",
        "S6_DISPATCH": "scout / recon.recon_coverage",
        "S7_TARGET_SIGNAL": "scout / recon.path_probe / recon.js_secret_probe / recon.wp_rest_users",
        "S8_HYPOTHESIS_EVIDENCE": "recon.path_probe / security.credential_assembly",
        "S9_INDEPENDENT_ORACLE": "attestation.attestor",
        "S10_CROSS_VERIFIED_EDGE": "attestation.attestor",
        "S11_CHAIN": "conductor.chain_oracle (not built)",
        "S12_OMEGA": "agents.omega",
    }
    return mapping.get(stage, "unknown")


def _adr_divergence_for_stage(stage: str) -> str:
    if stage in ("S7_TARGET_SIGNAL", "S8_HYPOTHESIS_EVIDENCE"):
        return "technique dispatch is instrumented (RECON_TECHNIQUE_ATTEMPTED) but per-technique non-404/non-junk signal is not a dedicated event type; S7 falls back to NodeDiscovered node-type heuristics"
    if stage == "S12_OMEGA":
        return "Omega report object is built but no OMEGA_REPORT_EMITTED event is written to the stream"
    return "none"


def _build_verdict(
    target: str,
    run_mode: str,
    test_env: str,
    events: list[AgentEvent],
    report: CoverageReport,
    catalog: tuple[Technique, ...],
) -> dict[str, Any]:
    stages, earliest, detail = _compute_funnel(events, report, catalog)
    by_type: dict[str, list[AgentEvent]] = {}
    for e in events:
        by_type.setdefault(e.event_type, []).append(e)
    tested = _tested_cells(report)
    catalog_by_id = {t.id: t for t in catalog}
    tested_without_signal: list[str] = []
    for c in tested:
        tech = catalog_by_id.get(c.technique_id)
        if not tech:
            tested_without_signal.append(f"{c.surface_id}/{c.technique_id}: unknown_technique")
            continue
        ok, reason = _technique_signal(tech, c.surface_id, events)
        if not ok:
            tested_without_signal.append(f"{c.surface_id}/{c.technique_id}: {reason}")
    _, absent_ids = _capability_absent_all_applicable(report)

    return {
        "target": target,
        "run_mode": run_mode,
        "test_env": test_env,
        "challenged_contract": "ADR §12.62 coverage-honesty doctrine + §12.64 recon coverage ledger",
        "decision_status": "ACCEPTED",
        "field_evidence": {
            "surfaces": len({(c.surface_id, c.surface_type) for c in report.cells}),
            "stacks_confirmed": _stacks_confirmed(events),
            "buckets": _bucket_counts(report),
            "not_assessed": list(report.not_assessed),
        },
        "funnel": [
            {
                "stage": s.stage,
                "passed": s.passed,
                "evidence": s.evidence,
            }
            for s in stages
        ],
        "earliest_failed_transition": earliest,
        "earliest_failed_detail": detail,
        "adr_code_divergence": _adr_divergence_for_stage(earliest),
        "existing_owner": _owner_for_stage(earliest),
        "next_vertical_slice": _next_slice_for_stage(
            earliest, report, catalog, tested_without_signal, absent_ids
        ),
        "new_gap_required": False,
    }


def _project_for_engagement(
    store: Any,
    engagement_id: str,
    catalog: tuple[Technique, ...],
    excluded_techniques: frozenset[str],
    test_env: str,
) -> dict[str, Any]:
    events = store.get_events(engagement_id)
    report = project_coverage(events, catalog, excluded_techniques=excluded_techniques)
    return _build_verdict(engagement_id, "A_replay", test_env, events, report, catalog)


def _load_diagnostic_config(path: str) -> DiagnosticConfig:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("diagnostic config must be a YAML mapping")

    engagement_ids = tuple(str(x) for x in data.get("engagement_ids", []))
    target_dicts = data.get("targets", [])
    targets = tuple(_dict_to_integrated_config(d) for d in target_dicts)
    excluded = frozenset(str(x) for x in data.get("excluded_techniques", []))
    return DiagnosticConfig(
        engagement_ids=engagement_ids,
        targets=targets,
        excluded_techniques=excluded,
    )


def _dict_to_integrated_config(data: dict[str, Any]) -> IntegratedConfig:
    scope = data.get("scope", {}) or {}
    tokens = data.get("ownership_tokens", {}) or {}
    if not isinstance(tokens, dict):
        raise ValueError("ownership_tokens must be a mapping")
    return IntegratedConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope.get("ip_ranges", [])),
        scope_domains=list(scope["domains"]),
        scope_exclusions=list(scope.get("exclusions", [])),
        recon_url=data["recon_url"],
        ownership_tokens={str(h).strip().lower(): str(t) for h, t in tokens.items()},
        consent_items=list(data.get("consent_items", [])),
        signed_by=data.get("signed_by", ""),
        signed_at=data.get("signed_at", ""),
    )


def _run_live_target(
    store: Any,
    target: IntegratedConfig,
    catalog: tuple[Technique, ...],
    excluded: frozenset[str],
    test_env: str,
) -> dict[str, Any]:
    assert_lab_only_target(target.recon_url)
    for host in target.scope_domains:
        assert_lab_only_target(host)

    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id=target.client_id, target=target.scope_domains[0])
    engagement_id = rec.engagement_id
    auth.enable_recon(
        engagement_id,
        Scope(
            ip_ranges=target.scope_ip_ranges,
            domains=target.scope_domains,
            exclusions=target.scope_exclusions,
        ),
    )
    rec = auth.get_record(engagement_id)
    profile = _build_signed_profile(engagement_id, target)

    base = LiveOriginDiscovery(engagement_id, auth)
    origin_discovery = CompositeOriginDiscovery(base, store, engagement_id)
    otx_client = recon_runner.build_otx_client(engagement_id)
    mnemonic_client = recon_runner.build_mnemonic_client(engagement_id)
    dns_resolver = DnspythonResolver()

    recon_runner.run_recon_for_engagement(
        engagement_id,
        None,
        auth,
        store,
        rec,
        secrets_manager=SecretsManager(),
        policy=PolicyEnforcer(),
        engagement_profile=profile,
        origin_discovery=origin_discovery,
        otx_client=otx_client,
        dns_resolver=dns_resolver,
        mnemonic_client=mnemonic_client,
    )

    events = store.get_events(engagement_id)
    report = project_coverage(events, catalog, excluded_techniques=excluded)
    return _build_verdict(
        target.client_id,
        "B_live_touch",
        test_env,
        events,
        report,
        catalog,
    )


def _is_in_memory(store: Any) -> bool:
    return isinstance(store, InMemoryEventStore)


def _test_env_name() -> str:
    machine = platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "oracle-arm64"
    return f"unsupported-{platform.system().lower()}-{machine}"


def _all_empty(store: Any, engagement_ids: Iterable[str]) -> bool:
    return all(not store.get_events(eid) for eid in engagement_ids)


def _detect_mode(store: Any, config: DiagnosticConfig) -> str:
    if config.engagement_ids:
        any_events = any(bool(store.get_events(eid)) for eid in config.engagement_ids)
        if any_events:
            return "A_replay"
        if _is_in_memory(store) and config.targets:
            return "B_live_touch"
        return "A_replay"
    if _is_in_memory(store) and config.targets:
        return "B_live_touch"
    return "no_data"


def run_diagnostic(
    store: Any,
    config: DiagnosticConfig,
    catalog: tuple[Technique, ...] | None = None,
    *,
    test_env: str = "",
    allow_live_touch: bool = False,
) -> list[dict[str, Any]]:
    """Entry point used by tests and CLI."""
    if catalog is None:
        catalog = load_catalog()
    if not test_env:
        test_env = _test_env_name()

    mode = _detect_mode(store, config)
    if mode == "B_live_touch" and not allow_live_touch:
        raise RuntimeError("[MODE B] NO persisted events and --allow-live-touch not set")
    if mode == "no_data":
        raise RuntimeError("No engagement_ids or live targets configured")

    results: list[dict[str, Any]] = []
    if mode == "A_replay":
        for eid in config.engagement_ids:
            results.append(
                _project_for_engagement(store, eid, catalog, config.excluded_techniques, test_env)
            )
    elif mode == "B_live_touch":
        for target in config.targets:
            results.append(
                _run_live_target(store, target, catalog, config.excluded_techniques, test_env)
            )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-Alpha Class-C CoverageLedger diagnostic")
    parser.add_argument("config", help="diagnostic YAML")
    parser.add_argument(
        "--allow-live-touch", action="store_true", help="permit Mode B live recon touch"
    )
    parser.add_argument("--test-env", default="", help="override test_env (tests only)")
    args = parser.parse_args(argv)

    test_env = args.test_env or _test_env_name()
    if not args.test_env and not test_env.startswith("oracle-arm64"):
        print(
            f"[REFUSE] test_env={test_env!r}; diagnostic JSON is emitted only on ARM64 Oracle",
            file=sys.stderr,
        )
        return 1

    config = _load_diagnostic_config(args.config)
    store = build_event_store()

    mode = _detect_mode(store, config)
    if mode == "B_live_touch" and not args.allow_live_touch:
        print(
            "[MODE B] NO persisted events — will perform ONE live recon touch per target (E1). "
            "This is NOT zero-touch. Authorized targets only. Use --allow-live-touch to proceed.",
            file=sys.stderr,
        )
        return 2

    try:
        results = run_diagnostic(
            store,
            config,
            test_env=test_env,
            allow_live_touch=args.allow_live_touch,
        )
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 3

    print(
        json.dumps(
            {"verdicts": results, "portfolio": _portfolio_roll_up(results)},
            sort_keys=True,
            indent=2,
        )
    )
    return 0


def _portfolio_roll_up(results: list[dict[str, Any]]) -> dict[str, Any]:
    transitions = [r["earliest_failed_transition"] for r in results]
    distinct = sorted(set(transitions))
    counts: dict[str, int] = {}
    for t in transitions:
        counts[t] = counts.get(t, 0) + 1
    if len(results) >= 2 and any(c >= 2 for c in counts.values()):
        lane = max(counts, key=lambda k: counts[k])
        return {
            "distinct_transitions": distinct,
            "counts": counts,
            "lane_signal": f"{counts[lane]}/{len(results)} targets break at {lane} -> that is the lane.",
        }
    return {
        "distinct_transitions": distinct,
        "counts": counts,
        "no_convergence": f"targets break at {set(transitions)} -> do NOT pick a lane from this evidence; widen sample.",
    }


if __name__ == "__main__":
    raise SystemExit(main())
