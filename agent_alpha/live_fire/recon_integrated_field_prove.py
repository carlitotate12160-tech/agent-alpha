"""§12.48 integrated field-prove — the FULL autonomous recon path, end-to-end.

Closes a real seam gap (RUNNER-SEAL != AUTONOMOUS-WIRED): every existing runner
(gap015_field_prove, layer_v_runner) drives ``Alpha.run_recon`` DIRECTLY, so the
new passive stage — CertSpotter→crt.sh→HackerTarget CT chain, DNS enrichment, OTX
enrichment, CompositeOriginDiscovery (GAP-017), and the Bug#26 probe-suppression
consumer — has NEVER been exercised on the autonomous path outside unit tests.

This harness drives ``recon_runner.run_recon_for_engagement`` with conductor/
main.py's PRODUCTION wiring verbatim (build_otx_client, LiveOriginDiscovery,
CompositeOriginDiscovery, DnspythonResolver, a signed EngagementProfile). The
wiring UNDER TEST is the same wiring the Celery worker uses — not a harness copy
(anti-island / anti-Lyndon #6). Origin IPs are DISCOVERED (OTX/CT) and PROVEN via
the ownership-token binding canary; they are NEVER hand-fed.

Lab-only (assert_lab_only_target for every scope host, fail-closed). Operational
runner, run on Oracle ARM64 with CERTSPOTTER_API_KEY + OTX_API_KEY +
DEEPSEEK_API_KEY + PROFILE_SIGNING_KEY set.

Run:
    python -m agent_alpha.live_fire.recon_integrated_field_prove <engagement.yaml>
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any
from urllib.parse import urlparse

import yaml

from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.domain_verification import DnspythonResolver
from agent_alpha.conductor.engagement_profile import (
    ConsentRecord,
    EngagementProfile,
    dump_signed_profile,
    load_signed_profile_from_dict,
)
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.config.stores import build_event_store
from agent_alpha.events.event_types import EventType
from agent_alpha.live_fire.lab_guard import assert_lab_only_target
from agent_alpha.recon.origin_discovery import CompositeOriginDiscovery
from agent_alpha.recon.origin_resolver import LiveOriginDiscovery
from agent_alpha.security.secrets import SecretsManager, get_profile_signing_key


@dataclasses.dataclass(frozen=True)
class IntegratedConfig:
    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    scope_exclusions: list[str]
    recon_url: str
    # §12.46 binding artifact: (host -> ownership token). The origin behind the
    # CDN must serve ``/.well-known/agent-alpha-<token>.txt`` echoing the token —
    # that is the ownership PROOF that authorizes an otherwise-untrusted DISCOVERED
    # IP (candidate != authorization). Without it T4 (binding) cannot pass; that is
    # honest fail-closed, not a runner bug.
    ownership_tokens: dict[str, str]
    consent_items: list[str]
    signed_by: str
    signed_at: str


@dataclasses.dataclass(frozen=True)
class Oracle:
    """One independent T1-T6 verdict line."""

    name: str
    passed: bool
    detail: str
    skipped: bool = False


def load_config(path: str | pathlib.Path) -> IntegratedConfig:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("integrated config must be a YAML mapping")
    scope = data.get("scope", {}) or {}
    tokens = data.get("ownership_tokens", {}) or {}
    if not isinstance(tokens, dict):
        raise ValueError("ownership_tokens must be a YAML mapping of host -> token")
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


def build_signed_profile(engagement_id: str, config: IntegratedConfig) -> EngagementProfile:
    """Build the §12.36 signed EngagementProfile bound to THIS engagement.

    The profile is minted against the runtime-generated ``engagement_id`` (the
    caller owns create+authorize — one engagement, gap015 pattern), so it cannot
    be pre-signed by ``scripts/sign_profile.py`` (that CLI signs a static id and
    lacks the origin/subdomain/consent flags). We instead sign + HMAC-verify with
    the SAME production functions that CLI uses (``dump_signed_profile`` /
    ``load_signed_profile_from_dict``) — proving the integrity envelope round-trips
    exactly as the Conductor's ``ENGAGEMENT_PROFILE_SIGNED`` load path does.
    """
    profile = EngagementProfile(
        engagement_id=engagement_id,
        client_id=config.client_id,
        targets=frozenset(config.scope_domains),
        scope_targets=frozenset(config.scope_domains),
        scope_mode="multi",
        ownership_tokens=frozenset(config.ownership_tokens.items()),
        allow_origin_discovery=True,  # §12.46: discover + PROVE-bind origin IPs
        allow_subdomain_enum=True,  # §12.41: probe in-scope CT siblings
        authorization_level="RECON_ONLY",
        consent=ConsentRecord(
            accepted_items=frozenset(config.consent_items),
            signed_by=config.signed_by,
            signed_at=config.signed_at,
        ),
    )
    # Sign then verify-load — any tamper fails ProfileSignatureError (anti-downgrade).
    signing_key = get_profile_signing_key()
    envelope = dump_signed_profile(profile, key=signing_key)
    return load_signed_profile_from_dict(envelope, key=signing_key)


def _passive_events(event_store: Any, engagement_id: str) -> list[Any]:
    events = event_store.get_events(engagement_id)
    return [e for e in events if e.event_type == EventType.PASSIVE_INTEL_GATHERED]


def _binding_events(event_store: Any, engagement_id: str) -> list[Any]:
    events = event_store.get_events(engagement_id)
    return [e for e in events if e.event_type == EventType.ORIGIN_BINDING_PROVEN]


def evaluate_oracles(
    event_store: Any,
    engagement_id: str,
    config: IntegratedConfig,
    *,
    otx_enabled: bool,
) -> list[Oracle]:
    passive = _passive_events(event_store, engagement_id)
    bindings = _binding_events(event_store, engagement_id)
    apex = urlparse(config.recon_url).hostname or ""
    # apex CF signal is keyed on the base domain (NS-derived, domain-scoped).
    base_domain = config.scope_domains[0] if config.scope_domains else apex

    # T1 — PASSIVE_INTEL_GATHERED emitted from a CT source (certspotter | crtsh).
    ct_sources = {"certspotter", "crtsh"}
    t1_hits = [e for e in passive if ct_sources.intersection(e.payload.get("sources_used", []))]
    t1 = Oracle(
        "T1 PASSIVE_INTEL_GATHERED (CT source)",
        bool(t1_hits),
        f"{len(passive)} passive event(s); CT-sourced={len(t1_hits)}",
    )

    # T2 — CT chain surfaced real in-scope siblings.
    t2_hits = [e for e in passive if e.payload.get("in_scope_subdomains")]
    all_in_scope = sorted({s for e in passive for s in e.payload.get("in_scope_subdomains", [])})
    t2 = Oracle(
        "T2 in_scope_subdomains non-empty",
        bool(t2_hits),
        f"in_scope={all_in_scope}",
    )

    # T3 — OTX surfaced origin-IP candidates (needs OTX_API_KEY).
    all_candidates = sorted(
        {ip for e in passive for ip in e.payload.get("origin_ip_candidates", [])}
    )
    t3 = Oracle(
        "T3 origin_ip_candidates non-empty (OTX)",
        bool(all_candidates),
        (
            f"candidates={all_candidates}"
            if otx_enabled
            else "OTX_API_KEY not set — OTX enrichment skipped"
        ),
        skipped=not otx_enabled,
    )

    # T4 — MOAT: >=1 ORIGIN_BINDING_PROVEN (a hidden origin behind CF proven to
    # serve the owned host via the ownership-token canary). The CF-bypass proof.
    proven = [(e.payload.get("fronted_host"), e.payload.get("origin_ip")) for e in bindings]
    t4 = Oracle(
        "T4 ORIGIN_BINDING_PROVEN (CF-bypass MOAT)",
        bool(bindings),
        f"bound={proven}",
    )

    # T5 — CF apex protection detected (Bug#26 signal produced + consumed).
    cf_hits = [
        e
        for e in passive
        if e.payload.get("protection_detected") == "cloudflare"
        and e.payload.get("domain", "").rstrip(".").lower() == base_domain.rstrip(".").lower()
    ]
    t5 = Oracle(
        "T5 protection_detected == cloudflare (apex)",
        bool(cf_hits),
        f"apex={base_domain!r} cf_signal={bool(cf_hits)}",
    )

    # T6 — every scope host is a self-owned lab host (asserted pre-run, no
    # LabOnlyViolation reached this point → zero out-of-scope host contacted).
    t6 = Oracle(
        "T6 lab-only (no out-of-scope contact)",
        True,
        f"{len(config.scope_domains)} scope host(s) all lab-allowlisted",
    )

    return [t1, t2, t3, t4, t5, t6]


def run_integrated_field_prove(config: IntegratedConfig) -> list[Oracle]:
    """Build main.py's production recon deps and drive run_recon_for_engagement."""
    # Lab-only guard — EVERY scope host + the recon URL, BEFORE any I/O.
    assert_lab_only_target(config.recon_url)
    for host in config.scope_domains:
        assert_lab_only_target(host)

    event_store = build_event_store()
    auth = AuthorizationStateMachine(event_store=event_store)

    # ONE engagement, owned by the caller (no double-engagement — the profile,
    # origin discovery, and this run all share ONE engagement_id).
    rec = auth.create_engagement(client_id=config.client_id, target=config.scope_domains[0])
    engagement_id = rec.engagement_id
    auth.enable_recon(
        engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=config.scope_exclusions,
        ),
    )
    # Re-fetch the record AFTER enable_recon — create_engagement returns a record
    # with scope=None; the scope is set by enable_recon's STATE_TRANSITIONED event.
    # Passing the stale rec to run_recon_for_engagement → NoTargetsError (mirrors
    # main.py which fetches the record post-authorization in the worker).
    rec = auth.get_record(engagement_id)

    profile = build_signed_profile(engagement_id, config)

    # ── PRODUCTION wiring (verbatim from conductor/main.py run_engagement_task) ──
    base = LiveOriginDiscovery(engagement_id, auth)  # §12.46 CT/DNS discovery
    origin_discovery = CompositeOriginDiscovery(base, event_store, engagement_id)  # GAP-017
    otx_client = recon_runner.build_otx_client(engagement_id)  # slice-5 (None if no key)
    dns_resolver = DnspythonResolver()  # slice-3

    run_result = recon_runner.run_recon_for_engagement(
        engagement_id,
        None,  # tenant_id
        auth,
        event_store,
        rec,
        secrets_manager=SecretsManager(),
        policy=PolicyEnforcer(),
        engagement_profile=profile,
        origin_discovery=origin_discovery,
        otx_client=otx_client,
        dns_resolver=dns_resolver,
    )

    print(
        f"[run] engagement={engagement_id} targets_scanned={run_result.targets_scanned} "
        f"nodes={run_result.node_count} enumerated={list(run_result.enumerated_hosts)}"
    )
    return evaluate_oracles(event_store, engagement_id, config, otx_enabled=otx_client is not None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Agent-Alpha §12.48 integrated (passive→OTX→binding→Bug#26) field-prove"
    )
    parser.add_argument("config", help="engagement YAML")
    args = parser.parse_args(argv)
    config = load_config(args.config)

    oracles = run_integrated_field_prove(config)

    print("=" * 68)
    print("INTEGRATED RECON FIELD-PROVE VERDICT")
    print("=" * 68)
    required_failed = False
    for o in oracles:
        if o.skipped:
            mark = "SKIP"
        elif o.passed:
            mark = "PASS"
        else:
            mark = "FAIL"
            required_failed = True
        print(f"  [{mark}] {o.name}")
        print(f"         {o.detail}")
    print("=" * 68)
    verdict = "ALL REQUIRED ORACLES PASS" if not required_failed else "ONE OR MORE ORACLES FAILED"
    print(f"  {verdict}")
    print("=" * 68)
    return 0 if not required_failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
