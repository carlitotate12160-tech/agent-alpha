# agent_alpha/conductor/recon_runner.py
"""C6a — the recon run pipeline executed inside the Celery worker (Shape B).

Wires the Phase-2 Alpha→Omega flow into the async run path. Celery args are
json-only (C1.7), so the worker cannot receive live dependencies (HttpClient, LLM
provider, graph store) over `.delay()`; they are built HERE, in-process. The two
seams — `build_recon_pipeline` and `resolve_recon_targets` — are module-level so a
hermetic test monkeypatches them to inject the same fakes the synchronous Phase-2
e2e uses (no live target, no LLM). Per-unit fan-out execution (via FanOutDispatcher)
and the live-fire FP<20% gate are C6b.
"""

from __future__ import annotations

import logging
import os
import pathlib
import socket
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.agents.omega.roaster import Report
from agent_alpha.agents.rate_limiter import Pacer
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.domain_verification import DnspythonResolver
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.conductor.reporting import build_engagement_report
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import EventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.llm.routing import resolve_reasoning_provider
from agent_alpha.recon.net_guard import is_internal_ip
from agent_alpha.recon.passive_discovery import PassiveDiscovery, PassiveDiscoveryResult
from agent_alpha.recon.passive_intel import (
    HistoricalDnsSource,
    OTXSource,
    PassiveDNSResolver,
    VirusTotalSource,
    WaybackSource,
    build_passive_intel_map,
    certspotter_discover,
    enrich_with_dns,
    enrich_with_historical_dns,
    enrich_with_mx_spf,
    enrich_with_otx,
    enrich_with_virustotal,
    enrich_with_wayback,
    hackertarget_fallback,
    record_passive_intel,
)
from agent_alpha.security.secrets import (
    get_certspotter_api_key,
    get_otx_api_key,
    get_virustotal_api_key,
)
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"


class BlockedTargetError(ValueError):
    """A recon target resolves to a non-routable / excluded address — refused by the
    SSRF guard (CWE-918). Fail-closed: a host that does not resolve is also blocked,
    so a control-plane worker can never be steered at internal infrastructure (cloud
    metadata, loopback, RFC1918) by tenant-supplied scope. This is platform
    self-protection and holds regardless of what an engagement's scope claims."""


def _resolve_ips(host: str) -> list[str]:
    """Resolve *host* to its IP literals. Seam: tests monkeypatch this to avoid DNS."""
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


def _screen_host(host: str) -> None:
    """Raise BlockedTargetError unless EVERY address *host* resolves to is public.

    Resolution-aware (catches a domain that points at an internal IP), fail-closed
    (no resolution -> blocked). NOTE residual: this validates at resolve time; a
    DNS-rebinding attacker could return a different IP at connect time. The complete
    control pins the connection to the screened IP (HttpClient hardening) and a
    network egress policy on the worker — tracked follow-up, not closed here.
    """
    try:
        ip_strs = _resolve_ips(host)
    except OSError as exc:  # gaierror is an OSError subclass
        raise BlockedTargetError(f"{host!r} does not resolve (fail-closed)") from exc
    if not ip_strs:
        raise BlockedTargetError(f"{host!r} resolved to no addresses (fail-closed)")
    for ip_str in ip_strs:
        if is_internal_ip(ip_str):
            raise BlockedTargetError(
                f"{host!r} resolves to non-routable/excluded {ip_str} — SSRF blocked (CWE-918)"
            )


class NoTargetsError(ValueError):
    """The engagement's verified scope yielded no scan targets. An empty recon is
    not a silent success (anti-Lyndon #3) — the worker records a failure instead."""


@dataclass(frozen=True)
class ReconPipeline:
    """The live recon agent plus the graph it populates (one per worker run)."""

    alpha: Any
    graph_store: Any


@dataclass(frozen=True)
class WallVerdict:
    """(#51 slice-1) Engagement-level wall verdict — read-only, derived from state that
    already exists (per-target handoff statuses × WAF_BLOCKED events). ``walled`` is True
    ONLY for a total WAF wall; a clean-but-empty engagement (has >=1 COMPLETE) and dead
    hosts (no WAF_BLOCKED) are NOT walled. ``reason`` ∈ {"waf_walled", "clear", "dead"}."""

    walled: bool
    blocked_hosts: tuple[str, ...]
    reason: Literal["waf_walled", "clear", "dead"]


@dataclass(frozen=True)
class ReconRunResult:
    """Opaque run metadata — never findings/report body (C1.8)."""

    node_count: int
    report: Report
    targets_scanned: int
    enumerated_hosts: tuple[str, ...] = ()
    wall_verdict: WallVerdict | None = None


def _handoff_status(msg: a2a_pb2.A2AMessage) -> int:
    """Extract the PhaseStatus int from a run_recon HandoffPayload."""
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    return payload.status


def derive_wall_verdict(
    store: EventStore,
    engagement_id: str,
    target_statuses: Sequence[int],
    *,
    after_sequence: int = 0,
) -> WallVerdict:
    """(#51 slice-1) Read-only engagement wall verdict. Pure aggregation over data that
    already exists — the per-target run_recon statuses (previously discarded) crossed with
    the WAF_BLOCKED events on the stream. Touches NO per-host reach code and takes NO
    action (anti-#6; the active hunt is slice-2). Verdict = f(state), never a hardcoded
    branch (anti-#11).

    ``after_sequence`` scopes the WAF_BLOCKED scan to events emitted AFTER that sequence
    number — i.e. the CURRENT run only. An engagement can be re-run after done/failed; a
    prior run's WAF evidence must never combine with this sweep's statuses, or a later
    clean/dead re-run is falsely audited ``waf_walled`` (Greptile/Aikido review).

    WAF-walled ⟺ no target ended COMPLETE AND at least one host emitted WAF_BLOCKED this
    run. This distinguishes a WAF wall from (a) a clean-but-empty site (would have >=1
    COMPLETE) and (b) dead/unreachable hosts (HOST_ABANDONED/EGRESS, never WAF_BLOCKED).
    """
    blocked_hosts = tuple(
        sorted(
            {
                str(e.payload.get("host", ""))
                for e in store.get_events(engagement_id, after_sequence)
                if e.event_type == EventType.WAF_BLOCKED and e.payload.get("host")
            }
        )
    )
    any_complete = any(s == a2a_pb2.COMPLETE for s in target_statuses)
    walled = (not any_complete) and bool(blocked_hosts)
    reason: Literal["waf_walled", "clear", "dead"]
    if walled:
        reason = "waf_walled"
    elif any_complete:
        reason = "clear"
    else:
        reason = "dead"
    return WallVerdict(walled=walled, blocked_hosts=blocked_hosts, reason=reason)


def _sweep_targets(
    pipeline: ReconPipeline, engagement_id: str, targets: Sequence[str]
) -> list[int]:
    """Run recon on each target, returning the readable handoff statuses. A run_recon that
    yields no handoff (a stub / contract-loose double) is SKIPPED, not fatal — the wall
    verdict is non-critical honesty and must never crash the engagement (resilience, same
    spirit as anti-#3 non-analyzable probes)."""
    statuses: list[int] = []
    for url in targets:
        handoff_msg = pipeline.alpha.run_recon(engagement_id, url)
        if handoff_msg is not None:
            statuses.append(_handoff_status(handoff_msg))
    return statuses


def _record_wall_verdict(
    store: EventStore,
    engagement_id: str,
    target_count: int,
    target_statuses: Sequence[int],
    *,
    after_sequence: int = 0,
) -> WallVerdict:
    """Derive the engagement wall verdict and, when walled, append the ENGAGEMENT_WALLED
    audit event (the trigger primitive slice-2 consumes). Returns the verdict for the
    caller to thread into ReconRunResult. Detection only — no offensive action."""
    verdict = derive_wall_verdict(
        store, engagement_id, target_statuses, after_sequence=after_sequence
    )
    if verdict.walled:
        store.append(
            EventType.ENGAGEMENT_WALLED,
            engagement_id,
            "conductor",
            {
                "blocked_hosts": list(verdict.blocked_hosts),
                "target_count": target_count,
                "reason": verdict.reason,
            },
        )
    return verdict


def build_recon_pipeline(
    engagement_id: str,
    tenant_id: str | None,
    auth: AuthorizationStateMachine,
    store: EventStore,
    secrets_manager: Any = None,
    publisher: Any = None,
    session_store: Any = None,
    *,
    policy: PolicyEnforcer | None = None,
    origin_discovery: Any = None,
    browser_solve: Any = None,
    engagement_profile: Any = None,
    browser_solve_viable: bool = False,
) -> ReconPipeline:
    """Construct a real recon pipeline (Alpha + its own graph) for one worker run.

    Heavy deps are built in-process because Celery args are json-only (C1.7). This
    is exercised for real under C6b live-fire; hermetic tests monkeypatch this seam.

    When *policy* is provided the pipeline resolves the default OPSEC profile
    (constants.DEFAULT_OPSEC_PROFILE) with ``evasion_authorized=False`` (RECON_ONLY
    = no spoofing without SOW, fail-closed) and injects the resulting UA / rate
    limit into the HttpClient.  When *policy* is None the HttpClient uses its own
    defaults — existing callers are unaffected.
    """
    # GAP-005 slice-2a: resolve OPSEC profile from policy when available.
    opsec: dict[str, object] | None = None
    if policy is not None:
        opsec = policy.resolve_opsec_profile(
            constants.DEFAULT_OPSEC_PROFILE, evasion_authorized=False
        )
    # §12.49 / §12.50 / GAP-026: Stealth by default from the 1st request.
    # StealthPacer (human burst-and-pause pacing + Gaussian jitter) is injected
    # when engagement_profile specifies opsec_stealth=True, or when running with
    # default unconstrained pipeline (engagement_profile is None).
    # When engagement_profile explicitly specifies opsec_stealth=False, fallback
    # to fixed-interval RateLimiter.
    stealth_pacer: Pacer | None = None
    if engagement_profile is not None and getattr(engagement_profile, "opsec_stealth", False):
        from agent_alpha.agents.stealth_pacer import StealthPacer

        stealth_pacer = StealthPacer(seed=engagement_id)
    elif engagement_profile is None:
        from agent_alpha.agents.stealth_pacer import StealthPacer

        stealth_pacer = StealthPacer(seed=engagement_id)
    http_client = HttpClient(engagement_id=engagement_id, opsec=opsec, rate_limiter=stealth_pacer)
    provider = resolve_reasoning_provider(api_key=os.environ["DEEPSEEK_API_KEY"])
    # Bug #14 root cause: Alpha is RECON_ONLY (§K9/§5) and must never even be
    # ABLE to load an access-phase rule (e.g. default_credentials_login,
    # phase: access — Beta's job). phase="recon" makes that a load-time
    # guarantee, not a hope that no access-phase rule happens to match.
    orchestrator = LLMOrchestrator(
        PlaybookEngine.from_directory(_PLAYBOOK_DIR, phase="recon"), provider
    )
    graph_store = NetworkXGraphStore()

    # Wire tenant-scoped monologue sink if publisher is provided (Phase 3 infra)
    monologue_sink = None
    if publisher is not None and tenant_id is not None:
        from agent_alpha.agents.monologue_stream import RedisMonologueSink

        monologue_sink = RedisMonologueSink(publisher, tenant_id, engagement_id)

    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
        monologue=monologue_sink,
        session_store=session_store,
        origin_discovery=origin_discovery,
        browser_solve=browser_solve,
        engagement_profile=engagement_profile,
        browser_solve_viable=browser_solve_viable,
    )
    return ReconPipeline(alpha=alpha, graph_store=graph_store)


def resolve_recon_targets(record: Any) -> list[str]:
    """Derive concrete scan URLs from an engagement's VERIFIED scope domains.

    Deterministic + order-preserving. The scope (set behind the auth gate) is the
    only source of targets — never free-form caller input. Empty → NoTargetsError
    (no silent no-op).
    """
    scope = getattr(record, "scope", None)
    domains = [
        d.strip() for d in (list(scope.domains) if scope is not None else []) if d and d.strip()
    ]
    if not domains:
        raise NoTargetsError(
            f"engagement {getattr(record, 'engagement_id', '?')!r} has no in-scope recon targets"
        )
    urls: list[str] = []
    for host in domains:
        _screen_host(host)  # SSRF guard (CWE-918) — raises BlockedTargetError if internal
        urls.append(f"https://{host}")
    return urls


def build_passive_discovery(
    engagement_id: str,
    auth: AuthorizationStateMachine,
    store: EventStore,
) -> PassiveDiscovery:
    """Construct a PassiveDiscovery instance for one worker run.

    Module-level seam (monkeypatchable, mirrors build_recon_pipeline): hermetic
    tests replace this to inject a fake crt.sh client without live network I/O.
    """
    from agent_alpha.agents.http_client import HttpClient

    return PassiveDiscovery(
        http_client=HttpClient(engagement_id=engagement_id),
        authorization=auth,
        event_store=store,
    )


def build_otx_client(engagement_id: str) -> OTXSource | None:
    """Build the OTX source from the configured key, or None if no key is set.

    §12.48 slice-5 seam: constructed at the Conductor entry (main.py) and injected
    into ``run_recon_for_engagement``. No key → None → OTX enrichment is skipped
    (graceful degradation, anti self-identifying UA via the stealth HttpClient)."""
    key = get_otx_api_key()
    if not key:
        return None
    from agent_alpha.agents.http_client import HttpClient
    from agent_alpha.recon.osint_sources import OtxClient

    return OtxClient(HttpClient(engagement_id=engagement_id), key)


def build_virustotal_client(engagement_id: str) -> VirusTotalSource | None:
    """Build the VirusTotal source from the configured key, or None if no key is set.

    §12.48 slice-2 (VT) seam: constructed at the Conductor entry (main.py) and
    injected into ``run_recon_for_engagement``. No key → None → VT enrichment is
    skipped (graceful degradation). VT provides historical DNS resolutions
    (origin IP candidates) + subdomains (grey-cloud hosts CT never logged)."""
    key = get_virustotal_api_key()
    if not key:
        return None
    from agent_alpha.agents.http_client import HttpClient
    from agent_alpha.recon.osint_sources import VirusTotalClient

    return VirusTotalClient(HttpClient(engagement_id=engagement_id), key)


def _apply_mx_spf(intel: Any, sources: tuple[str, ...]) -> tuple[Any, tuple[str, ...]]:
    """(§12.61 A2) Fold MX/SPF-derived origin candidates into *intel*, tagging ``"mx_spf"``
    in *sources* ONLY when it actually contributed (honest attribution — a domain with no
    usable MX/SPF adds nothing and is not tagged). Pure over already-collected DNS data;
    extracted to keep ``run_recon_for_engagement`` under the complexity cap (anti-noqa)."""
    before = (intel.origin_ip_candidates, intel.subdomains)
    intel = enrich_with_mx_spf(intel)
    if (intel.origin_ip_candidates, intel.subdomains) != before:
        sources = (*sources, "mx_spf")
    return intel, sources


def build_wayback_client(engagement_id: str) -> WaybackSource:
    """Build the keyless Wayback CDX source. §12.61: unlike OTX/VT (key-gated → may be
    None), Wayback needs NO key, so it is ALWAYS available. Uses the stealth HttpClient
    (anti self-identifying UA); the client itself fail-opens on any network error."""
    from agent_alpha.agents.http_client import HttpClient
    from agent_alpha.recon.osint_sources import WaybackClient

    return WaybackClient(HttpClient(engagement_id=engagement_id))


def build_mnemonic_client(engagement_id: str) -> HistoricalDnsSource:
    """Build the keyless Mnemonic PDNS historical-A-record source. §12.61 A1."""
    from agent_alpha.agents.http_client import HttpClient
    from agent_alpha.recon.osint_sources import MnemonicPdnsClient

    return MnemonicPdnsClient(HttpClient(engagement_id=engagement_id))


def build_osint_http_client(engagement_id: str) -> Any:
    """Module seam (monkeypatchable) for the OSINT-source HTTP client used by
    the §12.48 slice-2 keyless fallback. Same stealth ``HttpClient`` as recon
    (curl_cffi impersonate + stealth UA) — anti self-identifying User-Agent.
    """
    from agent_alpha.agents.http_client import HttpClient

    return HttpClient(engagement_id=engagement_id)


_log = logging.getLogger(__name__)


def run_recon_for_engagement(  # noqa: C901
    engagement_id: str,
    tenant_id: str | None,
    auth: AuthorizationStateMachine,
    store: EventStore,
    record: Any,
    secrets_manager: Any = None,
    session_store: Any = None,
    *,
    policy: PolicyEnforcer | None = None,
    origin_discovery: Any = None,
    browser_solve: Any = None,
    engagement_profile: Any = None,
    browser_solve_viable: bool = False,
    dns_resolver: PassiveDNSResolver | None = None,
    otx_client: OTXSource | None = None,
    vt_client: VirusTotalSource | None = None,
    wayback_client: WaybackSource | None = None,
    mnemonic_client: HistoricalDnsSource | None = None,
) -> ReconRunResult:
    """Scan every in-scope target with Alpha, then produce the Omega report.

    Shape B (single-task): one worker scans all of the engagement's targets in
    sequence and aggregates into ONE graph + the one event stream. Returns opaque
    metadata only; the worker keeps findings/report OUT of the Celery result
    backend (C1.8).
    """
    pipeline = build_recon_pipeline(
        engagement_id,
        tenant_id,
        auth,
        store,
        secrets_manager=secrets_manager,
        session_store=session_store,
        policy=policy,
        origin_discovery=origin_discovery,
        browser_solve=browser_solve,
        engagement_profile=engagement_profile,
        browser_solve_viable=browser_solve_viable,
    )
    targets = resolve_recon_targets(record)
    # §12.48 slice-3: fail-open DNS resolver (default = production DnspythonResolver;
    # tests inject a stub). Reuses the ONE production resolver, no second type (anti-#6).
    dns = dns_resolver if dns_resolver is not None else DnspythonResolver()

    # ── Passive crt.sh discovery (fail-open: crt.sh down must NOT break the engagement) ──
    enumerated: set[str] = set()
    discovered_in_scope: set[str] = set()
    seen_hosts: set[str] = set()
    for url in targets:
        host = urlparse(url).hostname
        if host is None or host in seen_hosts:
            continue
        seen_hosts.add(host)
        # §12.48 slice-4: passive CT/OSINT source CHAIN, ordered by reliability —
        # CertSpotter (primary CT, robust) -> crt.sh (fallback CT, flaky/often down)
        # -> HackerTarget (keyless last-resort). Try in order; STOP at the first
        # source that yields a surface (conserves rate-limited quotas — never a
        # second source call once one has hits). ONE stealth client shared by the
        # keyless HTTP sources (anti self-identifying UA). Each source fail-open.
        osint_client = build_osint_http_client(engagement_id)
        result: PassiveDiscoveryResult | None = None
        sources_used: tuple[str, ...] = ()

        # 1 — CertSpotter (primary). Optional Bearer key raises the limit; keyless works.
        try:
            cs = certspotter_discover(
                engagement_id,
                host,
                http_client=osint_client,
                authorization=auth,
                api_key=get_certspotter_api_key(),
            )
            if cs.discovered:
                result, sources_used = cs, ("certspotter",)
        except Exception:
            _log.warning(
                "CertSpotter discovery failed for %s (engagement %s) — continuing (fail-open)",
                host,
                engagement_id,
                exc_info=True,
            )

        # 2 — crt.sh fallback (emits PASSIVE_DISCOVERY). Keep its (possibly empty)
        # result object so downstream always has a result to record.
        if result is None or not result.discovered:
            try:
                pd = build_passive_discovery(engagement_id, auth, store)
                r = pd.discover(engagement_id, host)
                if r.discovered:
                    result, sources_used = r, ("crtsh",)
                elif result is None:
                    result = r
            except Exception:
                _log.warning(
                    "crt.sh fallback failed for %s (engagement %s) — continuing (fail-open)",
                    host,
                    engagement_id,
                    exc_info=True,
                )

        # 3 — HackerTarget keyless last-resort.
        if result is None or not result.discovered:
            try:
                fb = hackertarget_fallback(
                    engagement_id,
                    host,
                    http_client=osint_client,
                    authorization=auth,
                )
                if fb.discovered:
                    result, sources_used = fb, ("hackertarget",)
            except Exception:
                _log.warning(
                    "HackerTarget fallback failed for %s (engagement %s) — continuing (fail-open)",
                    host,
                    engagement_id,
                    exc_info=True,
                )

        if result is not None:
            enumerated.update(result.enumerated)
            discovered_in_scope.update(result.in_scope)
        # GAP-154: enrichment (DNS/OTX/VT/MX-SPF/Wayback) does NOT depend on the CT
        # logs — it must run even when EVERY CT source failed (result is None). A CT
        # outage must never silently disable DNS/MX/SPF/Wayback origin discovery for
        # the whole engagement (the GAP-154 root constraint). Seed an EMPTY
        # PassiveIntelMap keyed to host when result is None; build from the CT surface
        # otherwise. Enrich + record run UNCONDITIONALLY so PASSIVE_INTEL_GATHERED
        # always fires — a total-CT-fail engagement is recorded honestly, with whatever
        # DNS/MX/Wayback surfaces (anti-#3: never a silent empty skip).
        seed = result if result is not None else PassiveDiscoveryResult(host, (), (), ())
        # §12.48: build the unified PassiveIntelMap from the (crt.sh / fallback / empty)
        # seed and record PASSIVE_INTEL_GATHERED BEFORE any active recon runs.
        # sources_used records which OSINT source produced the CT surface (() on total fail).
        intel = build_passive_intel_map(seed)
        # §12.48 slice-3: DNS enrichment is external network I/O. Gate it
        # fail-closed behind the SAME RECON check crt.sh/HackerTarget use — a
        # refused engagement performs ZERO network, incl. DNS (CodeRabbit #357-1,
        # defense-in-depth). Refused → record the un-enriched map (DNS
        # fields stay empty), never query DNS.
        if auth.can_agent_proceed(a2a_pb2.ALPHA, engagement_id):
            intel = enrich_with_dns(intel, dns)
            intel_sources = (*sources_used, "dns")
            # §12.48 slice-5: OTX enrichment (origin-IP candidates + historical
            # paths). Injected at the Conductor entry only when a key is set —
            # None here = OTX off (existing tests + keyless deploys unaffected).
            if otx_client is not None:
                intel = enrich_with_otx(intel, otx_client)
                intel_sources = (*intel_sources, "otx")
            # §12.48 slice-2 (VT): VirusTotal enrichment (origin-IP candidates
            # + grey-cloud subdomains). Injected at the Conductor entry only
            # when a VT key is set — None here = VT off. VT finds origin IPs
            # and subdomains that crt.sh/OTX miss (e.g. a grey-cloud
            # subdomain → origin IP directly, no CF proxy).
            if vt_client is not None:
                intel = enrich_with_virustotal(intel, vt_client)
                intel_sources = (*intel_sources, "virustotal")
                # §12.48 Strategy B: VT subdomains that pass is_in_scope become
                # independent targets (not just origin-IP candidates). This is
                # the "side door" path — subdomains not fronted by CF are probed
                # directly. is_in_scope is the sole authority (suffix match when
                # Scope.allow_subdomains is set from EngagementProfile).
                host_norm = host.rstrip(".").lower()
                for sub in intel.subdomains:
                    sub_norm = sub.strip().lower().rstrip(".")
                    if not sub_norm or sub_norm == host_norm:
                        continue
                    if auth.is_in_scope(engagement_id, sub_norm):
                        discovered_in_scope.add(sub_norm)
            # §12.61 A2: MX/SPF-derived origin candidates from the DNS records already
            # fetched by enrich_with_dns (zero new I/O). AFTER VT target-promotion so MX
            # hosts feed origin candidates ONLY, never new scan targets.
            intel, intel_sources = _apply_mx_spf(intel, intel_sources)
            # §12.61: Wayback historical subdomains → ORIGIN CANDIDATES (via
            # CompositeOriginDiscovery) + historical paths → breadth. Placed AFTER the
            # VT subdomain→target promotion so historical (often defunct) subdomains
            # feed origin candidates ONLY, never new scan targets. Keyless → always on.
            if wayback_client is not None:
                intel = enrich_with_wayback(intel, wayback_client)
                intel_sources = (*intel_sources, "wayback")
            if mnemonic_client is not None:
                intel = enrich_with_historical_dns(intel, mnemonic_client)
                intel_sources = (*intel_sources, "mnemonic_pdns")
        else:
            intel_sources = sources_used
        record_passive_intel(store, engagement_id, intel, sources_used=intel_sources)

    # §12.41: extend targets with in-scope passive-discovered subdomains that
    # are not already targeted.  run_recon enforces auth/scope per-target, and
    # in_scope means the host already passed is_in_scope — safe to probe.
    for host in sorted(discovered_in_scope):
        u = f"https://{host}/"
        if u not in targets:
            targets.append(u)

    # #51 slice-1: capture each target's handoff status (previously discarded) so the
    # engagement-level wall verdict can be derived after the sweep — a fully WAF-walled
    # engagement must be recorded honestly, never as a silent FAILED/clean (anti-#3).
    # Snapshot the stream head BEFORE the sweep so the verdict scans only THIS run's
    # WAF_BLOCKED events — a re-run must not inherit a prior run's WAF evidence.
    prior_events = store.get_events(engagement_id)
    run_start_seq = prior_events[-1].sequence_number if prior_events else 0

    target_statuses = _sweep_targets(pipeline, engagement_id, targets)

    wall_verdict = _record_wall_verdict(
        store, engagement_id, len(targets), target_statuses, after_sequence=run_start_seq
    )

    report = build_engagement_report(pipeline.graph_store, store, engagement_id, style="technical")
    return ReconRunResult(
        node_count=pipeline.graph_store.node_count(),
        report=report,
        targets_scanned=len(targets),
        enumerated_hosts=tuple(sorted(enumerated)),
        wall_verdict=wall_verdict,
    )
