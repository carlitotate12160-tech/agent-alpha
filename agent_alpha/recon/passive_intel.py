# agent_alpha/recon/passive_intel.py
# Phase 4 — §12.48 slice-1: PassiveIntelMap (OSINT-before-touch, crt.sh only).
#
# §12.48 mandates a passive intelligence stage BEFORE any active HTTP probe to
# the target. This module holds the unified `PassiveIntelMap` data contract and
# the crt.sh slice that populates it.
#
# Slice-1 is ADDITIVE and reuses the EXISTING crt.sh source (`PassiveDiscovery`,
# §12.41): it makes NO new crt.sh call and re-implements NO parser (anti-Lyndon
# #6). It maps the already-fetched `PassiveDiscoveryResult` into the richer map
# shape and records the `PASSIVE_INTEL_GATHERED` audit event.
#
# The remaining `PassiveIntelMap` fields (origin IPs, MX/TXT, tech hints, NS,
# protection posture, historical paths) are the LOCKED §12.48 contract shape
# (point 4) consumed by downstream reach/planner logic (anti-#7). Each is fed by
# a NAMED later slice (VirusTotal → slice-2; DNSDumpster/NS → slice-3). An
# ungathered field is honest empty data (graceful degradation), NOT a scaffolded
# code path or unused param — no source seam for those exists in this module yet
# (deferred goes OUT, anti-#2).

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Protocol

from agent_alpha.a2a import a2a_pb2
from agent_alpha.events.event_types import EventType
from agent_alpha.recon.osint_sources import (
    fetch_certspotter_subdomains,
    fetch_hackertarget_subdomains,
)
from agent_alpha.recon.passive_discovery import PassiveDiscoveryResult

if TYPE_CHECKING:
    from agent_alpha.conductor.authorization import AuthorizationStateMachine
    from agent_alpha.events.store import EventStore


# ── Data contract (§12.48 point 4 — the single downstream shape, anti-#7) ──────


@dataclass(frozen=True)
class PassiveIntelMap:
    """Unified passive-intelligence surface map for one in-scope domain.

    Built with ZERO contact to the target. Slice-1 populates the crt.sh-derived
    fields only; the rest are empty until their named source slice lands.

    Attributes:
        domain:               The base domain the map describes.
        subdomains:           All CT-log hostnames (domain-filtered). [crt.sh]
        in_scope_subdomains:  Subset that passed ``is_in_scope``.        [crt.sh]
        origin_ip_candidates: Potential origin IPs (DNS history).   [slice-2 VT]
        mx_records:           Mail servers (can reveal origin).  [slice-3 DNSd.]
        txt_records:          SPF/DKIM/DMARC records.            [slice-3 DNSd.]
        tech_stack_hints:     Technology hints from passive sources.  [slice-2]
        protection_detected:  NS-derived vendor HINT (not confirmed proxy):
                              "cloudflare"|"akamai"|"sucuri"|"imperva"|None. [slice-3]
        nameservers:          NS records (CF NS ⇒ CF-proxied).         [slice-3]
        historical_paths:     Paths from Wayback / VT URL scans.       [slice-2]
    """

    domain: str
    subdomains: tuple[str, ...]
    in_scope_subdomains: tuple[str, ...]
    origin_ip_candidates: tuple[str, ...] = field(default_factory=tuple)
    mx_records: tuple[str, ...] = field(default_factory=tuple)
    txt_records: tuple[str, ...] = field(default_factory=tuple)
    tech_stack_hints: tuple[str, ...] = field(default_factory=tuple)
    protection_detected: str | None = None
    nameservers: tuple[str, ...] = field(default_factory=tuple)
    historical_paths: tuple[str, ...] = field(default_factory=tuple)


# ── crt.sh slice: PassiveDiscoveryResult → PassiveIntelMap (pure, no I/O) ──────


def build_passive_intel_map(result: PassiveDiscoveryResult) -> PassiveIntelMap:
    """Map an existing crt.sh ``PassiveDiscoveryResult`` into a ``PassiveIntelMap``.

    Pure and side-effect-free. Reuses the crt.sh output already fetched+parsed by
    ``PassiveDiscovery`` — NO new network call, NO re-parse (anti-#6). Only the
    crt.sh-derived fields are populated; all other fields keep their empty
    defaults until their named source slice lands.
    """
    return PassiveIntelMap(
        domain=result.domain,
        subdomains=result.discovered,
        in_scope_subdomains=result.in_scope,
    )


# ── Bug #26 consumer: read passive-intel signal for a host (domain-scoped) ─────


@dataclass(frozen=True)
class PassiveIntelSignal:
    """The Bug #26-relevant slice of a host's PassiveIntelMap, read back from the
    event stream at active-recon time: protection posture + historical paths."""

    protection_detected: str | None = None
    historical_paths: tuple[str, ...] = ()


def passive_intel_signal_for_host(
    event_store: object, engagement_id: str, host: str
) -> PassiveIntelSignal:
    """Latest ``PASSIVE_INTEL_GATHERED`` for *host* (domain-scoped) → protection +
    historical paths. Fail-open (empty signal) on any error / no matching event.

    Domain-scoped like CompositeOriginDiscovery (a signal produced for domain A
    must not steer probing of host B). Last matching event wins.
    """
    from agent_alpha.events.event_types import EventType

    host_norm = host.rstrip(".").lower()
    try:
        events = event_store.get_events(engagement_id)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — event-read boundary; degrade to empty signal
        return PassiveIntelSignal()

    protection: str | None = None
    paths: tuple[str, ...] = ()
    for ev in events:
        if getattr(ev, "event_type", None) != EventType.PASSIVE_INTEL_GATHERED:
            continue
        if ev.payload.get("domain", "").rstrip(".").lower() != host_norm:
            continue
        protection = ev.payload.get("protection_detected")
        paths = tuple(ev.payload.get("historical_paths", []) or [])
    return PassiveIntelSignal(protection_detected=protection, historical_paths=paths)


# ── §12.48 slice-3: DNS enrichment (MX/NS/TXT → protection posture) ────────────
#
# ADDITIVE over the sealed slice-1 map: enrich_with_dns takes an already-built
# PassiveIntelMap and returns a NEW one with the DNS-derived fields filled. The
# crt.sh fields (subdomains/in_scope) are copied verbatim via dataclasses.replace
# — slice-1 is never rewritten (anti-#10). Keyless, zero contact to the target
# (queries the domain's authoritative DNS, not the target's HTTP surface).
#
# PRODUCER ONLY: this fills the signal. Consuming protection_detected to skip
# blind path-probing (Bug #26 Layer 1/5) and MX → origin_ip_candidates (§12.46)
# are SEPARATE downstream slices — deliberately NOT scaffolded here (anti-#2).


class PassiveDNSResolver(Protocol):
    """Narrow read-only DNS seam for passive enrichment (fail-open).

    Structurally satisfied by the production ``DnspythonResolver``. Distinct from
    the ownership ``DNSResolver`` Protocol (TXT-only, fail-closed) on purpose: a
    missing record here degrades gracefully, it does NOT gate authorization.
    """

    def resolve_mx(self, domain: str) -> list[str]: ...  # pragma: no cover
    def resolve_ns(self, domain: str) -> list[str]: ...  # pragma: no cover
    def resolve_txt(self, domain: str) -> list[str]: ...  # pragma: no cover


# NS-suffix → protection vendor. SINGLE source of truth (anti-#7). A domain whose
# authoritative nameservers are the vendor's ⇒ the vendor proxies/fronts it. This
# is the keyless, deterministic, LLM-free protection signal (no HTTP fingerprint).
_NS_PROTECTION_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("cloudflare.com", "cloudflare"),
    ("akam.net", "akamai"),
    ("akamaiedge.net", "akamai"),
    ("sucuri.net", "sucuri"),
    ("incapdns.net", "imperva"),
    ("impervadns.net", "imperva"),
)


def classify_protection(nameservers: tuple[str, ...]) -> str | None:
    """Map authoritative nameservers → protection vendor HINT, or None.

    Pure. Matches a nameserver exactly or as a subdomain of a known vendor apex
    (e.g. ``dana.ns.cloudflare.com`` ⇒ ``cloudflare``). First match wins.

    HINT, NOT CONFIRMED PROXY (CodeRabbit #357-2). Vendor NS delegation does NOT
    prove the target is proxied/WAF'd: e.g. Cloudflare "DNS-only" (grey-cloud)
    serves the origin A-record directly with NO edge protection, yet still uses
    cloudflare.com nameservers. So this is a first-pass signal only. A downstream
    consumer (Bug #26 probe-suppression) MUST corroborate with an HTTP signal
    (``cf-ray`` / ``server: cloudflare`` response header) BEFORE acting on it —
    never skip a valid probe on the NS hint alone (that would be a false-negative).
    Corroboration is the consumer slice's job; this producer only emits the hint.
    """
    for ns in nameservers:
        n = ns.strip().lower().rstrip(".")
        for suffix, vendor in _NS_PROTECTION_SIGNATURES:
            if n == suffix or n.endswith("." + suffix):
                return vendor
    return None


def enrich_with_dns(intel: PassiveIntelMap, resolver: PassiveDNSResolver) -> PassiveIntelMap:
    """Return *intel* enriched with MX/NS/TXT records + protection posture.

    ADDITIVE (anti-#10): returns a NEW frozen map via ``replace`` — the slice-1
    crt.sh fields are preserved untouched. Fail-open per record type: the resolver
    returns ``[]`` on any DNS error, so a domain with no MX (etc.) yields empty
    records and ``protection_detected`` follows only from the NS records actually
    resolved. Never raises.
    """
    nameservers = tuple(resolver.resolve_ns(intel.domain))
    return replace(
        intel,
        mx_records=tuple(resolver.resolve_mx(intel.domain)),
        nameservers=nameservers,
        txt_records=tuple(resolver.resolve_txt(intel.domain)),
        protection_detected=classify_protection(nameservers),
    )


# ── §12.48 slice-5: OTX enrichment (origin IP candidates + historical paths) ──
#
# ADDITIVE over slice-1/3 (anti-#10): fills origin_ip_candidates + historical_paths,
# preserving every other field via replace. PRODUCER ONLY — the origin IPs are
# CANDIDATES; a later origin-binding consumer (verify_origin_binding) confirms them
# before any reach, and a later Bug #26 consumer uses the paths. Neither is
# scaffolded here (anti-#2). Deliberately NOT a subdomain source: the CT chain
# (CertSpotter/crt.sh) already covers subdomains (anti-redundancy / anti-sprawl).


class OTXSource(Protocol):
    """Seam for the OTX passive-DNS/URL source (fail-open, key-gated).

    Structurally satisfied by ``osint_sources.OtxClient``. Injected at the
    Conductor entry (main.py) only when an OTX key is configured — absent = OTX
    off, engagement unaffected (graceful degradation)."""

    def origin_ips_and_paths(
        self, domain: str
    ) -> tuple[tuple[str, ...], tuple[str, ...]]: ...  # pragma: no cover


def enrich_with_otx(intel: PassiveIntelMap, otx: OTXSource) -> PassiveIntelMap:
    """Return *intel* enriched with OTX origin-IP candidates + historical paths.

    ADDITIVE: NEW frozen map via replace; slice-1/3 fields untouched. Fail-open
    (the source returns empties on any error). Never raises.
    """
    origin_ips, historical_paths = otx.origin_ips_and_paths(intel.domain)
    return replace(
        intel,
        origin_ip_candidates=origin_ips,
        historical_paths=historical_paths,
    )


# ── §12.48 slice-2 (VT): VirusTotal enrichment (origin IPs + subdomains) ──────
#
# ADDITIVE over slice-1/3/5 (anti-#10): fills origin_ip_candidates (union with OTX)
# and extends subdomains with VT-discovered hosts. PRODUCER ONLY — origin IPs are
# CANDIDATES; CompositeOriginDiscovery + verify_origin_binding confirm them before
# any reach. VT subdomains are extra origin-candidate hosts (grey-cloud subdomains
# that CT never logged — a field grey-cloud subdomain case).


class VirusTotalSource(Protocol):
    """Seam for the VirusTotal v3 passive-DNS/subdomain source (fail-open, key-gated).

    Structurally satisfied by ``osint_sources.VirusTotalClient``. Injected at the
    Conductor entry (main.py) only when a VT key is configured — absent = VT off,
    engagement unaffected (graceful degradation)."""

    def origin_ips_and_subdomains(
        self, domain: str
    ) -> tuple[tuple[str, ...], tuple[str, ...]]: ...  # pragma: no cover


def enrich_with_virustotal(intel: PassiveIntelMap, vt: VirusTotalSource) -> PassiveIntelMap:
    """Return *intel* enriched with VT origin-IP candidates + VT subdomains.

    ADDITIVE: NEW frozen map via replace. Origin IPs are UNIONED with any OTX
    candidates already present (deduped) — VT and OTX see different histories.
    VT subdomains are appended to the crt.sh subdomains (deduped) — grey-cloud
    subdomains that CT never logged are the #1 real origin leak (e.g.
    a grey-cloud subdomain → origin IP directly, no CF proxy).

    Fail-open (the source returns empties on any error). Never raises.
    """
    vt_ips, vt_subs = vt.origin_ips_and_subdomains(intel.domain)
    # Union origin IPs (OTX + VT, deduped, order preserved)
    existing_ips = list(intel.origin_ip_candidates)
    seen_ips = set(existing_ips)
    for ip in vt_ips:
        if ip not in seen_ips:
            seen_ips.add(ip)
            existing_ips.append(ip)
    # Union subdomains (crt.sh + VT, deduped, order preserved)
    existing_subs = list(intel.subdomains)
    seen_subs = set(existing_subs)
    for sub in vt_subs:
        if sub not in seen_subs:
            seen_subs.add(sub)
            existing_subs.append(sub)
    return replace(
        intel,
        origin_ip_candidates=tuple(existing_ips),
        subdomains=tuple(existing_subs),
    )


# ── Event-sourced audit (§12.48: PASSIVE_INTEL_GATHERED before active recon) ───


def record_passive_intel(
    event_store: EventStore,
    engagement_id: str,
    intel: PassiveIntelMap,
    *,
    sources_used: tuple[str, ...] = ("crtsh",),
) -> None:
    """Append the ``PASSIVE_INTEL_GATHERED`` event for *intel*.

    Called during the passive stage, BEFORE any active recon event is appended
    (ordering is the caller's responsibility — the passive loop runs before
    ``Alpha.run_recon``). Payload is the full map, JSON-serialisable.
    """
    event_store.append(
        event_type=EventType.PASSIVE_INTEL_GATHERED,
        engagement_id=engagement_id,
        agent="alpha",
        payload={
            "domain": intel.domain,
            "subdomains": list(intel.subdomains),
            "in_scope_subdomains": list(intel.in_scope_subdomains),
            "origin_ip_candidates": list(intel.origin_ip_candidates),
            "mx_records": list(intel.mx_records),
            "txt_records": list(intel.txt_records),
            "tech_stack_hints": list(intel.tech_stack_hints),
            "protection_detected": intel.protection_detected,
            "nameservers": list(intel.nameservers),
            "historical_paths": list(intel.historical_paths),
            "sources_used": list(sources_used),
        },
    )


# ── §12.48 slice-2: keyless crt.sh fallback (HackerTarget) ─────────────────────


def hackertarget_fallback(
    engagement_id: str,
    domain: str,
    *,
    http_client: object,
    authorization: AuthorizationStateMachine,
) -> PassiveDiscoveryResult:
    """Fail-closed HackerTarget fallback used when crt.sh yields no names.

    Mirrors ``PassiveDiscovery.discover``'s contract so the caller can treat the
    two crt.sh/HackerTarget results identically (same canonical type, anti-#6):

      STEP 1 — fail-closed RECON gate BEFORE any network I/O.
      STEP 2 — single stealth GET to HackerTarget (no key, no self-ID UA).
      STEP 3 — parse + domain-filter.
      STEP 4 — partition via ``is_in_scope`` (sole scope authority).

    Never raises for a transport/parse failure (fetch is fail-open); returns an
    empty result. Emits NO event — the caller records the merged PassiveIntelMap.
    """
    # STEP 1 — fail-closed auth gate (BEFORE any network I/O)
    if not authorization.can_agent_proceed(a2a_pb2.ALPHA, engagement_id):
        return PassiveDiscoveryResult(domain, (), (), ())

    # STEP 2+3 — fetch (fail-open) + parse
    names = fetch_hackertarget_subdomains(domain, http_client=http_client)

    # STEP 4 — partition through the auth gate
    in_scope: list[str] = []
    enumerated: list[str] = []
    for host in names:
        if authorization.is_in_scope(engagement_id, host):
            in_scope.append(host)
        else:
            enumerated.append(host)

    return PassiveDiscoveryResult(
        domain=domain,
        discovered=tuple(names),
        in_scope=tuple(in_scope),
        enumerated=tuple(enumerated),
    )


# ── §12.48 slice-4: CertSpotter primary CT source (crt.sh demoted to fallback) ─


def certspotter_discover(
    engagement_id: str,
    domain: str,
    *,
    http_client: object,
    authorization: AuthorizationStateMachine,
    api_key: str | None = None,
) -> PassiveDiscoveryResult:
    """Primary CT-log discovery via CertSpotter. Same contract as ``hackertarget_
    fallback`` (canonical ``PassiveDiscoveryResult``, anti-#6): fail-closed RECON
    gate BEFORE any I/O, single stealth GET (optional Bearer key), parse +
    domain-filter, partition via ``is_in_scope`` (sole scope authority). Fail-open
    on transport/parse error (empty result). Emits NO event — the caller records
    the merged PassiveIntelMap.
    """
    # STEP 1 — fail-closed auth gate (BEFORE any network I/O)
    if not authorization.can_agent_proceed(a2a_pb2.ALPHA, engagement_id):
        return PassiveDiscoveryResult(domain, (), (), ())

    # STEP 2+3 — fetch (fail-open) + parse
    names = fetch_certspotter_subdomains(domain, http_client=http_client, api_key=api_key)

    # STEP 4 — partition through the auth gate
    in_scope: list[str] = []
    enumerated: list[str] = []
    for host in names:
        if authorization.is_in_scope(engagement_id, host):
            in_scope.append(host)
        else:
            enumerated.append(host)

    return PassiveDiscoveryResult(
        domain=domain,
        discovered=tuple(names),
        in_scope=tuple(in_scope),
        enumerated=tuple(enumerated),
    )
