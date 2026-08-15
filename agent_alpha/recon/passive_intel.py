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


# ── §12.61 A2: MX/SPF → origin candidates (pure consumer of enrich_with_dns data) ──
#
# MX hosts usually sit on ORIGIN infra (mail servers are rarely fronted by CF), and SPF
# ip4/ip6 literals declare the target's own sending IPs — both are strong origin hints.
# SE-Asia shared hosting (cPanel/Plesk) frequently co-locates web + mail on ONE IP and
# declares the origin's small subnet (/29) in SPF, so both signals are high-value locally.
# PRODUCER ONLY — every derived IP/host is a CANDIDATE, proven by token-canary binding
# (§12.46) before any reach; a third-party relay IP that does not serve the owned host is
# rejected. Zero new I/O: reads mx_records/txt_records already fetched by enrich_with_dns.

#: MX hosts belonging to a big mail provider (GLOBAL + major ASIAN clouds) are shared relay
#: infra, NOT the target's origin — drop them. Regional/self-hosted MX (in-domain OR a local
#: host like ``*.xserver.ne.jp``) is kept BY DEFAULT: on shared cPanel/Plesk it resolves to
#: the web origin. SINGLE source (anti-#7). Heuristic noise-filter — binding (§12.46) is the
#: real correctness gate, so this favours the dominant providers over exhaustiveness. NO
#: separate regional-hosting whitelist (dead config, Lyndon #2: "keep everything not
#: blocklisted" already retains regional hosts).
_BIG_CLOUD_MAIL_SUFFIXES: tuple[str, ...] = (
    # ── Global ──
    "google.com",
    "googlemail.com",
    "gmail.com",
    "outlook.com",
    "office365.com",
    "protection.outlook.com",
    "zoho.com",
    "zoho.in",
    "zoho.eu",
    "zohomail.com",
    "mimecast.com",
    "pphosted.com",
    "ppe-hosted.com",
    "protection.sophos.com",
    "sendgrid.net",
    "protonmail.ch",
    "proton.me",
    "icloud.com",
    "me.com",
    "amazonaws.com",
    "yandex.net",
    "mail.ru",
    # ── China / HK ──
    "mxhichina.com",  # Alibaba / Alimail
    "aliyun.com",
    "exmail.qq.com",  # Tencent Enterprise Mail
    "qiye.163.com",  # NetEase Enterprise Mail
    # ── Korea ──
    "worksmobile.com",  # Naver Works / LINE Works
    "naver.com",
    "daum.net",
    "kakao.com",
    # ── India ──
    "rediffmail.com",
    # ── Japan / Taiwan ──
    "iij.ad.jp",
    "trendmicro.com",  # email security gateway
    "openfind.com.tw",  # Taiwan mail vendor
)

#: SPF ip4/ip6 CIDRs with <= this many addresses are EXPANDED to individual candidate IPs
#: (a /28 = 16). Asian ISPs commonly allocate a /29 or /28 and co-locate web + mail in it,
#: so the origin often sits 1-2 IPs beside the mail server. Larger blocks (/27 and up) are
#: dropped — too many to token-bind, and the binding gate is the real filter anyway.
_SPF_MAX_CIDR_HOSTS = 16

#: Aggregate defence cap: total SPF-derived candidates per domain. A pathological SPF with
#: many /28 blocks (5 × 14 = 70) would otherwise trigger a probe storm that wrecks the
#: stealth pacer. Normal SPF has a handful of IPs, so this is only hit on abuse.
_SPF_MAX_TOTAL_CANDIDATES = 32


def parse_spf_ips(
    txt_records: tuple[str, ...],
    *,
    max_cidr_hosts: int = _SPF_MAX_CIDR_HOSTS,
    max_total: int = _SPF_MAX_TOTAL_CANDIDATES,
) -> tuple[str, ...]:
    """Extract SPF-declared origin-candidate IPs from TXT records (§12.61 A2).

    From each ``v=spf1`` record, take every ``ip4:``/``ip6:`` mechanism (SPF qualifier
    ``+ - ~ ?`` stripped) and expand SMALL CIDRs (<= *max_cidr_hosts* addresses, i.e. /28);
    larger ranges are dropped. The total is bounded by *max_total* (anti probe-storm on a
    pathological multi-/28 SPF). Pure, fail-open: malformed tokens are skipped, never raises.
    Order-preserving dedup. A returned IP is a CANDIDATE, confirmed by binding downstream.
    """
    import ipaddress

    out: list[str] = []
    seen: set[str] = set()
    for txt in txt_records:
        t = txt.strip()
        if not t.lower().startswith("v=spf1"):
            continue
        for token in t.split():
            mech = token.lstrip("+-~?")  # strip SPF qualifier
            low = mech.lower()
            if not (low.startswith("ip4:") or low.startswith("ip6:")):
                continue
            try:
                net = ipaddress.ip_network(mech.split(":", 1)[1], strict=False)
            except (ValueError, IndexError):
                continue
            if net.num_addresses > max_cidr_hosts:
                continue  # too big to bind — binding gate would not scale
            for ip in net.hosts():
                s = str(ip)
                if s not in seen:
                    seen.add(s)
                    out.append(s)
                    if len(out) >= max_total:
                        return tuple(out)  # aggregate cap — no probe storm
    return tuple(out)


def _mx_origin_hosts(mx_records: tuple[str, ...], domain: str) -> tuple[str, ...]:
    """MX hostnames that are plausible origin candidates: in-domain OR regional/self-hosted.
    Drops ONLY known big global mail providers (shared relay, never the target origin).
    ``mx_records`` may carry a priority prefix (``"10 mail.host."``) — take the host token."""
    out: list[str] = []
    seen: set[str] = set()
    for mx in mx_records:
        parts = mx.strip().split()
        host = parts[-1].rstrip(".").lower() if parts else ""
        if not host or host in seen:
            continue
        if any(host == s or host.endswith("." + s) for s in _BIG_CLOUD_MAIL_SUFFIXES):
            continue  # big global provider relay — not the target's origin
        seen.add(host)
        out.append(host)
    return tuple(out)


def enrich_with_mx_spf(intel: PassiveIntelMap) -> PassiveIntelMap:
    """(§12.61 A2) Derive origin candidates from ALREADY-collected MX + SPF — ZERO new I/O.

    SPF ip4/ip6 (small CIDRs expanded) → ``origin_ip_candidates`` (direct IPs). Non-big-cloud
    MX hostnames → ``subdomains`` (CompositeOriginDiscovery resolves them; a shared-hosting
    mail host resolves to the web origin). ADDITIVE ``replace``, fail-open. Every candidate is
    still proven by token-canary binding (§12.46) before any reach — no direct attack (#6).
    """
    spf_ips = parse_spf_ips(intel.txt_records)
    mx_hosts = _mx_origin_hosts(intel.mx_records, intel.domain)
    existing_ips = list(intel.origin_ip_candidates)
    seen_ip = set(existing_ips)
    for ip in spf_ips:
        if ip not in seen_ip:
            seen_ip.add(ip)
            existing_ips.append(ip)
    existing_subs = list(intel.subdomains)
    seen_sub = set(existing_subs)
    for host in mx_hosts:
        if host not in seen_sub:
            seen_sub.add(host)
            existing_subs.append(host)
    return replace(
        intel,
        origin_ip_candidates=tuple(existing_ips),
        subdomains=tuple(existing_subs),
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


# ── §12.61: Wayback historical source (subdomains → origin candidates + paths) ──


class WaybackSource(Protocol):
    """Seam for the keyless Wayback CDX historical-URL source (fail-open).

    Structurally satisfied by ``osint_sources.WaybackClient``. Keyless — unlike OTX/VT it
    needs no API key, so it is ALWAYS injected at the Conductor entry. Yields historical
    subdomains (→ origin candidates via CompositeOriginDiscovery) and historical paths
    (→ probe-steering breadth)."""

    def subdomains_and_paths(self, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        raise NotImplementedError


def enrich_with_wayback(intel: PassiveIntelMap, wayback: WaybackSource) -> PassiveIntelMap:
    """Return *intel* enriched with Wayback historical subdomains + paths.

    ADDITIVE (anti-#10): NEW frozen map via replace. Historical subdomains are UNIONED
    with crt.sh/VT subdomains (deduped, order preserved) → each becomes an ORIGIN
    CANDIDATE that CompositeOriginDiscovery resolves and verify_origin_binding proves
    (§12.61: a pre-CF subdomain often resolves to the origin IP directly). Historical
    paths are unioned with existing (OTX) paths for probe-steering breadth.

    PRODUCER ONLY — a historical subdomain is a CANDIDATE, never authorization: acted on
    only after token-canary binding to the owned host. Wayback is INDIRECT for the origin
    IP (subdomain→resolve); the DIRECT origin-IP source is MX/SPF (next slice).

    Fail-open: any error from the source → *intel* unchanged. Never raises.
    """
    try:
        wb_subs, wb_paths = wayback.subdomains_and_paths(intel.domain)
    except Exception:  # noqa: BLE001 — OSINT boundary; fail-open = no enrichment
        return intel
    existing_subs = list(intel.subdomains)
    seen_subs = set(existing_subs)
    for sub in wb_subs:
        if sub not in seen_subs:
            seen_subs.add(sub)
            existing_subs.append(sub)
    existing_paths = list(intel.historical_paths)
    seen_paths = set(existing_paths)
    for p in wb_paths:
        if p not in seen_paths:
            seen_paths.add(p)
            existing_paths.append(p)
    return replace(
        intel,
        subdomains=tuple(existing_subs),
        historical_paths=tuple(existing_paths),
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
