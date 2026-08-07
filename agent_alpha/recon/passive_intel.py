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

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agent_alpha.events.event_types import EventType

if TYPE_CHECKING:
    from agent_alpha.events.store import EventStore
    from agent_alpha.recon.passive_discovery import PassiveDiscoveryResult


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
        protection_detected:  "cloudflare"|"akamai"|"sucuri"|None.     [slice-3]
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


# ── Event-sourced audit (§12.48: PASSIVE_INTEL_GATHERED before active recon) ───


def record_passive_intel(
    event_store: EventStore,
    engagement_id: str,
    intel: PassiveIntelMap,
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
        },
    )
