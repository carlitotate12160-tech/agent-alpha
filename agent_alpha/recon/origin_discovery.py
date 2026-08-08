"""Origin-discovery seam — A1 Slice B.

Defines the ``OriginDiscovery`` protocol that downstream slices depend on.
A lab stand-in injects a fixed list; production = real source (CT / Shodan /
DNS-history → IPs).

Candidate ≠ authorization: every candidate MUST still pass
``assert_origin_authorized`` before use (enforced in Slice C).

No network I/O in this module — pure seam interface.
"""

from __future__ import annotations

from typing import Any, Protocol


class OriginDiscovery(Protocol):
    """Seam for discovering candidate origin IPs behind a fronted host."""

    def candidates(self, fronted_host: str) -> list[str]:
        """Return candidate origin IPs/hostnames for *fronted_host*.

        Sources in production: Certificate Transparency logs, Shodan,
        DNS history, etc.  In tests a stub injects a fixed list.
        """
        ...  # pragma: no cover


class StaticOriginDiscovery:
    """Fixed-list ``OriginDiscovery`` — lab/config stand-in for real
    CT/Shodan/DNS-history discovery (e.g. A1 field-prove).

    Authorization is NOT granted here: a returned candidate is only ACTED on
    if it is also in the signed ``EngagementProfile.authorized_origins``
    (Slice C, C9). This class merely stands in for the discovery step.
    """

    def __init__(self, candidates: list[str]) -> None:
        self._candidates = list(candidates)

    def candidates(self, fronted_host: str) -> list[str]:  # noqa: ARG002 (fixed lab list)
        return list(self._candidates)


# ── GAP-017 consumer: event-sourced OTX origin candidates → binding path ───────


class CompositeOriginDiscovery:
    """Union a base ``OriginDiscovery`` with event-sourced OTX origin-IP candidates.

    §12.48 slice-5 produced ``origin_ip_candidates`` (OTX passive DNS / url-worker
    IPs) into the ``PASSIVE_INTEL_GATHERED`` stream but nothing consumed them
    (GAP-017 dead-end). This wrapper feeds them into ``resolve_and_bind_origin``'s
    candidate list so each OTX IP is PROVEN by the same ``verify_origin_binding``
    token-canary — candidate ≠ authorization: an untrusted passive IP is only ever
    acted on after it demonstrably serves the owned host. Additive (anti-#10): the
    base discovery is unchanged; OTX IPs are unioned, base order preserved first.
    """

    def __init__(self, base: OriginDiscovery, event_store: Any, engagement_id: str) -> None:
        self._base = base
        self._event_store = event_store
        self._engagement_id = engagement_id

    def candidates(self, fronted_host: str) -> list[str]:
        from agent_alpha.events.event_types import EventType

        out: list[str] = list(self._base.candidates(fronted_host))
        seen = set(out)
        try:
            events = self._event_store.get_events(self._engagement_id)
        except Exception:  # noqa: BLE001 — event read boundary; degrade to base only
            return out
        host_norm = fronted_host.rstrip(".").lower()
        for ev in events:
            if getattr(ev, "event_type", None) != EventType.PASSIVE_INTEL_GATHERED:
                continue
            payload = ev.payload
            # SECURITY (CodeRabbit): scope candidates to the host they were
            # discovered for. get_events() returns ALL passive events for the
            # engagement; without this filter an IP found for host A would be
            # probed under host B's token + Host header (cross-host token leak /
            # collateral). Exact host match — binding proof is a backstop, not a
            # substitute for candidate scoping.
            if payload.get("domain", "").rstrip(".").lower() != host_norm:
                continue
            for ip in payload.get("origin_ip_candidates", []) or []:
                if ip not in seen:
                    seen.add(ip)
                    out.append(ip)
        return out
