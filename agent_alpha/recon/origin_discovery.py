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

from agent_alpha.recon.reach_strategy import is_cloudflare_ip, is_fronted_edge_ip


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

        # single exclusion choke — a fronted-edge (CF/Shopify/Fastly/…) IP is NEVER an origin,
        # regardless of which source produced it. Applied to EVERY append site so no source can
        # bypass it (GAP-160 / Aikido+Greptile: origin_ip_candidates fed edges in unfiltered).
        out: list[str] = [ip for ip in self._base.candidates(fronted_host) if not is_fronted_edge_ip(ip)]
        seen = set(out)

        def _add(ip: str) -> None:
            if ip not in seen and not is_fronted_edge_ip(ip):
                seen.add(ip)
                out.append(ip)

        try:
            events = self._event_store.get_events(self._engagement_id)
        except Exception:  # noqa: BLE001 — event read boundary; degrade to base only
            return out
        host_norm = fronted_host.strip().lower()

        for ev in events:
            if getattr(ev, "event_type", None) != EventType.PASSIVE_INTEL_GATHERED:
                continue
            payload = ev.payload
            # SECURITY (CodeRabbit): scope candidates to the domain they were
            # discovered for. get_events() returns ALL passive events for the
            # engagement; without this filter an IP found for domain A would be
            # probed under domain B's token + Host header (cross-domain token
            # leak / collateral). Passive intel is gathered per APEX domain (one
            # PASSIVE_INTEL_GATHERED per engagement target) but origin binding is
            # requested per blocked HOST — often a subdomain (pos.ex.com blocked
            # → needs apex ex.com's OTX/VT candidates, GAP-039). Match the apex
            # exactly OR a dot-boundary subdomain of it — same registrable
            # domain, same token scope. Cross-domain still rejected.
            domain_norm = payload.get("domain", "").rstrip(".").lower()
            if host_norm != domain_norm and not host_norm.endswith("." + domain_norm):
                continue

            # 1. origin_ip_candidates (OTX/VT/Mnemonic union)
            for ip in payload.get("origin_ip_candidates", []) or []:
                _add(ip)

            # 1.5 historical_a_records — two-tier pre-CF ranking.
            #     cf_first_seen stays is_cloudflare_ip (the CF MIGRATION boundary — do NOT broaden).
            #     origins excludes fronted-edge so doomed IPs aren't ranked; _add is the final gate.
            triples = payload.get("historical_a_records", []) or []
            cf_seen = [f for (ip, f, last) in triples if is_cloudflare_ip(ip)]
            cf_first_seen = min(cf_seen) if cf_seen else None
            origins = [(ip, f, last) for (ip, f, last) in triples if not is_fronted_edge_ip(ip)]
            if cf_first_seen is None:
                ranked = sorted(origins, key=lambda t: t[2], reverse=True)
            else:
                tier1 = sorted((t for t in origins if t[2] < cf_first_seen),  key=lambda t: t[2], reverse=True)
                tier2 = sorted((t for t in origins if t[2] >= cf_first_seen), key=lambda t: t[2], reverse=True)
                ranked = tier1 + tier2
            for ip, _f, _last in ranked:
                _add(ip)

            # 2. VT subdomains → resolve → _add (edge-filtered too)
            for sub in payload.get("subdomains", []) or []:
                sub_norm = sub.strip().lower().rstrip(".")
                if not sub_norm or sub_norm == host_norm:
                    continue
                for ip in _resolve_ipv4(sub_norm):
                    _add(ip)

        return out


def _resolve_ipv4(hostname: str) -> list[str]:
    """DNS resolve hostname → IPv4 addresses. Fail-open → [] on any error.

    Local import to keep the module's pure-seam intent (no socket at import time).
    """
    import socket

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        seen: set[str] = set()
        result: list[str] = []
        for info in infos:
            ip = str(info[4][0])
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
        return result
    except OSError:
        return []
