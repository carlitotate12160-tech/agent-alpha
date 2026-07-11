# agent_alpha/recon/passive_discovery.py
# Phase 2.5 — R2 slice-1: Passive crt.sh subdomain discovery.
#
# Passive-only surface expansion: queries crt.sh Certificate Transparency
# logs for subdomains, partitions results through the EXISTING exact-host
# auth gate (authorization.is_in_scope), and seeds only in-scope hosts to
# the Alpha frontier via enqueue_discovered_url.
#
# The ONLY network call in this module is the single crt.sh GET.
# No DNS resolution, no active probing, no subfinder/Shodan.

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.events.event_types import EventType

if TYPE_CHECKING:
    from agent_alpha.conductor.authorization import AuthorizationStateMachine
    from agent_alpha.events.store import EventStore

_log = logging.getLogger(__name__)


# ── crt.sh URL template ──────────────────────────────────────────────
# %25 = URL-encoded '%'; the leading %.<domain> is crt.sh's subdomain wildcard.

CRTSH_URL_TEMPLATE: str = "https://crt.sh/?q=%25.{domain}&output=json"


# ── Pure parser ───────────────────────────────────────────────────────


def parse_crtsh_names(crtsh_json: str, domain: str) -> list[str]:
    """Parse crt.sh JSON response → sorted, deduplicated, domain-filtered hostnames.

    For each certificate object, splits ``name_value`` on newlines, strips
    whitespace, lowercases, strips leading ``*.`` wildcards, and keeps only
    hosts that are exactly ``domain`` or end with ``.{domain}``.

    Never raises on malformed JSON (returns ``[]``).
    """
    try:
        entries = json.loads(crtsh_json)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []

    seen: set[str] = set()
    domain_lower = domain.strip().lower()
    suffix = "." + domain_lower

    for obj in entries:
        raw = obj.get("name_value", "")
        for line in raw.split("\n"):
            host = line.strip().lower()
            if host.startswith("*."):
                host = host[2:]
            if host == domain_lower or host.endswith(suffix):
                seen.add(host)

    return sorted(seen)


# ── Result dataclass ──────────────────────────────────────────────────


@dataclass(frozen=True)
class PassiveDiscoveryResult:
    """Immutable result of a passive subdomain discovery run.

    Attributes:
        domain:     The base domain that was queried.
        discovered: All hostnames found in CT logs (domain-filtered).
        in_scope:   Subset of discovered that passed ``is_in_scope``.
        enumerated: Subset of discovered that did NOT pass ``is_in_scope``
                    (recorded for audit, never seeded to the frontier).
    """

    domain: str
    discovered: tuple[str, ...]
    in_scope: tuple[str, ...]
    enumerated: tuple[str, ...]


# ── Discovery orchestrator ────────────────────────────────────────────


class PassiveDiscovery:
    """Passive crt.sh subdomain discovery, partitioned through the auth gate.

    Fail-closed: if the RECON gate refuses, returns an empty result and makes
    zero network calls. The single crt.sh GET is the ONLY network I/O.
    """

    def __init__(
        self,
        *,
        http_client: Any,
        authorization: AuthorizationStateMachine,
        event_store: EventStore,
    ) -> None:
        self._http = http_client
        self._auth = authorization
        self._event_store = event_store

    def discover(
        self,
        engagement_id: str,
        domain: str,
    ) -> PassiveDiscoveryResult:
        """Run passive discovery for *domain* under *engagement_id*.

        STEP 1 (fail-closed): check RECON gate BEFORE any network I/O.
        STEP 2: fetch crt.sh JSON.
        STEP 3: parse and filter hostnames.
        STEP 4: partition via ``is_in_scope``.
        """
        # STEP 1 — fail-closed auth gate (BEFORE any network I/O)
        if not self._auth.can_agent_proceed(a2a_pb2.ALPHA, engagement_id):
            return PassiveDiscoveryResult(domain, (), (), ())

        # STEP 2 — single crt.sh GET
        url = CRTSH_URL_TEMPLATE.format(domain=domain)
        resp = self._http.get(url)

        # STEP 3 — parse
        names = parse_crtsh_names(resp.text, domain)

        # STEP 4 — partition through the auth gate (is_in_scope is sole authority)
        in_scope: list[str] = []
        enumerated: list[str] = []
        for host in names:
            if self._auth.is_in_scope(engagement_id, host):
                in_scope.append(host)
            else:
                enumerated.append(host)

        result = PassiveDiscoveryResult(
            domain=domain,
            discovered=tuple(names),
            in_scope=tuple(in_scope),
            enumerated=tuple(enumerated),
        )

        # Event-sourced audit (ADR §7)
        self._event_store.append(
            event_type=EventType.PASSIVE_DISCOVERY,
            engagement_id=engagement_id,
            agent="alpha",
            payload={
                "discovered": list(result.discovered),
                "in_scope": list(result.in_scope),
                "enumerated": list(result.enumerated),
            },
        )

        _log.info(
            "Passive discovery for %s: %d discovered, %d in-scope, %d enumerated",
            domain,
            len(result.discovered),
            len(result.in_scope),
            len(result.enumerated),
        )

        return result


# ── Frontier seeder ───────────────────────────────────────────────────


def seed_frontier_from_passive(alpha: Any, result: PassiveDiscoveryResult) -> int:
    """Seed in-scope hosts from passive discovery into Alpha's work queue.

    Enqueues ``https://{host}/`` for each in-scope host via
    ``alpha.enqueue_discovered_url``. Enumerated hosts are NEVER enqueued.
    Idempotent: ``enqueue_discovered_url`` deduplicates internally.

    Returns the number of URLs present in ``alpha._work_queue`` after seeding.
    """
    for host in result.in_scope:
        alpha.enqueue_discovered_url(f"https://{host}/")
    return len(alpha._work_queue)
