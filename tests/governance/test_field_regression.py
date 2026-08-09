# tests/governance/test_field_regression.py
# Field-regression corpus — §12.60.
#
# This file is the CANONICAL home for field-shaped fixtures. Each entry
# encodes a real-world field failure as a permanent regression guard. A field
# bug may only be closed once its topology is represented here.
#
# RATCHET SEMANTICS: tests in this file assert field invariants that must
# never silently regress. Adding a test here is a one-way ratchet — removal
# requires an explicit ADR-level decision.
#
# ── Fixture Index ──────────────────────────────────────────────────────────
# [FR-001] ingco.co.id dead-subdomain topology (GAP-029, 2026-08-09)
#          19 dead subdomains × ~12 seed paths = 118 unreachable probes, ~25 min.
#          Invariant: ≤1 probe per dead host.
#
# Run on Oracle ARM64 / .venv312:
#   python -m pytest tests/governance/test_field_regression.py -v

from __future__ import annotations

import dataclasses
import pathlib
from typing import Any
from urllib.parse import urlparse

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")


# ── Shared infrastructure ────────────────────────────────────────────────────

@dataclasses.dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = dataclasses.field(default_factory=dict)


class FakeHttpClient:
    """Counts GETs; raises HttpClientError for roots of configured dead hosts."""

    def __init__(self, dead_hosts: set[str], live_routes: dict[str, FakeResponse] | None = None) -> None:
        self._dead = dead_hosts
        self._live = live_routes or {}
        self.calls: list[str] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(url)
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        if host in self._dead and parsed.path in ("", "/"):
            raise HttpClientError(f"connect timeout: {url}")
        return self._live.get(url, FakeResponse(404, "not found", {}))


class _NullProvider:
    """Never-callable LLM stub — field-regression tests must not hit the LLM tier."""

    model = "null"

    def complete(self, *args: object, **kwargs: object) -> object:
        raise AssertionError(
            "LLM provider called in field-regression test — dead hosts must never reach LLM"
        )


def _build_alpha(
    http: FakeHttpClient,
    *,
    domains: list[str],
    primary: str,
) -> tuple[Alpha, str, InMemoryEventStore]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="field_regression", target=primary)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=domains, exclusions=[]),
    )
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR),
        provider=_NullProvider(),
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orch,
        http_client=http,
    )
    return alpha, rec.engagement_id, store


# ═══════════════════════════════════════════════════════════════════════════════
# [FR-001] ingco.co.id dead-subdomain topology (GAP-029, 2026-08-09)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Field observation: 19 dead subdomains discovered via passive recon, each had
# ~12 seed paths queued → 118 unreachable probes, ~25 min wasted.
# This fixture encodes the exact field topology as a permanent regression guard.
#
# Invariant: total unreachable GETs == number of dead hosts (≤1/dead host).

# Exact number of subdomains from the field run (2026-08-09).
_INGCO_DEAD_COUNT = 19

# Number of seed paths enqueued per target by run_recon (approximate field value).
# The exact count doesn't matter — what matters is that multiple paths are seeded
# and only ONE probe reaches each dead host.
_INGCO_SEED_PATHS_PER_HOST = 12

# Synthetic dead subdomains shaped after the ingco topology.
_INGCO_DEAD_HOSTS = [f"dead-sub{i:02d}.ingco.example" for i in range(_INGCO_DEAD_COUNT)]


def test_ingco_dead_subdomain_topology() -> None:
    """[FR-001] ingco.co.id field regression: 19 dead subdomains × ~12 paths.

    Before GAP-029: 118 unreachable probes (~25 min).
    After GAP-029:  19 probes (≤1 per dead host, ~5 min).

    Invariant: total_unreachable_gets ≤ number_of_dead_hosts.
    This test is a PERMANENT RATCHET — it must never be removed without an ADR.
    """
    dead_set = set(_INGCO_DEAD_HOSTS)
    primary = _INGCO_DEAD_HOSTS[0]

    # Run one target at a time (mirrors run_recon per-target semantics).
    # Accumulate total unreachable GET calls across all 19 runs.
    total_unreachable_calls: dict[str, list[str]] = {}  # host -> calls

    for dead_host in _INGCO_DEAD_HOSTS:
        http = FakeHttpClient(dead_hosts={dead_host})
        alpha, eid, store = _build_alpha(
            http,
            domains=[dead_host],
            primary=dead_host,
        )
        alpha.run_recon(eid, f"https://{dead_host}/")

        calls_to_dead = [
            u for u in http.calls
            if (urlparse(u).hostname or urlparse(u).netloc) == dead_host
        ]
        total_unreachable_calls[dead_host] = calls_to_dead

        # Per-host invariant: exactly 1 probe (the root)
        assert len(calls_to_dead) <= 1, (
            f"[FR-001] {dead_host}: expected ≤1 GET, got {len(calls_to_dead)}. "
            f"Calls: {calls_to_dead}. "
            f"GAP-029 dead-host short-circuit is broken — ingco regression."
        )

        # HOST_ABANDONED event must be emitted per dead host (S1 audit)
        abandoned = [
            e for e in store.get_events(eid)
            if e.event_type == EventType.HOST_ABANDONED
            and e.payload.get("host") == dead_host
        ]
        assert len(abandoned) == 1, (
            f"[FR-001] {dead_host}: expected 1 HOST_ABANDONED event, got {len(abandoned)}."
        )

    # Global invariant: total unreachable probes ≤ number of dead hosts
    # (Before fix this would be ~19 × 12 = 228 probes for this synthetic topology)
    total_probe_count = sum(len(v) for v in total_unreachable_calls.values())
    assert total_probe_count <= _INGCO_DEAD_COUNT, (
        f"[FR-001] ingco topology REGRESSION: {total_probe_count} total unreachable probes "
        f"across {_INGCO_DEAD_COUNT} dead hosts (expected ≤{_INGCO_DEAD_COUNT}). "
        f"Per-host breakdown: { {h: len(v) for h, v in total_unreachable_calls.items()} }. "
        "GAP-029 dead-host short-circuit is broken."
    )
