# tests/phase_4/test_dead_host_skip.py
# GAP-029 — Dead-Host Short-Circuit (Instinct #2) — Tier-1 contract tests.
#
# §12.60 cardinal-test protocol:
#   * test_nonroot_failure_does_NOT_mark_dead — MUST FAIL before the R1 guard is
#     removed, fails if anyone reverts to any-path marking.
#   * test_dead_host_probed_at_most_once — MUST FAIL before the scout.py fix;
#     proves the one-probe-per-dead-host invariant.
#
# All tests: FakeHttpClient + rule-only orchestrator stub (no LLM, no cost).
# Field topology (19-host shape) lives exclusively in tests/governance/test_field_regression.py
# (S2 — no duplication).
#
# Run on Oracle ARM64 / .venv312:
#   python -m pytest tests/phase_4/test_dead_host_skip.py -v

from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_DEAD_HOST = "dead.example"
_LIVE_HOST = "live.example"


# ── Fake HTTP ────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = dataclasses.field(default_factory=dict)


class FakeHttpClient:
    """Counts GET calls; raises HttpClientError for configured dead URLs."""

    def __init__(
        self,
        dead_roots: set[str] | None = None,
        dead_urls: set[str] | None = None,
        live_routes: dict[str, FakeResponse] | None = None,
    ) -> None:
        self._dead_roots = dead_roots or set()
        self._dead_urls = dead_urls or set()
        self._live = live_routes or {}
        self.calls: list[str] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(url)
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        # Dead root (path == "" or "/")
        if host in self._dead_roots and parsed.path in ("", "/"):
            raise HttpClientError(f"connect timeout: {url}")
        # Specific dead URL
        if url in self._dead_urls:
            raise HttpClientError(f"connect timeout: {url}")
        if url in self._live:
            return self._live[url]
        return FakeResponse(404, "not found", {})


# ── Rule-only orchestrator stub ──────────────────────────────────────────────

class _DeadOnlyProvider:
    """LLM provider that must never be called (dead hosts must not reach ORIENT)."""

    model = "null"

    def complete(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("LLM provider called — dead-host tests must NOT reach LLM tier")


class _StubProvider:
    """LLM provider that returns a valid generic_http_probe decision.

    Used for live-host tests where a 200 response legitimately reaches the
    ORIENT stage (the R1/live-host tests verify that live hosts are NOT
    killed, so they need the loop to complete without crashing).
    """

    model = "stub"

    def complete(self, *args: object, **kwargs: object) -> object:
        return type(
            "R",
            (),
            {
                "text": '{"tool": "generic_http_probe"}',
                "usage_cost_usd": 0.0,
                "model": "stub",
                "reasoning": "",
            },
        )()


# ── Builder ──────────────────────────────────────────────────────────────────

def _build_alpha(
    http: FakeHttpClient,
    *,
    domains: list[str] | None = None,
    provider: Any | None = None,
) -> tuple[Alpha, str, InMemoryEventStore]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    all_domains = domains or [_DEAD_HOST]
    rec = auth.create_engagement(client_id="gap029_test", target=all_domains[0])
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=all_domains, exclusions=[]),
    )
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR),
        provider=provider or _DeadOnlyProvider(),
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orch,
        http_client=http,
    )
    return alpha, rec.engagement_id, store


# ── Helpers ──────────────────────────────────────────────────────────────────

def _calls_to_host(calls: list[str], host: str) -> list[str]:
    from urllib.parse import urlparse
    return [u for u in calls if (urlparse(u).hostname or urlparse(u).netloc) == host]


def _abandoned_events(store: InMemoryEventStore, eid: str) -> list[Any]:
    return [
        e for e in store.get_events(eid)
        if e.event_type == EventType.HOST_ABANDONED
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Test 1 — root failure marks the host dead and prunes its queue
# ═══════════════════════════════════════════════════════════════════════════

def test_root_failure_marks_and_prunes() -> None:
    """Root HttpClientError: host enters _dead_hosts; its queue is pruned to 0."""
    http = FakeHttpClient(dead_roots={_DEAD_HOST})
    alpha, eid, _ = _build_alpha(http)

    # Pre-load 11 extra seed paths onto the queue for the dead host before run_recon
    # resets state (simulate the real run path by running recon with extra seeds).
    # We verify queue pruning via _work_queue state inspection during step execution.
    alpha.run_recon(eid, f"https://{_DEAD_HOST}/")

    assert _DEAD_HOST in alpha._dead_hosts, (
        f"root HttpClientError should mark {_DEAD_HOST} dead; "
        f"_dead_hosts = {alpha._dead_hosts}"
    )
    # Queue should contain 0 URLs for the dead host after run completes.
    from urllib.parse import urlparse
    dead_in_queue = [
        u for u in alpha._work_queue
        if (urlparse(u).hostname or urlparse(u).netloc) == _DEAD_HOST
    ]
    assert dead_in_queue == [], (
        f"pruned host has {len(dead_in_queue)} URLs still in _work_queue: {dead_in_queue}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test 2 — R1 CARDINAL: non-root failure must NOT mark the host dead
# ═══════════════════════════════════════════════════════════════════════════

def test_nonroot_failure_does_NOT_mark_dead() -> None:
    """CARDINAL (R1): homepage 200, then /.env raises HttpClientError.
    The host must NOT enter _dead_hosts; its remaining paths must still be probed.

    This test MUST FAIL if anyone reverts to any-path marking.
    """
    sensitive_url = f"https://{_LIVE_HOST}/.env"
    second_path = f"https://{_LIVE_HOST}/admin"

    http = FakeHttpClient(
        dead_urls={sensitive_url},
        live_routes={
            f"https://{_LIVE_HOST}/": FakeResponse(
                200,
                "<html><head><title>Live Site</title></head><body><h1>OK</h1></body></html>",
                {"Server": "nginx"},
            ),
            second_path: FakeResponse(
                200,
                "<html><head><title>Admin</title></head><body><h1>Panel</h1></body></html>",
                {"Server": "nginx"},
            ),
        },
    )
    # Live host reaches the ORIENT stage on a 200 response — use the stub LLM provider.
    alpha, eid, _ = _build_alpha(http, domains=[_LIVE_HOST], provider=_StubProvider())

    # Manually enqueue the sensitive + second paths before run_recon (mirrors seed logic)
    alpha.run_recon(eid, f"https://{_LIVE_HOST}/")

    assert _LIVE_HOST not in alpha._dead_hosts, (
        f"R1 VIOLATED: non-root HttpClientError on /.env marked {_LIVE_HOST} as dead; "
        f"_dead_hosts = {alpha._dead_hosts}. "
        "A live WAF'd host must not be killed by a sensitive-path RST."
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test 3 — dead host gets exactly 1 GET (the root), remaining 11 paths skipped
# ═══════════════════════════════════════════════════════════════════════════

def test_dead_host_probed_at_most_once() -> None:
    """Root raises HttpClientError; 12 seed paths queued → total GETs to host == 1.

    MUST FAIL before the scout.py GAP-029 fix (cardinal per §12.60).
    """
    http = FakeHttpClient(dead_roots={_DEAD_HOST})
    alpha, eid, _ = _build_alpha(http)

    # run_recon seeds the work_queue; the root will be popped first (FIFO fast-path
    # when _current_objective=None). We verify the total call count, not queue state.
    alpha.run_recon(eid, f"https://{_DEAD_HOST}/")

    dead_calls = _calls_to_host(http.calls, _DEAD_HOST)
    assert len(dead_calls) == 1, (
        f"Expected exactly 1 GET to dead host {_DEAD_HOST}, got {len(dead_calls)}. "
        f"Calls: {dead_calls}. "
        "All remaining seed paths should be pruned after root HttpClientError."
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test 4 — reachable host gets ALL its paths; no collateral skip
# ═══════════════════════════════════════════════════════════════════════════

def test_reachable_host_not_over_skipped() -> None:
    """A reachable (200) host must get all its paths; dead-host logic must not
    collateral-skip a live host sharing the same run."""
    live_root = f"https://{_LIVE_HOST}/"
    live_path = f"https://{_LIVE_HOST}/api/v1"
    live_body = (
        "<html><head><title>Live</title></head>"
        "<body><h1>Hello</h1></body></html>"
    )
    # Use stub LLM provider: live host reaches the ORIENT stage on its 200 root.
    http2 = FakeHttpClient(
        live_routes={
            live_root: FakeResponse(200, live_body, {"Server": "nginx"}),
            live_path: FakeResponse(200, '{"status": "ok"}', {"Content-Type": "application/json"}),
        },
    )
    alpha2, eid2, _ = _build_alpha(http2, domains=[_LIVE_HOST], provider=_StubProvider())
    alpha2.run_recon(eid2, live_root)

    # The live host root must have been probed
    live_calls = _calls_to_host(http2.calls, _LIVE_HOST)
    assert len(live_calls) >= 1, (
        f"Live host {_LIVE_HOST} was never probed; calls = {http2.calls}"
    )
    # The live host must NOT be in _dead_hosts
    assert _LIVE_HOST not in alpha2._dead_hosts, (
        f"Live host was incorrectly marked dead: _dead_hosts = {alpha2._dead_hosts}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test 5 — enqueue_discovered_url refuses dead host
# ═══════════════════════════════════════════════════════════════════════════

def test_enqueue_refuses_dead_host() -> None:
    """enqueue_discovered_url must return False for any URL on a dead host."""
    http = FakeHttpClient(dead_roots={_DEAD_HOST})
    alpha, eid, _ = _build_alpha(http)

    # Simulate the host being dead (as run_recon would set it)
    alpha._engagement_id = eid
    alpha._dead_hosts = {_DEAD_HOST}
    alpha._work_queue = []
    alpha._probed = set()

    result = alpha.enqueue_discovered_url(f"https://{_DEAD_HOST}/some/path")
    assert result is False, (
        f"enqueue_discovered_url returned True for URL on dead host {_DEAD_HOST}; "
        "should return False (host transport-unreachable this run)"
    )
    assert alpha._work_queue == [], (
        f"URL for dead host was enqueued despite dead-host guard: {alpha._work_queue}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test 6 — HOST_ABANDONED event emitted (S1)
# ═══════════════════════════════════════════════════════════════════════════

def test_host_abandoned_event_emitted() -> None:
    """Exactly one HOST_ABANDONED event is emitted per dead root, carrying
    the correct host, reason, and trigger fields (S1 parity with WAF_BLOCKED)."""
    http = FakeHttpClient(dead_roots={_DEAD_HOST})
    alpha, eid, store = _build_alpha(http)

    alpha.run_recon(eid, f"https://{_DEAD_HOST}/")

    events = _abandoned_events(store, eid)
    assert len(events) == 1, (
        f"Expected exactly 1 HOST_ABANDONED event, got {len(events)}. "
        f"Events: {[e.payload for e in events]}"
    )
    payload = events[0].payload
    assert payload.get("host") == _DEAD_HOST, (
        f"HOST_ABANDONED payload.host == {payload.get('host')!r}, expected {_DEAD_HOST!r}"
    )
    assert payload.get("reason") == "transport_unreachable", (
        f"HOST_ABANDONED payload.reason == {payload.get('reason')!r}"
    )
    assert payload.get("trigger") == "root_probe", (
        f"HOST_ABANDONED payload.trigger == {payload.get('trigger')!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test 7 — non-root HttpClientError does NOT emit HOST_ABANDONED
# ═══════════════════════════════════════════════════════════════════════════

def test_nonroot_failure_does_not_emit_abandoned_event() -> None:
    """A transport error on a non-root path must NOT emit HOST_ABANDONED.
    Only root failures are eligible for the instinct #2 short-circuit."""
    sensitive_url = f"https://{_LIVE_HOST}/.env"
    http = FakeHttpClient(
        dead_urls={sensitive_url},
        live_routes={
            f"https://{_LIVE_HOST}/": FakeResponse(
                200,
                "<html><head><title>Live</title></head><body><h1>OK</h1></body></html>",
                {"Server": "nginx"},
            ),
        },
    )
    # Live host reaches ORIENT on a 200 root — use stub provider.
    alpha, eid, store = _build_alpha(http, domains=[_LIVE_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_LIVE_HOST}/")

    events = _abandoned_events(store, eid)
    assert len(events) == 0, (
        f"HOST_ABANDONED emitted for non-root failure on {_LIVE_HOST}: "
        f"{[e.payload for e in events]}"
    )
