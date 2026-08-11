# tests/phase_4/test_egress_block.py
# GAP-037 — Stop-on-Block (mid-run egress death) — Tier-1 contract tests.
# Reuses the GAP-029 FakeHttpClient/_build_alpha harness (test_dead_host_skip).
# CodeRabbit fixes: #3 assert consecutive_failures == THRESHOLD in the event payload;
#   #4 the "no false abort" test queues ALL dead hosts in ONE run (cross-host
#   accumulation), so it fails if the `host in _host_ok` guard is removed.
# Run on Oracle ARM64 / .venv312.
from __future__ import annotations

from urllib.parse import urlparse

from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from tests.phase_4.test_dead_host_skip import (
    FakeHttpClient, FakeResponse, _StubProvider, _build_alpha,
)

_TH = constants.EGRESS_BLOCK_THRESHOLD
_HOST = "reached.example"


def _egress_events(store, eid):
    return [e for e in store.get_events(eid) if e.event_type == EventType.EGRESS_BLOCKED]


def test_aborts_after_threshold_on_reached_host() -> None:
    """Root 200 (host reached), then every seed path times out → the run aborts with
    one EGRESS_BLOCKED event whose payload records exactly THRESHOLD failures (#3)."""
    root = f"https://{_HOST}/"
    http = FakeHttpClient(live_routes={root: FakeResponse(200, "<html>ok</html>", {})})

    def blocking_get(url, **kw):
        http.calls.append(url)
        if urlparse(url).path in ("", "/"):
            return FakeResponse(200, "<html>ok</html>", {})
        raise HttpClientError(f"blocked: {url}")

    http.get = blocking_get  # type: ignore[method-assign]
    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, root)

    assert alpha._egress_blocked is True
    evs = _egress_events(store, eid)
    assert len(evs) == 1
    # #3: an implementation that aborts after 1 failure must NOT pass.
    assert evs[0].payload["consecutive_failures"] == _TH, evs[0].payload
    host_calls = [u for u in http.calls if _HOST in u]
    assert len(host_calls) <= _TH + 2, host_calls  # bounded, not the whole queue


def test_no_abort_on_many_dead_hosts_single_run() -> None:
    """CARDINAL (#4): after a live host is reached (in _host_ok), > THRESHOLD
    dead-from-start hosts must NOT accumulate egress failures — they never entered
    _host_ok, so _note_transport_fail returns early. Fails if the `host in _host_ok`
    guard is removed (all dead hosts would count → egress abort)."""
    dead = [f"d{i}.example" for i in range(_TH + 3)]
    target = "hub.example"
    root = f"https://{target}/"
    http = FakeHttpClient(
        dead_roots=set(dead),
        live_routes={root: FakeResponse(200, "<html>ok</html>", {})},
    )
    alpha, eid, store = _build_alpha(
        http, domains=[target, *dead], provider=_StubProvider()
    )
    alpha.run_recon(eid, root)
    # After the run, target is in _host_ok (root succeeded). Simulate dead host
    # root failures — the guard must reject them (not in _host_ok = GAP-029's job).
    assert target in alpha._host_ok, "target must be reached before dead hosts fail"
    for d in dead:
        alpha._note_transport_fail(d)
    assert alpha._egress_blocked is False, "dead-from-start hosts must not egress-abort"
    assert alpha._consecutive_transport_fail == 0
    assert _egress_events(store, eid) == []
