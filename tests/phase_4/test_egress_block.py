# tests/phase_4/test_egress_block.py
# GAP-037 — Stop-on-Block (mid-run egress death) — Tier-1 contract tests.
# Reuses the GAP-029 FakeHttpClient/_build_alpha harness (test_dead_host_skip).
#   * test_no_abort_on_dead_from_start_hosts — cardinal: many dead-from-start hosts
#     must NOT trigger egress-abort (that is GAP-029's job). Fails if the
#     `host in _host_ok` guard is dropped.
# Run on Oracle ARM64 / .venv312.
from __future__ import annotations

from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from tests.phase_4.test_dead_host_skip import (
    FakeHttpClient, FakeResponse, _StubProvider, _build_alpha,
)

_HOST = "reached.example"


def _egress_events(store, eid):
    return [e for e in store.get_events(eid) if e.event_type == EventType.EGRESS_BLOCKED]


def test_aborts_after_threshold_on_reached_host() -> None:
    """Root 200 (host reached), then every seed path times out → run aborts with
    an EGRESS_BLOCKED event after ~THRESHOLD failures, NOT the whole queue."""
    root = f"https://{_HOST}/"
    http = FakeHttpClient(live_routes={root: FakeResponse(200, "<html>ok</html>", {})})
    # every non-root URL on the host raises (IP-block simulation) via default 404? No —
    # force timeouts: mark all seed paths dead by making non-live gets raise.
    orig_get = http.get
    def blocking_get(url, **kw):
        from urllib.parse import urlparse
        p = urlparse(url)
        if p.path in ("", "/"):
            return orig_get(url, **kw)  # root ok
        http.calls.append(url)
        from agent_alpha.agents.http_client import HttpClientError
        raise HttpClientError(f"blocked: {url}")
    http.get = blocking_get  # type: ignore[method-assign]

    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, root)

    assert alpha._egress_blocked is True
    assert len(_egress_events(store, eid)) == 1
    # bounded: root + at most THRESHOLD blocked probes before abort (+small slack)
    host_calls = [u for u in http.calls if _HOST in u]
    assert len(host_calls) <= constants.EGRESS_BLOCK_THRESHOLD + 2, host_calls


def test_no_abort_on_dead_from_start_hosts() -> None:
    """CARDINAL: many hosts dead FROM START (never reached) must NOT egress-abort —
    that is GAP-029 (dead-host skip), not a mid-run block."""
    domains = [f"d{i}.example" for i in range(constants.EGRESS_BLOCK_THRESHOLD + 3)]
    http = FakeHttpClient(dead_roots=set(domains))
    alpha, eid, store = _build_alpha(http, domains=domains, provider=_StubProvider())
    for d in domains:
        alpha.run_recon(eid, f"https://{d}/")
    assert alpha._egress_blocked is False
    assert _egress_events(store, eid) == []
