# tests/phase_2_5/test_recon_runner.py
"""Contract: #51 slice-1 — engagement-level WAF-wall detection (read-only).

recon_runner scans every target of an engagement with ONE Alpha, then (until now)
threw away each run_recon status and returned a report. A fully WAF-walled engagement
was therefore indistinguishable from a clean-but-empty one — the agent "surrendered"
silently (anti-Lyndon #3). This slice derives an ENGAGEMENT-level wall verdict from
state that ALREADY exists (per-target handoff statuses × WAF_BLOCKED events) and records
it as a first-class ENGAGEMENT_WALLED audit event + a ReconRunResult field.

Detection ONLY — the active engagement-level origin hunt is slice-2, behind the same
allow_origin_discovery / allow_evasion consent gates the per-host reach already enforces.
This slice touches NO per-host reach code (anti-#6 duplicate).

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_recon_runner.py -v
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.recon_runner import derive_wall_verdict
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

_HOST_A = "a.example.com"
_HOST_B = "b.example.com"


def _engagement(store: InMemoryEventStore, host: str = _HOST_A) -> str:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", host)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[host], exclusions=[]))
    return rec.engagement_id


def _waf(store: InMemoryEventStore, eng: str, host: str) -> None:
    store.append(
        EventType.WAF_BLOCKED, eng, "alpha", {"host": host, "path": "/", "status_code": 403}
    )


# ── derive_wall_verdict: the engagement-level verdict, from existing state ─────


def test_walled_when_all_targets_blocked_and_none_complete() -> None:
    """CARDINAL: no target COMPLETE + >=1 WAF_BLOCKED host = the whole engagement is
    walled. This is the honest outcome the silent-FAILED path used to hide."""
    store = InMemoryEventStore()
    eng = _engagement(store)
    _waf(store, eng, _HOST_A)
    _waf(store, eng, _HOST_B)

    v = derive_wall_verdict(store, eng, [a2a_pb2.FAILED, a2a_pb2.BLOCKED])

    assert v.walled is True
    assert v.reason == "waf_walled"
    assert set(v.blocked_hosts) == {_HOST_A, _HOST_B}


def test_not_walled_when_any_target_completes() -> None:
    """If we got through ANYWHERE (a COMPLETE), it is not a total wall — even if another
    host was WAF-blocked."""
    store = InMemoryEventStore()
    eng = _engagement(store)
    _waf(store, eng, _HOST_A)

    v = derive_wall_verdict(store, eng, [a2a_pb2.FAILED, a2a_pb2.COMPLETE])

    assert v.walled is False
    assert v.reason == "clear"


def test_dead_hosts_not_reported_as_walled() -> None:
    """No WAF_BLOCKED at all → targets failed because unreachable (dead), NOT walled.
    Honest distinction: a dead host is not a defended host."""
    store = InMemoryEventStore()
    eng = _engagement(store)

    v = derive_wall_verdict(store, eng, [a2a_pb2.FAILED, a2a_pb2.FAILED])

    assert v.walled is False
    assert v.reason == "dead"
    assert v.blocked_hosts == ()


# ── wiring: the autonomous path emits ENGAGEMENT_WALLED (RUNNER-SEAL != WIRED) ─


class _WallingAlpha:
    """Fake Alpha: every target is WAF-blocked (emits WAF_BLOCKED) and hands off FAILED."""

    def __init__(self, store: InMemoryEventStore) -> None:
        self._store = store

    def run_recon(self, engagement_id: str, target_url: str) -> a2a_pb2.A2AMessage:
        host = urlparse(target_url).hostname or ""
        self._store.append(
            EventType.WAF_BLOCKED,
            engagement_id,
            "alpha",
            {"host": host, "path": "/", "status_code": 403},
        )
        msg = a2a_pb2.A2AMessage()
        payload = a2a_pb2.HandoffPayload(status=a2a_pb2.FAILED, findings_count=0)
        msg.payload = payload.SerializeToString()
        return msg


def test_run_recon_for_engagement_emits_engagement_walled(monkeypatch: pytest.MonkeyPatch) -> None:
    """The LIVE Conductor path must emit ENGAGEMENT_WALLED on a walled sweep and carry
    the verdict on ReconRunResult — not just the derive_ helper in isolation."""
    store = InMemoryEventStore()
    eng = _engagement(store)
    auth = AuthorizationStateMachine(event_store=store)

    pipeline = recon_runner.ReconPipeline(alpha=_WallingAlpha(store), graph_store=NetworkXGraphStore())
    monkeypatch.setattr(recon_runner, "build_recon_pipeline", lambda *a, **kw: pipeline)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [f"https://{_HOST_A}/"])
    monkeypatch.setattr(recon_runner, "certspotter_discover", lambda *a, **kw: None)
    monkeypatch.setattr(recon_runner, "build_passive_discovery", lambda *a, **kw: None)
    monkeypatch.setattr(recon_runner, "hackertarget_fallback", lambda *a, **kw: None)
    monkeypatch.setattr(recon_runner, "enrich_with_dns", lambda intel, dns: intel)

    result = recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=object()
    )

    assert result.wall_verdict is not None
    assert result.wall_verdict.walled is True
    walled = [e for e in store.get_events(eng) if e.event_type == EventType.ENGAGEMENT_WALLED]
    assert len(walled) == 1
    assert _HOST_A in walled[0].payload.get("blocked_hosts", [])
