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
from agent_alpha.conductor.recon_runner import derive_terminal_status, derive_wall_verdict
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


def test_prior_run_waf_does_not_wall_a_clean_rerun() -> None:
    """Greptile/Aikido regression: an engagement re-run after done/failed must NOT inherit
    a PRIOR run's WAF_BLOCKED evidence. Scoping the scan to events after the current run's
    start seq means a later dead/clean sweep (no NEW WAF) is honestly 'dead', not walled."""
    store = InMemoryEventStore()
    eng = _engagement(store)
    _waf(store, eng, _HOST_A)  # a PRIOR run hit a WAF
    run_start = store.get_events(eng)[-1].sequence_number  # snapshot after the prior run

    # Current re-run: the target went dead (FAILED) and emitted NO new WAF_BLOCKED.
    v = derive_wall_verdict(store, eng, [a2a_pb2.FAILED], after_sequence=run_start)

    assert v.walled is False
    assert v.reason == "dead"
    assert v.blocked_hosts == ()


# ── 187a: derive_terminal_status — honest handoff status, never hardcoded COMPLETE ─


def test_terminal_status_complete_when_all_targets_complete() -> None:
    """All targets finished recon → COMPLETE (chain may advance)."""
    assert derive_terminal_status([a2a_pb2.COMPLETE, a2a_pb2.COMPLETE]) == a2a_pb2.COMPLETE


def test_terminal_status_complete_on_mixed_when_any_complete() -> None:
    """CARDINAL: an operator advances on the surface they mapped — one COMPLETE among
    failures is still COMPLETE (route_next then decides Beta-vs-Omega from the graph)."""
    assert derive_terminal_status([a2a_pb2.FAILED, a2a_pb2.COMPLETE]) == a2a_pb2.COMPLETE
    assert derive_terminal_status([a2a_pb2.COMPLETE, a2a_pb2.BLOCKED]) == a2a_pb2.COMPLETE


def test_terminal_status_failed_when_no_target_completes() -> None:
    """CARDINAL (anti-#3): zero COMPLETE — all-failed, all-blocked, or WAF-walled — must
    be FAILED, never a hardcoded COMPLETE that would false-advance the chain to Beta."""
    assert derive_terminal_status([a2a_pb2.FAILED, a2a_pb2.FAILED]) == a2a_pb2.FAILED
    assert derive_terminal_status([a2a_pb2.BLOCKED, a2a_pb2.BLOCKED]) == a2a_pb2.FAILED
    assert derive_terminal_status([a2a_pb2.FAILED, a2a_pb2.BLOCKED]) == a2a_pb2.FAILED


def test_terminal_status_failed_on_empty() -> None:
    """No readable per-target status (stub sweep / zero targets) → FAILED, fail-closed."""
    assert derive_terminal_status([]) == a2a_pb2.FAILED


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
    # 187a: a walled sweep (0 COMPLETE) hands off FAILED, not a hardcoded COMPLETE.
    assert result.status == a2a_pb2.FAILED
    walled = [e for e in store.get_events(eng) if e.event_type == EventType.ENGAGEMENT_WALLED]
    assert len(walled) == 1
    assert _HOST_A in walled[0].payload.get("blocked_hosts", [])


class _NoneReturningAlpha:
    """Fake Alpha whose run_recon returns no handoff (stub) — the sweep must survive it."""

    def run_recon(self, engagement_id: str, target_url: str) -> None:
        return None


def test_none_handoff_does_not_crash_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Greptile P1 regression: a run_recon returning None (stub/contract-loose double) must
    NOT crash the engagement task over the non-critical wall verdict. The sweep completes;
    with no readable status and no WAF this run, the verdict is honestly not-walled."""
    store = InMemoryEventStore()
    eng = _engagement(store)
    auth = AuthorizationStateMachine(event_store=store)

    pipeline = recon_runner.ReconPipeline(
        alpha=_NoneReturningAlpha(), graph_store=NetworkXGraphStore()
    )
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
    assert result.wall_verdict.walled is False
    # 187a: no readable per-target status → FAILED (fail-closed), never COMPLETE.
    assert result.status == a2a_pb2.FAILED


class _CompletingAlpha:
    """Fake Alpha that hands off COMPLETE (recon finished on the target)."""

    def run_recon(self, engagement_id: str, target_url: str) -> a2a_pb2.A2AMessage:
        msg = a2a_pb2.A2AMessage()
        payload = a2a_pb2.HandoffPayload(status=a2a_pb2.COMPLETE, findings_count=1)
        msg.payload = payload.SerializeToString()
        return msg


def test_run_recon_for_engagement_status_complete_when_target_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-regression: a target that finishes recon hands off COMPLETE, so the autonomous
    spine can still advance (route_next → Beta/Omega). 187a must not break the happy path."""
    store = InMemoryEventStore()
    eng = _engagement(store)
    auth = AuthorizationStateMachine(event_store=store)

    pipeline = recon_runner.ReconPipeline(
        alpha=_CompletingAlpha(), graph_store=NetworkXGraphStore()
    )
    monkeypatch.setattr(recon_runner, "build_recon_pipeline", lambda *a, **kw: pipeline)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [f"https://{_HOST_A}/"])
    monkeypatch.setattr(recon_runner, "certspotter_discover", lambda *a, **kw: None)
    monkeypatch.setattr(recon_runner, "build_passive_discovery", lambda *a, **kw: None)
    monkeypatch.setattr(recon_runner, "hackertarget_fallback", lambda *a, **kw: None)
    monkeypatch.setattr(recon_runner, "enrich_with_dns", lambda intel, dns: intel)

    result = recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=object()
    )

    assert result.status == a2a_pb2.COMPLETE

