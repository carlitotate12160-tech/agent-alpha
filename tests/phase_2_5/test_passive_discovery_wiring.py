# tests/phase_2_5/test_passive_discovery_wiring.py
"""Contract: R2 slice-1b — PassiveDiscovery is WIRED into the Conductor live recon
path (recon_runner.run_recon_for_engagement), not an island (anti-Lyndon #2).

Slice-1 shipped passive_discovery.py + 10 unit tests (#129/#130), but grep on prod
shows ZERO live callers -> the module is dead code. Slice-1b stitches it in so that,
per engagement: crt.sh is consulted, the PASSIVE_DISCOVERY audit event lands on the
REAL event stream, and the enumerated (found-not-probed) surface is CONSUMED
(surfaced on ReconRunResult) rather than emitted into the void.

Design (ADR §7 / slice-1b):
  - New module seam recon_runner.build_passive_discovery(engagement_id, auth, store)
    -> PassiveDiscovery  (monkeypatchable, mirrors build_recon_pipeline).
  - run_recon_for_engagement: for each in-scope root host (derived from the resolved
    targets), call discover() FAIL-OPEN — crt.sh being down must NOT break the
    engagement (auth stays fail-closed) — and aggregate result.enumerated into a new
    ReconRunResult.enumerated_hosts field.
  - seed_frontier_from_passive is DELIBERATELY NOT wired here: under exact-host scope
    its in_scope hosts are already resolve_recon_targets() targets (a no-op). It
    becomes live at R2 slice-2 (wildcard).

RED until slice-1b lands: recon_runner has no build_passive_discovery seam, and
ReconRunResult has no enumerated_hosts field.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_passive_discovery_wiring.py -v
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.passive_discovery import PassiveDiscovery
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parent.parent / "phase_2" / "fixtures" / "playbooks"

_ROOT = "lab-target.invalid"
_ADMIN = "admin.lab-target.invalid"  # discovered subdomain, NOT in SOW -> enumerated
_CDN = "cdn.lab-target.invalid"  # discovered subdomain, NOT in SOW -> enumerated
_TARGET_URL = f"https://{_ROOT}"

_CRTSH_JSON = f'[{{"name_value":"{_ROOT}\\n{_ADMIN}"}},{{"name_value":"{_CDN}"}}]'


class _StubProvider:
    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "deepseek-v4-pro"})()


class _Resp:
    def __init__(self, status_code: int, text: str, headers: dict[str, str], url: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.url = url


class _ScanHttpClient:
    """Alpha's target-facing client — no real network; irrelevant to this wiring test."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return _Resp(404, "", {}, url)


class _CrtShClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return _Resp(200, _CRTSH_JSON, {}, url)


class _BoomCrtShClient:
    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        raise RuntimeError("crt.sh unreachable")


def _setup(store: InMemoryEventStore) -> tuple[AuthorizationStateMachine, str, Any]:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    return auth, rec.engagement_id, rec


def _fake_pipeline(
    auth: AuthorizationStateMachine, graph: NetworkXGraphStore, store: InMemoryEventStore
) -> Any:
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR), provider=_StubProvider()
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph,
        event_store=store,
        orchestrator=orch,
        http_client=_ScanHttpClient(),
    )
    return recon_runner.ReconPipeline(alpha=alpha, graph_store=graph)


def _wire_common(
    monkeypatch: pytest.MonkeyPatch,
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
    crt_client: Any,
) -> dict[str, int]:
    graph = NetworkXGraphStore()
    monkeypatch.setattr(
        recon_runner, "build_recon_pipeline", lambda *a, **k: _fake_pipeline(auth, graph, store)
    )
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [_TARGET_URL])
    called = {"n": 0}

    def _build_pd(*a: object, **k: object) -> PassiveDiscovery:
        called["n"] += 1
        return PassiveDiscovery(http_client=crt_client, authorization=auth, event_store=store)

    # raising=False: the seam does not exist yet (RED) — set it so the assertions,
    # not an AttributeError at setattr time, are what fail.
    monkeypatch.setattr(recon_runner, "build_passive_discovery", _build_pd, raising=False)
    return called


def test_wired_discovery_emits_event_and_surfaces_enumerated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryEventStore()
    auth, eng, rec = _setup(store)
    called = _wire_common(monkeypatch, auth, store, _CrtShClient())

    result = recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec
    )

    # W1 dead-seam: the live path actually invoked the discovery seam (not an island).
    assert called["n"] >= 1, (
        "run_recon_for_engagement never called build_passive_discovery — module still an island (#2)"
    )
    # W2 audit event on the REAL engagement stream.
    evs = [e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_DISCOVERY]
    assert len(evs) >= 1, "no PASSIVE_DISCOVERY event on the engagement stream — discovery not live"
    # W3 enumerated surface is CONSUMED (reaches the result), not emitted into the void.
    assert set(result.enumerated_hosts) == {_ADMIN, _CDN}


def test_discovery_failure_is_non_fatal_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryEventStore()
    auth, eng, rec = _setup(store)
    _wire_common(monkeypatch, auth, store, _BoomCrtShClient())

    # crt.sh blows up — the engagement recon + report MUST still complete (fail-open OSINT).
    result = recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec
    )

    assert result is not None and result.report is not None, (
        "a crt.sh failure aborted the whole engagement — OSINT must be fail-open"
    )
    assert tuple(result.enumerated_hosts) == ()  # no surface, but no crash
