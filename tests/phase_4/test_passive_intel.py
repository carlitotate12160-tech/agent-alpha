# tests/phase_4/test_passive_intel.py
"""Contract: §12.48 slice-1 — PassiveIntelMap (OSINT-before-touch, crt.sh only).

Two layers:
  * UNIT — build_passive_intel_map maps an EXISTING PassiveDiscoveryResult into
    the map (reuse, no re-parse, anti-#6); slice-2+ fields stay empty (honest
    ungathered data, not scaffold); record_passive_intel emits the event.
  * WIRED-PROOF (§12.35 Rule 2) — PASSIVE_INTEL_GATHERED lands on the REAL
    engagement stream via recon_runner.run_recon_for_engagement, and crt.sh is
    consulted exactly ONCE per host (anti double-recon), and the pre-existing
    PASSIVE_DISCOVERY event + enumerated surface are NOT regressed.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_4/test_passive_intel.py -v
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
from agent_alpha.recon.passive_discovery import PassiveDiscovery, PassiveDiscoveryResult
from agent_alpha.recon.passive_intel import (
    PassiveIntelMap,
    build_passive_intel_map,
    record_passive_intel,
)
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parent.parent / "phase_2" / "fixtures" / "playbooks"


# ── UNIT ──────────────────────────────────────────────────────────────


def test_map_reuses_crtsh_result_no_reparse() -> None:
    """build_passive_intel_map maps the crt.sh result fields 1:1 (anti-#6:
    reuse the already-parsed output, do not re-implement the parser)."""
    result = PassiveDiscoveryResult(
        domain="ex.com",
        discovered=("ex.com", "a.ex.com", "b.ex.com"),
        in_scope=("ex.com", "a.ex.com"),
        enumerated=("b.ex.com",),
    )
    intel = build_passive_intel_map(result)

    assert isinstance(intel, PassiveIntelMap)
    assert intel.domain == "ex.com"
    assert intel.subdomains == ("ex.com", "a.ex.com", "b.ex.com")
    assert intel.in_scope_subdomains == ("ex.com", "a.ex.com")


def test_slice2_fields_are_empty_not_scaffolded() -> None:
    """Ungathered fields are honest empty data (graceful degradation), populated
    only when their named source slice (VT/DNSDumpster) lands — never fabricated."""
    intel = build_passive_intel_map(
        PassiveDiscoveryResult(domain="ex.com", discovered=(), in_scope=(), enumerated=())
    )
    assert intel.origin_ip_candidates == ()
    assert intel.mx_records == ()
    assert intel.txt_records == ()
    assert intel.tech_stack_hints == ()
    assert intel.nameservers == ()
    assert intel.historical_paths == ()
    assert intel.protection_detected is None


def test_record_emits_passive_intel_gathered() -> None:
    """record_passive_intel appends exactly one PASSIVE_INTEL_GATHERED event
    carrying the full map payload."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client", "ex.com")
    eng = rec.engagement_id

    intel = build_passive_intel_map(
        PassiveDiscoveryResult(
            domain="ex.com",
            discovered=("ex.com", "a.ex.com"),
            in_scope=("ex.com",),
            enumerated=("a.ex.com",),
        )
    )
    record_passive_intel(store, eng, intel)

    evs = [e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED]
    assert len(evs) == 1
    payload = evs[0].payload
    assert payload["domain"] == "ex.com"
    assert payload["subdomains"] == ["ex.com", "a.ex.com"]
    assert payload["in_scope_subdomains"] == ["ex.com"]
    assert payload["protection_detected"] is None


def test_frozen_immutable() -> None:
    intel = build_passive_intel_map(
        PassiveDiscoveryResult(domain="ex.com", discovered=(), in_scope=(), enumerated=())
    )
    with pytest.raises((AttributeError, TypeError)):
        intel.domain = "evil.com"  # type: ignore[misc]


# ── WIRED-PROOF (§12.35 Rule 2 — non-island) ──────────────────────────

_ROOT = "lab-target.invalid"
_ADMIN = "admin.lab-target.invalid"  # discovered, NOT in SOW → enumerated
_TARGET_URL = f"https://{_ROOT}"
_CRTSH_JSON = f'[{{"name_value":"{_ROOT}\\n{_ADMIN}"}}]'


class _Resp:
    def __init__(self, status_code: int, text: str, headers: dict[str, str], url: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.url = url


class _ScanHttpClient:
    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        return _Resp(404, "", {}, url)


class _CrtShClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return _Resp(200, _CRTSH_JSON, {}, url)


class _StubProvider:
    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "deepseek-v4-pro"})()


def _fake_pipeline(auth: Any, graph: Any, store: Any) -> Any:
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


def test_passive_intel_gathered_on_live_path_single_crtsh_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WIRED-PROOF: run_recon_for_engagement emits PASSIVE_INTEL_GATHERED on the
    real stream, calls crt.sh exactly once per host (anti double-recon), and does
    NOT regress the pre-existing PASSIVE_DISCOVERY event."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    graph = NetworkXGraphStore()
    crt = _CrtShClient()
    monkeypatch.setattr(
        recon_runner, "build_recon_pipeline", lambda *a, **k: _fake_pipeline(auth, graph, store)
    )
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [_TARGET_URL])
    monkeypatch.setattr(
        recon_runner,
        "build_passive_discovery",
        lambda *a, **k: PassiveDiscovery(http_client=crt, authorization=auth, event_store=store),
    )

    recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec
    )

    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    disc_evs = [e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_DISCOVERY]
    assert len(intel_evs) == 1, "PASSIVE_INTEL_GATHERED not on the live stream — island (#2)"
    assert len(disc_evs) == 1, "PASSIVE_DISCOVERY regressed"
    # anti double-recon: exactly one crt.sh GET for the one host.
    assert len(crt.calls) == 1, f"crt.sh called {len(crt.calls)}x — double-recon regression"
    # intel event carries the crt.sh-derived surface.
    assert intel_evs[0].payload["in_scope_subdomains"] == [_ROOT]

    # ordering (§12.48): passive intel appended before any active recon event.
    seqs_intel = intel_evs[0].sequence_number
    active = [
        e
        for e in store.get_events(eng)
        if e.event_type not in (EventType.PASSIVE_DISCOVERY, EventType.PASSIVE_INTEL_GATHERED)
        and e.agent == "alpha"
    ]
    if active:
        assert seqs_intel < min(e.sequence_number for e in active), (
            "PASSIVE_INTEL_GATHERED not appended before active recon events (§12.48)"
        )


# ══════════════════════════════════════════════════════════════════════
# §12.48 slice-2 — keyless crt.sh → HackerTarget fallback
# ══════════════════════════════════════════════════════════════════════

from agent_alpha.recon.osint_sources import parse_hackertarget_hosts  # noqa: E402
from agent_alpha.recon.passive_intel import hackertarget_fallback  # noqa: E402

_HT_CSV = "ex.com,1.2.3.4\napi.ex.com,1.2.3.5\nvpn.other.com,9.9.9.9\n"


# ── UNIT: HackerTarget parser ─────────────────────────────────────────


def test_hackertarget_parser_domain_filtered() -> None:
    names = parse_hackertarget_hosts(_HT_CSV, "ex.com")
    assert names == ["api.ex.com", "ex.com"]  # sorted, deduped, other.com dropped


def test_hackertarget_parser_error_body_is_empty() -> None:
    # HackerTarget returns a plaintext error/marker instead of rows → treat as no data.
    assert parse_hackertarget_hosts("error invalid host", "ex.com") == []
    assert parse_hackertarget_hosts("API count exceeded", "ex.com") == []
    assert parse_hackertarget_hosts("", "ex.com") == []


class _HtHttp:
    def __init__(self, body: str) -> None:
        self._body = body
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return _Resp(200, self._body, {}, url)


class _BoomHttp:
    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        raise RuntimeError("hackertarget down")


def test_fallback_partitions_via_auth_gate() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client", "ex.com")
    # scope = root + api.ex.com only; vpn.other.com is out of scope.
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=["ex.com", "api.ex.com"], exclusions=[]),
    )
    res = hackertarget_fallback(
        rec.engagement_id, "ex.com", http_client=_HtHttp(_HT_CSV), authorization=auth
    )
    assert set(res.in_scope) == {"ex.com", "api.ex.com"}
    assert res.enumerated == ()  # other.com was domain-filtered out by the parser


def test_fallback_fail_closed_when_recon_not_authorized() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client", "ex.com")  # created, RECON not enabled
    ht = _HtHttp(_HT_CSV)
    res = hackertarget_fallback(rec.engagement_id, "ex.com", http_client=ht, authorization=auth)
    assert res.discovered == () and ht.calls == []  # no network before the gate passes


def test_fallback_is_fail_open_on_transport_error() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client", "ex.com")
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=["ex.com"], exclusions=[]))
    res = hackertarget_fallback(
        rec.engagement_id, "ex.com", http_client=_BoomHttp(), authorization=auth
    )
    assert res.discovered == ()  # transport blew up → empty, no raise


# ── WIRED-PROOF: fallback triggers on crt.sh-empty, not on crt.sh-hit ──


class _EmptyCrtSh:
    """crt.sh reachable but returns no rows (rate-limit/503 body) → parse == []."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return _Resp(200, "[]", {}, url)


def _wire(monkeypatch: pytest.MonkeyPatch, auth: Any, store: Any, crt: Any, ht_http: Any) -> None:
    graph = NetworkXGraphStore()
    monkeypatch.setattr(
        recon_runner, "build_recon_pipeline", lambda *a, **k: _fake_pipeline(auth, graph, store)
    )
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [_TARGET_URL])
    monkeypatch.setattr(
        recon_runner,
        "build_passive_discovery",
        lambda *a, **k: PassiveDiscovery(http_client=crt, authorization=auth, event_store=store),
    )
    monkeypatch.setattr(recon_runner, "build_osint_http_client", lambda *a, **k: ht_http)


def test_fallback_fires_on_live_path_when_crtsh_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    crt = _EmptyCrtSh()
    ht_http = _HtHttp(f"{_ROOT},1.2.3.4\n")  # HackerTarget finds the in-scope root
    _wire(monkeypatch, auth, store, crt, ht_http)

    recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec
    )

    assert len(crt.calls) == 1, "crt.sh should be tried once"
    assert len(ht_http.calls) == 1, "HackerTarget fallback should fire when crt.sh empty"
    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1
    assert intel_evs[0].payload["sources_used"] == ["hackertarget"]
    assert intel_evs[0].payload["in_scope_subdomains"] == [_ROOT]


def test_no_fallback_when_crtsh_has_results(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    crt = _CrtShClient()  # returns the root → non-empty
    ht_http = _HtHttp(f"{_ROOT},1.2.3.4\n")
    _wire(monkeypatch, auth, store, crt, ht_http)

    recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec
    )

    assert ht_http.calls == [], "HackerTarget must NOT be called when crt.sh already has names"
    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert intel_evs[0].payload["sources_used"] == ["crtsh"]


class _DownCrtSh:
    """crt.sh unreachable — .get raises (connection refused / timeout)."""

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        raise RuntimeError("crt.sh unreachable")


def test_fallback_fires_when_crtsh_down(monkeypatch: pytest.MonkeyPatch) -> None:
    """§12.48 slice-2 (bug-fix): crt.sh DOWN (exception → result is None) must ALSO
    trigger the HackerTarget fallback — not only the reachable-but-empty case. This
    is the headline resilience scenario (crt.sh outage)."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    ht_http = _HtHttp(f"{_ROOT},1.2.3.4\n")  # HackerTarget still finds the in-scope root
    _wire(monkeypatch, auth, store, _DownCrtSh(), ht_http)

    recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec
    )

    assert len(ht_http.calls) == 1, "HackerTarget must fire when crt.sh is DOWN (exception)"
    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1
    assert intel_evs[0].payload["sources_used"] == ["hackertarget"]
    assert intel_evs[0].payload["in_scope_subdomains"] == [_ROOT]
    # crt.sh raised BEFORE emitting its own event → no PASSIVE_DISCOVERY, only intel.
    assert [e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_DISCOVERY] == []


def test_fallback_down_both_fail_is_non_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    """crt.sh down AND HackerTarget empty → engagement still completes, no crash,
    no intel event with a surface (fail-open end-to-end)."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    _wire(monkeypatch, auth, store, _DownCrtSh(), _HtHttp(""))  # HT returns empty body

    result = recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec
    )
    assert result is not None and result.report is not None
    assert tuple(result.enumerated_hosts) == ()
