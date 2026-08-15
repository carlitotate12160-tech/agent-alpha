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
from agent_alpha.recon.osint_sources import parse_wayback_cdx
from agent_alpha.recon.passive_discovery import PassiveDiscovery, PassiveDiscoveryResult
from agent_alpha.recon.passive_intel import (
    PassiveIntelMap,
    build_passive_intel_map,
    enrich_with_wayback,
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


class _NullDNS:
    """No-op DNS resolver for slice-1/2 WIRED tests that don't exercise slice-3.
    Prevents the default DnspythonResolver from making real lab-target.invalid
    lookups (test isolation, CodeRabbit #357-6). resolve_* all fail-open to []."""

    def resolve_mx(self, domain: str) -> list[str]:
        return []

    def resolve_ns(self, domain: str) -> list[str]:
        return []

    def resolve_txt(self, domain: str) -> list[str]:
        return []


_NULL_DNS = _NullDNS()


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
    # CertSpotter primary returns empty here → chain falls to crt.sh (asserted below).
    monkeypatch.setattr(
        recon_runner,
        "certspotter_discover",
        lambda eid, host, **k: PassiveDiscoveryResult(host, (), (), ()),
    )
    monkeypatch.setattr(recon_runner, "build_osint_http_client", lambda *a, **k: _ScanHttpClient())

    recon_runner.run_recon_for_engagement(
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
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


def test_hackertarget_parser_error_subdomain_not_dropped() -> None:
    # A valid hostname like error.ex.com must NOT be dropped just because the
    # "error" marker appears as a substring — the marker check is first-line only.
    body = "error.ex.com,1.2.3.4\napi.ex.com,1.2.3.5\n"
    assert parse_hackertarget_hosts(body, "ex.com") == ["api.ex.com", "error.ex.com"]


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
    # CertSpotter is now the primary CT source; return empty so the slice-1/2
    # chain falls through to crt.sh/HackerTarget exactly as these tests assert.
    monkeypatch.setattr(
        recon_runner,
        "certspotter_discover",
        lambda eid, host, **k: PassiveDiscoveryResult(host, (), (), ()),
    )


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
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
    )

    assert len(crt.calls) == 1, "crt.sh should be tried once"
    assert len(ht_http.calls) == 1, "HackerTarget fallback should fire when crt.sh empty"
    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1
    assert intel_evs[0].payload["sources_used"] == ["hackertarget", "dns"]
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
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
    )

    assert ht_http.calls == [], "HackerTarget must NOT be called when crt.sh already has names"
    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert intel_evs[0].payload["sources_used"] == ["crtsh", "dns"]


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
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
    )

    assert len(ht_http.calls) == 1, "HackerTarget must fire when crt.sh is DOWN (exception)"
    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1
    assert intel_evs[0].payload["sources_used"] == ["hackertarget", "dns"]
    assert intel_evs[0].payload["in_scope_subdomains"] == [_ROOT]
    # crt.sh raised BEFORE emitting its own event → no PASSIVE_DISCOVERY, only intel.
    assert [e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_DISCOVERY] == []


def test_fallback_down_both_fail_is_non_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    """crt.sh down AND HackerTarget empty → engagement still completes, no crash.

    GAP-154: enrichment no longer depends on the CT surface — on total CT failure a
    PASSIVE_INTEL_GATHERED event STILL fires (anti-#3: recorded honestly, never a
    silent skip), but with an EMPTY surface here because DNS is null and no MX/SPF/
    Wayback data exists. sources_used == ["dns"] (CT contributed nothing, DNS ran)."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    _wire(monkeypatch, auth, store, _DownCrtSh(), _HtHttp(""))  # HT returns empty body

    result = recon_runner.run_recon_for_engagement(
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
    )
    assert result is not None and result.report is not None
    assert tuple(result.enumerated_hosts) == ()

    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1, "GAP-154: intel event fires even on total CT failure (anti-#3)"
    assert intel_evs[0].payload["sources_used"] == ["dns"], "no CT source contributed; DNS ran"
    assert intel_evs[0].payload["subdomains"] == []
    assert intel_evs[0].payload["in_scope_subdomains"] == []
    assert intel_evs[0].payload["origin_ip_candidates"] == []


def test_enrichment_runs_on_total_ct_failure_with_dns_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GAP-154 headline: EVERY CT source down/empty (result is None) must NOT disable
    DNS/MX/SPF enrichment. With SPF declaring an origin IP, the emitted intel event
    carries that origin candidate — proving enrichment is no longer gated on CT."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    # Total CT failure: CertSpotter empty (via _wire), crt.sh DOWN, HackerTarget empty.
    _wire(monkeypatch, auth, store, _DownCrtSh(), _HtHttp(""))

    # DNS DOES resolve: SPF declares the origin's own /32, MX is an in-domain mail host.
    dns = _StubDNS(
        mx=["10 mail.lab-target.invalid."],
        txt=["v=spf1 ip4:203.0.113.7 -all"],
    )

    recon_runner.run_recon_for_engagement(
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=dns,
    )

    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1, "intel event must fire on total CT failure"
    payload = intel_evs[0].payload
    # SPF ip4 → origin candidate; in-domain MX → subdomain candidate. Both derived with
    # ZERO CT surface — the gate-fix delivered origin discovery a CT outage used to kill.
    assert "203.0.113.7" in payload["origin_ip_candidates"]
    assert "mail.lab-target.invalid" in payload["subdomains"]
    assert "dns" in payload["sources_used"] and "mx_spf" in payload["sources_used"]
    assert "crtsh" not in payload["sources_used"]
    assert "hackertarget" not in payload["sources_used"]


# ══════════════════════════════════════════════════════════════════════
# §12.48 slice-3 — DNS enrichment (MX/NS/TXT → protection posture)
# ══════════════════════════════════════════════════════════════════════

from agent_alpha.recon.passive_intel import (  # noqa: E402
    classify_protection,
    enrich_with_dns,
)


class _StubDNS:
    """Injectable PassiveDNSResolver stub returning canned, DISTINCTIVE records.

    Distinctive values (not just non-empty) so a passing WIRED assertion can ONLY
    be satisfied by enrich_with_dns actually running on the live path — closes the
    #3 hole where 'is not None' would pass from any source.
    """

    def __init__(
        self,
        mx: list[str] | None = None,
        ns: list[str] | None = None,
        txt: list[str] | None = None,
    ) -> None:
        self._mx = mx or []
        self._ns = ns or []
        self._txt = txt or []

    def resolve_mx(self, domain: str) -> list[str]:
        return list(self._mx)

    def resolve_ns(self, domain: str) -> list[str]:
        return list(self._ns)

    def resolve_txt(self, domain: str) -> list[str]:
        return list(self._txt)


# ── UNIT: protection classifier (keyless, deterministic, LLM-free) ────


def test_classify_protection_cloudflare_ns_subdomain() -> None:
    assert classify_protection(("dana.ns.cloudflare.com", "kip.ns.cloudflare.com")) == "cloudflare"


def test_classify_protection_akamai_and_sucuri() -> None:
    assert classify_protection(("a1-2.akam.net",)) == "akamai"
    assert classify_protection(("ns1.sucuri.net",)) == "sucuri"


def test_classify_protection_self_hosted_is_none() -> None:
    assert classify_protection(("ns1.self-hosted.example", "ns2.self-hosted.example")) is None
    assert classify_protection(()) is None


# ── UNIT: enrich fills DNS fields, preserves slice-1, frozen ──────────


def test_enrich_fills_dns_and_preserves_slice1() -> None:
    base = build_passive_intel_map(
        PassiveDiscoveryResult(
            domain="ex.com",
            discovered=("ex.com", "a.ex.com"),
            in_scope=("ex.com",),
            enumerated=("a.ex.com",),
        )
    )
    out = enrich_with_dns(
        base,
        _StubDNS(
            mx=["mail.ex.com"],
            ns=["dana.ns.cloudflare.com"],
            txt=["v=spf1 -all"],
        ),
    )
    # DNS fields filled
    assert out.mx_records == ("mail.ex.com",)
    assert out.nameservers == ("dana.ns.cloudflare.com",)
    assert out.txt_records == ("v=spf1 -all",)
    assert out.protection_detected == "cloudflare"
    # slice-1 fields preserved verbatim (additive, anti-#10)
    assert out.subdomains == ("ex.com", "a.ex.com")
    assert out.in_scope_subdomains == ("ex.com",)
    # returned a NEW frozen object (replace, not mutate)
    assert out is not base
    with pytest.raises((AttributeError, TypeError)):
        out.protection_detected = "akamai"  # type: ignore[misc]


def test_enrich_fail_open_empty_resolver() -> None:
    base = build_passive_intel_map(
        PassiveDiscoveryResult(
            domain="ex.com", discovered=("ex.com",), in_scope=("ex.com",), enumerated=()
        )
    )
    out = enrich_with_dns(base, _StubDNS())  # all lookups return []
    assert out.mx_records == ()
    assert out.nameservers == ()
    assert out.txt_records == ()
    assert out.protection_detected is None  # no raise, honest empty signal


# ── WIRED-PROOF (§12.35 Rule 2 — non-island): DNS signal on the live path ──


def test_dns_signal_on_live_path_via_injected_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_recon_for_engagement, given an injected stub resolver, records the DNS
    signal in the PASSIVE_INTEL_GATHERED payload — proving enrich_with_dns runs on
    the AUTONOMOUS Conductor path, not as an island (#2). Distinctive stub values
    make the assertion unforgeable (#3); crt.sh-once guards double-recon (no
    slice-1/2 regression)."""
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

    stub = _StubDNS(
        mx=["mail.lab-target.invalid"],
        ns=["dana.ns.cloudflare.com", "kip.ns.cloudflare.com"],
        txt=["v=spf1 -all"],
    )
    recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec, dns_resolver=stub
    )

    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1, "PASSIVE_INTEL_GATHERED not on the live stream — island (#2)"
    payload = intel_evs[0].payload
    # DNS signal reached the live event via the injected resolver (unforgeable values)
    assert payload["nameservers"] == ["dana.ns.cloudflare.com", "kip.ns.cloudflare.com"]
    assert payload["protection_detected"] == "cloudflare"
    assert payload["mx_records"] == ["mail.lab-target.invalid"]
    assert payload["txt_records"] == ["v=spf1 -all"]
    assert "dns" in payload["sources_used"]
    # anti double-recon: crt.sh still exactly once (slice-1/2 not regressed)
    assert len(crt.calls) == 1, f"crt.sh called {len(crt.calls)}x — double-recon regression"
    assert payload["in_scope_subdomains"] == [_ROOT]


# ══════════════════════════════════════════════════════════════════════
# §12.48 slice-4 — CertSpotter primary CT source (crt.sh demoted to fallback)
# ══════════════════════════════════════════════════════════════════════

from agent_alpha.recon.osint_sources import (  # noqa: E402
    fetch_certspotter_subdomains,
    parse_certspotter_names,
)
from agent_alpha.recon.passive_intel import certspotter_discover  # noqa: E402

_CS_JSON = f'[{{"dns_names":["{_ROOT}","{_ADMIN}","*.{_ROOT}"]}}]'


class _CsHttp:
    """CertSpotter stub — records the Authorization header + returns canned JSON."""

    def __init__(self, body: str) -> None:
        self._body = body
        self.last_headers: dict[str, str] | None = None
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None, **k: object) -> _Resp:
        self.calls.append(url)
        self.last_headers = headers
        return _Resp(200, self._body, {}, url)


class _CsBoom:
    def get(self, url: str, *, headers: dict[str, str] | None = None, **k: object) -> _Resp:
        raise RuntimeError("certspotter down")


# ── UNIT: parser ──────────────────────────────────────────────────────


def test_parse_certspotter_names_domain_filtered_dedup_wildcard() -> None:
    body = '[{"dns_names":["ex.com","a.ex.com","*.ex.com","vpn.other.com"]}]'
    # *.ex.com -> ex.com (dedup); other.com dropped; sorted.
    assert parse_certspotter_names(body, "ex.com") == ["a.ex.com", "ex.com"]


def test_parse_certspotter_error_object_is_empty() -> None:
    # CertSpotter returns an OBJECT (not array) on error/rate-limit → no data.
    assert parse_certspotter_names('{"message":"rate limited"}', "ex.com") == []
    assert parse_certspotter_names("", "ex.com") == []


# ── UNIT: fetch (bearer key + fail-open) ──────────────────────────────


def test_fetch_certspotter_sends_bearer_when_key_present() -> None:
    http = _CsHttp('[{"dns_names":["ex.com"]}]')
    names = fetch_certspotter_subdomains("ex.com", http_client=http, api_key="SECRET_K")
    assert names == ["ex.com"]
    assert http.last_headers == {"Authorization": "Bearer SECRET_K"}


def test_fetch_certspotter_keyless_no_auth_header() -> None:
    http = _CsHttp('[{"dns_names":["ex.com"]}]')
    fetch_certspotter_subdomains("ex.com", http_client=http, api_key=None)
    assert http.last_headers is None


def test_fetch_certspotter_fail_open_on_transport_error() -> None:
    assert fetch_certspotter_subdomains("ex.com", http_client=_CsBoom()) == []


# ── UNIT: certspotter_discover gate + partition ───────────────────────


def test_certspotter_discover_partitions_via_auth_gate() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client", "ex.com")
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=["ex.com"], exclusions=[]))
    body = '[{"dns_names":["ex.com","admin.ex.com"]}]'  # admin not in SOW -> enumerated
    res = certspotter_discover(
        rec.engagement_id, "ex.com", http_client=_CsHttp(body), authorization=auth
    )
    assert res.in_scope == ("ex.com",)
    assert res.enumerated == ("admin.ex.com",)


def test_certspotter_discover_fail_closed_when_not_authorized() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client", "ex.com")  # RECON not enabled
    http = _CsHttp('[{"dns_names":["ex.com"]}]')
    res = certspotter_discover(rec.engagement_id, "ex.com", http_client=http, authorization=auth)
    assert res.discovered == () and http.calls == []  # no network before gate passes


# ── WIRED-PROOF (§12.35 Rule 2): CertSpotter wins primary on the live path ──


def test_certspotter_primary_wins_on_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_recon_for_engagement uses CertSpotter FIRST; when it yields a surface,
    crt.sh is NOT called (primary wins, quota conserved) and PASSIVE_INTEL_GATHERED
    records sources_used == ['certspotter']. Real certspotter_discover on the
    autonomous path (non-island, #2); crt.sh-not-called proves the reorder."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _ROOT)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_ROOT], exclusions=[]))
    eng = rec.engagement_id

    graph = NetworkXGraphStore()
    crt = _CrtShClient()  # must NOT be called
    monkeypatch.setattr(
        recon_runner, "build_recon_pipeline", lambda *a, **k: _fake_pipeline(auth, graph, store)
    )
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [_TARGET_URL])
    monkeypatch.setattr(
        recon_runner,
        "build_passive_discovery",
        lambda *a, **k: PassiveDiscovery(http_client=crt, authorization=auth, event_store=store),
    )
    # CertSpotter primary client returns the CT surface (real certspotter_discover runs).
    monkeypatch.setattr(recon_runner, "build_osint_http_client", lambda *a, **k: _CsHttp(_CS_JSON))

    recon_runner.run_recon_for_engagement(
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
    )

    intel_evs = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ]
    assert len(intel_evs) == 1
    payload = intel_evs[0].payload
    assert payload["sources_used"] == ["certspotter", "dns"]  # CertSpotter won; DNS enrich appended
    assert payload["in_scope_subdomains"] == [_ROOT]
    assert crt.calls == [], "crt.sh must NOT be called when CertSpotter (primary) has hits"


# ══════════════════════════════════════════════════════════════════════
# §12.48 slice-5 — OTX enrichment (origin-IP candidates + historical paths)
# ══════════════════════════════════════════════════════════════════════

from agent_alpha.recon.osint_sources import (  # noqa: E402
    OtxClient,
    parse_otx_historical_paths,
    parse_otx_origin_ips,
)
from agent_alpha.recon.passive_intel import enrich_with_otx  # noqa: E402

# NOTE: real global IPs — RFC-5737 doc ranges (203.0.113.x etc.) are is_global=False
# and would be (correctly) filtered out, so they can't be used as "kept" fixtures.
_OTX_PDNS = (
    '{"passive_dns":[{"hostname":"a.ex.com","address":"45.33.32.156"},'
    '{"hostname":"b.ex.com","address":"10.0.0.5"}]}'
)  # 10.x is private → dropped
_OTX_URLS = (
    '{"url_list":[{"url":"https://ex.com/wp-login.php",'
    '"result":{"urlworker":{"ip":"159.65.10.20"}}},'
    '{"url":"https://ex.com/","result":{"urlworker":{"ip":"127.0.0.1"}}}]}'
)  # loopback dropped, "/" path dropped


class _OtxHttp:
    def __init__(self, pdns: str, urls: str) -> None:
        self._pdns, self._urls = pdns, urls
        self.last_headers: dict[str, str] | None = None
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None, **k: object) -> _Resp:
        self.calls.append(url)
        self.last_headers = headers
        body = self._pdns if "passive_dns" in url else self._urls
        return _Resp(200, body, {}, url)


# ── UNIT: parsers (public-IP filter, path extraction) ─────────────────


def test_parse_otx_origin_ips_public_only_deduped() -> None:
    ips = parse_otx_origin_ips(_OTX_PDNS, _OTX_URLS)
    # 203.0.113.10 (pdns) + 198.51.100.7 (urlworker); private 10.x + loopback dropped.
    assert ips == ["159.65.10.20", "45.33.32.156"]


def test_parse_otx_origin_ips_fail_open_on_garbage() -> None:
    assert parse_otx_origin_ips("not json", "{}") == []


def test_parse_otx_historical_paths_excludes_root() -> None:
    assert parse_otx_historical_paths(_OTX_URLS) == ["/wp-login.php"]  # "/" dropped


# ── UNIT: OtxClient (header + fail-open) ──────────────────────────────


def test_otx_client_sends_key_header_and_returns_ips_paths() -> None:
    http = _OtxHttp(_OTX_PDNS, _OTX_URLS)
    ips, paths = OtxClient(http, "OTX_K").origin_ips_and_paths("ex.com")
    assert ips == ("159.65.10.20", "45.33.32.156")
    assert paths == ("/wp-login.php",)
    assert http.last_headers == {"X-OTX-API-KEY": "OTX_K"}


# ── UNIT: enrich_with_otx (additive, preserves slice-1/3) ─────────────


class _StubOtx:
    def __init__(self, ips: tuple[str, ...], paths: tuple[str, ...]) -> None:
        self._ips, self._paths = ips, paths

    def origin_ips_and_paths(self, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return self._ips, self._paths


def test_enrich_with_otx_fills_and_preserves() -> None:
    base = build_passive_intel_map(
        PassiveDiscoveryResult("ex.com", ("ex.com", "a.ex.com"), ("ex.com",), ("a.ex.com",))
    )
    out = enrich_with_otx(base, _StubOtx(("203.0.113.10",), ("/wp-login.php",)))
    assert out.origin_ip_candidates == ("203.0.113.10",)
    assert out.historical_paths == ("/wp-login.php",)
    # slice-1 fields preserved
    assert out.in_scope_subdomains == ("ex.com",)
    assert out is not base
    with pytest.raises((AttributeError, TypeError)):
        out.origin_ip_candidates = ()  # type: ignore[misc]


# ── WIRED-PROOF (§12.35 Rule 2): OTX enrichment on the live path ──────


def test_otx_enrichment_on_live_path_via_injected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_recon_for_engagement, given an injected OTX client, records origin-IP
    candidates + historical paths + 'otx' in sources_used on the live event —
    proving enrich_with_otx runs on the autonomous path (non-island, #2)."""
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
    monkeypatch.setattr(
        recon_runner,
        "certspotter_discover",
        lambda eid, host, **k: PassiveDiscoveryResult(host, (), (), ()),
    )
    monkeypatch.setattr(recon_runner, "build_osint_http_client", lambda *a, **k: _ScanHttpClient())

    otx = _StubOtx(("203.0.113.10",), ("/wp-login.php",))
    recon_runner.run_recon_for_engagement(
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
        otx_client=otx,
    )

    payload = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ][0].payload
    assert payload["origin_ip_candidates"] == ["203.0.113.10"]
    assert payload["historical_paths"] == ["/wp-login.php"]
    assert "otx" in payload["sources_used"]


# ══════════════════════════════════════════════════════════════════════
# §12.48 slice-2 (VT) — VirusTotal enrichment (origin IPs + subdomains)
# ══════════════════════════════════════════════════════════════════════

from agent_alpha.recon.osint_sources import (  # noqa: E402
    VirusTotalClient,
    parse_vt_origin_ips,
    parse_vt_subdomains,
)
from agent_alpha.recon.passive_intel import enrich_with_virustotal  # noqa: E402

# VT v3 resolutions body — id format is "<ip><host>" concatenation
_VT_RESOLUTIONS = (
    '{"data":['
    '{"id":"157.230.37.62quantum-laboratories.com","attributes":{"date":1646373277}},'
    '{"id":"104.21.31.151quantum-laboratories.com","attributes":{"date":1781671663}},'
    '{"id":"10.0.0.5internal.example.com","attributes":{"date":1600000000}}'
    "]}"
)  # 10.x is private → dropped
_VT_SUBDOMAINS = (
    '{"data":['
    '{"id":"qs.quantum-laboratories.com","type":"subdomain"},'
    '{"id":"erpdev.quantum-laboratories.com","type":"subdomain"},'
    '{"id":"evil.other.com","type":"subdomain"},'
    '{"id":"quantum-laboratories.com","type":"subdomain"}'
    "]}"
)  # evil.other.com is NOT a subdomain of quantum-laboratories.com → dropped


class _VtHttp:
    def __init__(self, resols: str, subs: str) -> None:
        self._resols, self._subs = resols, subs
        self.last_headers: dict[str, str] | None = None
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None, **k: object) -> _Resp:
        self.calls.append(url)
        self.last_headers = headers
        body = self._resols if "resolutions" in url else self._subs
        return _Resp(200, body, {}, url)


# ── UNIT: parsers ─────────────────────────────────────────────────────


def test_parse_vt_origin_ips_extracts_public_only() -> None:
    ips = parse_vt_origin_ips(_VT_RESOLUTIONS)
    # 157.230.37.62 extracted from id prefix; 104.21.31.151 is CF but still public
    # (parser does NOT filter CF — that's origin_resolver's job); 10.x dropped.
    assert "157.230.37.62" in ips
    assert "104.21.31.151" in ips
    assert "10.0.0.5" not in ips


def test_parse_vt_origin_ips_fail_open_on_garbage() -> None:
    assert parse_vt_origin_ips("not json") == []


def test_parse_vt_subdomains_filters_to_base_domain() -> None:
    subs = parse_vt_subdomains(_VT_SUBDOMAINS, "quantum-laboratories.com")
    assert "qs.quantum-laboratories.com" in subs
    assert "erpdev.quantum-laboratories.com" in subs
    assert "quantum-laboratories.com" in subs
    assert "evil.other.com" not in subs


def test_parse_vt_subdomains_fail_open_on_garbage() -> None:
    assert parse_vt_subdomains("not json", "ex.com") == []


# ── UNIT: VirusTotalClient (header + fail-open) ───────────────────────


def test_vt_client_sends_key_header_and_returns_ips_subs() -> None:
    http = _VtHttp(_VT_RESOLUTIONS, _VT_SUBDOMAINS)
    ips, subs = VirusTotalClient(http, "VT_K").origin_ips_and_subdomains("quantum-laboratories.com")
    assert "157.230.37.62" in ips
    assert "qs.quantum-laboratories.com" in subs
    assert http.last_headers == {"x-apikey": "VT_K"}


# ── UNIT: enrich_with_virustotal (additive, unions with OTX, preserves) ─


class _StubVt:
    def __init__(self, ips: tuple[str, ...], subs: tuple[str, ...]) -> None:
        self._ips, self._subs = ips, subs

    def origin_ips_and_subdomains(self, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return self._ips, self._subs


def test_enrich_with_virustotal_unions_ips_and_subs() -> None:
    base = build_passive_intel_map(
        PassiveDiscoveryResult(
            "ex.com",
            ("ex.com", "a.ex.com"),
            ("ex.com",),
            ("a.ex.com",),
        )
    )
    # Simulate OTX already filled origin_ip_candidates
    from agent_alpha.recon.passive_intel import enrich_with_otx

    otx_filled = enrich_with_otx(base, _StubOtx(("45.33.32.156",), ("/wp-login.php",)))
    # VT adds a NEW IP + a NEW subdomain
    out = enrich_with_virustotal(otx_filled, _StubVt(("157.230.37.62",), ("qs.ex.com",)))
    # Origin IPs unioned (OTX + VT, deduped)
    assert "45.33.32.156" in out.origin_ip_candidates
    assert "157.230.37.62" in out.origin_ip_candidates
    # Subdomains unioned (crt.sh + VT, deduped)
    assert "a.ex.com" in out.subdomains
    assert "qs.ex.com" in out.subdomains
    # slice-1 fields preserved
    assert out.in_scope_subdomains == ("ex.com",)
    # OTX historical_paths preserved (not overwritten by VT)
    assert out.historical_paths == ("/wp-login.php",)
    assert out is not otx_filled


def test_enrich_with_virustotal_dedupes_existing_ips() -> None:
    base = build_passive_intel_map(PassiveDiscoveryResult("ex.com", ("ex.com",), ("ex.com",), ()))
    otx_filled = enrich_with_otx(base, _StubOtx(("157.230.37.62",), ()))
    # VT returns the SAME IP — must not duplicate
    out = enrich_with_virustotal(otx_filled, _StubVt(("157.230.37.62",), ()))
    assert out.origin_ip_candidates.count("157.230.37.62") == 1


# ── WIRED-PROOF (§12.35 Rule 2): VT enrichment on the live path ────────


def test_vt_enrichment_on_live_path_via_injected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_recon_for_engagement, given an injected VT client, records origin-IP
    candidates + subdomains + 'virustotal' in sources_used on the live event —
    proving enrich_with_virustotal runs on the autonomous path (non-island, #2)."""
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
    monkeypatch.setattr(
        recon_runner,
        "certspotter_discover",
        lambda eid, host, **k: PassiveDiscoveryResult(host, (), (), ()),
    )
    monkeypatch.setattr(recon_runner, "build_osint_http_client", lambda *a, **k: _ScanHttpClient())

    vt = _StubVt(("157.230.37.62",), ("qs." + _ROOT,))
    recon_runner.run_recon_for_engagement(
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
        vt_client=vt,
    )

    payload = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ][0].payload
    assert "157.230.37.62" in payload["origin_ip_candidates"]
    assert any("qs." in s for s in payload["subdomains"])
    assert "virustotal" in payload["sources_used"]


# ── §12.61: Wayback CDX historical source (subdomains → origin candidates + paths) ──


def test_parse_wayback_cdx_extracts_domain_hosts_and_paths() -> None:
    """CDX JSON → in-domain historical hostnames + non-root paths; header row skipped,
    cross-domain host dropped (scope guard mirrors CompositeOriginDiscovery)."""
    cdx = (
        '[["original"],'
        '["http://origin.acme.com/old-admin"],'
        '["https://acme.com/login"],'
        '["http://cdn.evil-other.com/x"]]'
    )
    subs, paths = parse_wayback_cdx(cdx, "acme.com")
    assert set(subs) == {"origin.acme.com", "acme.com"}
    assert "cdn.evil-other.com" not in subs
    assert set(paths) == {"/old-admin", "/login"}


def test_parse_wayback_cdx_fail_open_on_garbage() -> None:
    assert parse_wayback_cdx("not json", "acme.com") == ((), ())
    assert parse_wayback_cdx("", "acme.com") == ((), ())
    assert parse_wayback_cdx("{}", "acme.com") == ((), ())


def test_parse_wayback_cdx_skips_malformed_row_keeps_good() -> None:
    """CodeRabbit: one malformed archived URL (bad IPv6 literal → urlparse ValueError)
    must be skipped, NOT discard the good rows."""
    cdx = (
        '[["original"],'
        '["http://good.acme.com/a"],'
        '["http://[1:2:3:4/oops"],'
        '["https://acme.com/b"]]'
    )
    subs, paths = parse_wayback_cdx(cdx, "acme.com")
    assert "good.acme.com" in subs
    assert "acme.com" in subs
    assert "/a" in paths and "/b" in paths


def test_wayback_cdx_url_is_https() -> None:
    """Aikido/CodeRabbit/Sourcery consensus: the CDX endpoint must be HTTPS, not plaintext."""
    from agent_alpha.recon.osint_sources import WAYBACK_CDX_URL_TEMPLATE

    assert WAYBACK_CDX_URL_TEMPLATE.startswith("https://")


# ── §12.61 A2: MX/SPF → origin candidates (pure consumer of already-collected DNS) ──


def test_parse_spf_ips_extracts_pass_ip4_only() -> None:
    """PASS-qualified ip4 (bare or +) extracted; SMALL CIDRs expanded, big /24 dropped.
    DISAVOWED mechanisms (-ip4/~/?) are NOT promoted (Aikido: target says 'not my sender').
    ip6 is dropped (GAP-155: transport lacks IPv6 URL bracketing)."""
    from agent_alpha.recon.passive_intel import parse_spf_ips

    txt = ["v=spf1 +ip4:198.51.100.5 -ip4:203.0.113.0/30 ip4:192.0.2.0/24 ip6:2001:db8::1 ~all"]
    ips = parse_spf_ips(txt)
    assert "198.51.100.5" in ips  # PASS-qualified (+) single ip4
    assert not any(ip.startswith("203.0.113.") for ip in ips)  # -ip4 DISAVOWED → NOT promoted
    assert not any(ip.startswith("192.0.2.") for ip in ips)  # /24 too big → dropped
    assert not any(":" in ip for ip in ips)  # ip6 dropped (GAP-155)


def test_parse_spf_ips_rejects_malformed_header_and_disavowed() -> None:
    """'v=spf1evil' is NOT SPF (exact first-token match, Aikido); softfail/neutral dropped."""
    from agent_alpha.recon.passive_intel import parse_spf_ips

    assert parse_spf_ips(["v=spf1evil ip4:198.51.100.9 -all"]) == ()  # malformed header
    assert parse_spf_ips(["v=spf1 ~ip4:198.51.100.9 ?ip4:198.51.100.10 -all"]) == ()  # disavowed


def test_parse_spf_ips_extracts_single_ip4_slash32() -> None:
    """The COMMON case: a single-IP SPF (implicit /32) IS extracted — .hosts() on Python>=3.9
    (Oracle 3.12.13) yields the /32 address (Sourcery's 'empty /32' does not apply to our env)."""
    from agent_alpha.recon.passive_intel import parse_spf_ips

    assert parse_spf_ips(["v=spf1 ip4:203.0.113.7 -all"]) == ("203.0.113.7",)


def test_parse_spf_ips_ignores_non_spf_txt() -> None:
    from agent_alpha.recon.passive_intel import parse_spf_ips

    assert parse_spf_ips(["google-site-verification=abc", "v=DMARC1; p=none"]) == ()
    assert parse_spf_ips([]) == ()


def test_parse_spf_ips_expands_slash28_asian_isp() -> None:
    """Asian ISP /28 allocation (16 addrs, 14 usable) is expanded — the origin often sits
    beside the mail server in the same block on shared regional infra."""
    from agent_alpha.recon.passive_intel import parse_spf_ips

    ips = parse_spf_ips(["v=spf1 ip4:103.150.20.16/28 ~all"])
    assert "103.150.20.17" in ips
    assert len(ips) == 14  # /28 usable hosts (network + broadcast excluded)


def test_parse_spf_ips_aggregate_cap_prevents_probe_storm() -> None:
    """A pathological multi-/28 SPF (3 × 14 = 42) is capped at the aggregate limit."""
    from agent_alpha.recon.passive_intel import _SPF_MAX_TOTAL_CANDIDATES, parse_spf_ips

    spf = "v=spf1 ip4:10.0.0.0/28 ip4:10.0.1.0/28 ip4:10.0.2.0/28 ~all"
    ips = parse_spf_ips([spf])
    assert len(ips) == _SPF_MAX_TOTAL_CANDIDATES  # 32, not 42


def test_mx_spf_keeps_in_domain_drops_off_domain_mx() -> None:
    """SCOPE BOUNDARY (Aikido/Greptile #421): off-domain mail infra — big-cloud relays AND
    third-party regional hosting (xserver.ne.jp) alike — is out of the authorized SOW and must
    NOT become an origin-binding target. Only in-domain MX hosts are kept."""
    from agent_alpha.recon.passive_intel import enrich_with_mx_spf

    base = PassiveIntelMap(
        domain="corp.cn",
        subdomains=(),
        in_scope_subdomains=(),
        mx_records=(
            "10 mxn.mxhichina.com",  # off-domain big-cloud
            "10 mail.exmail.qq.com",  # off-domain big-cloud
            "10 sv123.xserver.ne.jp",  # off-domain third-party hosting
            "10 mail.corp.cn",  # IN-DOMAIN — kept
        ),
        txt_records=(),
    )
    out = enrich_with_mx_spf(base)
    assert out.subdomains == ("mail.corp.cn",)  # ONLY the in-domain MX host


def test_enrich_with_mx_spf_derives_candidates_additive() -> None:
    """SPF ip4 → origin_ip_candidates; IN-DOMAIN MX → subdomains (off-domain infra dropped —
    scope boundary); every other field preserved (additive)."""
    from agent_alpha.recon.passive_intel import enrich_with_mx_spf

    base = PassiveIntelMap(
        domain="acme.co.id",
        subdomains=("www.acme.co.id",),
        in_scope_subdomains=(),
        origin_ip_candidates=("1.1.1.1",),
        mx_records=("10 mail.acme.co.id", "20 aspmx.l.google.com", "10 mx.niagahoster.com"),
        txt_records=("v=spf1 ip4:103.150.20.17 ~all",),
    )
    out = enrich_with_mx_spf(base)
    assert "103.150.20.17" in out.origin_ip_candidates  # SPF ip4
    assert "1.1.1.1" in out.origin_ip_candidates  # additive — kept
    assert "mail.acme.co.id" in out.subdomains  # in-domain MX kept
    assert not any("google" in s for s in out.subdomains)  # off-domain big-cloud dropped
    assert not any("niagahoster" in s for s in out.subdomains)  # off-domain hosting dropped
    assert "www.acme.co.id" in out.subdomains  # additive — kept


def test_enrich_with_mx_spf_deduplicates_reemitted_candidates() -> None:
    """Re-emit safety (Sourcery #421): an SPF IP / in-domain MX already present in the map is
    NOT duplicated — enrich is idempotent on its own output (additive-dedup)."""
    from agent_alpha.recon.passive_intel import enrich_with_mx_spf

    base = PassiveIntelMap(
        domain="acme.co.id",
        subdomains=("mail.acme.co.id",),  # MX host already present
        in_scope_subdomains=(),
        origin_ip_candidates=("203.0.113.7",),  # SPF IP already present
        mx_records=("10 mail.acme.co.id",),
        txt_records=("v=spf1 ip4:203.0.113.7 -all",),
    )
    out = enrich_with_mx_spf(base)
    assert out.origin_ip_candidates.count("203.0.113.7") == 1  # no dup IP
    assert out.subdomains.count("mail.acme.co.id") == 1  # no dup host


def test_mx_spf_enrichment_on_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """§12.61 A2 WIRED-PROOF: SPF ip4 → origin_ip_candidates and a non-big-cloud MX host →
    subdomains land on the live PASSIVE_INTEL_GATHERED event with 'mx_spf' in sources_used —
    enrich_with_mx_spf runs on the autonomous path (non-island, anti-#2)."""
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
    monkeypatch.setattr(
        recon_runner,
        "certspotter_discover",
        lambda eid, host, **k: PassiveDiscoveryResult(host, (), (), ()),
    )
    monkeypatch.setattr(recon_runner, "build_osint_http_client", lambda *a, **k: _ScanHttpClient())

    dns = _StubDNS(
        mx=["10 mail." + _ROOT, "20 aspmx.l.google.com"],
        txt=["v=spf1 ip4:203.0.113.7 include:_spf.google.com ~all"],
        ns=[],
    )
    recon_runner.run_recon_for_engagement(
        engagement_id=eng, tenant_id=None, auth=auth, store=store, record=rec, dns_resolver=dns
    )

    payload = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ][0].payload
    assert "203.0.113.7" in payload["origin_ip_candidates"]  # SPF ip4 literal
    assert "mail." + _ROOT in payload["subdomains"]  # in-domain MX host
    assert not any("google.com" in s for s in payload["subdomains"])  # big-cloud MX dropped
    assert "mx_spf" in payload["sources_used"]


class _StubWayback:
    def __init__(self, subs: tuple[str, ...], paths: tuple[str, ...]) -> None:
        self._subs = tuple(subs)
        self._paths = tuple(paths)

    def subdomains_and_paths(self, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return self._subs, self._paths


def test_enrich_with_wayback_unions_and_preserves_other_fields() -> None:
    """ADDITIVE: historical subdomains + paths unioned+deduped; every other field
    (incl. origin_ip_candidates, in_scope_subdomains) untouched."""
    base = PassiveIntelMap(
        domain="acme.com",
        subdomains=("www.acme.com",),
        in_scope_subdomains=("www.acme.com",),
        origin_ip_candidates=("1.2.3.4",),
        historical_paths=("/from-otx",),
    )
    out = enrich_with_wayback(base, _StubWayback(("origin.acme.com", "www.acme.com"), ("/wb",)))
    assert out.subdomains == ("www.acme.com", "origin.acme.com")  # unioned, deduped, order kept
    assert out.historical_paths == ("/from-otx", "/wb")
    assert out.origin_ip_candidates == ("1.2.3.4",)  # additive — untouched
    assert out.in_scope_subdomains == ("www.acme.com",)


def test_enrich_with_wayback_fail_open_when_source_raises() -> None:
    class _Boom:
        def subdomains_and_paths(self, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
            raise RuntimeError("wayback down")

    base = PassiveIntelMap(domain="acme.com", subdomains=("www.acme.com",), in_scope_subdomains=())
    out = enrich_with_wayback(base, _Boom())
    assert out.subdomains == ("www.acme.com",)  # unchanged; never raises


def test_wayback_enrichment_on_live_path_via_injected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """§12.61 WIRED-PROOF (RUNNER-SEAL != WIRED): run_recon_for_engagement, given an
    injected Wayback client, records the historical subdomain (→ origin candidate via
    CompositeOriginDiscovery) + historical path + 'wayback' in sources_used on the live
    event — enrich_with_wayback runs on the autonomous path, not an island (anti-#2)."""
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
    monkeypatch.setattr(
        recon_runner,
        "certspotter_discover",
        lambda eid, host, **k: PassiveDiscoveryResult(host, (), (), ()),
    )
    monkeypatch.setattr(recon_runner, "build_osint_http_client", lambda *a, **k: _ScanHttpClient())

    wb = _StubWayback(("origin." + _ROOT,), ("/legacy-admin",))
    recon_runner.run_recon_for_engagement(
        engagement_id=eng,
        tenant_id=None,
        auth=auth,
        store=store,
        record=rec,
        dns_resolver=_NULL_DNS,
        wayback_client=wb,
    )

    payload = [
        e for e in store.get_events(eng) if e.event_type == EventType.PASSIVE_INTEL_GATHERED
    ][0].payload
    assert "origin." + _ROOT in payload["subdomains"]
    assert "/legacy-admin" in payload["historical_paths"]
    assert "wayback" in payload["sources_used"]


# ══════════════════════════════════════════════════════════════════════
# Bug #26 consumer — passive_intel_signal_for_host (domain-scoped read)
# ══════════════════════════════════════════════════════════════════════

from agent_alpha.recon.passive_intel import (  # noqa: E402
    PassiveIntelSignal,
    passive_intel_signal_for_host,
)


def test_passive_intel_signal_domain_scoped_read() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    eng = auth.create_engagement("c", "ex.com").engagement_id
    store.append(
        event_type=EventType.PASSIVE_INTEL_GATHERED,
        engagement_id=eng,
        agent="alpha",
        payload={
            "domain": "ex.com",
            "protection_detected": "cloudflare",
            "historical_paths": ["/wp-login.php", "/api/v1"],
        },
    )
    sig = passive_intel_signal_for_host(store, eng, "ex.com")
    assert sig.protection_detected == "cloudflare"
    assert sig.historical_paths == ("/wp-login.php", "/api/v1")
    # SECURITY: a signal for ex.com must NOT steer probing of a different host.
    assert passive_intel_signal_for_host(store, eng, "other.com") == PassiveIntelSignal()


def test_passive_intel_signal_fail_open() -> None:
    class _Boom:
        def get_events(self, engagement_id: str) -> list[object]:
            raise RuntimeError("event store down")

    assert passive_intel_signal_for_host(_Boom(), "e", "h") == PassiveIntelSignal()
