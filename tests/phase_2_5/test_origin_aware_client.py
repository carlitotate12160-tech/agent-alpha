# tests/phase_2_5/test_origin_aware_client.py
"""§12.46 Slice 2 - OriginAwareHttpClient routing/gate/fail-close (hermetic)."""

from __future__ import annotations

import pathlib
import types

import pytest

import agent_alpha
from agent_alpha.agents import origin_aware_client as mod
from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.agents.origin_aware_client import (
    OriginAwareHttpClient,
    OriginUnreachableError,
)
from agent_alpha.events.event_types import EventType


class _FakeInner:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def get(self, url, **kw):
        self.calls.append({"method": "GET", "url": url, **kw})
        return "GET_RESP"

    def post(self, url, **kw):
        self.calls.append({"method": "POST", "url": url, **kw})
        return "POST_RESP"


class _FakeEvent:
    def __init__(self, event_type, payload):
        self.event_type = event_type
        self.payload = payload


class _FakeStore:
    def __init__(self, waf_hosts=(), *, raises: bool = False):
        self._events = [_FakeEvent(EventType.WAF_BLOCKED, {"host": h}) for h in waf_hosts]
        self.queried_eids: list[str] = []
        self._raises = raises

    def get_events(self, engagement_id):
        self.queried_eids.append(engagement_id)
        if self._raises:
            raise RuntimeError("store down")
        return self._events


def _profile(*, authorized=frozenset(), discovery=False):
    return types.SimpleNamespace(
        authorized_origins=frozenset(authorized), allow_origin_discovery=discovery
    )


@pytest.fixture
def gate_spy(monkeypatch):
    calls = []
    monkeypatch.setattr(mod, "assert_origin_authorized_or_bound", lambda *a, **k: calls.append(a))
    return calls


def _bind(monkeypatch, ips):
    monkeypatch.setattr(mod, "proven_origins", lambda *_a, **_k: frozenset(ips))


# ── origin-direct on proven binding ───────────────────────────────────────────
def test_post_origin_direct_on_proven_binding(monkeypatch, gate_spy):
    _bind(monkeypatch, {"168.110.192.62"})
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner, profile=_profile(discovery=True), event_store=_FakeStore(), engagement_id="e1"
    )
    c.post("https://odoo.alpha-ai.web.id/xmlrpc/2/common", data={"x": "1"})
    call = inner.calls[-1]
    assert call["url"] == "https://168.110.192.62/xmlrpc/2/common"
    assert call["headers"]["Host"] == "odoo.alpha-ai.web.id"
    assert call["verify"] is False
    assert call["data"] == {"x": "1"}
    assert gate_spy and gate_spy[-1][0] == "168.110.192.62"


def test_get_origin_direct_parity(monkeypatch, gate_spy):
    _bind(monkeypatch, {"168.110.192.62"})
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner, profile=_profile(discovery=True), event_store=_FakeStore(), engagement_id="e1"
    )
    c.get("https://wp.alpha-ai.web.id/wp-login.php", cookies={"s": "1"})
    call = inner.calls[-1]
    assert call["url"] == "https://168.110.192.62/wp-login.php"
    assert call["headers"]["Host"] == "wp.alpha-ai.web.id"
    assert call["verify"] is False
    assert call["cookies"] == {"s": "1"}


def test_signed_authorized_origin_routes_direct(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(authorized={"10.0.0.5"}, discovery=True),
        event_store=_FakeStore(),
        engagement_id="e1",
    )
    c.post("https://x.example.com/a")
    assert inner.calls[-1]["url"] == "https://10.0.0.5/a"


def test_fail_closed_when_host_is_waf_blocked(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=_FakeStore(waf_hosts={"odoo.alpha-ai.web.id"}),
        engagement_id="e1",
    )
    with pytest.raises(OriginUnreachableError):
        c.post("https://odoo.alpha-ai.web.id/xmlrpc/2/common")
    assert inner.calls == []


def test_reachable_host_no_wafblock_plain_passthrough(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=_FakeStore(waf_hosts=set()),
        engagement_id="e1",
    )
    c.get("https://hub.niagamas.com/")
    call = inner.calls[-1]
    assert call["url"] == "https://hub.niagamas.com/"
    assert "Host" not in (call["headers"] or {})
    assert gate_spy == []


def test_gate_denial_propagates(monkeypatch):
    _bind(monkeypatch, {"168.110.192.62"})

    def _deny(*a, **k):
        raise RuntimeError("OriginNotAuthorizedError")

    monkeypatch.setattr(mod, "assert_origin_authorized_or_bound", _deny)
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner, profile=_profile(discovery=True), event_store=_FakeStore(), engagement_id="e1"
    )
    with pytest.raises(RuntimeError, match="OriginNotAuthorized"):
        c.post("https://odoo.alpha-ai.web.id/xmlrpc/2/common")
    assert inner.calls == []


# ── REVIEW #1: discovery=False + WAF-blocked -> refuse (evidence-based) ────────
def test_non_discovery_wafblocked_fails_closed(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=False),
        event_store=_FakeStore(waf_hosts={"blocked.test"}),
        engagement_id="e1",
    )
    with pytest.raises(OriginUnreachableError):
        c.get("https://blocked.test/x")
    assert inner.calls == []


# ── REVIEW #2: _fronted_hosts fail-open (store error, proven_origins stubbed) ──
def test_fronted_hosts_fail_open_on_store_error(monkeypatch, gate_spy):
    _bind(monkeypatch, set())  # proven_origins stubbed -> only _fronted_hosts hits the store
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=_FakeStore(raises=True),
        engagement_id="e1",
    )
    c.get("https://whatever.test/x")
    assert inner.calls[-1]["url"] == "https://whatever.test/x"


# ── CODERABBIT: proven_origins() runs FIRST — must ALSO fail-open (real path) ──
def test_proven_origins_fail_open_on_store_error(gate_spy):
    """proven_origins() hits the store BEFORE _fronted_hosts. If it raises there,
    the wrapper must fail-open (no binding) -> plain, not crash. Real proven_origins
    (NOT stubbed) + a raising store — the exact gap CodeRabbit flagged."""
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=_FakeStore(raises=True),
        engagement_id="e1",
    )
    c.get("https://whatever.test/x")  # must NOT crash (proven_origins raised, caught)
    assert inner.calls[-1]["url"] == "https://whatever.test/x"


# ── REVIEW #3: cross-host isolation ───────────────────────────────────────────
def test_cross_host_isolation(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=_FakeStore(waf_hosts={"apex.test"}),
        engagement_id="e1",
    )
    c.get("https://hub.test/ok")
    assert inner.calls[-1]["url"] == "https://hub.test/ok"
    with pytest.raises(OriginUnreachableError):
        c.get("https://apex.test/x")


# ── REVIEW #4: Beta MUST catch HttpClientError (source guard + catchability) ───
def test_beta_source_catches_httpclienterror() -> None:
    src = (pathlib.Path(agent_alpha.__file__).parent / "agents/beta/strike.py").read_text()
    assert "except HttpClientError" in src


def test_fail_close_is_catchable_as_httpclienterror(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    c = OriginAwareHttpClient(
        _FakeInner(),
        profile=_profile(discovery=True),
        event_store=_FakeStore(waf_hosts={"apex.test"}),
        engagement_id="e1",
    )
    caught = False
    try:
        c.get("https://apex.test/x")
    except HttpClientError:
        caught = True
    assert caught


def test_origin_unreachable_is_httpclienterror() -> None:
    assert issubclass(OriginUnreachableError, HttpClientError)


# ── REVIEW #5: correct engagement_id queried ──────────────────────────────────
def test_host_is_fronted_queries_correct_engagement(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    store = _FakeStore(waf_hosts=set())
    c = OriginAwareHttpClient(
        _FakeInner(), profile=_profile(discovery=True), event_store=store, engagement_id="eng-XYZ"
    )
    c.get("https://h.test/x")
    assert store.queried_eids == ["eng-XYZ"]


# ── REVIEW #6: fronted set cached — one store scan across many routes ──────────
def test_fronted_set_cached_single_store_query(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    store = _FakeStore(waf_hosts={"apex.test"})
    c = OriginAwareHttpClient(
        _FakeInner(), profile=_profile(discovery=True), event_store=store, engagement_id="e1"
    )
    for _ in range(5):
        c.get("https://hub.test/ok")
    assert len(store.queried_eids) == 1
