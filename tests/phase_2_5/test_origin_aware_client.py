# tests/phase_2_5/test_origin_aware_client.py
"""§12.46 Slice 2 - OriginAwareHttpClient routing/gate + fail-close logic (hermetic).

Owns the WRAPPER's own logic. proven_origins / assert_origin_authorized_or_bound
are sealed elsewhere -> stubbed. Live XML-RPC reach seal = Oracle.
"""

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
    """Event store returning WAF_BLOCKED events for the given fronted hosts.
    Records the engagement_id it was queried with (isolation/eid coverage) and
    can simulate a store failure (fail-open coverage)."""

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
    resp = c.post("https://odoo.alpha-ai.web.id/xmlrpc/2/common", data={"x": "1"})
    assert resp == "POST_RESP"
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


# ── fail-closed: host recon CONFIRMED fronted (WAF_BLOCKED) + no origin ────────
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


# ── BUG-FIX (hub): reachable host, no WAF_BLOCKED -> plain, NOT refused ────────
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


# ── REVIEW #1: behavior change pinned — discovery=False + WAF-blocked -> refuse ─
def test_non_discovery_wafblocked_fails_closed(monkeypatch, gate_spy):
    """A WAF-confirmed host is NEVER naked-hit, INDEPENDENT of the discovery flag.
    (Old code passed through when discovery=False; new code is evidence-based.)"""
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=False),  # NOT a discovery engagement
        event_store=_FakeStore(waf_hosts={"blocked.test"}),
        engagement_id="e1",
    )
    with pytest.raises(OriginUnreachableError):
        c.get("https://blocked.test/x")
    assert inner.calls == []


# ── REVIEW #2: fail-open — store error -> reachable (plain), never crash ───────
def test_fail_open_on_store_error(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=_FakeStore(raises=True),  # get_events raises
        engagement_id="e1",
    )
    c.get("https://whatever.test/x")  # must NOT raise
    assert inner.calls[-1]["url"] == "https://whatever.test/x"  # plain passthrough


# ── REVIEW #3: cross-host isolation — block for A must NOT refuse B ────────────
def test_cross_host_isolation(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=_FakeStore(waf_hosts={"apex.test"}),  # only apex blocked
        engagement_id="e1",
    )
    c.get("https://hub.test/ok")  # different host -> plain, NOT refused
    assert inner.calls[-1]["url"] == "https://hub.test/ok"
    with pytest.raises(OriginUnreachableError):  # blocked host still refused
        c.get("https://apex.test/x")


# ── REVIEW #4a: source guard — Beta MUST catch HttpClientError (not RuntimeError)
def test_beta_source_catches_httpclienterror() -> None:
    src = (pathlib.Path(agent_alpha.__file__).parent / "agents/beta/strike.py").read_text()
    assert "except HttpClientError" in src, (
        "Beta must catch HttpClientError so a wrapper fail-close is a graceful skip, "
        "not a crash. If this changed to e.g. `except RuntimeError`, the fix regresses."
    )


# ── REVIEW #4b: behavioral — the raise IS caught by `except HttpClientError` ───
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
    except HttpClientError:  # EXACTLY how Beta catches it (strike.py)
        caught = True
    assert caught


def test_origin_unreachable_is_httpclienterror() -> None:
    assert issubclass(OriginUnreachableError, HttpClientError)


# ── REVIEW #5: _host_is_fronted queries the CORRECT engagement_id ──────────────
def test_host_is_fronted_queries_correct_engagement(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    store = _FakeStore(waf_hosts=set())
    c = OriginAwareHttpClient(
        _FakeInner(), profile=_profile(discovery=True), event_store=store, engagement_id="eng-XYZ"
    )
    c.get("https://h.test/x")
    assert store.queried_eids == ["eng-XYZ"]


# ── REVIEW #6: fronted-host set cached — store queried ONCE across many routes ─
def test_fronted_set_cached_single_store_query(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    store = _FakeStore(waf_hosts={"apex.test"})
    c = OriginAwareHttpClient(
        _FakeInner(), profile=_profile(discovery=True), event_store=store, engagement_id="e1"
    )
    for _ in range(5):
        c.get("https://hub.test/ok")
    assert len(store.queried_eids) == 1  # one scan, not per-_route
