# tests/phase_2_5/test_origin_aware_client.py
"""§12.46 Slice 2 - OriginAwareHttpClient routing/gate logic (hermetic).

Exercises the WRAPPER's own logic (rewrite + Host + verify=False + fail-closed).
proven_origins / assert_origin_authorized_or_bound are already sealed
(phase_2_5) -> stubbed here so this test owns only the wrapper. Live XML-RPC
reach seal = Oracle.
"""

from __future__ import annotations

import types

import pytest

from agent_alpha.agents import origin_aware_client as mod
from agent_alpha.agents.origin_aware_client import (
    OriginAwareHttpClient,
    OriginUnreachableError,
)


class _FakeInner:
    """Records the exact call the wrapper delegates (the seam under test)."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def get(self, url, **kw):
        self.calls.append({"method": "GET", "url": url, **kw})
        return "GET_RESP"

    def post(self, url, **kw):
        self.calls.append({"method": "POST", "url": url, **kw})
        return "POST_RESP"


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


# ── J-direct: proven-bound host -> rewrite to IP + Host + verify=False + gate ──
def test_post_origin_direct_on_proven_binding(monkeypatch, gate_spy):
    _bind(monkeypatch, {"168.110.192.62"})
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(discovery=True),
        event_store=object(),
        engagement_id="e1",
    )
    resp = c.post("https://odoo.alpha-ai.web.id/xmlrpc/2/common", data={"x": "1"})
    assert resp == "POST_RESP"
    call = inner.calls[-1]
    assert call["url"] == "https://168.110.192.62/xmlrpc/2/common"  # rewritten to IP
    assert call["headers"]["Host"] == "odoo.alpha-ai.web.id"  # fronted vhost
    assert call["verify"] is False  # IP-literal cert (ADR §12.33)
    assert call["data"] == {"x": "1"}  # POST body preserved (reuse HttpClient)
    assert gate_spy and gate_spy[-1][0] == "168.110.192.62"  # gate ran on the IP
    assert gate_spy[-1][1] == "odoo.alpha-ai.web.id"


def test_get_origin_direct_parity(monkeypatch, gate_spy):
    _bind(monkeypatch, {"168.110.192.62"})
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner, profile=_profile(discovery=True), event_store=object(), engagement_id="e1"
    )
    c.get("https://wp.alpha-ai.web.id/wp-login.php", cookies={"s": "1"})
    call = inner.calls[-1]
    assert call["url"] == "https://168.110.192.62/wp-login.php"
    assert call["headers"]["Host"] == "wp.alpha-ai.web.id"
    assert call["verify"] is False
    assert call["cookies"] == {"s": "1"}


# ── signed cooperative path (no binding event) still authorizes direct ──
def test_signed_authorized_origin_routes_direct(monkeypatch, gate_spy):
    _bind(monkeypatch, set())  # no ORIGIN_BINDING_PROVEN
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner,
        profile=_profile(authorized={"10.0.0.5"}, discovery=True),
        event_store=object(),
        engagement_id="e1",
    )
    c.post("https://x.example.com/a")
    assert inner.calls[-1]["url"] == "https://10.0.0.5/a"


# ── fail-closed: fronted (discovery) + no origin -> refuse the naked WAF hit ──
def test_fail_closed_when_fronted_and_unbound(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner, profile=_profile(discovery=True), event_store=object(), engagement_id="e1"
    )
    with pytest.raises(OriginUnreachableError):
        c.post("https://odoo.alpha-ai.web.id/xmlrpc/2/common")
    assert inner.calls == []  # nothing left the wrapper


# ── non-discovery (direct target) + no origin -> plain passthrough ──
def test_plain_passthrough_when_not_discovery(monkeypatch, gate_spy):
    _bind(monkeypatch, set())
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner, profile=_profile(discovery=False), event_store=object(), engagement_id="e1"
    )
    c.get("https://direct.internal/health", verify=True)
    call = inner.calls[-1]
    assert call["url"] == "https://direct.internal/health"  # unchanged
    assert "Host" not in (call["headers"] or {})  # no override
    assert call["verify"] is True  # caller's verify preserved
    assert gate_spy == []  # gate not invoked on plain path


# ── gate raises -> propagate, never silent bypass ──
def test_gate_denial_propagates(monkeypatch):
    _bind(monkeypatch, {"168.110.192.62"})

    def _deny(*a, **k):
        raise RuntimeError("OriginNotAuthorizedError")

    monkeypatch.setattr(mod, "assert_origin_authorized_or_bound", _deny)
    inner = _FakeInner()
    c = OriginAwareHttpClient(
        inner, profile=_profile(discovery=True), event_store=object(), engagement_id="e1"
    )
    with pytest.raises(RuntimeError, match="OriginNotAuthorized"):
        c.post("https://odoo.alpha-ai.web.id/xmlrpc/2/common")
    assert inner.calls == []  # denied before any transport
