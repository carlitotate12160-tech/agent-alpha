"""Contract (RED): Alpha survives unreachable / slow targets — no crash.

Closes the Phase 2 live-fire blocker. Today `Alpha.step()` calls
`self.http_client.get(url)` with NO guard; the production HttpClient is
httpx-backed and raises `httpx.ConnectError` / `httpx.TimeoutException` 
on an unreachable or slow host. That exception propagates out of the
cognitive loop and out of `run_recon()` → the agent CRASHES. The fake
client in conftest never raises, so this path is currently UNTESTED
(anti-Lyndon #3: an untested failure path masquerading as "done").

Required two-layer interface (implementation, ≤2 files):

  Layer 1 — agent_alpha/agents/http_client.py
    Add `class HttpClientError(Exception)`. `HttpClient.get` wraps the
    httpx call: on `httpx.TimeoutException` or `httpx.TransportError` 
    (covers ConnectError, ReadError, etc.) re-raise as `HttpClientError`.
    Alpha must NOT import httpx — the domain error decouples it.

  Layer 2 — agent_alpha/agents/alpha/scout.py
    In `step()`, wrap the `self.http_client.get(url)` call in
    try/except `HttpClientError`. On failure: treat the probe as
    non-analysable — do NOT increment `_analyzable_probes`, return
    {"discovered_nodes": 0, "cost_usd": 0.0}. Existing terminal logic
    then yields status FAILED (no silent success), never a crash.

VERIFY: Oracle ARM64 only (`.venv/bin/python3 -m pytest` / `make check`).
Until both layers land, every test here is RED (HttpClientError is part
of the contract and does not yet exist).
"""

from __future__ import annotations

import httpx
import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient, HttpClientError
from agent_alpha.graph.nodes import NodeType


def _handoff(msg: "a2a_pb2.A2AMessage") -> "a2a_pb2.HandoffPayload":
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    return payload


# ── Test doubles ──────────────────────────────────────────────────────


class _RaisingHttpClient:
    """An authorized-but-unreachable target: get() raises the domain error
    the production HttpClient is contracted to raise on transport failure.
    Records calls so we can prove Alpha actually tried before giving up."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0):
        self.calls.append(url)
        raise self._exc


class _ExplodingOrchestrator:
    """ORIENT must never run for a probe that failed at OBSERVE. If Alpha
    reaches .decide() after a transport failure, the catch is in the wrong
    place — this turns that bug into a loud, immediate failure."""

    def decide(self, observation: dict) -> object:
        raise AssertionError("orchestrator.decide() called after a transport failure")


# ── Layer 1: HttpClient converts httpx transport errors → HttpClientError ──


def test_connect_error_is_wrapped_as_httpclienterror():
    """An unreachable host (ConnectError) surfaces as the domain error,
    not a raw httpx exception leaking the transport into the agent."""

    def _refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = HttpClient(engagement_id="eng-net-1", transport=httpx.MockTransport(_refuse))

    with pytest.raises(HttpClientError):
        client.get("https://unreachable.invalid/")


def test_timeout_is_wrapped_as_httpclienterror():
    """A slow host (ReadTimeout, a TimeoutException) surfaces as the domain
    error — Alpha must never hang nor see a raw httpx timeout."""

    def _stall(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = HttpClient(engagement_id="eng-net-2", transport=httpx.MockTransport(_stall))

    with pytest.raises(HttpClientError):
        client.get("https://slowloris.invalid/")


def test_httpclienterror_is_not_an_httpx_exception():
    """The domain error must NOT subclass httpx — that is the decoupling
    guarantee (Alpha catches HttpClientError without importing httpx)."""
    assert not issubclass(HttpClientError, httpx.HTTPError)


# ── Layer 2: Alpha handles HttpClientError → FAILED, never crashes ─────────


def test_alpha_unreachable_target_fails_not_crash(
    recon_engagement, graph_store, event_store
):
    """The headline contract: an authorized target that is down/timing out
    yields a terminal FAILED handoff — the agent returns normally instead
    of raising out of the cognitive loop."""
    auth, engagement_id = recon_engagement
    http = _RaisingHttpClient(HttpClientError("connection refused"))

    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_ExplodingOrchestrator(),
        http_client=http,
    )

    # Must NOT raise — this call crashing IS the bug under test.
    msg = agent.run_recon(engagement_id, "https://lab-target.invalid/trigger-error")

    handoff = _handoff(msg)
    assert handoff.status == a2a_pb2.FAILED          # no silent success
    assert handoff.findings_count == 0
    assert http.calls, "Alpha must have actually attempted the fetch"


def test_unreachable_target_writes_no_graph_nodes(
    recon_engagement, graph_store, event_store
):
    """A failed OBSERVE must not fabricate findings — the AttackGraph stays
    empty (anti-Lyndon #3: a crash-or-empty probe is never a conclusion)."""
    auth, engagement_id = recon_engagement
    http = _RaisingHttpClient(HttpClientError("read timed out"))

    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_ExplodingOrchestrator(),
        http_client=http,
    )

    agent.run_recon(engagement_id, "https://lab-target.invalid/trigger-error")

    assert graph_store.nodes_by_type(NodeType.ASSET) == []
    assert graph_store.nodes_by_type(NodeType.VULNERABILITY) == []
