# tests/phase_2_5/test_response_classifier.py
"""Contract: R3 slice-1 — ONE canonical response classifier, wired into the core
OBSERVE loop, so WAF/CF blocks are recognised on ANY recon path (not just the two
probes that hand-roll the 403/429/503 check today) — and a block is never dressed
as "clean" (anti-Lyndon #3, both directions).

RED at #131 (confirmed): agent_alpha/recon/response_classifier.py does not exist, and
scout.step()'s OBSERVE never emits WAF_BLOCKED (only js_secret_probe / odoo_dbmanager_
probe do). Import fails -> all tests RED until R3 slice-1 lands.

GREEN when:
  - classify_response(status_code, body, transport_error) -> Verdict{OK,EMPTY,
    TRANSPORT_FAIL,BLOCKED} exists (403/429/503 -> BLOCKED; 200+body -> OK; empty ->
    EMPTY; transport -> TRANSPORT_FAIL). Conservative: a 200 with a real body is NEVER
    BLOCKED.
  - scout.step() classifies each fetched response via classify_response; BLOCKED ->
    emit EventType.WAF_BLOCKED (REUSE existing event) + treat as non-analyzable.
  - js_secret_probe / odoo_dbmanager_probe migrate their 403/429/503 check to
    classify_response (single source of truth, anti-#7).

Anti-#3 is SYMMETRIC: W1 = a real block is recorded; W2/W3/C1 = a clean/empty response
is NEVER mislabelled as blocked.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_response_classifier.py -v
"""

from __future__ import annotations

import dataclasses
import inspect

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

# Net-new canonical classifier (RED: module does not exist yet).
from agent_alpha.recon.response_classifier import Verdict, classify_response

_HOST = "target.example.com"
_SEED = f"https://{_HOST}/"


# ---------------------------------------------------------------------------
# C1 — the canonical classifier, BOTH directions
# ---------------------------------------------------------------------------


def test_classify_response_verdicts() -> None:
    # Direction (a): a real block signal is BLOCKED.
    assert classify_response(status_code=403, body="Forbidden") is Verdict.BLOCKED
    assert classify_response(status_code=429, body="Too Many Requests") is Verdict.BLOCKED
    assert (
        classify_response(status_code=503, body="<html>Just a moment...</html>") is Verdict.BLOCKED
    )
    # Direction (b): clean / empty / transport are NEVER BLOCKED (anti false-BLOCKED).
    assert classify_response(status_code=200, body="<html><body>hello</body></html>") is Verdict.OK
    assert classify_response(status_code=200, body="") is Verdict.EMPTY
    assert classify_response(status_code=200, body="   \n  ") is Verdict.EMPTY
    assert classify_response(status_code=404, body="<html>Not Found</html>") is Verdict.OK
    assert classify_response(status_code=0, body="", transport_error=True) is Verdict.TRANSPORT_FAIL


def test_classify_response_is_pure_and_conservative() -> None:
    # A legitimate 200 page that merely CONTAINS the word 'forbidden' in its body is
    # NOT a block — only the status code carries the block verdict in slice-1.
    assert (
        classify_response(status_code=200, body="Access to admin is forbidden for guests")
        is Verdict.OK
    )


# ---------------------------------------------------------------------------
# Alpha harness (real Alpha; fake HTTP + orchestrator) — mirrors frontier e2e
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str]
    url: str


class _FakeHttpClient:
    def __init__(self, routes: dict[str, _Resp]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:  # noqa: ARG002
        self.calls.append(url)
        return self._routes.get(url, _Resp(404, "", {}, url))


@dataclasses.dataclass
class _Decision:
    tool: str = "generic_http_probe"
    tier: str = "rule"
    reasoning: str = "stub"
    cost_usd: float = 0.0


class _StubOrchestrator:
    def decide(self, observation: dict[str, object]) -> _Decision:  # noqa: ARG002
        return _Decision()


def _make_recon_alpha(routes: dict[str, _Resp]) -> tuple[Alpha, str, InMemoryEventStore]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="client_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=_StubOrchestrator(),
        http_client=_FakeHttpClient(routes),
    )
    return alpha, rec.engagement_id, store


def _waf_events(store: InMemoryEventStore, eng: str) -> list[object]:
    return [e for e in store.get_events(eng) if e.event_type == EventType.WAF_BLOCKED]


# ---------------------------------------------------------------------------
# W1 — core OBSERVE emits WAF_BLOCKED on a 403 (direction a)
# ---------------------------------------------------------------------------


def test_observe_emits_waf_blocked_on_403() -> None:
    alpha, eng, store = _make_recon_alpha({_SEED: _Resp(403, "Forbidden", {}, _SEED)})
    alpha.run_recon(eng, _SEED)
    assert len(_waf_events(store, eng)) >= 1, (
        "a 403 recon probe did not emit WAF_BLOCKED from the core OBSERVE loop — "
        "a WAF block is being treated as clean/no-progress (false success #3)"
    )


# ---------------------------------------------------------------------------
# W2 — clean 200 does NOT emit WAF_BLOCKED (direction b — anti false-positive)
# ---------------------------------------------------------------------------


def test_observe_no_waf_blocked_on_clean_200() -> None:
    alpha, eng, store = _make_recon_alpha(
        {_SEED: _Resp(200, "<html><body>ok</body></html>", {"server": "nginx"}, _SEED)}
    )
    alpha.run_recon(eng, _SEED)
    assert _waf_events(store, eng) == [], (
        "a clean 200 was mislabelled as WAF-blocked (false BLOCKED)"
    )


# ---------------------------------------------------------------------------
# W3 — reachable-but-empty is EMPTY, not BLOCKED
# ---------------------------------------------------------------------------


def test_observe_empty_is_not_blocked() -> None:
    alpha, eng, store = _make_recon_alpha({_SEED: _Resp(200, "", {}, _SEED)})
    alpha.run_recon(eng, _SEED)
    assert _waf_events(store, eng) == [], (
        "an empty (reachable) response was mislabelled as WAF-blocked"
    )


# ---------------------------------------------------------------------------
# D1 — de-dup driver: the existing probes use the canonical classifier (anti-#7)
# ---------------------------------------------------------------------------


def test_js_secret_probe_uses_canonical_classifier() -> None:
    import agent_alpha.recon.js_secret_probe as js

    src = inspect.getsource(js)
    assert "classify_response" in src, (
        "js_secret_probe still hand-rolls its 403/429/503 WAF check — migrate it to the "
        "canonical classify_response so the rule has a single source of truth (anti-#7)"
    )
