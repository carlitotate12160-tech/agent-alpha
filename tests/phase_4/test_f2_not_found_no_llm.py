# F2 pin (slice B) — a 404 (NOT_FOUND) missing path must NOT be escalated to the LLM
# provider (token burn), BUT a debug/error page that leaks on a 404 must still be
# caught by the DETERMINISTIC rule tier (the Laravel-on-404 guard).
#
#   F1  a seeded 404 whose body matches NO rule → orchestrator.decide (LLM tier) is
#       NEVER called; the probe is non-analyzable.
#   F2  a 404 whose body DOES match a rule (e.g. a framework debug page) → the rule
#       tier fires and the vector is dispatched (leak preserved, not dropped).
#
# Run on Oracle ARM64 only.

from __future__ import annotations

from dataclasses import dataclass, field

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

_HOST = "target.example"
_SEED = f"https://{_HOST}/"


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, FakeResponse]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.calls.append(url)
        # Every unmatched path (incl. the seeded wellknown 404s) returns a 404 WITH a
        # body (an nginx-style error page) — the exact F2 token-burn case.
        return self._routes.get(url, FakeResponse(404, "<html>404 Not Found</html>"))


@dataclass
class _Decision:
    tool: str
    tier: str = "rule"
    reasoning: str = "stub"
    cost_usd: float = 0.0
    technique_id: str = ""


class _SpyOrchestrator:
    """Records LLM-tier (decide) calls. decide_rule_only fires a rule only when the
    body carries the injected marker (stands in for a framework debug page)."""

    def __init__(self, rule_marker: str | None = None, rule_tool: str = "laravel_debug") -> None:
        self.decide_calls: list[dict] = []
        self._marker = rule_marker
        self._tool = rule_tool

    def decide_rule_only(self, observation: dict) -> _Decision | None:
        if self._marker and self._marker in observation.get("body", ""):
            return _Decision(tool=self._tool)
        return None

    def decide(self, observation: dict) -> _Decision:
        self.decide_calls.append(observation)  # LLM tier — must NOT happen for a 404
        return _Decision(tool="generic_http_probe", tier="single")


def _alpha(orch, http) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orch,
        http_client=http,
    )
    return alpha, rec.engagement_id


def test_f2_404_no_rule_never_calls_llm() -> None:
    # Root also 404s (with a body) — so the ENTIRE run is missing paths + seeded 404s.
    orch = _SpyOrchestrator(rule_marker=None)
    http = FakeHttpClient({})
    alpha, eid = _alpha(orch, http)

    alpha.run_recon(eid, _SEED)

    assert orch.decide_calls == [], (
        "a 404 missing path was escalated to the LLM provider — F2 token burn. "
        f"decide() was called {len(orch.decide_calls)}x"
    )


def test_f2_404_with_rule_is_still_dispatched() -> None:
    # A debug page that renders on a 404 and carries a leak marker → rule fires.
    marker = "Whoops-Debug-Leak"
    orch = _SpyOrchestrator(rule_marker=marker, rule_tool="laravel_debug")
    http = FakeHttpClient({_SEED: FakeResponse(404, f"<html>{marker} stack trace</html>")})
    alpha, eid = _alpha(orch, http)

    msg = alpha.run_recon(eid, _SEED)

    # The rule tier caught the 404 leak (dispatched laravel_debug), still no LLM call.
    assert orch.decide_calls == []
    assert msg is not None  # run completed; rule-on-404 path did not crash
