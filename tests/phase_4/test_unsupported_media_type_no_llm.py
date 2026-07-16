# Bug #10 pin — an HTTP 415 (Unsupported Media Type) is an ORIGIN
# content-negotiation rejection (observed: Cloudways/WP without an Accept
# header), NOT the target's real content and NOT a WAF/CF block.
#
# Unlike a 404 (F2, tests/phase_4/test_f2_not_found_no_llm.py), a 415 must be
# non-analyzable at BOTH tiers:
#   - never escalated to the LLM (token burn on an error page — same F2 guard)
#   - never given to the RULE tier either (the body is the origin's generic
#     error page; a rule match on it reproduces Bug #2/#14's page-wide-marker
#     false-positive pattern — a leaked debug page CAN legitimately render on
#     a 404, but a 415 content-negotiation rejection carries no such signal)
#   - no frontier expansion (a 415 error page's links are not real hrefs)
#
# Run on Oracle ARM64 only:
#     .venv312/bin/python3 -m pytest tests/phase_4/test_unsupported_media_type_no_llm.py -v

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
        # Every unmatched path returns 415 with a Cloudways-style error body —
        # including any href the (buggy) frontier expansion might enqueue.
        return self._routes.get(url, FakeResponse(415, "<html>Unsupported Media Type</html>"))


@dataclass
class _Decision:
    tool: str
    tier: str = "rule"
    reasoning: str = "stub"
    cost_usd: float = 0.0
    technique_id: str = ""


class _SpyOrchestrator:
    """Records BOTH tier entry points. A 415 must call neither."""

    def __init__(self) -> None:
        self.decide_calls: list[dict] = []
        self.decide_rule_only_calls: list[dict] = []

    def decide_rule_only(self, observation: dict) -> _Decision | None:
        self.decide_rule_only_calls.append(observation)
        return None

    def decide(self, observation: dict) -> _Decision:
        self.decide_calls.append(observation)  # LLM tier — must NOT happen for a 415
        return _Decision(tool="generic_http_probe", tier="single")


def _alpha(orch: _SpyOrchestrator, http: FakeHttpClient) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    graph_store = NetworkXGraphStore()
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=store,
        orchestrator=orch,
        http_client=http,
    )
    return alpha, rec.engagement_id


def test_415_never_calls_llm() -> None:
    orch = _SpyOrchestrator()
    http = FakeHttpClient({})
    alpha, eid = _alpha(orch, http)

    alpha.run_recon(eid, _SEED)

    assert orch.decide_calls == [], (
        "a 415 origin rejection was escalated to the LLM provider — token burn "
        f"on an error page. decide() was called {len(orch.decide_calls)}x"
    )


def test_415_never_reaches_rule_tier() -> None:
    """Different from F2/404: a 415 must not even be OFFERED to the rule tier,
    because the body is guaranteed to be the origin's generic error page, not
    target content — offering it up reproduces Bug #2/#14 (page-wide markers
    matching inside an unrelated error page)."""
    orch = _SpyOrchestrator()
    http = FakeHttpClient({})
    alpha, eid = _alpha(orch, http)

    alpha.run_recon(eid, _SEED)

    assert orch.decide_rule_only_calls == [], (
        "a 415 origin rejection reached the RULE tier — this reintroduces the "
        f"Bug #2/#14 false-positive pattern. decide_rule_only() called "
        f"{len(orch.decide_rule_only_calls)}x"
    )


def test_415_body_hrefs_are_not_enqueued() -> None:
    """Bug #11/#17 adjacent: a 415 error page's links must never expand the
    frontier — they are not the target's real navigation."""
    body = '<html><a href="/should-not-be-crawled">link</a></html>'
    orch = _SpyOrchestrator()
    http = FakeHttpClient({_SEED: FakeResponse(415, body)})
    alpha, eid = _alpha(orch, http)

    alpha.run_recon(eid, _SEED)

    assert f"https://{_HOST}/should-not-be-crawled" not in http.calls, (
        "an href inside a 415 error page was crawled — frontier expansion "
        "must only fire on Verdict.OK"
    )
