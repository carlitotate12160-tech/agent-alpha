"""Contract: Beta live-fire runner drives Beta end-to-end and scores it against
ground truth — rule-tier (no LLM), proof-bearing, leak-free.

Hermetic: a URL-aware fake HTTP server (vuln grants access on any applied cred;
hardened rejects) + the real login playbook + a NO-LLM provider that raises if
called (proving Beta stays rule-tier). The same redaction-fixed code path runs,
so a long session value must NOT show up in the scored leak scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.beta_runner import _NoLLMProvider, run_beta_live_fire
from agent_alpha.live_fire.runner import EngagementConfig, TargetSpec
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine, PlaybookRule

VULN = "http://127.0.0.1:9101/login"
HARDENED = "http://127.0.0.1:9102/login"
LONG_SESSION = "longsessionvalue1234567890abcdef"  # >12 chars: the leak scan would catch it
LOGIN_BODY = '<html><form><input type="password"></form> please log in</html>'


@dataclass
class _R:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""


class _Fake:
    """URL-aware: vuln grants access once any credential is applied; hardened
    rejects. Unauthenticated requests return a login page (so the playbook matches
    and Beta stays rule-tier)."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def _resp(self, url: str, authed: bool) -> _R:
        self.calls.append(url)
        if not authed:
            return _R(200, LOGIN_BODY, {}, url)
        if VULN in url:
            return _R(
                200,
                "<html>admin dashboard, welcome administrator</html>",
                {"set-cookie": f"session={LONG_SESSION}; Path=/; HttpOnly"},
                url,
            )
        return _R(401, LOGIN_BODY, {}, url)  # hardened: default creds rejected

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _R:
        return self._resp(url, bool(headers or cookies))

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        return self._resp(url, bool(data or json_body or headers or cookies))


def _login_orchestrator() -> LLMOrchestrator:
    rule = PlaybookRule(
        name="default_credentials_login",
        tool="default_creds",
        tier="rule",
        technique_id="T1078.001",
        indicators=[{"body_contains": 'type="password"'}],
        phase="access",
    )
    # _NoLLMProvider raises if the LLM is ever reached → proves rule-tier.
    return LLMOrchestrator(PlaybookEngine([rule]), _NoLLMProvider())


def _config() -> EngagementConfig:
    return EngagementConfig(
        client_id="login_lab",
        scope_ip_ranges=["127.0.0.1/32"],
        scope_domains=["127.0.0.1"],
        targets=[
            TargetSpec(url=VULN, host="127.0.0.1", ground_truth_vulnerable=True),
            TargetSpec(url=HARDENED, host="127.0.0.1", ground_truth_vulnerable=False),
        ],
    )


def test_beta_live_fire_scores_against_ground_truth_leak_free() -> None:
    results = run_beta_live_fire(
        _config(),
        auth=AuthorizationStateMachine(event_store=InMemoryEventStore()),
        http_client=_Fake(),
        orchestrator=_login_orchestrator(),
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
    )
    by_url = {r.url: r for r in results}

    vuln = by_url[VULN]
    assert vuln.gained_access is True  # default creds work -> access
    assert vuln.proof_count >= 1  # proof-bearing
    assert vuln.leak_suspected is False  # redaction fix holds through the runner
    assert vuln.correct is True

    hardened = by_url[HARDENED]
    assert hardened.gained_access is False  # rejected -> no access
    assert hardened.correct is True

    assert all(r.correct for r in results)  # overall PASS
