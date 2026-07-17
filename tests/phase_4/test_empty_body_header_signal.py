# RED tests — empty-body header-signal fix. A response with an EMPTY body but a
# meaningful HEADER (Basic-Auth WWW-Authenticate, Tomcat/S3 Server) must still be
# fingerprinted: scout routes Verdict.EMPTY through the RULE tier (never the LLM),
# so a header-only signal is not lost when the body is blank.
#
# Closes the http_basic_auth.yaml slice-1 limitation. classify_response is
# UNTOUCHED (still returns EMPTY); the fix is in scout._step_once consumer flow.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_empty_body_header_signal.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self._responses = responses
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        # Unmapped seeded paths -> 404 with a body (NOT_FOUND, non-analyzable).
        return self._responses.get(url, FakeResponse(404, "not found"))


class _StubProvider:
    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _alpha(graph, store, http):
    from agent_alpha.agents.alpha.scout import Alpha
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.security.secrets import SecretsManager
    from agent_alpha.tools.playbook import PlaybookEngine

    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="empty_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider=_StubProvider()
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph,
        event_store=store,
        orchestrator=orch,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    return alpha, rec.engagement_id


def test_empty_body_401_basic_auth_is_fingerprinted() -> None:
    # The fix: EMPTY body + WWW-Authenticate: Basic -> http_basic_auth ASSET.
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {_ROOT: FakeResponse(401, "", {"WWW-Authenticate": 'Basic realm="Restricted"'})}
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    labels = {
        label for a in graph.nodes_by_type(NodeType.ASSET) for label in a.properties.tech_stack
    }
    assert "http_basic_auth" in labels  # empty body no longer hides the header signal


def test_empty_body_without_signal_stays_non_analyzable() -> None:
    # Guard: EMPTY body with no meaningful header remains a non-analyzable dud —
    # no ASSET, no finding. (The change must not turn every blank body into work.)
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient({_ROOT: FakeResponse(200, "", {"Server": "nginx"})})
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    assert list(graph.nodes_by_type(NodeType.ASSET)) == []
    assert alpha._findings == 0
