# RED tests — GraphQL endpoint detection (slice-2). DETECT-only fingerprint.
#
#   RULE (R*)  : a GraphQL GET-response signature selects graphql_fingerprint.
#   WIRING (W*): the fingerprint is REACHABLE via Alpha.run_recon (non-island, #2).
#
# SCOPE GUARD: slice-2 detects that a GraphQL SURFACE exists (from the GET the loop
# already does on the seeded /graphql path). It does NOT send an introspection query
# or any GraphQL operation -- schema harvest is a slice-3 active probe / gated. The
# fingerprint reuses the capability handler: persists a "graphql" ASSET node, mints
# nothing, no _findings (fingerprint != payable finding, anti-#3).
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_graphql_detection.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"
_GQL_URL = f"https://{_HOST}/graphql"
_GQL_NOQUERY = '{"errors":[{"message":"Must provide query string."}]}'
_GRAPHIQL_HTML = "<html><head><title>GraphiQL</title></head><body>GraphiQL</body></html>"


def _engine() -> Any:
    from agent_alpha.tools.playbook import PlaybookEngine

    return PlaybookEngine.from_directory(_PLAYBOOK_DIR)


# ── RULE: GraphQL GET signatures select graphql_fingerprint ─────────────────


def test_r1_no_query_error_selects_graphql() -> None:
    d = _engine().match({"body": _GQL_NOQUERY, "headers": {}})
    assert d is not None and d.tool == "graphql_fingerprint"


def test_r2_graphiql_ide_selects_graphql() -> None:
    d = _engine().match({"body": _GRAPHIQL_HTML, "headers": {}})
    assert d is not None and d.tool == "graphql_fingerprint"


def test_r3_plain_page_is_not_graphql() -> None:
    assert _engine().match({"body": "<html>hello world</html>", "headers": {}}) is None


# ── WIRING: reachable via Alpha.run_recon (Oracle / py3.12) ─────────────────


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self._responses = responses
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        return self._responses.get(url, FakeResponse(404, "not found"))


class _StubProvider:
    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _alpha(graph: Any, store: Any, http: FakeHttpClient) -> tuple[Any, str]:
    from agent_alpha.agents.alpha.scout import Alpha
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.security.secrets import SecretsManager
    from agent_alpha.tools.playbook import PlaybookEngine

    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="graphql_lab", target=_HOST)
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


def test_w1_graphql_fingerprint_registered() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    store = InMemoryEventStore()
    alpha, _ = _alpha(NetworkXGraphStore(), store, FakeHttpClient({}))
    assert "graphql_fingerprint" in alpha._dispatch_registry


def test_w3_run_recon_fingerprints_graphql_surface() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    # /graphql is a seeded surface path; the GET returns the no-query error signature.
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>"),
            _GQL_URL: FakeResponse(400, _GQL_NOQUERY),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    assets = list(graph.nodes_by_type(NodeType.ASSET))
    labels = {label for a in assets for label in getattr(a.properties, "tech_stack", [])}
    assert "graphql" in labels  # minted via the LIVE loop -> non-island


def test_w4_graphql_fingerprint_is_not_a_payable_finding() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>"),
            _GQL_URL: FakeResponse(400, _GQL_NOQUERY),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    assert alpha._findings == 0
