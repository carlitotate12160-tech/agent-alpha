# RED tests — surface-discovery slice-1 (OpenAPI/Swagger frontier feeder). Two tiers:
#
#   UNIT (U*)  : extract_api_surface() parses a spec body into concrete endpoint URLs.
#   WIRING (W*): a discovered endpoint is REACHABLE in the LIVE recon path
#                (Alpha.run_recon) — the feeder actually grows the frontier (anti-#2).
#
# AUTHORED BY: Claude (test/gate lane). Bodies (surface_discovery.extract_api_surface,
#              surface_openapi.yaml, scout _handle_surface_discovery + dispatch +
#              run_recon SURFACE_DISCOVERY_PATHS seed) are the IDE lane.
#
# DESIGN: DETECT/enumerate only. The handler parses the already-fetched spec and
# enqueues each concrete endpoint through the existing in-scope guard; it mints
# nothing (surface = reach, not a payable finding, anti-#3). Templated paths and
# GraphQL introspection are out of slice-1 scope (documented in U5/U6).
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_surface_discovery.py -v

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from typing import Any

from agent_alpha.recon.surface_discovery import extract_api_surface

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"
_SPEC_URL = f"https://{_HOST}/openapi.json"
_HEALTH_URL = f"https://{_HOST}/api/health"

_OPENAPI_SPEC = json.dumps(
    {
        "openapi": "3.0.1",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/api/health": {"get": {}},
            "/api/status": {"get": {}},
            "/users/{id}": {"get": {}},  # templated -> skipped in slice-1
        },
    }
)


# ── UNIT: the parser ────────────────────────────────────────────────────────


def test_u1_openapi3_concrete_paths_become_absolute_urls() -> None:
    urls = extract_api_surface(_OPENAPI_SPEC, _SPEC_URL)
    assert urls == [_HEALTH_URL, f"https://{_HOST}/api/status"]  # order preserved
    assert all("{" not in u for u in urls)  # templated path dropped


def test_u2_swagger2_basepath_is_prefixed() -> None:
    body = json.dumps({"swagger": "2.0", "basePath": "/v1", "paths": {"/ping": {"get": {}}}})
    assert extract_api_surface(body, _SPEC_URL) == [f"https://{_HOST}/v1/ping"]


def test_u3_non_spec_json_yields_nothing() -> None:
    # A plain JSON object that is not an OpenAPI/Swagger doc must not be mistaken.
    assert extract_api_surface(json.dumps({"paths": {"/x": {}}}), _SPEC_URL) == []


def test_u4_garbage_and_empty_yield_nothing_not_crash() -> None:
    assert extract_api_surface("<html>not json</html>", _SPEC_URL) == []
    assert extract_api_surface("", _SPEC_URL) == []
    assert extract_api_surface("   ", _SPEC_URL) == []


def test_u5_graphql_introspection_is_out_of_slice1_scope() -> None:
    # GraphQL introspection is a schema, not URL paths — slice-2 concern, [] here.
    body = json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}})
    assert extract_api_surface(body, _SPEC_URL) == []


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
    rec = auth.create_engagement(client_id="surface_lab", target=_HOST)
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


def test_w1_surface_probe_registered_in_dispatch() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    store = InMemoryEventStore()
    alpha, _ = _alpha(NetworkXGraphStore(), store, FakeHttpClient({}))
    assert "surface_discovery_probe" in alpha._dispatch_registry


def test_w2_playbook_selects_surface_probe_for_openapi_body() -> None:
    from agent_alpha.tools.playbook import PlaybookEngine

    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    decision = engine.match({"body": _OPENAPI_SPEC, "headers": {}})
    assert decision is not None
    assert decision.tool == "surface_discovery_probe"


def test_w3_run_recon_seeds_spec_then_probes_discovered_endpoint() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>"),
            _SPEC_URL: FakeResponse(200, _OPENAPI_SPEC),
            _HEALTH_URL: FakeResponse(200, "ok"),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    # /openapi.json was a seeded surface path; its endpoints reached the frontier
    # and were probed via the LIVE loop -> the feeder is not an island.
    assert _SPEC_URL in http.get_calls
    assert _HEALTH_URL in http.get_calls


def test_w4_surface_discovery_is_not_a_payable_finding() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>"),
            _SPEC_URL: FakeResponse(200, _OPENAPI_SPEC),
            _HEALTH_URL: FakeResponse(200, "ok"),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    assert alpha._findings == 0
