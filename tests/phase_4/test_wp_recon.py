# WordPress recon-depth battery — fingerprint-keyed playbooks (STACK_CATALOG.md).
#
# Four capabilities deepen the WP stack, each keyed on a body signature via its own
# pure-data playbook and dispatched through Alpha's registry:
#   wp_rest_routes  — DETECT-only route surface (asset property, zero findings)
#   wp_rest_users   — FINDING: username disclosure + USER nodes (cred-reuse feed)
#   woocommerce     — FINDING when body confirms wc/v3; absent = InsufficientData
#   wp_version      — FINDING (low sev) from readme.html + <meta generator>
#
# CARDINAL (anti-#3): a 200 body is NEVER a finding on its own — the finding gate is
# a confirmed BODY SIGNATURE. WordPress soft-404 returns 200 with an HTML body;
# test_soft_404_body_is_not_a_finding pins that the HANDLER (not the playbook) gates.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_wp_recon.py -v

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from types import SimpleNamespace

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "wp.example"
_REST_ROOT = f"https://{_HOST}/wp-json/"
_USERS_URL = f"https://{_HOST}/wp-json/wp/v2/users"
_WC_URL = f"https://{_HOST}/wp-json/wc/v3"
_README_URL = f"https://{_HOST}/readme.html"
_SITE_ROOT = f"https://{_HOST}/"
_PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, FakeResponse] | None = None) -> None:
        self._routes = routes or {}
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        return self._routes.get(url, FakeResponse(404, ""))


class _StubProvider:
    model = "stub"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, *args: object, **kwargs: object):
        self.calls += 1
        return type(
            "R",
            (),
            {"text": '{"tool": "generic_http_probe"}', "usage_cost_usd": 0.0, "model": "stub"},
        )()


def _alpha(http: FakeHttpClient, graph: NetworkXGraphStore | None = None) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="wp_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR, phase="recon")
    orchestrator = LLMOrchestrator(engine, _StubProvider())
    alpha = Alpha(
        authorization=auth,
        graph_store=graph or NetworkXGraphStore(),
        event_store=store,
        orchestrator=orchestrator,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    alpha._engagement_id = rec.engagement_id  # direct-handler tests set live run state
    return alpha, rec.engagement_id


def _users_body(*slugs: str) -> str:
    return json.dumps(
        [
            {"id": i + 1, "name": s.title(), "slug": s, "avatar_urls": {"24": "http://a/g"}}
            for i, s in enumerate(slugs)
        ]
    )


def _route_index(route_keys: list[str], namespaces: list[str] | None = None) -> str:
    return json.dumps(
        {
            "name": "Lab",
            "namespaces": namespaces if namespaces is not None else ["wp/v2"],
            "routes": {k: {"namespace": "wp/v2"} for k in route_keys},
        }
    )


# ── 1. REST users disclosure (FINDING + USER nodes) ──────────────────────────


def test_rest_users_disclosure_from_body() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    decision = SimpleNamespace(tool="wp_rest_users")
    alpha._handle_wp_rest_users(
        FakeResponse(200, _users_body("admin", "editor")), decision, _USERS_URL
    )

    assert alpha._findings == 1, "a parseable users array is a username-disclosure finding"
    users = graph.nodes_by_type(NodeType.USER)
    assert {u.properties.username for u in users} == {"admin", "editor"}
    assert len(users) == 2, "each disclosed slug must become a USER node (cred-reuse feed)"
    vulns = {n.id for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    assert f"vuln:{_HOST}:wp_rest_user_disclosure" in vulns


# ── 2. CARDINAL: soft-404 (200 + HTML) is NOT a finding ──────────────────────


def test_soft_404_body_is_not_a_finding() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    html = "<!DOCTYPE html><html><body><h1>Not Found</h1></body></html>"
    decision = SimpleNamespace(tool="wp_rest_users")
    added = alpha._handle_wp_rest_users(FakeResponse(200, html), decision, _USERS_URL)

    assert added == 0
    assert alpha._findings == 0, "a 200 HTML soft-404 must NEVER be a finding (anti-#3)"
    assert graph.nodes_by_type(NodeType.USER) == []
    assert graph.nodes_by_type(NodeType.VULNERABILITY) == []


# ── 3. Route surface = asset property, NOT findings ──────────────────────────


def test_route_surface_is_asset_property_not_findings() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    keys = [f"/wp/v2/thing{i}" for i in range(50)]
    decision = SimpleNamespace(tool="wp_rest_routes")
    alpha._handle_wp_rest_routes(FakeResponse(200, _route_index(keys)), decision, _REST_ROOT)

    assert alpha._findings == 0, "a route surface is reach, never a payable finding"
    assets = graph.nodes_by_type(NodeType.ASSET)
    assert len(assets) == 1
    props = assets[0].properties
    assert set(props.rest_routes) == set(keys)
    assert props.rest_routes_total_count == 50
    assert props.rest_routes_truncated is False
    assert constants.STACK_WP in props.tech_stack


# ── 4. Route surface caps at 200 ─────────────────────────────────────────────


def test_route_surface_caps_at_200() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    keys = [f"/wp/v2/r{i}" for i in range(500)]
    decision = SimpleNamespace(tool="wp_rest_routes")
    alpha._handle_wp_rest_routes(FakeResponse(200, _route_index(keys)), decision, _REST_ROOT)

    props = graph.nodes_by_type(NodeType.ASSET)[0].properties
    assert len(props.rest_routes) == 200, "inventory is capped at WP_REST_ROUTES_CAP"
    assert props.rest_routes_truncated is True
    assert props.rest_routes_total_count == 500
    assert alpha._findings == 0


# ── 5. Only allowlisted routes escalate ──────────────────────────────────────


def test_only_allowlisted_routes_escalate() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    keys = ["/wp/v2/users", "/random-plugin/v1/foo", "/wp/v2/posts"]
    decision = SimpleNamespace(tool="wp_rest_routes")
    alpha._handle_wp_rest_routes(FakeResponse(200, _route_index(keys)), decision, _REST_ROOT)

    assert _USERS_URL in alpha._work_queue, "an allowlisted route must be escalated to the frontier"
    assert not any("random-plugin" in u for u in alpha._work_queue), (
        "a non-allowlisted plugin route must NOT be escalated (anti-#3 over-probe)"
    )


# ── 6. WooCommerce absent = InsufficientData (not error, not finding) ────────


def test_woocommerce_absent_is_insufficient_not_error() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    # A /wp-json/ index with wp/v2 only — no wc/* route.
    body = _route_index(["/wp/v2/posts"], namespaces=["wp/v2"])
    decision = SimpleNamespace(tool="woocommerce")
    added = alpha._handle_woocommerce(FakeResponse(200, body), decision, _WC_URL)

    assert added == 0, "no wc/v3 shape → InsufficientData, not a finding"
    assert alpha._findings == 0
    assert graph.nodes_by_type(NodeType.VULNERABILITY) == []


# ── 7. WP version from readme.html + <meta generator> ────────────────────────


def test_wp_version_from_readme_and_meta() -> None:
    meta_body = (
        '<html><head><meta name="generator" content="WordPress 6.5.2">'
        "</head><body>home</body></html>"
    )
    http = FakeHttpClient({_SITE_ROOT: FakeResponse(200, meta_body)})
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(http, graph)

    readme = (
        "<html><body><h1>WordPress</h1>"
        "<p>Semantic Personal Publishing Platform</p>"
        "<p>Version 6.5.2</p></body></html>"
    )
    decision = SimpleNamespace(tool="wp_version")
    alpha._handle_wp_version(FakeResponse(200, readme), decision, _README_URL)

    assert alpha._findings == 1, "a parseable version is a (low-sev) disclosure finding"
    assert _SITE_ROOT in http.get_calls, (
        "the handler must make the 2nd request for <meta generator>"
    )
    vulns = {n.id: n for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    vuln_id = f"vuln:{_HOST}:wp_version_disclosure"
    assert vuln_id in vulns
    assert "6.5.2" in vulns[vuln_id].properties.affected_service
