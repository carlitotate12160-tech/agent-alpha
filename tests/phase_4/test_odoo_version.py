from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from typing import Any

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, VulnerabilityProperties
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.odoo_dbmanager_probe import parse_odoo_version
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "target.example"
_SEED = f"https://{_HOST}/"
_REAL_PLAYBOOK_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"
)

# Odoo fingerprinted page
_ODOO_PAGE = (
    '<html><head><script src="/web/static/src/js/boot.js"></script></head>'
    '<body>odoo.define("web.example", function () {});</body></html>'
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, dict[str, FakeResponse]]) -> None:
        # Map method -> url -> response
        self._routes = routes
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, Any, bool]] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        return self._routes.get("GET", {}).get(url, FakeResponse(404, ""))

    def post(
        self, url: str, json_body: Any = None, allow_redirects: bool = True, **kwargs: Any
    ) -> FakeResponse:
        self.post_calls.append((url, json_body, allow_redirects))
        return self._routes.get("POST", {}).get(url, FakeResponse(404, ""))


class _StubProvider:
    model = "stub"

    def complete(self, *args: object, **kwargs: object) -> Any:
        return type(
            "R",
            (),
            {"text": '{"tool": "generic_http_probe"}', "usage_cost_usd": 0.001, "model": "stub"},
        )()


def _alpha(http: FakeHttpClient, do_enable_recon: bool = True) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="odoo_lab", target=_HOST)
    if do_enable_recon:
        auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))

    engine = PlaybookEngine.from_directory(_REAL_PLAYBOOK_DIR, phase="recon")
    orchestrator = LLMOrchestrator(engine, _StubProvider())
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orchestrator,
        http_client=http,
    )
    return alpha, rec.engagement_id


def test_odoo_fingerprint_mints_version_disclosure() -> None:
    # Positive case: Odoo page fingerprinted -> POST /version_info -> mint vuln & asset
    routes = {
        "GET": {
            _SEED: FakeResponse(200, _ODOO_PAGE),
        },
        "POST": {
            f"https://{_HOST}{constants.ODOO_VERSION_INFO_PATH}": FakeResponse(
                200,
                json.dumps({"result": {"server_version": "12.0-20221012", "server_serie": "12.0"}}),
            )
        },
    }
    alpha, eid = _alpha(FakeHttpClient(routes))

    alpha.run_recon(eid, _SEED)

    # Asset must be merged
    asset = alpha.graph_store.get_node(f"asset:{_HOST}")
    assert asset is not None
    assert "odoo" in asset.properties.tech_stack

    # Vuln must be minted
    vuln_id = f"vuln:{_HOST}:odoo_version_disclosure"
    vuln = alpha.graph_store.get_node(vuln_id)
    assert vuln is not None
    assert vuln.type == NodeType.VULNERABILITY
    assert isinstance(vuln.properties, VulnerabilityProperties)
    assert vuln.properties.affected_service == "Odoo 12.0-20221012"
    assert vuln.properties.cvss_score == 3.1
    assert vuln.properties.exploit_available is False

    # Edge EXPLOITS must exist
    edge = alpha.graph_store.get_edge(source_id=f"asset:{_HOST}", target_id=vuln_id)
    assert edge is not None

    # findings count EXACTLY 1 (anti double-count)
    assert alpha._findings == 1


def test_odoo_fingerprint_version_tier_negative() -> None:
    # Cardinal negative: state < RECON_ONLY -> no POST, no finding
    routes = {
        "GET": {
            _SEED: FakeResponse(200, _ODOO_PAGE),
        },
        "POST": {
            f"https://{_HOST}{constants.ODOO_VERSION_INFO_PATH}": FakeResponse(
                200, json.dumps({"result": {"server_version": "12.0-20221012"}})
            )
        },
    }
    http = FakeHttpClient(routes)
    alpha, eid = _alpha(http, do_enable_recon=False)

    alpha.run_recon(eid, _SEED)

    assert len(http.post_calls) == 0
    assert alpha.graph_store.get_node(f"vuln:{_HOST}:odoo_version_disclosure") is None
    assert alpha._findings == 0


def test_odoo_fingerprint_no_redirects() -> None:
    # 3xx redirect -> should NOT be followed, returns 0, no finding
    routes = {
        "GET": {
            _SEED: FakeResponse(200, _ODOO_PAGE),
        },
        "POST": {
            f"https://{_HOST}{constants.ODOO_VERSION_INFO_PATH}": FakeResponse(
                301, "<html>Redirecting</html>", headers={"Location": "https://other.com/evil"}
            )
        },
    }
    http = FakeHttpClient(routes)
    alpha, eid = _alpha(http)

    alpha.run_recon(eid, _SEED)

    assert len(http.post_calls) == 1
    # Check that allow_redirects=False was passed
    url, body, allow_redirects = http.post_calls[0]
    assert allow_redirects is False

    assert alpha.graph_store.get_node(f"vuln:{_HOST}:odoo_version_disclosure") is None
    assert alpha._findings == 0


def test_odoo_fingerprint_anti_3_403_waf_blocked() -> None:
    # Anti-#3: WAF blocks version_info -> WAF_BLOCKED event, no finding, no version
    routes = {
        "GET": {
            _SEED: FakeResponse(200, _ODOO_PAGE),
        },
        "POST": {
            f"https://{_HOST}{constants.ODOO_VERSION_INFO_PATH}": FakeResponse(
                403, "<html>CF block</html>"
            )
        },
    }
    alpha, eid = _alpha(FakeHttpClient(routes))

    alpha.run_recon(eid, _SEED)

    assert alpha.graph_store.get_node(f"vuln:{_HOST}:odoo_version_disclosure") is None

    waf_events = [
        e for e in alpha.event_store.get_events(eid) if e.event_type == EventType.WAF_BLOCKED
    ]
    assert len(waf_events) == 1
    assert waf_events[0].payload["path"] == constants.ODOO_VERSION_INFO_PATH


def test_odoo_fingerprint_parser_tolerant() -> None:
    # Parser tolerant: non-JSON / missing field -> returns None -> no finding
    assert parse_odoo_version({}) is None
    assert parse_odoo_version({"result": {}}) is None

    routes = {
        "GET": {
            _SEED: FakeResponse(200, _ODOO_PAGE),
        },
        "POST": {
            f"https://{_HOST}{constants.ODOO_VERSION_INFO_PATH}": FakeResponse(
                200, "<html>Not JSON</html>"
            )
        },
    }
    alpha, eid = _alpha(FakeHttpClient(routes))

    alpha.run_recon(eid, _SEED)

    assert alpha.graph_store.get_node(f"vuln:{_HOST}:odoo_version_disclosure") is None


def test_generic_handlers_still_dispatch() -> None:
    # Regression: Ensure that other fingerprint rules still dispatch correctly
    routes = {
        "GET": {
            _SEED: FakeResponse(200, "tomcat server", headers={"server": "tomcat"}),
        }
    }

    class TomcatStubProvider:
        model = "stub"

        def complete(self, *args: object, **kwargs: object) -> Any:
            return type(
                "R",
                (),
                {"text": '{"tool": "tomcat_fingerprint"}', "usage_cost_usd": 0.0, "model": "stub"},
            )()

    http = FakeHttpClient(routes)
    alpha, eid = _alpha(http)
    alpha.orchestrator = LLMOrchestrator(
        PlaybookEngine.from_directory(_REAL_PLAYBOOK_DIR, phase="recon"),
        TomcatStubProvider(),
    )

    alpha.run_recon(eid, _SEED)

    asset = alpha.graph_store.get_node(f"asset:{_HOST}")
    assert asset is not None
    assert "tomcat" in asset.properties.tech_stack
