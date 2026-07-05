# tests/phase_3/test_odoo_wiring.py
#
# Slice 1b — wire the Odoo dbmanager probe into the LIVE path (kills #2 island).
# AUTHORED BY: Claude (test/gate lane).
#
# PINS:
#   Reachability (production RULE-tier selection):
#     R1  an Odoo fingerprint deterministically selects odoo_dbmanager_probe.
#     R2  a plain page selects NEITHER odoo nor another vector (anti-#3 over-probe).
#     R3  regression: WP / Laravel / SPA rules still select their own tools.
#   Dispatch (anti-#2: the handler is actually reached + runs the sealed vector):
#     D1  odoo_dbmanager_probe is registered in Alpha's dispatch registry.
#     D2  dispatching it on an exposed manager lands an Odoo exposure vuln in the graph.
#   Catalog:
#     C1  odoo_dbmanager_probe is in RECON_TOOL_CATALOG (else coerced to generic).

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from types import SimpleNamespace

import agent_alpha.tools as tools_pkg
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.tools.playbook import PlaybookEngine

_PROD_PLAYBOOKS = pathlib.Path(tools_pkg.__file__).resolve().parent / "playbooks"
_HOST = "erp.lab-odoo.example"

_ODOO_BODY = (
    '<html><head><script src="/web/static/src/js/main.js"></script>'
    '<script>odoo.define("x", function () {});</script></head>'
    "<body><t t-name='web.assets_common'></t></body></html>"
)
_PLAIN_BODY = "<html><body><h1>Welcome</h1><script src='/js/analytics.js'></script></body></html>"
_ODOO_EXPOSED = (
    "<html><head><title>Odoo</title></head><body>"
    "<h1>Manage Databases</h1>"
    "<form action='/web/database/create'></form>"
    "<a href='/web/database/backup'>Backup</a>"
    "<a href='/web/database/drop'>Delete</a>"
    "<label>Master Password</label>"
    "<script src='/web/static/src/js/main.js'></script></body></html>"
)


def _tool_for(body: str) -> str | None:
    decision = PlaybookEngine.from_directory(_PROD_PLAYBOOKS).match({"body": body})
    return decision.tool if decision is not None else None


# ── reachability ────────────────────────────────────────────────────


def test_odoo_fingerprint_selects_odoo_dbmanager_probe() -> None:
    assert _tool_for(_ODOO_BODY) == "odoo_dbmanager_probe"


def test_plain_page_does_not_select_odoo_probe() -> None:
    assert _tool_for(_PLAIN_BODY) != "odoo_dbmanager_probe"


def test_wp_and_laravel_rules_unaffected() -> None:
    assert _tool_for("<html>Whoops! Illuminate\\Foundation error</html>") == "laravel_debug_probe"
    assert (
        _tool_for('<meta name="generator" content="WordPress 6.5"><a href="/wp-content/x">')
        == "wp_config_probe"
    )


# ── catalog ─────────────────────────────────────────────────────────


def test_probe_is_in_recon_tool_catalog() -> None:
    assert "odoo_dbmanager_probe" in constants.RECON_TOOL_CATALOG


# ── dispatch (anti-#2) ──────────────────────────────────────────────


@dataclass
class _Resp:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class _Http:
    def __init__(self, responses: dict[str, _Resp]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return self._responses.get(url, _Resp(404, "Not Found"))


def _alpha(http: _Http) -> tuple[Alpha, str]:
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="odoo_lab", target=_HOST)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=["203.0.113.7/32"], domains=[_HOST], exclusions=[], db_endpoints=[]),
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=event_store,
        orchestrator=SimpleNamespace(),
        http_client=http,
    )
    alpha._engagement_id = rec.engagement_id
    alpha._ran_campaigns = set()
    return alpha, rec.engagement_id


def test_probe_is_registered_in_dispatch_registry() -> None:
    alpha, _ = _alpha(_Http({}))
    assert "odoo_dbmanager_probe" in alpha._dispatch_registry


def test_dispatch_lands_odoo_exposure_in_graph() -> None:
    http = _Http({f"https://{_HOST}/web/database/manager": _Resp(200, _ODOO_EXPOSED)})
    alpha, _ = _alpha(http)
    decision = SimpleNamespace(tool="odoo_dbmanager_probe")
    n = alpha._handle_odoo_dbmanager(_Resp(200, ""), decision, f"https://{_HOST}/")
    assert n == 1
    vulns = alpha.graph_store.nodes_by_type(NodeType.VULNERABILITY)
    assert any("odoo_dbmanager" in v.id for v in vulns)
