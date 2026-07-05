# tests/phase_3/test_odoo_dbmanager_probe.py
#
# RED test — Odoo /web/database/manager exposure recon (Phase 4 breadth, Odoo).
# AUTHORED BY: Claude (test/gate lane). Bodies (classify_odoo_dbmanager,
#              verify_odoo_dbmanager_exposure) mirror the wp_config_probe contract.
#
# PINS:
#   T1  classifier: live manager markers -> "exposed".
#   T2  classifier: Odoo but management disabled -> "present_locked" (anti-#3).
#   T3  classifier: non-Odoo body -> "not_odoo".
#   T4  exposed 200 -> 1 VULNERABILITY(odoo_dbmanager_exposed) + odoo ASSET, return 1.
#   T5  present_locked 200 -> 0 exposure vuln (anti-#3 false-positive guard).
#   T6  non-Odoo 200 -> no odoo asset, no vuln.
#   T7  WAF (403) -> WAF_BLOCKED event, 0 vuln, NOT clean.
#   T8  out-of-scope co-tenant host -> never probed (scope gate).
#   T9  below RECON_ONLY tier -> fail-closed, nothing probed.
#   T10 probe URL is https:// (never plaintext).
#   T11 network error -> no crash, no finding.

from __future__ import annotations

from dataclasses import dataclass

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.odoo_dbmanager_probe import (
    EXPOSED,
    NOT_ODOO,
    ODOO_DBMANAGER_PATH,
    PRESENT_LOCKED,
    classify_odoo_dbmanager,
    verify_odoo_dbmanager_exposure,
)

_HOST = "erp.lab-odoo.example"

_EXPOSED_BODY = (
    "<html><head><title>Odoo</title></head><body>"
    "<h1>Manage Databases</h1>"
    "<form action='/web/database/create'>Create Database</form>"
    "<a href='/web/database/backup'>Backup</a>"
    "<a href='/web/database/restore'>Restore</a>"
    "<a href='/web/database/drop'>Delete</a>"
    "<label>Master Password</label>"
    "<script src='/web/static/src/js/main.js'></script>"
    "</body></html>"
)
_LOCKED_BODY = (
    "<html><head><title>Odoo</title></head><body>"
    "<script src='/web/static/src/js/main.js'></script>"
    "Database management disabled. Please contact your administrator."
    "</body></html>"
)
_NON_ODOO_BODY = "<html><body><h1>Welcome to nginx!</h1></body></html>"


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


class FakeHttpClient:
    def __init__(self, responses: dict[str, FakeResponse | Exception] | None = None) -> None:
        self._responses = responses or {}
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        r = self._responses.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            return FakeResponse(status_code=404, text="")
        return r


def _recon_engagement(
    event_store: InMemoryEventStore,
    *,
    domains: list[str] | None = None,
    state: a2a_pb2.PhaseStatus = a2a_pb2.RECON_ONLY,
) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="odoo_lab", target=_HOST)
    if state == a2a_pb2.RECON_ONLY:
        auth.enable_recon(
            rec.engagement_id,
            Scope(
                ip_ranges=["203.0.113.7/32"],
                domains=domains or [_HOST],
                exclusions=[],
                db_endpoints=[],
            ),
        )
    return auth, rec.engagement_id


@dataclass
class Ctx:
    auth: AuthorizationStateMachine
    engagement_id: str
    http: FakeHttpClient
    graph: NetworkXGraphStore
    event_store: InMemoryEventStore

    @property
    def args(self) -> dict:
        return dict(
            engagement_id=self.engagement_id,
            auth=self.auth,
            http_client=self.http,
            scope_hosts=[_HOST],
            graph_store=self.graph,
            event_store=self.event_store,
        )


def _ctx(responses: dict[str, FakeResponse | Exception] | None = None) -> Ctx:
    event_store = InMemoryEventStore()
    auth, eid = _recon_engagement(event_store)
    return Ctx(auth, eid, FakeHttpClient(responses), NetworkXGraphStore(), event_store)


def _url(host: str = _HOST) -> str:
    return f"https://{host}{ODOO_DBMANAGER_PATH}"


# ── classifier (pure) ──────────────────────────────────────────────


def test_classifier_exposed():
    assert classify_odoo_dbmanager(_EXPOSED_BODY) == EXPOSED


def test_classifier_present_locked_is_not_exposed():
    assert classify_odoo_dbmanager(_LOCKED_BODY) == PRESENT_LOCKED


def test_classifier_non_odoo():
    assert classify_odoo_dbmanager(_NON_ODOO_BODY) == NOT_ODOO


# ── verifier ───────────────────────────────────────────────────────


def test_exposed_manager_yields_one_vulnerability_and_odoo_asset():
    ctx = _ctx({_url(): FakeResponse(200, _EXPOSED_BODY)})
    n = verify_odoo_dbmanager_exposure(**ctx.args)
    assert n == 1
    vulns = ctx.graph.nodes_by_type(NodeType.VULNERABILITY)
    assert len(vulns) == 1
    assert "odoo_dbmanager" in vulns[0].id
    assert vulns[0].properties.exploit_available is False
    assets = ctx.graph.nodes_by_type(NodeType.ASSET)
    assert any("odoo" in a.properties.tech_stack for a in assets)


def test_present_locked_is_not_an_exposure_finding():
    ctx = _ctx({_url(): FakeResponse(200, _LOCKED_BODY)})
    n = verify_odoo_dbmanager_exposure(**ctx.args)
    assert n == 0
    assert ctx.graph.nodes_by_type(NodeType.VULNERABILITY) == []


def test_non_odoo_yields_nothing():
    ctx = _ctx({_url(): FakeResponse(200, _NON_ODOO_BODY)})
    n = verify_odoo_dbmanager_exposure(**ctx.args)
    assert n == 0
    assert ctx.graph.nodes_by_type(NodeType.VULNERABILITY) == []
    assert ctx.graph.nodes_by_type(NodeType.ASSET) == []


def test_waf_block_is_recorded_not_clean():
    ctx = _ctx({_url(): FakeResponse(403, "Request blocked")})
    n = verify_odoo_dbmanager_exposure(**ctx.args)
    assert n == 0
    assert any(
        e.event_type == EventType.WAF_BLOCKED for e in ctx.event_store.get_events(ctx.engagement_id)
    )
    assert ctx.graph.nodes_by_type(NodeType.VULNERABILITY) == []


def test_out_of_scope_host_never_probed():
    ctx = _ctx({_url(): FakeResponse(200, _EXPOSED_BODY)})
    args = ctx.args
    args["scope_hosts"] = ["sibling.odoo.sh"]  # not in scope.domains
    verify_odoo_dbmanager_exposure(**args)
    assert ctx.http.get_calls == []


def test_below_recon_tier_fails_closed():
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="odoo_lab", target=_HOST)  # stays CREATED
    http = FakeHttpClient({_url(): FakeResponse(200, _EXPOSED_BODY)})
    n = verify_odoo_dbmanager_exposure(
        engagement_id=rec.engagement_id,
        auth=auth,
        http_client=http,
        scope_hosts=[_HOST],
        graph_store=NetworkXGraphStore(),
        event_store=event_store,
    )
    assert n == 0
    assert http.get_calls == []


def test_probe_url_is_https():
    ctx = _ctx({_url(): FakeResponse(200, _EXPOSED_BODY)})
    verify_odoo_dbmanager_exposure(**ctx.args)
    assert ctx.http.get_calls
    assert all(u.startswith("https://") for u in ctx.http.get_calls)


def test_network_error_is_not_a_finding():
    ctx = _ctx({_url(): ConnectionError("unreachable")})
    n = verify_odoo_dbmanager_exposure(**ctx.args)
    assert n == 0
    assert ctx.graph.nodes_by_type(NodeType.VULNERABILITY) == []
