# RED tests — Odoo two-rule split, slice 2 of 2 (NARROW probe on DB-manager body).
#
# The coarse odoo_fingerprint rule (test_odoo_fingerprint_seeds_not_probe.py) only
# DETECTS Odoo and seeds /web/database/manager. This file pins the NARROW rule:
# odoo_dbmanager_probe must fire ONLY on an actual DB-manager body signature
# (master_pwd + list_db) that classifies as EXPOSED (>= ODOO_DBMANAGER_MIN_ACTION_
# MARKERS), and it must persist the exposure finding (VULNERABILITY node,
# exploit_available=False, plus ASSET(odoo) + EXPLOITS edge).
#
# anti-#7: the EXPOSED body is built from the real ODOO_DBMANAGER_ACTION_MARKERS
# (imported from odoo_dbmanager_probe), never a redefined marker list here. The
# body deliberately omits the coarse fingerprint markers (/web/static/, odoo.define,
# /web/login) so ONLY the narrow rule can match — pinning the split, not a tie-break.
#
# Expected RED (production not written yet): the narrow master_pwd/list_db rule does
# not exist, so an EXPOSED-but-not-fingerprinted body matches no rule, falls to the
# LLM stub (generic_http_probe), and no exposure is persisted.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest \
#     tests/phase_4/test_odoo_dbmanager_narrow_trigger.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.odoo_dbmanager_probe import (
    EXPOSED,
    ODOO_DBMANAGER_ACTION_MARKERS,
    ODOO_DBMANAGER_MIN_ACTION_MARKERS,
    ODOO_DBMANAGER_PATH,
    classify_odoo_dbmanager,
)
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "odoo.example"
_MANAGER_URL = f"https://{_HOST}{ODOO_DBMANAGER_PATH}"
_VULN_ID = f"vuln:{_HOST}:odoo_dbmanager_exposed"
_ASSET_ID = f"asset:{_HOST}"
_REAL_PLAYBOOK_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"
)

# EXPOSED DB-manager body: master_pwd + list_db (the narrow-rule signature) plus
# >= MIN real action markers (reused from the probe's SSOT -> classify == EXPOSED),
# and NO coarse fingerprint marker so only the narrow rule can select this page.
_ACTION_MARKERS = ODOO_DBMANAGER_ACTION_MARKERS[:ODOO_DBMANAGER_MIN_ACTION_MARKERS]
_EXPOSED_MANAGER_BODY = (
    "<html><body>master_pwd list_db " + " ".join(_ACTION_MARKERS) + "</body></html>"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, FakeResponse]) -> None:
        self._routes = routes
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
            {"text": '{"tool": "generic_http_probe"}', "usage_cost_usd": 0.001, "model": "stub"},
        )()


def _alpha(graph: NetworkXGraphStore, provider: _StubProvider, http: FakeHttpClient):
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="odoo_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    engine = PlaybookEngine.from_directory(_REAL_PLAYBOOK_DIR, phase="recon")
    orchestrator = LLMOrchestrator(engine, provider)
    alpha = Alpha(
        authorization=auth,
        graph_store=graph,
        event_store=store,
        orchestrator=orchestrator,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    return alpha, rec.engagement_id


def test_exposed_body_is_a_precondition() -> None:
    # Sanity: the fixture is genuinely EXPOSED per the REAL classifier (anti-#7 —
    # we assert through the probe's own logic, not a hand-rolled expectation).
    assert classify_odoo_dbmanager(_EXPOSED_MANAGER_BODY) == EXPOSED


def test_manager_body_selects_narrow_probe_rule() -> None:
    # The narrow rule must fire on the DB-manager body signature...
    engine = PlaybookEngine.from_directory(_REAL_PLAYBOOK_DIR, phase="recon")

    decision = engine.match({"body": _EXPOSED_MANAGER_BODY, "headers": {}})

    assert decision is not None, "a live DB-manager body must match the narrow rule"
    assert decision.tool == "odoo_dbmanager_probe", (
        f"a master_pwd/list_db DB-manager body must select odoo_dbmanager_probe, "
        f"not {decision.tool!r}"
    )
    assert decision.tier == "rule"


def test_narrow_probe_persists_exposure_via_frontier() -> None:
    graph = NetworkXGraphStore()
    provider = _StubProvider()
    http = FakeHttpClient({_MANAGER_URL: FakeResponse(200, _EXPOSED_MANAGER_BODY)})
    alpha, eid = _alpha(graph, provider, http)

    # Drive the REAL recon loop against the live manager surface (non-island).
    alpha.run_recon(eid, _MANAGER_URL)

    assert "odoo_dbmanager_probe" in alpha._ran_campaigns, (
        "the narrow rule must actually run the probe on the DB-manager body"
    )

    vulns = {n.id: n for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    assert _VULN_ID in vulns, "an exposed DB-manager must persist an exposure VULNERABILITY node"
    assert vulns[_VULN_ID].properties.exploit_available is False, (
        "recon proves the surface only — exploit_available stays False (OFFENSIVE is Gamma)"
    )

    assets = {n.id: n for n in graph.nodes_by_type(NodeType.ASSET)}
    assert _ASSET_ID in assets, "the exposed host must be persisted as an ASSET"
    assert "odoo" in assets[_ASSET_ID].properties.tech_stack

    edges = graph.edges_by_relationship(RelationshipType.EXPLOITS)
    assert any(e.source_id == _ASSET_ID and e.target_id == _VULN_ID for e in edges), (
        "the ASSET must EXPLOITS-edge to the exposure VULNERABILITY"
    )
