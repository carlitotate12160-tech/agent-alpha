# Bug #2/#6 pin — end-to-end proof that the exclude_tools wiring actually
# reaches production behaviour, not just the underlying playbook.py/
# orchestrator.py mechanism (those are unit-tested separately in
# tests/phase_2/test_playbook_engine.py and tests/phase_2/test_llm_orchestrator.py).
#
# Real PlaybookEngine (loaded from the actual agent_alpha/tools/playbooks/
# directory, phase="recon" — exactly what build_recon_pipeline() constructs)
# + real LLMOrchestrator + a stub LLM provider. Two Odoo-fingerprinted pages:
# page 1 triggers the coarse odoo_fingerprint RULE (post two-rule split — it
# used to be odoo_dbmanager_probe; the tool that fires on page 1 changed, the
# anti-#2 guarantee did NOT); page 2 has the identical fingerprint and, before
# this fix, would have hit the same RULE tier decision forever (decide() checks
# RULE before LLM, unconditionally) even though the handler is a no-op the second
# time (idempotency guard). After the fix it must reach the LLM tier instead —
# which requires odoo_fingerprint to be recorded as a run-once campaign in
# _ran_campaigns (a plain capability-handler reuse does NOT do this).
#
# A THIRD page (a live /web/database/manager body carrying master_pwd + list_db)
# must still select the NARROW odoo_dbmanager_probe — proven through a real run
# down the scout frontier (non-island), not a unit-island call.
#
# Run on Oracle ARM64 only:
#     .venv312/bin/python3 -m pytest tests/phase_4/test_rule_llm_starvation_fix.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.odoo_dbmanager_probe import (
    ODOO_DBMANAGER_ACTION_MARKERS,
    ODOO_DBMANAGER_MIN_ACTION_MARKERS,
    ODOO_DBMANAGER_PATH,
)
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "target.example"
_SEED = f"https://{_HOST}/"
_PAGE2 = f"https://{_HOST}/about"
_MANAGER_URL = f"https://{_HOST}{ODOO_DBMANAGER_PATH}"
_VULN_ID = f"vuln:{_HOST}:odoo_dbmanager_exposed"
_REAL_PLAYBOOK_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"
)

# A live DB-manager body: master_pwd + list_db (narrow-rule signature) plus >= MIN
# real action markers (reused from the probe SSOT -> classifies EXPOSED, anti-#7).
# No coarse fingerprint marker, so ONLY the narrow rule can select it.
_ACTION_MARKERS = ODOO_DBMANAGER_ACTION_MARKERS[:ODOO_DBMANAGER_MIN_ACTION_MARKERS]
_ODOO_MANAGER_BODY = (
    "<html><body>master_pwd list_db " + " ".join(_ACTION_MARKERS) + "</body></html>"
)

# Genuine Odoo fingerprint (matches odoo_dbmanager.yaml's any_indicator) plus
# an in-scope link to a second page carrying the identical fingerprint.
_ODOO_PAGE_1 = (
    '<html><head><script src="/web/static/src/js/boot.js"></script></head>'
    '<body>odoo.define("web.example", function () {});'
    '<a href="/about">About</a></body></html>'
)
_ODOO_PAGE_2 = (
    '<html><head><script src="/web/static/src/js/boot.js"></script></head>'
    '<body>odoo.define("web.example", function () {});</body></html>'
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, FakeResponse]) -> None:
        self._routes = routes

    def get(self, url: str) -> FakeResponse:
        # Everything not explicitly mapped (well-known leak paths, surface
        # discovery paths, the probe's own /web/database/manager check) is a
        # safe non-analyzable 404 — irrelevant noise for this test.
        return self._routes.get(url, FakeResponse(404, ""))


class _StubProvider:
    """Records every call; returns a fixed, always-valid tool selection."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, *args: object, **kwargs: object):
        self.calls += 1
        return type(
            "R",
            (),
            {"text": '{"tool": "generic_http_probe"}', "usage_cost_usd": 0.001, "model": "stub"},
        )()


def _alpha(provider: _StubProvider, http: FakeHttpClient) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    # phase="recon" — exactly what build_recon_pipeline() constructs for Alpha.
    engine = PlaybookEngine.from_directory(_REAL_PLAYBOOK_DIR, phase="recon")
    orchestrator = LLMOrchestrator(engine, provider)
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orchestrator,
        http_client=http,
    )
    return alpha, rec.engagement_id


def test_second_odoo_page_reaches_llm_tier_after_probe_already_ran() -> None:
    provider = _StubProvider()
    http = FakeHttpClient(
        {
            _SEED: FakeResponse(200, _ODOO_PAGE_1),
            _PAGE2: FakeResponse(200, _ODOO_PAGE_2),
        }
    )
    alpha, eid = _alpha(provider, http)

    alpha.run_recon(eid, _SEED)

    assert "odoo_fingerprint" in alpha._ran_campaigns, (
        "test setup invalid: page 1's Odoo fingerprint never triggered the coarse "
        "odoo_fingerprint RULE as a run-once campaign (post two-rule split) — without "
        "that recording, page 2 cannot be excluded at the RULE tier and this test "
        "would prove nothing"
    )
    assert provider.calls >= 1, (
        "Bug #2/#6 regression: the second Odoo-fingerprinted page was still "
        "handed the same RULE decision instead of reaching the LLM tier once "
        "odoo_dbmanager_probe had already run this engagement"
    )


def test_live_manager_body_selects_narrow_probe_via_frontier() -> None:
    # The two-rule split must NOT lose the narrow trigger: an ordinary Odoo root
    # fingerprints (odoo_fingerprint) and seeds /web/database/manager; the manager
    # page carries the live DB-manager body, and the NARROW rule must fire
    # odoo_dbmanager_probe on it — proven by a real run down the scout frontier,
    # not a unit-island call. RED today: the manager URL is only reached via the
    # verifier's internal re-fetch (never enqueued to the frontier), so it is not
    # in _probed.
    provider = _StubProvider()
    http = FakeHttpClient(
        {
            _SEED: FakeResponse(200, _ODOO_PAGE_1),
            _MANAGER_URL: FakeResponse(200, _ODOO_MANAGER_BODY),
        }
    )
    alpha, eid = _alpha(provider, http)

    alpha.run_recon(eid, _SEED)

    assert _MANAGER_URL in alpha._probed, (
        "the manager page must be reached through the fingerprint's frontier seed "
        "(non-island), not a probe-internal re-fetch"
    )
    assert "odoo_dbmanager_probe" in alpha._ran_campaigns, (
        "the narrow rule must fire odoo_dbmanager_probe on the live DB-manager body"
    )
    vuln_ids = {n.id for n in alpha.graph_store.nodes_by_type(NodeType.VULNERABILITY)}
    assert _VULN_ID in vuln_ids, "the exposed manager must persist an exposure VULNERABILITY node"
