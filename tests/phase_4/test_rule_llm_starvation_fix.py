# Bug #2/#6 pin — end-to-end proof that the exclude_tools wiring actually
# reaches production behaviour, not just the underlying playbook.py/
# orchestrator.py mechanism (those are unit-tested separately in
# tests/phase_2/test_playbook_engine.py and tests/phase_2/test_llm_orchestrator.py).
#
# Real PlaybookEngine (loaded from the actual agent_alpha/tools/playbooks/
# directory, phase="recon" — exactly what build_recon_pipeline() constructs)
# + real LLMOrchestrator + a stub LLM provider. Two Odoo-fingerprinted pages:
# page 1 triggers odoo_dbmanager_probe via the RULE tier (as before); page 2
# has the identical fingerprint and, before this fix, would have hit the same
# RULE tier decision forever (decide() checks RULE before LLM,
# unconditionally) even though the handler is a no-op the second time
# (idempotency guard). After the fix it must reach the LLM tier instead.
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
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "target.example"
_SEED = f"https://{_HOST}/"
_PAGE2 = f"https://{_HOST}/about"
_REAL_PLAYBOOK_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"
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

    assert "odoo_dbmanager_probe" in alpha._ran_campaigns, (
        "test setup invalid: the Odoo fingerprint on page 1 never triggered the RULE tier at all"
    )
    assert provider.calls >= 1, (
        "Bug #2/#6 regression: the second Odoo-fingerprinted page was still "
        "handed the same RULE decision instead of reaching the LLM tier once "
        "odoo_dbmanager_probe had already run this engagement"
    )
