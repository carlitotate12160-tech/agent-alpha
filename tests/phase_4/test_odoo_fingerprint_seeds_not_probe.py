# RED tests — Odoo two-rule split, slice 1 of 2 (fingerprint -> seed, NOT probe).
#
# TODAY odoo_dbmanager.yaml fires odoo_dbmanager_probe on ANY Odoo marker
# (/web/static/, odoo.define, /web/login). That pre-empts the LLM on the FIRST
# Odoo page (Bug #2 starvation) and drives verify_odoo_dbmanager_exposure, which
# re-fetches /web/database/manager (double-recon). This file pins the CORRECTED
# coarse tier: an ordinary Odoo page must select a DETECT-only odoo_fingerprint
# RULE that persists ASSET(odoo) and SEEDS /web/database/manager to the frontier
# — it must NOT run odoo_dbmanager_probe (that is the narrow tier, pinned in
# test_odoo_dbmanager_narrow_trigger.py).
#
# DESIGN NOTE (flaw the sealed contract exposes): for the SECOND identical Odoo
# page to reach the LLM (anti-#2), odoo_fingerprint must be recorded in
# Alpha._ran_campaigns after the first hit, so decide_excluding() skips its rule
# thereafter. The existing _handle_capability_fingerprint deliberately does NOT
# populate _ran_campaigns (tomcat/s3 may re-fire), so a literal capability-handler
# reuse will NOT satisfy this — the production fix needs a thin
# _handle_odoo_fingerprint wrapper that records the run-once campaign then
# delegates. These tests encode that CONTRACT, not the shortcut.
#
# Expected RED (production not written yet):
#   * test_ordinary_odoo_page_selects_odoo_fingerprint_rule  -> AssertionError:
#     the broad rule still returns "odoo_dbmanager_probe".
#   * test_run_recon_seeds_manager_and_does_not_run_probe     -> AssertionError:
#     odoo_dbmanager_probe still fires (present in _ran_campaigns) and the
#     manager path is re-fetched internally, never seeded to the frontier.
#   * test_second_odoo_page_reaches_llm_via_fingerprint_exclusion -> AssertionError:
#     odoo_fingerprint is not yet recorded in _ran_campaigns.
#
# Run on Oracle ARM64 only (system python 3.10 fails StrEnum):
#   .venv312/bin/python3 -m pytest \
#     tests/phase_4/test_odoo_fingerprint_seeds_not_probe.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.odoo_dbmanager_probe import ODOO_DBMANAGER_PATH
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "target.example"
_SEED = f"https://{_HOST}/"
_PAGE2 = f"https://{_HOST}/about"
_MANAGER_URL = f"https://{_HOST}{ODOO_DBMANAGER_PATH}"
_REAL_PLAYBOOK_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"
)

# An ORDINARY Odoo page: Odoo-fingerprinted (odoo.define + /web/static/) but with
# NO DB-manager body signature (no master_pwd / list_db / action markers). It must
# route via the coarse odoo_fingerprint rule, never the narrow probe.
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
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        # Everything not explicitly mapped (well-known leak paths, surface
        # discovery paths, the seeded manager path) is a safe non-analyzable 404.
        return self._routes.get(url, FakeResponse(404, ""))


class _StubProvider:
    """Records every call; returns a fixed, always-valid tool selection. The LLM
    tier must NEVER be the path that fingerprints an Odoo page (that is the RULE
    tier's job) — provider.calls counts genuine escalations only."""

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


def _alpha(provider: _StubProvider, http: FakeHttpClient) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="odoo_lab", target=_HOST)
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


def test_ordinary_odoo_page_selects_odoo_fingerprint_rule() -> None:
    # The REAL recon PlaybookEngine (the SSOT for rule selection) must classify an
    # ordinary Odoo page as the coarse fingerprint, NOT the narrow DB-manager probe.
    engine = PlaybookEngine.from_directory(_REAL_PLAYBOOK_DIR, phase="recon")

    decision = engine.match({"body": _ODOO_PAGE_1, "headers": {}})

    assert decision is not None, "an Odoo-fingerprinted page must still match a RULE"
    assert decision.tool == "odoo_fingerprint", (
        "an ordinary Odoo page (no master_pwd / list_db) must select the coarse "
        f"odoo_fingerprint rule, not {decision.tool!r} — the broad DB-manager rule "
        "is the Bug #2 starvation + double-recon root cause"
    )
    assert decision.tier == "rule"


def test_run_recon_seeds_manager_and_does_not_run_probe() -> None:
    provider = _StubProvider()
    http = FakeHttpClient({_SEED: FakeResponse(200, _ODOO_PAGE_1)})
    alpha, eid = _alpha(provider, http)

    # Observe the frontier-seed effect directly (not by re-reading YAML): the
    # fingerprint handler routes /web/database/manager through the same in-scope
    # enqueue_discovered_url guard as every other discovery.
    seeded: list[str] = []
    original_enqueue = alpha.enqueue_discovered_url

    def _spy(url: str) -> None:
        seeded.append(url)
        original_enqueue(url)

    alpha.enqueue_discovered_url = _spy  # type: ignore[method-assign]

    alpha.run_recon(eid, _SEED)

    assert _MANAGER_URL in seeded, (
        "the coarse fingerprint must SEED /web/database/manager to the frontier "
        "(the narrow probe then classifies the body the loop fetches — no re-fetch)"
    )
    assert _MANAGER_URL in alpha._probed, (
        "the seeded manager path must be reached through the LIVE frontier "
        "(popped + probed), proving a non-island wiring — not an internal re-fetch"
    )
    assert "odoo_dbmanager_probe" not in alpha._ran_campaigns, (
        "an ordinary Odoo page must NOT run odoo_dbmanager_probe — that coarse "
        "trigger is the double-recon / starvation bug being split out"
    )


def test_second_odoo_page_reaches_llm_via_fingerprint_exclusion() -> None:
    # anti-#2 guarantee, carried across the refactor: once odoo_fingerprint has
    # fired for this engagement it becomes a run-once campaign, so a SECOND
    # identically-fingerprinted page is excluded at the RULE tier and reaches the
    # LLM instead of being handed the same deterministic decision forever.
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
        "odoo_fingerprint must be recorded as a run-once campaign so decide_excluding "
        "skips its rule on the second page — a plain _handle_capability_fingerprint "
        "reuse (which never records _ran_campaigns) does NOT satisfy anti-#2"
    )
    assert provider.calls >= 1, (
        "Bug #2 regression: the second Odoo-fingerprinted page was still handed the "
        "same RULE decision instead of reaching the LLM tier once odoo_fingerprint "
        "had already run this engagement"
    )
