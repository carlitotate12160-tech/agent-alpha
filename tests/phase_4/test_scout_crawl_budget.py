# Stack-agnostic organic-crawl budget (MAX_ORGANIC_CRAWL_PER_HOST).
#
# _frontier_expansion_allowed() already bounds WP hosts via
# WP_CRAWL_ALLOW_PATH_PREFIXES, but returns True (permissive) for any host
# NOT tagged STACK_WP. Laravel/Odoo/unknown hosts therefore crawl every
# organic href unbounded (field evidence: unibis.co.id 2026-07-29, 20min /
# 30+ product pages). This test file pins the universal per-host cap on
# ORGANIC-crawl hrefs only. Catalog seeds call enqueue_discovered_url()
# directly and MUST stay uncounted/unfiltered.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_scout_crawl_budget.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from types import SimpleNamespace

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "laravel.example"
_SITE_ROOT = f"https://{_HOST}/"
_PLAYBOOK_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, FakeResponse] | None = None) -> None:
        self._routes = routes or {}
        self.get_calls: list[str] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.get_calls.append(url)
        return self._routes.get(url, FakeResponse(404, ""))


class _StubProvider:
    model = "stub"

    def complete(self, *args: object, **kwargs: object):
        return type(
            "R",
            (),
            {"text": '{"tool": "generic_http_probe"}', "usage_cost_usd": 0.0, "model": "stub"},
        )()


def _alpha(http: FakeHttpClient) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="budget_lab", target=_HOST)
    auth.enable_recon(
        rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[])
    )
    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR, phase="recon")
    orchestrator = LLMOrchestrator(engine, _StubProvider())
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orchestrator,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    alpha._engagement_id = rec.engagement_id
    return alpha, rec.engagement_id


def _make_hrefs(host: str, prefix: str, count: int) -> str:
    """Build HTML with *count* same-origin <a> tags to /{prefix}/{i}."""
    links = "".join(
        f'<a href="/{prefix}/{i}">link {i}</a>' for i in range(count)
    )
    return f"<html><body>plain site{links}</body></html>"


# ── 1. Laravel/unknown host: 30 organic hrefs → exactly 25 enqueued ────────


def test_unknown_host_30_organic_hrefs_caps_at_25() -> None:
    """A non-WP host with 30 organic /product/* hrefs: exactly
    MAX_ORGANIC_CRAWL_PER_HOST (25) must be enqueued, 5 rejected by budget."""
    homepage = _make_hrefs(_HOST, "product", 30)
    routes = {_SITE_ROOT: FakeResponse(200, homepage)}
    for i in range(30):
        url = f"https://{_HOST}/product/{i}"
        routes[url] = FakeResponse(200, "<html></html>")
    http = FakeHttpClient(routes)
    alpha, eng_id = _alpha(http)

    alpha.run_recon(eng_id, _SITE_ROOT)

    product_calls = [c for c in http.get_calls if "/product/" in c]
    assert len(product_calls) == constants.MAX_ORGANIC_CRAWL_PER_HOST, (
        f"Expected exactly {constants.MAX_ORGANIC_CRAWL_PER_HOST} product-page "
        f"fetches, got {len(product_calls)}: {product_calls}"
    )


# ── 2. WP host: 30 /product/* hrefs → 0 enqueued (WP allowlist first) ──────


def test_wp_host_product_hrefs_rejected_by_allowlist() -> None:
    """A WP-tagged host with 30 /product/* hrefs: WP allowlist rejects them
    before the budget matters — 0 enqueued.

    The host is tagged STACK_WP during the run by including 'wp-content' in
    the homepage body, which triggers the wp_fingerprint playbook."""
    links = "".join(
        f'<a href="/product/{i}">link {i}</a>' for i in range(30)
    )
    homepage = f"<html><body>wp-content{links}</body></html>"
    routes = {
        _SITE_ROOT: FakeResponse(200, homepage),
        f"https://{_HOST}/wp-json/": FakeResponse(404, ""),
        f"https://{_HOST}/readme.html": FakeResponse(404, ""),
    }
    http = FakeHttpClient(routes)
    alpha, eng_id = _alpha(http)

    alpha.run_recon(eng_id, _SITE_ROOT)

    product_calls = [c for c in http.get_calls if "/product/" in c]
    assert len(product_calls) == 0, (
        f"WP allowlist must reject /product/* before budget; got {product_calls}"
    )


# ── 3. WP host: 40 /wp-content/plugins/* hrefs → capped at 25 ──────────────


def test_wp_host_allowlisted_paths_capped_by_budget() -> None:
    """A WP-tagged host with 40 /wp-content/plugins/* hrefs: these pass the
    WP allowlist, but the budget still caps them at 25.

    The host is tagged STACK_WP during the run by including 'wp-content' in
    the homepage body, which triggers the wp_fingerprint playbook."""
    links = "".join(
        f'<a href="/wp-content/plugins/{i}">plugin {i}</a>' for i in range(40)
    )
    homepage = f"<html><body>wp-content{links}</body></html>"
    routes = {
        _SITE_ROOT: FakeResponse(200, homepage),
        f"https://{_HOST}/wp-json/": FakeResponse(404, ""),
        f"https://{_HOST}/readme.html": FakeResponse(404, ""),
    }
    for i in range(40):
        url = f"https://{_HOST}/wp-content/plugins/{i}"
        routes[url] = FakeResponse(200, "<html></html>")
    http = FakeHttpClient(routes)
    alpha, eng_id = _alpha(http)

    alpha.run_recon(eng_id, _SITE_ROOT)

    plugin_calls = [
        c for c in http.get_calls if "/wp-content/plugins/" in c and c != _SITE_ROOT
    ]
    assert len(plugin_calls) == constants.MAX_ORGANIC_CRAWL_PER_HOST, (
        f"Budget must cap even allowlisted WP paths at "
        f"{constants.MAX_ORGANIC_CRAWL_PER_HOST}; got {len(plugin_calls)}"
    )


# ── 4. Catalog seeds still enqueued after organic budget exhausted ─────────


def test_catalog_seeds_bypass_organic_budget() -> None:
    """WELL_KNOWN_LEAK_PATHS must be fully enqueued even after the organic
    budget for that host is exhausted. Catalog seeds call
    enqueue_discovered_url() directly — they are not organic and not counted."""
    # Exhaust the budget manually
    homepage = _make_hrefs(_HOST, "product", 30)
    routes = {_SITE_ROOT: FakeResponse(200, homepage)}
    for i in range(30):
        url = f"https://{_HOST}/product/{i}"
        routes[url] = FakeResponse(200, "<html></html>")
    # Add a catalog-seed route that should still be fetched
    seed_url = f"https://{_HOST}/.git/config"
    routes[seed_url] = FakeResponse(404, "")
    http = FakeHttpClient(routes)
    alpha, eng_id = _alpha(http)

    alpha.run_recon(eng_id, _SITE_ROOT)

    # The catalog seed must have been fetched despite budget exhaustion
    assert seed_url in http.get_calls, (
        f"Catalog seed {seed_url} must bypass organic budget; "
        f"calls: {http.get_calls}"
    )


# ── 5. Budget resets between run_recon() calls ─────────────────────────────


def test_budget_resets_between_run_recon_calls() -> None:
    """The organic crawl counter is per-run state, not per-instance.
    A second run_recon() must start with a fresh budget."""
    homepage = _make_hrefs(_HOST, "product", 30)
    routes = {_SITE_ROOT: FakeResponse(200, homepage)}
    for i in range(30):
        url = f"https://{_HOST}/product/{i}"
        routes[url] = FakeResponse(200, "<html></html>")
    http = FakeHttpClient(routes)
    alpha, eng_id = _alpha(http)

    # First run — exhausts budget
    alpha.run_recon(eng_id, _SITE_ROOT)
    first_count = len([c for c in http.get_calls if "/product/" in c])
    assert first_count == constants.MAX_ORGANIC_CRAWL_PER_HOST

    # Reset http client to track second run
    http.get_calls.clear()

    # Second run — budget must be fresh
    alpha.run_recon(eng_id, _SITE_ROOT)
    second_count = len([c for c in http.get_calls if "/product/" in c])
    assert second_count == constants.MAX_ORGANIC_CRAWL_PER_HOST, (
        f"Budget must reset between runs; second run got {second_count} "
        f"product fetches (expected {constants.MAX_ORGANIC_CRAWL_PER_HOST})"
    )


# ── 6. Duplicate hrefs do not consume budget (regression) ────────────────────


def test_duplicate_hrefs_do_not_consume_budget() -> None:
    """Duplicate hrefs rejected by enqueue_discovered_url() must not consume
    the organic crawl budget. The budget increment now happens only when
    enqueue_discovered_url() returns True (successful enqueue)."""
    import pytest

    # Monkeypatch the budget cap to 3 for this test
    original_cap = constants.MAX_ORGANIC_CRAWL_PER_HOST
    constants.MAX_ORGANIC_CRAWL_PER_HOST = 3

    try:
        # Homepage with 3 duplicate hrefs to /same-link
        homepage = (
            "<html><body>"
            '<a href="/same-link">link1</a>'
            '<a href="/same-link">link2</a>'
            '<a href="/same-link">link3</a>'
            "</body></html>"
        )
        routes = {_SITE_ROOT: FakeResponse(200, homepage)}
        # Add 3 distinct hrefs that should be enqueued
        for i in range(3):
            url = f"https://{_HOST}/distinct/{i}"
            routes[url] = FakeResponse(200, "<html></html>")
        http = FakeHttpClient(routes)
        alpha, eng_id = _alpha(http)

        alpha.run_recon(eng_id, _SITE_ROOT)

        # All 3 distinct hrefs must be enqueued (budget not exhausted by duplicates)
        distinct_calls = [c for c in http.get_calls if "/distinct/" in c]
        assert len(distinct_calls) == 3, (
            f"Expected 3 distinct hrefs enqueued, got {len(distinct_calls)}: {distinct_calls}"
        )

        # Budget count must be 3 (not 6), because duplicates were deduped before increment
        assert alpha._organic_crawl_count.get(_HOST, 0) == 3, (
            f"Budget count must be 3 (distinct enqueues), got "
            f"{alpha._organic_crawl_count.get(_HOST, 0)}"
        )
    finally:
        # Restore original cap
        constants.MAX_ORGANIC_CRAWL_PER_HOST = original_cap
