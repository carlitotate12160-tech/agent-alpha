# R2 — WP selective crawl. A WP-fingerprinted host must not have its content
# pages (product/blog/category/about) queued for LLM-tier probing; only the
# known WP-internal surface (wp-admin, wp-json, wp-content/plugins|themes,
# xmlrpc.php) is worth crawling. Field evidence: unibis.co.id (2026-07-29) —
# 1249s / ~30 product-page probes / 0 findings from any of them, because
# _extract_hrefs had no selectivity and enqueue_discovered_url had no budget.
#
# CARDINAL (this file's reason to exist): the gate must apply ONLY to
# organically-discovered hrefs, never to deterministic catalog seeds
# (wp_fingerprint.frontier_seeds = "/wp-json/", "/readme.html" — neither one
# matches WP_CRAWL_ALLOW_PATH_PREFIXES). test_wp_recon.py's
# test_wp_battery_autofires_on_fingerprint already pins that those seeds keep
# firing; this file pins the NEW gate itself plus that same non-interference
# from the opposite direction.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_wp_crawl_selectivity.py -v

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

_HOST = "unibis.example"
_SITE_ROOT = f"https://{_HOST}/"
_README_URL = f"https://{_HOST}/readme.html"
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
    rec = auth.create_engagement(client_id="wp_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
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


# ── 1. Unit: the gate itself, direct ──────────────────────────────────────


def test_gate_permissive_before_any_fingerprint() -> None:
    """Unknown host (never fingerprinted) — gate is a no-op (backward compat)."""
    alpha, _ = _alpha(FakeHttpClient())
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/product/tin-a") is True


def test_gate_blocks_content_path_after_wp_tag() -> None:
    """After wp_fingerprint tags the host, a product page is rejected."""
    alpha, _ = _alpha(FakeHttpClient())
    alpha._host_stack[_HOST] = {constants.STACK_WP}
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/product/tin-a") is False
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/about") is False
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/blog/post-1") is False


def test_gate_allows_wp_surface_after_wp_tag() -> None:
    """Security-relevant WP paths still pass once the host is tagged."""
    alpha, _ = _alpha(FakeHttpClient())
    alpha._host_stack[_HOST] = {constants.STACK_WP}
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/wp-content/plugins/foo/x.js") is True
    assert (
        alpha._frontier_expansion_allowed(f"https://{_HOST}/wp-content/themes/bar/style.css")
        is True
    )
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/wp-admin/plugins.php") is True
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/wp-json/wc/v3") is True
    assert alpha._frontier_expansion_allowed(f"https://{_HOST}/xmlrpc.php") is True


# ── 2. CARDINAL regression: deterministic seeds bypass the gate ───────────


def test_fingerprint_own_seeds_are_never_gated() -> None:
    """wp_fingerprint's frontier_seeds ("/wp-json/", "/readme.html") must
    enqueue even though NEITHER matches WP_CRAWL_ALLOW_PATH_PREFIXES.

    This is the reason the gate lives in the frontier-expansion call site
    (organic hrefs only) and NOT inside enqueue_discovered_url (shared by
    every deterministic seed path). If this test fails, the gate has been
    moved to the wrong seam and WP_battery auto-fire (test_wp_recon.py #10)
    is silently broken.
    """
    body = "<html><body>wp-content</body></html>"
    alpha, _ = _alpha(FakeHttpClient({_SITE_ROOT: FakeResponse(200, body)}))

    decision = SimpleNamespace(tool="wp_fingerprint")
    alpha._handle_capability_fingerprint(FakeResponse(200, body), decision, _SITE_ROOT)

    assert f"https://{_HOST}/wp-json/" in alpha._work_queue
    assert _README_URL in alpha._work_queue
    assert constants.STACK_WP in alpha._host_stack[_HOST]


# ── 3. E2E: full run_recon — content hrefs dropped, WP surface href kept ──


def test_e2e_content_hrefs_dropped_wp_surface_href_kept() -> None:
    """Homepage links to 2 product pages + 1 wp-admin page. After run_recon,
    the product pages must NEVER have been fetched (dropped before queueing);
    the wp-admin page IS fetched (selective crawl kept it)."""
    homepage = (
        "<html><body>wp-content"
        '<a href="/product/tin-a">Tin A</a>'
        '<a href="/product/tin-b">Tin B</a>'
        '<a href="/wp-admin/plugins.php">Plugins</a>'
        "</body></html>"
    )
    routes = {
        _SITE_ROOT: FakeResponse(200, homepage),
        f"https://{_HOST}/wp-admin/plugins.php": FakeResponse(200, "<html></html>"),
        f"https://{_HOST}/wp-json/": FakeResponse(404, ""),
        _README_URL: FakeResponse(404, ""),
    }
    http = FakeHttpClient(routes)
    alpha, eng_id = _alpha(http)

    alpha.run_recon(eng_id, _SITE_ROOT)

    assert not any("/product/" in c for c in http.get_calls), (
        f"content page was fetched — selective crawl did not hold: {http.get_calls}"
    )
    assert f"https://{_HOST}/wp-admin/plugins.php" in http.get_calls, (
        "WP-internal surface href must still be crawled"
    )


# ── 4. Regression: non-WP host is completely unaffected ───────────────────


def test_non_wp_host_crawl_unaffected() -> None:
    """A host that never matches wp_fingerprint keeps today's FIFO behaviour —
    every same-origin href is still enqueued, product-style paths included."""
    homepage = (
        "<html><body>Just a plain site, no CMS markers here."
        '<a href="/products">Products</a>'
        '<a href="/contact">Contact</a>'
        "</body></html>"
    )
    http = FakeHttpClient({_SITE_ROOT: FakeResponse(200, homepage)})
    alpha, eng_id = _alpha(http)

    alpha.run_recon(eng_id, _SITE_ROOT)

    assert any("/products" in c for c in http.get_calls), (
        "non-WP host must keep crawling ordinary same-origin hrefs (no false-positive gating)"
    )
