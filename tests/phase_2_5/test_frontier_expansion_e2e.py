"""Contract: R1 frontier expansion PROVEN END-TO-END through ``run_recon``.

Why this file exists (the gap #127 left open):
  The 14 tests in ``test_frontier_expansion.py`` prove the R1 SEAMS in isolation —
  they call ``enqueue_discovered_url`` / ``_extract_hrefs`` directly, and assert
  ``step()`` *contains* the calls via ``inspect.getsource`` (a source-substring
  guard). NONE of them drive ``run_recon``. So "the frontier actually grows and
  the discovered in-scope URLs actually get probed during a real recon loop" was
  code-verified-reachable but NOT execution-proven. A source-substring can pass
  while the call sits behind a dead branch; only running the loop closes that
  (anti-Lyndon #2: dead code treated as done).

These tests run the FULL recon loop (``run_recon`` -> ``run_cognitive_loop`` ->
``step`` x N) against a deterministic in-memory HTTP double and assert on
``http_client.calls`` — i.e. what Alpha *actually fetched*:

  T1  discovered same-origin in-scope links are fetched  (frontier grew + drained)
  T2  a cross-host link is NEVER fetched                 (same-origin scope safety)
  T3  a dead-end seed fetches only the seed              (anti-#11 differential; no
                                                           phantom expansion)
  T4  threshold=5 lets a deep link survive 3 dud probes  (turns the T0 magic-number
                                                           assertion into behaviour)

Design note surfaced while writing this (peer review, non-blocking):
  ``_extract_hrefs`` filters to SAME scheme+host as the seed, so the live R1 path
  only follows same-origin links. The unit test ``test_subdomain_href_enqueued``
  asserts ``enqueue_discovered_url`` accepts *subdomains*, but the live path never
  delivers a subdomain href to it (``_extract_hrefs`` drops cross-host first).
  That capability is therefore exercised only by the unit test, not end-to-end —
  it becomes live when R2 relaxes discovery to cross-host. Flagged, not fixed.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_frontier_expansion_e2e.py -v
Expected: 4 passed, 0 failed.
"""

from __future__ import annotations

import dataclasses

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

# ---------------------------------------------------------------------------
# Fixtures / doubles  (real Alpha + real auth/graph/event store; fake HTTP+LLM)
# ---------------------------------------------------------------------------

_SCOPE_HOST = "target.example.com"

_SEED = f"https://{_SCOPE_HOST}/"
_PRODUCTS = f"https://{_SCOPE_HOST}/products"
_CONTACT = f"https://{_SCOPE_HOST}/contact"
_EVIL = "https://evil.example.net/steal"  # cross-host -> must never be fetched


@dataclasses.dataclass(frozen=True)
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str]
    url: str


class _FakeHttpClient:
    """Deterministic HttpClient double. ``calls`` records every fetched URL so a
    test can assert Alpha *actually reached out* (not fabricated). Unknown URLs
    return an empty 404 (non-analyzable) rather than raising."""

    def __init__(self, routes: dict[str, _Resp]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:  # noqa: ARG002
        self.calls.append(url)
        return self._routes.get(url, _Resp(404, "", {}, url))


@dataclasses.dataclass
class _Decision:
    # A generic tool (NOT in Alpha._dispatch_registry) -> _handle_generic_probe,
    # which records one ASSET node (=1 progress) and never fabricates a finding.
    tool: str = "generic_http_probe"
    tier: str = "rule"
    reasoning: str = "e2e stub: generic probe"
    cost_usd: float = 0.0


class _StubOrchestrator:
    """Fixed generic decision. R1 frontier behaviour does not depend on tool
    routing (routing is covered by phase_2/phase_3 tests); pinning the decision
    keeps this test focused on frontier growth."""

    def decide(self, observation: dict[str, object]) -> _Decision:  # noqa: ARG002
        return _Decision()


def _page(url: str, body: str) -> _Resp:
    return _Resp(200, body, {"server": "nginx"}, url)


def _make_recon_alpha(routes: dict[str, _Resp]) -> tuple[Alpha, str]:
    """Real Alpha cleared to RECON_ONLY with scope = {target.example.com}."""
    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="client_lab", target=_SCOPE_HOST)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=[_SCOPE_HOST], exclusions=[]),
    )
    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_StubOrchestrator(),
        http_client=_FakeHttpClient(routes),
    )
    return agent, rec.engagement_id


_SEED_BODY = (
    "<html><body>"
    '<a href="/products">Products</a>'
    f'<a href="https://{_SCOPE_HOST}/contact">Contact</a>'
    f'<a href="{_EVIL}">External</a>'
    "</body></html>"
)


# ---------------------------------------------------------------------------
# T1 — frontier GROWS and discovered in-scope links are actually probed
# ---------------------------------------------------------------------------


def test_run_recon_probes_discovered_in_scope_links() -> None:
    agent, eng = _make_recon_alpha(
        {
            _SEED: _page(_SEED, _SEED_BODY),
            _PRODUCTS: _page(_PRODUCTS, "<html><body>products</body></html>"),
            _CONTACT: _page(_CONTACT, "<html><body>contact</body></html>"),
        }
    )

    agent.run_recon(eng, _SEED)
    calls = agent.http_client.calls

    assert _SEED in calls, "seed was never fetched — recon did not start"
    assert _PRODUCTS in calls, (
        "discovered same-origin in-scope link '/products' was never probed — "
        "frontier did NOT grow end-to-end (the exact gap #127's unit tests could not catch)"
    )
    assert _CONTACT in calls, "discovered in-scope link '/contact' was never probed"


# ---------------------------------------------------------------------------
# T2 — cross-host link is NEVER fetched (same-origin scope safety, anti-#3)
# ---------------------------------------------------------------------------


def test_run_recon_never_probes_cross_host_link() -> None:
    agent, eng = _make_recon_alpha(
        {
            _SEED: _page(_SEED, _SEED_BODY),
            _PRODUCTS: _page(_PRODUCTS, "<html><body>products</body></html>"),
            _CONTACT: _page(_CONTACT, "<html><body>contact</body></html>"),
        }
    )

    agent.run_recon(eng, _SEED)

    assert _EVIL not in agent.http_client.calls
    assert not any("evil" in c for c in agent.http_client.calls), (
        "a cross-host link was fetched — frontier expanded beyond the seed origin "
        "(scope/legal boundary breach)"
    )


# ---------------------------------------------------------------------------
# T3 — dead-end seed fetches only the seed (Lyndon #11 differential)
# ---------------------------------------------------------------------------


def test_run_recon_dead_end_seed_probes_only_seed() -> None:
    dead = f"https://{_SCOPE_HOST}/lonely"
    agent, eng = _make_recon_alpha({dead: _page(dead, "<html><body>no links here</body></html>")})

    agent.run_recon(eng, dead)

    assert agent.http_client.calls == [dead], (
        "a link-free page produced extra fetches — frontier growth is not driven "
        f"by page content (Lyndon #11). calls={agent.http_client.calls}"
    )


# ---------------------------------------------------------------------------
# T4 — threshold=5 lets a deep link survive intervening dud probes
#      (converts test_frontier_expansion.py::T0's magic-number assertion into
#       an observable behaviour: raising ALPHA_RECON_NO_PROGRESS_ITERS to 5
#       is what allows the crawl to reach a good link past ≤3 non-analyzable duds)
# ---------------------------------------------------------------------------


def test_run_recon_reaches_deep_link_past_dud_probes() -> None:
    d1 = f"https://{_SCOPE_HOST}/d1"
    d2 = f"https://{_SCOPE_HOST}/d2"
    d3 = f"https://{_SCOPE_HOST}/d3"
    deep = f"https://{_SCOPE_HOST}/deep"

    # Seed links (document order) to 3 dud endpoints then a good one. The duds
    # return empty bodies -> non-analyzable -> 0 progress -> idle counter climbs.
    # At threshold=1 the loop would stop after the first dud and never reach
    # 'deep'; at threshold=5 the crawl survives the 3 duds and probes 'deep'.
    seed_body = (
        "<html><body>"
        f'<a href="{d1}">d1</a><a href="{d2}">d2</a>'
        f'<a href="{d3}">d3</a><a href="{deep}">deep</a>'
        "</body></html>"
    )
    agent, eng = _make_recon_alpha(
        {
            _SEED: _page(_SEED, seed_body),
            d1: _Resp(200, "", {}, d1),  # empty body -> non-analyzable dud
            d2: _Resp(200, "", {}, d2),
            d3: _Resp(200, "", {}, d3),
            deep: _page(deep, "<html><body>deep page</body></html>"),
        }
    )

    agent.run_recon(eng, _SEED)
    calls = agent.http_client.calls

    assert deep in calls, (
        "deep in-scope link was not reached after 3 dud probes — "
        "ALPHA_RECON_NO_PROGRESS_ITERS is too low for the crawl to survive dud "
        "endpoints mid-drain (this is the behaviour T0's '>=5' magic number stands for)"
    )
    # All three duds were genuinely attempted before the good link (proves the
    # loop drained through them rather than luck-ordering around them).
    assert {d1, d2, d3}.issubset(set(calls))
