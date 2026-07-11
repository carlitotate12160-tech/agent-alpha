"""Contract: Alpha's _work_queue GROWS as handlers discover in-scope URLs.

RED at current HEAD (confirmed, 2026-07-10):
  1. ``grep -rn enqueue_discovered_url agent_alpha/`` → zero matches
  2. ``ALPHA_RECON_NO_PROGRESS_ITERS = 1``  (one idle cycle kills recon before new
     queue entries can run — confirmed in agent_alpha/config/constants.py)
  3. ``scout.py.step()`` never calls ``_work_queue.append`` (grep-confirmed)
  4. No ``_extract_hrefs`` helper exists

These tests define the R1 INTERFACE (TDD-first).  They go GREEN when:
  - ``Alpha.enqueue_discovered_url(url)`` is implemented (scope-enforced via
    ``self.authorization.is_in_scope``, dedup-guarded via ``_probed | _work_queue``)
  - ``Alpha._extract_hrefs(html, base_url)`` produces absolute, same-host hrefs
  - ``Alpha.step()`` calls ``enqueue_discovered_url`` for each href from
    ``_extract_hrefs(resp.text, url)`` after PERSIST
  - ``ALPHA_RECON_NO_PROGRESS_ITERS >= 5`` in constants.py

Lyndon checks:
  #2 — T5 guards via inspect.getsource (dead-code preventer)
  #3 — T3/T4 enforce honest rejection (no silent scope bypass)
  #11 — T6 differential: different HTML surface → different queue growth

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_frontier_expansion.py -v
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_alpha.agents.alpha import scout as scout_module
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.config import constants

# ---------------------------------------------------------------------------
# Minimal test doubles
# ---------------------------------------------------------------------------

_SCOPE_HOST = "target.example.com"
_ENGAGEMENT = "eng-frontier-r1"


class _FakeAuth:
    """Scope: only target.example.com (+ subdomains) are in-scope."""

    def can_agent_proceed(self, *_: Any, **__: Any) -> bool:
        return True

    def is_in_scope(self, engagement_id: str, host: str) -> bool:
        # engagement_id ignored; deterministic for tests
        return host == _SCOPE_HOST or host.endswith(f".{_SCOPE_HOST}")


@dataclass
class _FakeResp:
    text: str
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)


class _FakeHttpClient:
    """Returns a configurable response; never raises."""

    def __init__(self, body: str = "<html></html>") -> None:
        self._body = body

    def get(self, url: str) -> _FakeResp:  # noqa: ARG002
        return _FakeResp(text=self._body)


@dataclass
class _FakeDecision:
    tool: str = "generic"
    tier: str = "rule"
    reasoning: str = "test stub"
    cost_usd: float = 0.0


class _FakeOrchestrator:
    def decide(self, observation: dict[str, Any]) -> _FakeDecision:
        return _FakeDecision()


def _make_alpha(body: str = "<html></html>") -> Alpha:
    """Alpha wired with scope=target.example.com, no live deps."""
    a = Alpha(
        authorization=_FakeAuth(),
        graph_store=None,  # not needed for frontier-expansion tests
        event_store=None,
        orchestrator=_FakeOrchestrator(),
        http_client=_FakeHttpClient(body),
    )
    # Simulate post-run_recon() state: engagement + seed in queue
    a._engagement_id = _ENGAGEMENT
    a._work_queue = [f"https://{_SCOPE_HOST}"]
    a._probed = set()
    return a


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def alpha() -> Alpha:
    return _make_alpha()


@pytest.fixture
def alpha_single_page() -> Alpha:
    """Alpha whose target page has no outbound links — queue must not grow."""
    return _make_alpha(body="<html><body>No links here.</body></html>")


@pytest.fixture
def alpha_multi_link() -> Alpha:
    """Alpha whose target page has two in-scope links + one out-of-scope link."""
    body = """<html><body>
    <a href="/products">Products</a>
    <a href="https://target.example.com/contact">Contact</a>
    <a href="https://evil.com/steal">External (out-of-scope)</a>
    </body></html>"""
    return _make_alpha(body=body)


# ---------------------------------------------------------------------------
# T0 — threshold guard
# ---------------------------------------------------------------------------


def test_no_progress_threshold_allows_frontier_growth() -> None:
    """``ALPHA_RECON_NO_PROGRESS_ITERS = 1`` kills recon after one idle cycle —
    before any URL enqueued by step() can run.  R1 requires >= 5."""
    assert constants.ALPHA_RECON_NO_PROGRESS_ITERS >= 5, (
        f"ALPHA_RECON_NO_PROGRESS_ITERS={constants.ALPHA_RECON_NO_PROGRESS_ITERS}; "
        "frontier entries enqueued by step() would never run (queue grows on cycle N, "
        "threshold fires on cycle N, new URLs never popped on cycle N+1)."
    )


# ---------------------------------------------------------------------------
# T1 — interface exists
# ---------------------------------------------------------------------------


def test_alpha_has_enqueue_discovered_url() -> None:
    """Alpha must expose ``enqueue_discovered_url`` — the frontier enqueue seam.
    Without this method the test suite cannot call it directly, and step() has
    nothing to call either."""
    assert hasattr(Alpha, "enqueue_discovered_url"), (
        "Alpha.enqueue_discovered_url not found.  "
        "R1 requires this method on the class (not just in step())."
    )


def test_alpha_has_extract_hrefs() -> None:
    """Alpha must expose ``_extract_hrefs(html, base_url) -> list[str]``.
    Separating HTML parsing from queue logic keeps step() testable in isolation."""
    assert hasattr(Alpha, "_extract_hrefs"), (
        "Alpha._extract_hrefs not found.  "
        "R1 requires this helper so step() and T6 can use it independently."
    )


# ---------------------------------------------------------------------------
# T2 — in-scope URL is enqueued
# ---------------------------------------------------------------------------


def test_in_scope_href_enqueued(alpha: Alpha) -> None:
    """A discovered href on the same base domain must enter ``_work_queue``."""
    initial = len(alpha._work_queue)
    alpha.enqueue_discovered_url(f"https://{_SCOPE_HOST}/products")
    assert len(alpha._work_queue) == initial + 1
    assert f"https://{_SCOPE_HOST}/products" in alpha._work_queue


def test_subdomain_href_enqueued(alpha: Alpha) -> None:
    """A href on a subdomain of the scope host must also be accepted."""
    initial = len(alpha._work_queue)
    alpha.enqueue_discovered_url(f"https://shop.{_SCOPE_HOST}/cart")
    assert len(alpha._work_queue) == initial + 1


# ---------------------------------------------------------------------------
# T3 — out-of-scope URL is NOT enqueued
# ---------------------------------------------------------------------------


def test_out_of_scope_href_rejected(alpha: Alpha) -> None:
    """A href to a different domain must NOT enter ``_work_queue``.

    Without this guard, a redirect or injected link could expand recon beyond
    client scope — a scope-violation and potential legal boundary breach."""
    initial = len(alpha._work_queue)
    alpha.enqueue_discovered_url("https://evil.com/steal")
    assert len(alpha._work_queue) == initial, (
        "Out-of-scope href was enqueued — scope enforcement missing."
    )


def test_out_of_scope_similar_suffix_rejected(alpha: Alpha) -> None:
    """``notexample.com`` must not match a scope of ``example.com``.
    A suffix check without a dot-boundary is a common scope-bypass bug."""
    initial = len(alpha._work_queue)
    alpha.enqueue_discovered_url(f"https://not{_SCOPE_HOST}/page")
    assert len(alpha._work_queue) == initial


# ---------------------------------------------------------------------------
# T4 — duplicate deduplication
# ---------------------------------------------------------------------------


def test_duplicate_url_not_enqueued_twice(alpha: Alpha) -> None:
    """Enqueuing the same URL twice must result in exactly one entry (dedup).
    Without dedup, a link-cycle would produce infinite re-scanning."""
    url = f"https://{_SCOPE_HOST}/login"
    alpha.enqueue_discovered_url(url)
    alpha.enqueue_discovered_url(url)
    assert alpha._work_queue.count(url) == 1


def test_already_probed_url_not_re_enqueued(alpha: Alpha) -> None:
    """A URL that has already been probed (in ``_probed``) must not be re-enqueued.
    Otherwise a revisit loop defeats the no-progress detection."""
    url = f"https://{_SCOPE_HOST}/already-seen"
    alpha._probed.add(url)
    alpha.enqueue_discovered_url(url)
    assert url not in alpha._work_queue


# ---------------------------------------------------------------------------
# T5 — dead-seam guard: step() calls enqueue_discovered_url (anti-Lyndon #2)
# ---------------------------------------------------------------------------


def test_step_calls_enqueue_discovered_url() -> None:
    """``step()`` must call ``enqueue_discovered_url()`` on the live path.

    The method existing is not enough — it must be called from step() so that
    frontier growth actually happens during recon (Lyndon #2: dead code = done)."""
    src = inspect.getsource(scout_module.Alpha.step) + inspect.getsource(
        scout_module.Alpha._step_once
    )
    assert "enqueue_discovered_url(" in src, (
        "Alpha.step()/_step_once() does not call enqueue_discovered_url() — "
        "frontier expansion is dead code (Lyndon #2)."
    )


def test_step_calls_extract_hrefs() -> None:
    """``step()`` must call ``_extract_hrefs()`` to obtain hrefs from the response body.
    Without this call, HTML parsing never feeds the frontier."""
    src = inspect.getsource(scout_module.Alpha.step) + inspect.getsource(
        scout_module.Alpha._step_once
    )
    assert "_extract_hrefs(" in src, (
        "Alpha.step()/_step_once() does not call _extract_hrefs() — "
        "hrefs are never extracted from response body (dead-seam, Lyndon #2)."
    )


# ---------------------------------------------------------------------------
# T6 — differential: different HTML surface → different queue growth
# ---------------------------------------------------------------------------


def test_extract_hrefs_multi_link_page(alpha_multi_link: Alpha) -> None:
    """``_extract_hrefs`` on a page with 2 in-scope + 1 out-of-scope links must
    return exactly the 2 in-scope absolute URLs.

    This is the Lyndon #11 differential: next_action = f(HTML content), not static."""
    seed = f"https://{_SCOPE_HOST}"
    body = alpha_multi_link.http_client.get(seed).text
    hrefs = alpha_multi_link._extract_hrefs(body, seed)

    in_scope = [h for h in hrefs if _SCOPE_HOST in h]
    out_of_scope = [h for h in hrefs if "evil.com" in h]

    assert len(in_scope) == 2, f"Expected 2 in-scope hrefs, got {in_scope}"
    assert len(out_of_scope) == 0, f"Out-of-scope hrefs leaked into result: {out_of_scope}"
    assert f"https://{_SCOPE_HOST}/products" in in_scope
    assert f"https://{_SCOPE_HOST}/contact" in in_scope


def test_extract_hrefs_dead_end_page(alpha_single_page: Alpha) -> None:
    """``_extract_hrefs`` on a page with no links must return an empty list.
    A dead-end page must not invent phantom URLs."""
    seed = f"https://{_SCOPE_HOST}"
    body = alpha_single_page.http_client.get(seed).text
    hrefs = alpha_single_page._extract_hrefs(body, seed)
    assert hrefs == [], f"Expected [], got {hrefs}"


def test_frontier_grows_on_multi_link_target_not_on_dead_end(
    alpha_multi_link: Alpha, alpha_single_page: Alpha
) -> None:
    """Lyndon #11 differential (integration slice):
    After manually feeding hrefs from each HTML body:
      - multi-link alpha: queue grows by 2 in-scope hrefs
      - dead-end alpha: queue unchanged

    This confirms enqueue_discovered_url + _extract_hrefs compose correctly."""
    seed = f"https://{_SCOPE_HOST}"

    # Simulate what step() does after PERSIST
    for href in alpha_multi_link._extract_hrefs(alpha_multi_link.http_client.get(seed).text, seed):
        alpha_multi_link.enqueue_discovered_url(href)

    for href in alpha_single_page._extract_hrefs(
        alpha_single_page.http_client.get(seed).text, seed
    ):
        alpha_single_page.enqueue_discovered_url(href)

    # multi-link queue grew; dead-end queue unchanged (still just the seed)
    assert len(alpha_multi_link._work_queue) > len(alpha_single_page._work_queue), (
        "Queue growth was identical regardless of HTML content — "
        "frontier expansion is not driven by graph state (Lyndon #11)."
    )
    # Exact expectation: multi-link has seed + 2; dead-end has seed only
    assert len(alpha_multi_link._work_queue) == 3  # seed + /products + /contact
    assert len(alpha_single_page._work_queue) == 1  # seed only
