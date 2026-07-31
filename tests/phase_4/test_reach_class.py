# tests/phase_4/test_reach_class.py
"""ADR §12.41 — per-host reach-class: entry-point differential + tiered transport.

RED-first: the cardinal test (test_legit_reload_page_classified_clear_content_used)
MUST fail under PR #278 (where a legit reload page was discarded as CHALLENGE)
and pass after the §12.41 slice-1 (where it is CLEAR and analyzed).

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_4/test_reach_class.py -v
"""

from __future__ import annotations

import dataclasses
from typing import Any
from urllib.parse import urlparse

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

_HOST = "target.example.com"
_SEED = f"https://{_HOST}/"
_PATH2 = f"https://{_HOST}/about/"


# ---------------------------------------------------------------------------
# Fake HTTP client + orchestrator (mirrors test_response_classifier.py harness)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str]
    url: str


class _FakeHttpClient:
    def __init__(self, routes: dict[str, _Resp]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _Resp:  # noqa: ARG002
        self.calls.append(url)
        return self._routes.get(url, _Resp(404, "", {}, url))


@dataclasses.dataclass
class _Decision:
    tool: str = "generic_http_probe"
    tier: str = "rule"
    reasoning: str = "stub"
    cost_usd: float = 0.0


class _StubOrchestrator:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def decide(self, observation: dict[str, object]) -> _Decision:  # noqa: ARG002
        self.calls.append(observation)
        return _Decision()

    def decide_rule_only(self, observation: dict[str, object]) -> _Decision | None:  # noqa: ARG002
        return None


# ---------------------------------------------------------------------------
# Fake browser_solve (for _classify_host_reach)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _BrowserResult:
    status_code: int
    body: str
    headers: dict[str, str]
    challenge_solved: bool
    challenge_encountered: bool = False


class _FakeBrowserSolve:
    def __init__(self, result: _BrowserResult) -> None:
        self._result = result
        self.calls: list[str] = []

    def solve_and_fetch(self, url: str, engagement_id: str = "") -> _BrowserResult:  # noqa: ARG002
        self.calls.append(url)
        return self._result


# ---------------------------------------------------------------------------
# Fake engagement profile with allow_evasion=True
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _FakeProfile:
    allow_evasion: bool = True
    authorized_origins: list[str] = dataclasses.field(default_factory=list)
    scope_targets: list[str] = dataclasses.field(default_factory=lambda: [_HOST])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alpha(
    routes: dict[str, _Resp],
    browser_solve: Any | None = None,
    browser_solve_viable: bool = True,
    allow_evasion: bool = True,
) -> tuple[Alpha, str, InMemoryEventStore, _StubOrchestrator, _FakeHttpClient]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="client_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    orchestrator = _StubOrchestrator()
    http_client = _FakeHttpClient(routes)
    profile = _FakeProfile(allow_evasion=allow_evasion)
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orchestrator,
        http_client=http_client,
        browser_solve=browser_solve,
        engagement_profile=profile,
        browser_solve_viable=browser_solve_viable,
    )
    return alpha, rec.engagement_id, store, orchestrator, http_client


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

# A legit small page with a reload — should be CLEAR (FP-safe)
_LEGIT_RELOAD_PAGE = (
    "<html>\n<head>\n<title>We moved</title>\n"
    '<meta http-equiv="refresh" content="2;url=/new-location" />\n'
    "</head>\n<body>\n"
    "<h1>We moved!</h1>\n"
    "<p>This page has been relocated.</p>\n"
    '<a href="/new-location">Click here</a>\n'
    '<a href="/about">About</a>\n'
    '<a href="/contact">Contact</a>\n'
    '<a href="/services">Services</a>\n'
    "</body>\n</html>\n"
)

# CF soft-200 interstitial shell
_CF_SHELL = (
    "<html>\n<head>\n<title>One moment, please...</title>\n"
    "</head>\n<body>\n"
    "<p>One moment, please...</p>\n"
    "<script>\n"
    "setTimeout(function(){window.location.reload();},5000);\n"
    "</script>\n</body>\n</html>\n"
)

# Rich real WP content (what browser would return after solving CF)
_RICH_WP = (
    "<html>\n<head>\n<title>My Site</title>\n"
    '<link rel="stylesheet" href="/wp-content/themes/mytheme/style.css" />\n'
    "</head>\n<body>\n"
    "<h1>Welcome</h1>\n"
    "<p>Real content here.</p>\n"
    '<a href="/about/">About</a>\n'
    '<a href="/blog/">Blog</a>\n'
    '<a href="/contact/">Contact</a>\n'
    '<a href="/services/">Services</a>\n'
    "</body>\n</html>\n"
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_legit_reload_page_classified_clear_content_used() -> None:
    """CARDINAL: a legit small page with a reload is CLEAR — the browser probe
    returns ~same content → reach_class="clear" → the page is ANALYZED (not
    skipped, not waf-blocked). FP-safe."""
    # Browser returns the same content as httpx → no gain → "clear"
    browser = _FakeBrowserSolve(
        _BrowserResult(
            status_code=200,
            body=_LEGIT_RELOAD_PAGE,
            headers={},
            challenge_solved=False,
            challenge_encountered=False,
        )
    )
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(200, _LEGIT_RELOAD_PAGE, {"server": "nginx"}, _SEED)},
        browser_solve=browser,
    )
    alpha.run_recon(eng, _SEED)

    # reach_class must be "clear" — browser saw same content, no challenge
    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "clear", (
        f"Legit reload page classified as {alpha._reach_class.get(host)!r} — "
        "must be 'clear' (FP-safe: browser confirmed no challenge)"
    )
    # The page was analyzed (orchestrator was called with the body)
    assert len(orchestrator.calls) > 0, (
        "Legit page was not analyzed — orchestrator.decide() was never called. "
        "A 'clear' reach-class must fall through to normal analysis."
    )
    assert "We moved" in orchestrator.calls[0].get("body", ""), (
        "The legit page content was not passed to the orchestrator — it was discarded or replaced."
    )
    # No WAF_BLOCKED event
    waf_events = [e for e in store.get_events(eng) if e.event_type == EventType.WAF_BLOCKED]
    assert waf_events == [], "A clear host must not emit WAF_BLOCKED"


def test_cf_soft200_challenged_uses_browser_body() -> None:
    """A CF soft-200 shell → browser probe returns rich real body +
    challenge_solved → reach_class="challenged", real body analyzed."""
    browser = _FakeBrowserSolve(
        _BrowserResult(
            status_code=200,
            body=_RICH_WP,
            headers={"server": "cloudflare"},
            challenge_solved=True,
            challenge_encountered=True,
        )
    )
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _SEED)},
        browser_solve=browser,
    )
    alpha.run_recon(eng, _SEED)

    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "challenged", (
        f"CF soft-200 shell classified as {alpha._reach_class.get(host)!r} — "
        "must be 'challenged' (browser solved and gained content)"
    )
    # Browser was called exactly once
    assert len(browser.calls) == 1, (
        f"Browser was called {len(browser.calls)} times — must be exactly 1"
    )
    # The rich WP content was analyzed (not the shell)
    assert len(orchestrator.calls) > 0, "Challenged host must analyze the browser body"
    analyzed_body = orchestrator.calls[0].get("body", "")
    assert "wp-content" in analyzed_body or "Welcome" in analyzed_body, (
        "The browser's rich body was not analyzed — the CF shell was used instead"
    )


def test_js_spa_not_mislabeled_challenged() -> None:
    """CARDINAL: a JS-SPA whose browser DOM is richer than the httpx thin
    shell but challenge_solved=False must be 'clear' — NOT 'challenged'.
    The orchestrator must analyze the httpx body (the SPA shell), not the
    browser body.  RED today (pre-fix: gained alone → challenged)."""
    # SPA shell (httpx sees a thin JS loader)
    spa_shell = (
        "<html>\n<head>\n<title>App</title>\n"
        '<script src="/app.js"></script>\n'
        "</head>\n<body>\n"
        '<div id="root"></div>\n'
        "</body>\n</html>\n"
    )
    # Browser-rendered SPA (much richer DOM, but NOT a solved challenge)
    spa_rendered = (
        "<html>\n<head>\n<title>App</title>\n"
        '<script src="/app.js"></script>\n'
        "</head>\n<body>\n"
        '<div id="root">\n'
        "<nav><a href='/dashboard'>Dashboard</a><a href='/settings'>Settings</a></nav>\n"
        "<main><h1>Welcome back</h1><p>Your projects:</p>\n"
        "<ul><li>Project Alpha</li><li>Project Beta</li><li>Project Gamma</li></ul>\n"
        "</main>\n"
        "<footer>© 2026 App Inc.</footer>\n"
        "</div>\n"
        "</body>\n</html>\n"
    )
    browser = _FakeBrowserSolve(
        _BrowserResult(
            status_code=200,
            body=spa_rendered,
            headers={},
            challenge_solved=False,  # NOT a solved challenge — just a SPA
            challenge_encountered=False,
        )
    )
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(200, spa_shell, {"server": "nginx"}, _SEED)},
        browser_solve=browser,
    )
    alpha.run_recon(eng, _SEED)

    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "clear", (
        f"JS-SPA classified as {alpha._reach_class.get(host)!r} — "
        "must be 'clear' (challenge_solved=False, browser DOM is just a rendered SPA)"
    )
    # The orchestrator must have analyzed the httpx body (SPA shell), not the browser body
    assert len(orchestrator.calls) > 0, (
        "SPA page was not analyzed — orchestrator.decide() was never called"
    )
    analyzed_body = orchestrator.calls[0].get("body", "")
    assert '<div id="root"></div>' in analyzed_body, (
        "The httpx SPA shell was not passed to the orchestrator — "
        "the browser-rendered body was used instead (mislabel as challenged)"
    )
    # No WAF_BLOCKED event
    waf_events = [e for e in store.get_events(eng) if e.event_type == EventType.WAF_BLOCKED]
    assert waf_events == [], "A clear host must not emit WAF_BLOCKED"


def test_challenged_host_entry_analyzed_then_subsequent_paths_skipped() -> None:
    """A challenged host — the ENTRY path is analyzed via the browser body
    (browser called exactly once); a SECOND path on the same host is SKIPPED
    (INCONCLUSIVE, orchestrator NOT called for it, browser NOT called again).
    Replaces test_challenged_host_classified_once_paths_reuse_memo."""
    browser = _FakeBrowserSolve(
        _BrowserResult(
            status_code=200,
            body=_RICH_WP,
            headers={"server": "cloudflare"},
            challenge_solved=True,
            challenge_encountered=True,
        )
    )
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={
            _SEED: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _SEED),
            _PATH2: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _PATH2),
        },
        browser_solve=browser,
    )
    # Manually enqueue _PATH2 so both paths are visited
    alpha._engagement_id = eng
    alpha.enqueue_discovered_url(_PATH2)
    alpha.run_recon(eng, _SEED)

    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "challenged"

    # Browser called exactly once for the host (not per-path)
    assert len(browser.calls) == 1, (
        f"Browser called {len(browser.calls)} times on a challenged host — "
        "must be exactly 1 probe per host, not per path"
    )

    # Entry path: orchestrator was called with the browser body
    assert len(orchestrator.calls) == 1, (
        f"Orchestrator called {len(orchestrator.calls)} times — "
        "must be exactly 1 (entry path only; subsequent path skipped)"
    )
    analyzed_body = orchestrator.calls[0].get("body", "")
    assert "wp-content" in analyzed_body or "Welcome" in analyzed_body, (
        "Entry path was not analyzed with the browser body"
    )

    # Second path: must be SKIPPED (not analyzed)
    # Verify the entry body was consumed (popped from cache)
    assert host not in alpha._reach_body_cache, (
        "The entry body was not consumed — it should have been popped from cache"
    )


def test_challenge_not_solved_is_blocked() -> None:
    """CF challenge encountered but browser couldn't solve it →
    reach_class="blocked". Browser called exactly once; subsequent
    paths on same host are skipped (no duplicate browser calls).
    This is the alpha-ai.web.id real-world case."""
    browser = _FakeBrowserSolve(
        _BrowserResult(
            status_code=403,
            body=_CF_SHELL,
            headers={"server": "cloudflare"},
            challenge_solved=False,
            challenge_encountered=True,
        )
    )
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={
            _SEED: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _SEED),
            _PATH2: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _PATH2),
        },
        browser_solve=browser,
    )
    alpha._engagement_id = eng
    alpha.enqueue_discovered_url(_PATH2)
    alpha.run_recon(eng, _SEED)

    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "blocked", (
        f"Unsolved challenge classified as {alpha._reach_class.get(host)!r} — "
        "must be 'blocked' (challenge encountered but not solved)"
    )
    # Browser called exactly once (entry classify), not per-path
    assert len(browser.calls) == 1, (
        f"Browser called {len(browser.calls)} times — must be exactly 1 "
        "(entry classify only, not per-path spray)"
    )
    # Both paths SKIPPED — orchestrator never called on a blocked host
    assert len(orchestrator.calls) == 0, (
        f"Orchestrator called {len(orchestrator.calls)} times — "
        "must be 0 (all paths on a blocked host are INCONCLUSIVE-skipped)"
    )


def test_no_consent_is_unresolved_and_analyzes() -> None:
    """When browser is not viable (no consent), reach_class="unresolved" →
    body still analyzed (no skip, no FP). Zero regression from today."""
    # No browser_solve injected → browser_solve is None → "unresolved"
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(200, _LEGIT_RELOAD_PAGE, {"server": "nginx"}, _SEED)},
        browser_solve=None,
        browser_solve_viable=False,
    )
    alpha.run_recon(eng, _SEED)

    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "unresolved", (
        f"Without consent, reach_class must be 'unresolved', got {alpha._reach_class.get(host)!r}"
    )
    # The httpx body was still analyzed — not skipped
    assert len(orchestrator.calls) > 0, (
        "Without consent, the page must still be analyzed (FP-safe fallback)"
    )


# ---------------------------------------------------------------------------
# ORIGIN_DIRECT Reach Strategy Loop Tests (Phase 4)
# ---------------------------------------------------------------------------
def test_origin_direct_returns_first_useful() -> None:
    """Test that ORIGIN_DIRECT iterates through multiple authorized origins and returns the first useful one.

    When the first origin returns a non-useful response (e.g., 404 Not Found),
    the strategy must continue to the next origin. If the second origin returns a 200 OK,
    that response should be returned and used for further analysis.
    """
    from agent_alpha.recon.reach_transport import OriginDirectResult
    from unittest.mock import patch
    
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(403, _CF_SHELL, {"server": "cloudflare"}, _SEED)}
    )
    alpha._engagement_profile.authorized_origins = ["198.51.100.1", "198.51.100.2"]
    
    class FakeOriginDiscovery:
        def candidates(self, host: str) -> list[str]:
            return ["198.51.100.1", "198.51.100.2"]
            
    alpha._origin_discovery = FakeOriginDiscovery()
    
    def fake_origin_direct(host: str, origin_ip: str, path: str) -> OriginDirectResult:
        if origin_ip == "198.51.100.1":
            return OriginDirectResult(404, "Not Found", {"server": "nginx"})
        return OriginDirectResult(200, "Real Content", {"server": "nginx"})

    with patch("agent_alpha.agents.alpha.scout.origin_direct_fetch", side_effect=fake_origin_direct):
        alpha.run_recon(eng, _SEED)
        
    assert len(orchestrator.calls) == 1
    assert "Real Content" in orchestrator.calls[0].get("body", "")


def test_origin_direct_skips_redirects() -> None:
    """Test that ORIGIN_DIRECT skips redirect responses and continues to the next origin.

    When the first origin returns a 302 Found redirect, the strategy must skip it
    and continue to the next authorized origin. If the second returns 200 OK, it is used.
    """
    from agent_alpha.recon.reach_transport import OriginDirectResult
    from unittest.mock import patch
    
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(403, _CF_SHELL, {"server": "cloudflare"}, _SEED)}
    )
    alpha._engagement_profile.authorized_origins = ["198.51.100.1", "198.51.100.2"]
    
    class FakeOriginDiscovery:
        def candidates(self, host: str) -> list[str]:
            return ["198.51.100.1", "198.51.100.2"]
            
    alpha._origin_discovery = FakeOriginDiscovery()
    
    def fake_origin_direct(host: str, origin_ip: str, path: str) -> OriginDirectResult:
        if origin_ip == "198.51.100.1":
            return OriginDirectResult(302, "Found", {"location": "/login"})
        return OriginDirectResult(200, "Real Content", {"server": "nginx"})

    with patch("agent_alpha.agents.alpha.scout.origin_direct_fetch", side_effect=fake_origin_direct):
        alpha.run_recon(eng, _SEED)
        
    assert len(orchestrator.calls) == 1
    assert "Real Content" in orchestrator.calls[0].get("body", "")


def test_origin_direct_single_origin_works() -> None:
    """Test that ORIGIN_DIRECT works correctly with a single authorized origin.

    Ensures no regression in the fallback logic: if there is only one origin
    and it returns a 200 OK, that response is returned immediately.
    """
    from agent_alpha.recon.reach_transport import OriginDirectResult
    from unittest.mock import patch
    
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(403, _CF_SHELL, {"server": "cloudflare"}, _SEED)}
    )
    alpha._engagement_profile.authorized_origins = ["198.51.100.1"]
    
    class FakeOriginDiscovery:
        def candidates(self, host: str) -> list[str]:
            return ["198.51.100.1"]
            
    alpha._origin_discovery = FakeOriginDiscovery()
    
    def fake_origin_direct(host: str, origin_ip: str, path: str) -> OriginDirectResult:
        return OriginDirectResult(200, "Single Origin Content", {"server": "nginx"})

    with patch("agent_alpha.agents.alpha.scout.origin_direct_fetch", side_effect=fake_origin_direct):
        alpha.run_recon(eng, _SEED)
        
    assert len(orchestrator.calls) == 1
    assert "Single Origin Content" in orchestrator.calls[0].get("body", "")


def test_origin_direct_all_origins_raise() -> None:
    """Test that ORIGIN_DIRECT gracefully falls back if all origins raise exceptions.

    If every fetch attempt to the authorized origins results in a RuntimeError
    (e.g., connection reset), the strategy must catch these exceptions and
    ultimately return None, signaling that reach is not viable.
    """
    from unittest.mock import patch
    
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(403, _CF_SHELL, {"server": "cloudflare"}, _SEED)}
    )
    alpha._engagement_profile.authorized_origins = ["198.51.100.1", "198.51.100.2"]
    
    class FakeOriginDiscovery:
        def candidates(self, host: str) -> list[str]:
            return ["198.51.100.1", "198.51.100.2"]
            
    alpha._origin_discovery = FakeOriginDiscovery()
    
    def fake_origin_direct(host: str, origin_ip: str, path: str) -> None:
        raise RuntimeError("Connection reset")

    with patch("agent_alpha.agents.alpha.scout.origin_direct_fetch", side_effect=fake_origin_direct):
        alpha.run_recon(eng, _SEED)
        
    assert len(orchestrator.calls) == 0


def test_origin_direct_returns_first_useful_immediately() -> None:
    """Test that ORIGIN_DIRECT short-circuits and returns early upon finding a useful response.

    If the first origin returns a useful response (e.g., 200 OK), the strategy
    must return it immediately without issuing requests to the remaining origins.
    """
    from agent_alpha.recon.reach_transport import OriginDirectResult
    from unittest.mock import patch
    
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(403, _CF_SHELL, {"server": "cloudflare"}, _SEED)}
    )
    alpha._engagement_profile.authorized_origins = ["198.51.100.1", "198.51.100.2"]
    
    class FakeOriginDiscovery:
        def candidates(self, host: str) -> list[str]:
            return ["198.51.100.1", "198.51.100.2"]
            
    alpha._origin_discovery = FakeOriginDiscovery()
    
    call_count = 0
    def fake_origin_direct(host: str, origin_ip: str, path: str) -> OriginDirectResult:
        nonlocal call_count
        call_count += 1
        return OriginDirectResult(200, "First Content", {"server": "nginx"})

    with patch("agent_alpha.agents.alpha.scout.origin_direct_fetch", side_effect=fake_origin_direct):
        alpha.run_recon(eng, _SEED)
        
    assert call_count == 1
    assert len(orchestrator.calls) == 1
    assert "First Content" in orchestrator.calls[0].get("body", "")


def test_origin_direct_skips_blocked_verdicts() -> None:
    """Test that ORIGIN_DIRECT skips responses classified as BLOCKED, even if they return 200 OK.

    Some WAFs (e.g., Imperva) may return a 200 OK status code but serve an "Access Denied"
    block page. The strategy must use the classifier to determine if the response is actually
    useful, and if blocked, continue to the next origin.
    """
    from agent_alpha.recon.reach_transport import OriginDirectResult
    from unittest.mock import patch
    
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(403, _CF_SHELL, {"server": "cloudflare"}, _SEED)}
    )
    alpha._engagement_profile.authorized_origins = ["198.51.100.1", "198.51.100.2"]
    
    class FakeOriginDiscovery:
        def candidates(self, host: str) -> list[str]:
            return ["198.51.100.1", "198.51.100.2"]
            
    alpha._origin_discovery = FakeOriginDiscovery()
    
    def fake_origin_direct(host: str, origin_ip: str, path: str) -> OriginDirectResult:
        if origin_ip == "198.51.100.1":
            return OriginDirectResult(200, "Access Denied by WAF", {"server": "imperva"})
        return OriginDirectResult(200, "Clean Content", {"server": "nginx"})

    from agent_alpha.recon.response_classifier import Verdict
    original_classify = __import__("agent_alpha.recon.response_classifier", fromlist=["classify_response"]).classify_response
    
    def fake_classify(*, status_code: int, body: str, headers: dict[str, str]) -> Verdict:
        if "Access Denied" in body:
            return Verdict.BLOCKED
        return original_classify(status_code=status_code, body=body, headers=headers)

    with patch("agent_alpha.agents.alpha.scout.origin_direct_fetch", side_effect=fake_origin_direct):
        with patch("agent_alpha.agents.alpha.scout.classify_response", side_effect=fake_classify):
            alpha.run_recon(eng, _SEED)
        
    assert len(orchestrator.calls) == 1
    assert "Clean Content" in orchestrator.calls[0].get("body", "")
