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


def test_challenged_host_classified_once_paths_reuse_memo() -> None:
    """A 2nd path on a challenged host does NOT re-invoke browser (memo holds).
    A 'blocked' host's later paths are SKIPPED."""
    browser = _FakeBrowserSolve(
        _BrowserResult(
            status_code=200,
            body=_RICH_WP,
            headers={"server": "cloudflare"},
            challenge_solved=True,
        )
    )
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={
            _SEED: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _SEED),
            _PATH2: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _PATH2),
        },
        browser_solve=browser,
    )
    alpha.run_recon(eng, _SEED)

    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "challenged"
    # Browser called exactly once for the host (not per-path)
    assert len(browser.calls) == 1, (
        f"Browser called {len(browser.calls)} times on a challenged host — "
        "memo must hold: exactly 1 probe per host, not per path"
    )


def test_no_consent_is_unresolved_and_analyzes() -> None:
    """When browser is not viable (no consent), reach_class="unresolved" →
    body still analyzed (no skip, no FP). Zero regression from today."""
    # No browser_solve injected → browser_solve is None → "unresolved"
    alpha, eng, store, orchestrator, http_client = _make_alpha(
        routes={_SEED: _Resp(200, _CF_SHELL, {"server": "cloudflare"}, _SEED)},
        browser_solve=None,
        browser_solve_viable=False,
    )
    alpha.run_recon(eng, _SEED)

    host = urlparse(_SEED).hostname or ""
    assert alpha._reach_class.get(host) == "unresolved", (
        f"Without consent, reach_class must be 'unresolved', got {alpha._reach_class.get(host)!r}"
    )
    # The httpx body (CF shell) was still analyzed — not skipped
    assert len(orchestrator.calls) > 0, (
        "Without consent, the page must still be analyzed (FP-safe fallback)"
    )
