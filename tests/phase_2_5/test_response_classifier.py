# tests/phase_2_5/test_response_classifier.py
"""Contract: R3 slice-1 — ONE canonical response classifier, wired into the core
OBSERVE loop, so WAF/CF blocks are recognised on ANY recon path (not just the two
probes that hand-roll the 403/429/503 check today) — and a block is never dressed
as "clean" (anti-Lyndon #3, both directions).

RED at #131 (confirmed): agent_alpha/recon/response_classifier.py does not exist, and
scout.step()'s OBSERVE never emits WAF_BLOCKED (only js_secret_probe / odoo_dbmanager_
probe do). Import fails -> all tests RED until R3 slice-1 lands.

GREEN when:
  - classify_response(status_code, body, transport_error) -> Verdict{OK,EMPTY,
    TRANSPORT_FAIL,BLOCKED} exists (403/429/503 -> BLOCKED; 200+body -> OK; empty ->
    EMPTY; transport -> TRANSPORT_FAIL). Conservative: a 200 with a real body is NEVER
    BLOCKED.
  - scout.step() classifies each fetched response via classify_response; BLOCKED ->
    emit EventType.WAF_BLOCKED (REUSE existing event) + treat as non-analyzable.
  - js_secret_probe / odoo_dbmanager_probe migrate their 403/429/503 check to
    classify_response (single source of truth, anti-#7).

Anti-#3 is SYMMETRIC: W1 = a real block is recorded; W2/W3/C1 = a clean/empty response
is NEVER mislabelled as blocked.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_response_classifier.py -v
"""

from __future__ import annotations

import dataclasses
import inspect

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

# Net-new canonical classifier (RED: module does not exist yet).
from agent_alpha.recon.response_classifier import (
    RELOAD_SHELL_MAX_BYTES,
    Verdict,
    classify_response,
)

_HOST = "target.example.com"
_SEED = f"https://{_HOST}/"


# ---------------------------------------------------------------------------
# C1 — the canonical classifier, BOTH directions
# ---------------------------------------------------------------------------


def test_classify_response_verdicts() -> None:
    # Direction (a): a real block signal is BLOCKED.
    assert classify_response(status_code=403, body="Forbidden") is Verdict.BLOCKED
    assert classify_response(status_code=429, body="Too Many Requests") is Verdict.BLOCKED
    assert (
        classify_response(status_code=503, body="<html>Just a moment...</html>") is Verdict.BLOCKED
    )
    # Direction (b): clean / empty / transport are NEVER BLOCKED (anti false-BLOCKED).
    assert classify_response(status_code=200, body="<html><body>hello</body></html>") is Verdict.OK
    assert classify_response(status_code=200, body="") is Verdict.EMPTY
    assert classify_response(status_code=200, body="   \n  ") is Verdict.EMPTY
    # F2: a 404 WITH a body is NOT_FOUND (missing path — rule tier may look, but the
    # LLM is never consulted). A 404 with an EMPTY body stays EMPTY (unchanged).
    assert classify_response(status_code=404, body="<html>Not Found</html>") is Verdict.NOT_FOUND
    assert classify_response(status_code=410, body="gone") is Verdict.NOT_FOUND
    assert classify_response(status_code=404, body="") is Verdict.EMPTY
    assert classify_response(status_code=0, body="", transport_error=True) is Verdict.TRANSPORT_FAIL
    # Bug #10: a 415 WITH a body (Cloudways/WP content-negotiation rejection) is
    # UNSUPPORTED_MEDIA_TYPE — never OK (it is not the target's real content) and
    # never BLOCKED (it is not a WAF/CF signal, so it must not pollute WAF_BLOCKED
    # audit evidence). A 415 with an empty body stays EMPTY (same precedence as 404).
    assert (
        classify_response(status_code=415, body="<html>Unsupported Media Type</html>")
        is Verdict.UNSUPPORTED_MEDIA_TYPE
    )
    assert classify_response(status_code=415, body="") is Verdict.EMPTY


def test_classify_response_is_pure_and_conservative() -> None:
    # A legitimate 200 page that merely CONTAINS the word 'forbidden' in its body is
    # NOT a block — only the status code carries the block verdict in slice-1.
    assert (
        classify_response(status_code=200, body="Access to admin is forbidden for guests")
        is Verdict.OK
    )


# ---------------------------------------------------------------------------
# Alpha harness (real Alpha; fake HTTP + orchestrator) — mirrors frontier e2e
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
    def decide(self, observation: dict[str, object]) -> _Decision:  # noqa: ARG002
        return _Decision()


def _make_recon_alpha(routes: dict[str, _Resp]) -> tuple[Alpha, str, InMemoryEventStore]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="client_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=_StubOrchestrator(),
        http_client=_FakeHttpClient(routes),
    )
    return alpha, rec.engagement_id, store


def _waf_events(store: InMemoryEventStore, eng: str) -> list[object]:
    return [e for e in store.get_events(eng) if e.event_type == EventType.WAF_BLOCKED]


# ---------------------------------------------------------------------------
# W1 — core OBSERVE emits WAF_BLOCKED on a 403 (direction a)
# ---------------------------------------------------------------------------


def test_observe_emits_waf_blocked_on_403() -> None:
    alpha, eng, store = _make_recon_alpha({_SEED: _Resp(403, "Forbidden", {}, _SEED)})
    alpha.run_recon(eng, _SEED)
    assert len(_waf_events(store, eng)) >= 1, (
        "a 403 recon probe did not emit WAF_BLOCKED from the core OBSERVE loop — "
        "a WAF block is being treated as clean/no-progress (false success #3)"
    )


# ---------------------------------------------------------------------------
# W2 — clean 200 does NOT emit WAF_BLOCKED (direction b — anti false-positive)
# ---------------------------------------------------------------------------


def test_observe_no_waf_blocked_on_clean_200() -> None:
    alpha, eng, store = _make_recon_alpha(
        {_SEED: _Resp(200, "<html><body>ok</body></html>", {"server": "nginx"}, _SEED)}
    )
    alpha.run_recon(eng, _SEED)
    assert _waf_events(store, eng) == [], (
        "a clean 200 was mislabelled as WAF-blocked (false BLOCKED)"
    )


# ---------------------------------------------------------------------------
# W3 — reachable-but-empty is EMPTY, not BLOCKED
# ---------------------------------------------------------------------------


def test_observe_empty_is_not_blocked() -> None:
    alpha, eng, store = _make_recon_alpha({_SEED: _Resp(200, "", {}, _SEED)})
    alpha.run_recon(eng, _SEED)
    assert _waf_events(store, eng) == [], (
        "an empty (reachable) response was mislabelled as WAF-blocked"
    )


# ---------------------------------------------------------------------------
# U1 — a 415 (content-negotiation rejection) is NEVER recorded as WAF_BLOCKED
# ---------------------------------------------------------------------------


def test_observe_415_is_not_blocked() -> None:
    alpha, eng, store = _make_recon_alpha(
        {_SEED: _Resp(415, "<html>Unsupported Media Type</html>", {}, _SEED)}
    )
    alpha.run_recon(eng, _SEED)
    assert _waf_events(store, eng) == [], (
        "a 415 content-negotiation rejection was mislabelled as WAF-blocked evidence "
        "(Bug #10 fix must not reuse BLOCKED/WAF_BLOCKED for 415)"
    )


# ---------------------------------------------------------------------------
# D1 — de-dup driver: the existing probes use the canonical classifier (anti-#7)
# ---------------------------------------------------------------------------


def test_js_secret_probe_uses_canonical_classifier() -> None:
    import agent_alpha.recon.js_secret_probe as js

    src = inspect.getsource(js)
    assert "classify_response" in src, (
        "js_secret_probe still hand-rolls its 403/429/503 WAF check — migrate it to the "
        "canonical classify_response so the rule has a single source of truth (anti-#7)"
    )


# ---------------------------------------------------------------------------
# D2 — CF soft-200 reload interstitial is CHALLENGE (field-proven)
# ---------------------------------------------------------------------------

_CF_SOFT200_INTERSTITIAL = (
    "<html>\n<head>\n<title>One moment, please...</title>\n"
    "<style>\n"
    "#cf-spinner-please-wait { spinner-styles }\n"
    ".spinner { border: 4px solid rgba(0,0,0,.1); border-radius: 50%; }\n"
    "</style>\n</head>\n<body>\n"
    '<div id="cf-spinner-please-wait">\n'
    '<div class="spinner"></div>\n'
    "<p>One moment, please...</p>\n"
    "</div>\n"
    "<script>\n"
    "setTimeout(function(){window.location.reload();},5000);\n"
    "</script>\n</body>\n</html>\n"
    "<!-- padding to ~11.8KB -->\n" + (" " * 11000) + "\n"
)

_WP_HOMEPAGE = (
    "<html>\n<head>\n<title>My WordPress Site</title>\n"
    '<link rel="stylesheet" href="/wp-content/themes/mytheme/style.css" />\n'
    "</head>\n<body>\n"
    "<header><nav>\n"
    '<a href="/about/">About Us</a>\n'
    '<a href="/blog/">Blog</a>\n'
    '<a href="/contact/">Contact</a>\n'
    '<a href="/services/">Services</a>\n'
    "</nav></header>\n"
    "<article>\n"
    "<h1>Welcome to Our Site</h1>\n"
    "<p>We are a leading company in our field.</p>\n"
    '<img src="/wp-content/uploads/2024/hero.jpg" />\n'
    "</article>\n"
    "<footer><p>&copy; 2024 My Company</p></footer>\n"
    "</body>\n</html>\n"
)

_META_REFRESH_REAL_PAGE = (
    "<html>\n<head>\n<title>This page has moved</title>\n"
    '<meta http-equiv="refresh" content="2;url=/new-location" />\n'
    "</head>\n<body>\n"
    "<nav>\n"
    '<a href="/home">Home</a>\n'
    '<a href="/about">About</a>\n'
    '<a href="/products">Products</a>\n'
    "</nav>\n"
    "<article>\n"
    "<h1>We have moved!</h1>\n"
    "<p>This page has been relocated. You will be redirected automatically.</p>\n"
    '<p>If you are not redirected, <a href="/new-location">click here</a>.</p>\n'
    "</article>\n"
    "</body>\n</html>\n"
)


def test_soft200_js_reload_interstitial_is_challenge() -> None:
    """A CF soft-200 interstitial (setTimeout + location.reload, no real content)
    must be classified as CHALLENGE, not OK — so the reach ladder triggers."""
    verdict = classify_response(
        status_code=200,
        body=_CF_SOFT200_INTERSTITIAL,
        headers={"server": "cloudflare", "cf-ray": "abc123"},
    )
    assert verdict is Verdict.CHALLENGE, (
        f"CF soft-200 reload interstitial classified as {verdict} instead of CHALLENGE — "
        "the reach ladder (browser_solve/camoufox) will never trigger"
    )


def test_large_catchall_spa_with_reload_signal_stays_ok() -> None:
    """CARDINAL (field-confirmed on a 200 catch-all SPA target): a LARGE 200
    catch-all SPA shell that merely SHIPS a reload signal
    (bundled setTimeout+location.reload) with few anchors and no <article> must
    NOT be mislabeled CHALLENGE. A genuine reload interstitial is small; a large
    body is application content. Without the size gate this false-CHALLENGE
    short-circuits scout.py soft-404 suppression and recon never converges on a
    catch-all-200 target."""
    body = (
        "<!DOCTYPE html><html><head><title>ExampleStore</title></head><body>"
        '<div id="app"></div>'
        "<script>setTimeout(function(){window.location.reload();},1000);</script>"
        + ("<span>x</span>" * 4000)  # push body well past RELOAD_SHELL_MAX_BYTES
        + "</body></html>"
    )
    assert len(body) >= RELOAD_SHELL_MAX_BYTES  # precondition: this is a large body
    verdict = classify_response(status_code=200, body=body)
    assert verdict is Verdict.OK, (
        f"large catch-all SPA shell classified as {verdict} instead of OK — the "
        "reload-interstitial detector fired on application content, mislabeling a "
        "200 catch-all SPA as CHALLENGE (short-circuits soft-404 suppression)"
    )


def test_legit_wp_homepage_stays_ok() -> None:
    """CARDINAL: a normal 200 WordPress homepage (wp-content, real anchors,
    no auto-reload) must stay OK. This is the FP guard — the whole point."""
    verdict = classify_response(
        status_code=200,
        body=_WP_HOMEPAGE,
        headers={"server": "cloudflare"},
    )
    assert verdict is Verdict.OK, (
        f"Legitimate WP homepage classified as {verdict} instead of OK — "
        "false positive: the reload-interstitial detector over-fired"
    )


def test_small_legit_meta_refresh_not_misclassed() -> None:
    """A real page using meta-refresh to a same-site URL with real content
    (anchors, article) must stay OK — don't over-fire on legitimate meta-refresh."""
    verdict = classify_response(
        status_code=200,
        body=_META_REFRESH_REAL_PAGE,
        headers={"server": "nginx"},
    )
    assert verdict is Verdict.OK, (
        f"Legitimate meta-refresh page with real content classified as {verdict} "
        "instead of OK — the reload-interstitial detector over-fired on a real page"
    )


def test_is_reload_shell_hint_fires_on_soft200() -> None:
    """The cost-gate hint fires on a CF soft-200 shell so the reach layer
    knows to probe — but it is a boolean hint, never a Verdict."""
    from agent_alpha.recon.response_classifier import is_reload_shell

    assert is_reload_shell(_CF_SOFT200_INTERSTITIAL) is True, (
        "is_reload_shell must fire on a thin reload shell so the reach layer probes"
    )


def test_is_reload_shell_hint_does_not_fire_on_real_content() -> None:
    """The cost-gate hint must NOT fire on a large real page even if it
    contains a reload script — only thin shells are suspicious."""
    from agent_alpha.recon.response_classifier import is_reload_shell

    big_page = "<html><body><p>real content</p>" + ("x" * 20000) + "</body></html>"
    assert is_reload_shell(big_page) is False, (
        "is_reload_shell must not fire on a large real page (>15KB)"
    )


# ---------------------------------------------------------------------------
# J1 — is_json_response truth table (JSON-body tool precondition SSOT)
# ---------------------------------------------------------------------------


def test_is_json_response_truth_table() -> None:
    """Four corners: header vs. body, JSON vs. non-JSON."""
    from agent_alpha.recon.response_classifier import is_json_response

    # JSON header + HTML body → True (header is authoritative)
    assert is_json_response("application/json", "<html>oops</html>") is True
    # text/html + JSON body → True (body inspection recovers a stripped header)
    assert is_json_response("text/html", '{"routes": {}}') is True
    # text/html + HTML body → False (neither signal)
    assert is_json_response("text/html", "<html>product page</html>") is False
    # empty body + no json header → False
    assert is_json_response("", "") is False
