"""FROZEN contract (architect-authored — IDE implements the playbooks; do NOT edit assertions).

Closes the REACHABILITY half of the Alpha vector dispatch (the dispatch SEAM is already
merged + green). Today wp_config_probe / js_secret_probe are dispatched only when a
StubOrchestrator injects decision.tool — no PRODUCTION path selects them, because
agent_alpha/tools/playbooks/ has only laravel_debug.yaml + default_credentials_login.yaml.
The LLM ORIENT tier has no tool catalog either. So a real autonomous engagement can never
reach the WP/JS vectors.

This pins the deterministic RULE-tier selection. The IDE adds two data-only playbooks:
    agent_alpha/tools/playbooks/wp_config.yaml   -> action.tool: wp_config_probe
    agent_alpha/tools/playbooks/js_secret.yaml   -> action.tool: js_secret_probe
following the existing laravel_debug.yaml schema (name / match.any_indicator / action).

Design constraint the tests ENFORCE (not the exact indicators — those are the IDE's craft):
  * WP is a clean stack fingerprint (wp-content / wp-includes / generator=WordPress) —
    fire on WP, do NOT fire on a plain page.
  * js_secret is NOT a stack fingerprint: almost every page has <script>. The indicator
    MUST be SPA/bundle-specific (hashed bundle chunk, SPA root shell) — it MUST fire on a
    bundled SPA and MUST NOT fire on a plain page that merely has an ordinary <script>
    (e.g. analytics). A loose "<script>" indicator = js_secret probing every target =
    over-probing + FP inflation (anti-Lyndon #3). The negative test below is the teeth.

Pure PlaybookEngine — no Alpha, no network, no LLM. RED until the two playbooks exist.
Authoritative run: Oracle ARM64 (`.venv/bin/python3 -m pytest`).
"""

from __future__ import annotations

import pathlib

import agent_alpha.tools as tools_pkg
from agent_alpha.tools.playbook import PlaybookEngine

_PROD_PLAYBOOKS = pathlib.Path(tools_pkg.__file__).resolve().parent / "playbooks"

# A bundled-SPA shell: root mount + a content-hashed JS chunk (webpack/vite style).
_SPA_BODY = (
    '<html><body><div id="root"></div>'
    '<script src="/static/js/main.a1b2c3d4.js"></script></body></html>'
)
# A clean WordPress page.
_WP_BODY = (
    '<html><head><link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    '<meta name="generator" content="WordPress 6.5"></head>'
    '<body><script src="/wp-includes/js/jquery/jquery.min.js"></script></body></html>'
)
# A plain marketing page: HAS an ordinary <script> (analytics), but is neither WP nor an SPA.
_PLAIN_BODY = (
    "<html><body><h1>Welcome</h1><p>About us.</p>"
    '<script src="/js/analytics.js"></script></body></html>'
)


def _tool_for(body: str) -> str | None:
    """RULE-tier tool selected for an observation body, or None if no rule matches."""
    engine = PlaybookEngine.from_directory(_PROD_PLAYBOOKS)
    decision = engine.match({"body": body})
    return decision.tool if decision is not None else None


def test_wp_fingerprint_selects_wp_config_probe() -> None:
    """A WordPress page deterministically selects wp_config_probe (RED until wp_config.yaml)."""
    assert _tool_for(_WP_BODY) == "wp_config_probe"


def test_spa_bundle_selects_js_secret_probe() -> None:
    """A bundled SPA deterministically selects js_secret_probe (RED until js_secret.yaml)."""
    assert _tool_for(_SPA_BODY) == "js_secret_probe"


def test_plain_page_selects_neither_vector() -> None:
    """A plain page with an ordinary <script> must select NEITHER WP nor JS vector.

    This is the anti-#3 teeth: a js_secret indicator loose enough to fire on any <script>
    would probe every target's bundles — over-probing + false positives. It must be
    SPA/bundle-specific, so a plain analytics page selects neither.
    """
    assert _tool_for(_PLAIN_BODY) not in {"wp_config_probe", "js_secret_probe"}


def test_laravel_playbook_still_selects_laravel_debug() -> None:
    """Regression: adding WP/JS playbooks must not disturb the existing Laravel rule."""
    assert _tool_for("<html>Whoops! Illuminate\\Foundation error</html>") == "laravel_debug_probe"
