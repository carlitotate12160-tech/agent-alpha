"""GAP-036: login/auth-surface pages get a deterministic RECON rule decision
(auth_surface_probe) instead of falling to the LLM tier — which picks the nearest
framework-vuln tool (laravel_debug_probe) and wastes a probe. Synthetic bodies only.
"""

from __future__ import annotations

import pathlib

from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")


def _recon_engine() -> PlaybookEngine:
    return PlaybookEngine.from_directory(_PLAYBOOK_DIR, phase="recon")


def test_login_page_matches_recon_rule_not_llm() -> None:
    engine = _recon_engine()
    obs = {
        "body": '<form><input name="user"><input type="password" name="pw"></form>',
        "headers": {},
    }
    decision = engine.match(obs)
    assert decision is not None
    assert decision.tool == "auth_surface_probe"
    assert decision.tier == "rule"


def test_single_quoted_password_matches() -> None:
    engine = _recon_engine()
    decision = engine.match({"body": "<input type='password'>", "headers": {}})
    assert decision is not None and decision.tool == "auth_surface_probe"


def test_vue_dynamic_binding_matches_via_name() -> None:
    """pos.niagamas.com uses :type binding (no type="password" literal) but has
    name="password" — the rule must still fire (anti-GAP-036 regression)."""
    engine = _recon_engine()
    body = '<input :type="showPassword ? \'text\' : \'password\'" name="password">'
    decision = engine.match({"body": body, "headers": {}})
    assert decision is not None and decision.tool == "auth_surface_probe"


def test_id_password_matches() -> None:
    engine = _recon_engine()
    decision = engine.match({"body": '<input id="password" type="text">', "headers": {}})
    assert decision is not None and decision.tool == "auth_surface_probe"


def test_autocomplete_current_password_matches() -> None:
    engine = _recon_engine()
    decision = engine.match(
        {"body": '<input autocomplete="current-password">', "headers": {}}
    )
    assert decision is not None and decision.tool == "auth_surface_probe"


def test_forget_password_email_only_does_not_match_login_rule() -> None:
    """A page with no password <input> (e.g. forget-password, email only) must NOT
    fire the login rule — it falls through (to LLM) rather than over-firing."""
    engine = _recon_engine()
    decision = engine.match(
        {"body": '<form><input type="email" name="email"></form>', "headers": {}}
    )
    assert decision is None or decision.tool != "auth_surface_probe"


def test_auth_surface_probe_registered_in_scout() -> None:
    """The rule's tool must be a real dispatch target (else DECIDE routes nowhere)."""
    import re

    src = pathlib.Path("agent_alpha/agents/alpha/scout.py").read_text()
    block = src.split("self._dispatch_registry", 1)[1].split("}", 1)[0]
    keys = set(re.findall(r'"([a-z_]+)":', block))
    assert "auth_surface_probe" in keys


# ── CodeRabbit PR#395: single-quoted attributes must also match (quote-agnostic) ─


def test_single_quoted_name_password_matches() -> None:
    engine = _recon_engine()
    d = engine.match({"body": "<input name='password'>", "headers": {}})
    assert d is not None and d.tool == "auth_surface_probe"


def test_single_quoted_id_password_matches() -> None:
    engine = _recon_engine()
    d = engine.match({"body": "<input id='password' type='text'>", "headers": {}})
    assert d is not None and d.tool == "auth_surface_probe"


def test_single_quoted_autocomplete_matches() -> None:
    engine = _recon_engine()
    d = engine.match({"body": "<input autocomplete='current-password'>", "headers": {}})
    assert d is not None and d.tool == "auth_surface_probe"


def test_vue_single_quoted_binding_matches_via_name() -> None:
    engine = _recon_engine()
    body = "<input :type=\"showPassword ? 'text' : 'password'\" name='password'>"
    d = engine.match({"body": body, "headers": {}})
    assert d is not None and d.tool == "auth_surface_probe"


def test_name_password_outside_input_tag_does_not_match() -> None:
    """A JSON/JS body mentioning name:"password" (no <input>) must NOT fire."""
    engine = _recon_engine()
    d = engine.match({"body": '{"field":{"name":"password"}}', "headers": {}})
    assert d is None or d.tool != "auth_surface_probe"
