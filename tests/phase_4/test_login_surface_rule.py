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
    """The rule's tool must be a real dispatch target (else DECIDE routes nowhere).

    Introspects the live Alpha instance instead of parsing scout.py source text,
    so the test survives refactor of the dispatch construction (e.g. catalog
    derivation with nested _generic/_special dicts).
    """
    from agent_alpha.agents.alpha.scout import Alpha
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.security.secrets import SecretsManager
    from agent_alpha.tools.playbook import PlaybookEngine

    class _StubProvider:
        model = "stub"

        def complete(self, *a: object, **k: object) -> object:
            return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()

    class _FakeHttp:
        def get(self, url: str) -> object:
            return type("R", (), {"status_code": 404, "text": "", "headers": {}})()

    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="auth_surface_wiring", target="test.example")
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=["test.example"], exclusions=[]))
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=LLMOrchestrator(
            playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR),
            provider=_StubProvider(),
        ),
        http_client=_FakeHttp(),
        secrets_manager=SecretsManager(),
    )
    assert "auth_surface_probe" in alpha._dispatch_registry


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
