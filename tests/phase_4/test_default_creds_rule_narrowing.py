# Bug #14 pin (real files, not synthetic fixtures):
#   1. default_credentials_login.yaml no longer matches page-wide nav text
#      ("Login" / "Sign in" / "Log in" / "Sign In") — only a real password
#      <input> or a specific product fingerprint (Grafana).
#   2. Alpha's real production pipeline (build_recon_pipeline) cannot load
#      this rule at all — RECON_ONLY, phase="recon" filter — a structural
#      guarantee, not a hope the indicator never matches.
#
# Run on Oracle ARM64 only:
#     .venv312/bin/python3 -m pytest tests/phase_4/test_default_creds_rule_narrowing.py -v

from __future__ import annotations

import pathlib

from agent_alpha.tools.playbook import PlaybookEngine

_REAL_PLAYBOOK_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"
)


def _engine(*, phase: str | None = None) -> PlaybookEngine:
    return PlaybookEngine.from_directory(_REAL_PLAYBOOK_DIR, phase=phase)


# ---------------------------------------------------------------------------
# 1. Indicator narrowing
# ---------------------------------------------------------------------------


def test_plain_nav_login_text_no_longer_matches() -> None:
    """The field-observed false positive: an ordinary article page whose nav
    chrome has a 'Login' link in the header. Before the fix this matched
    default_credentials_login on 75/162 pages of a real engagement."""
    article_page = (
        "<html><head><title>Company Blog</title></head>"
        "<body><nav><a href='/login'>Login</a></nav>"
        "<article>Our Q3 product update...</article></body></html>"
    )
    decision = _engine().match({"body": article_page, "headers": {}})
    assert decision is None, "a plain nav 'Login' link must not trigger default_creds"


def test_sign_in_and_log_in_variants_no_longer_match() -> None:
    for phrase in ("Sign in", "Sign In", "Log in"):
        body = f"<html><body><footer>{phrase} to your account</footer></body></html>"
        decision = _engine().match({"body": body, "headers": {}})
        assert decision is None, f"nav text {phrase!r} must not trigger default_creds"


def test_real_password_field_still_matches() -> None:
    """The functional signal is preserved: an actual login FORM still fires
    the rule — this is not a blanket removal, only the page-wide chrome text."""
    login_page = '<html><body><form><input type="password" name="pwd"></form></body></html>'
    decision = _engine().match({"body": login_page, "headers": {}})
    assert decision is not None
    assert decision.tool == "default_creds"


def test_grafana_fingerprint_still_matches() -> None:
    decision = _engine().match({"body": "<title>Grafana</title>", "headers": {}})
    assert decision is not None
    assert decision.tool == "default_creds"


# ---------------------------------------------------------------------------
# 2. Structural phase gate — Alpha cannot load the rule at all
# ---------------------------------------------------------------------------


def test_recon_phase_engine_never_loads_default_creds_rule() -> None:
    """Even a page that WOULD match (real password field) must not fire
    default_creds through a phase='recon' engine — the rule is not loaded,
    full stop. This is what build_recon_pipeline() actually constructs for
    Alpha; this test proves it without needing DEEPSEEK_API_KEY / a live
    Celery task."""
    recon_engine = _engine(phase="recon")
    login_page = '<html><body><form><input type="password" name="pwd"></form></body></html>'
    decision = recon_engine.match({"body": login_page, "headers": {}})
    assert decision is None, (
        "default_credentials_login (phase: access) was loaded into a "
        "phase='recon' engine — Alpha must never be able to reach it"
    )


def test_access_phase_engine_still_has_the_rule() -> None:
    """Sanity: the filter is selective, not a blanket removal — Beta
    (phase='access', via main.py's run_agent_task) must still get it."""
    access_engine = _engine(phase="access")
    login_page = '<html><body><form><input type="password" name="pwd"></form></body></html>'
    decision = access_engine.match({"body": login_page, "headers": {}})
    assert decision is not None
    assert decision.tool == "default_creds"


def test_unfiltered_engine_still_has_both_recon_and_access_rules() -> None:
    """Sanity: phase=None (the default, used by every live_fire runner that
    tests end-to-end recon->access chains in one process) is unchanged."""
    everything = _engine(phase=None)
    assert (
        everything.match({"body": '<form><input type="password"></form>', "headers": {}})
        is not None
    )
