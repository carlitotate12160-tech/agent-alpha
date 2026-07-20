# tests/phase_2_5/test_transport_resilience.py
"""Contract: §12.33 slice-9a — Mitigation-class discriminator + lockout governor
+ planner escalation trigger.

8 tests. The DIFFERENTIAL tests (T6/T7) prove that different mitigation classes
produce different evasion techniques — the anti-#11 invariant (class drives
technique, not a fixed ladder).

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_transport_resilience.py -v
"""

from __future__ import annotations

from agent_alpha.config.constants import EVASION_MAX_ESCALATIONS_PER_HOST
from agent_alpha.recon.transport_resilience import (
    EvasionPlanner,
    EvasionTechnique,
    LockoutGovernor,
    MitigationClass,
    classify_mitigation,
)

# ── T1: classify_mitigation — cf-mitigated challenge header → BROWSER ─────────


def test_cf_mitigated_challenge_header_classifies_browser() -> None:
    """A 403 with cf-mitigated: challenge header → MitigationClass.BROWSER."""
    result = classify_mitigation(
        status_code=403,
        body="<html>Attention Required</html>",
        headers={"cf-mitigated": "challenge", "server": "cloudflare"},
        path="/api/users",
    )
    assert result is MitigationClass.BROWSER


# ── T2: classify_mitigation — .bak path → ABORT ──────────────────────────────


def test_bak_path_classifies_abort() -> None:
    """A 403 on a .bak path → MitigationClass.ABORT (never escalate)."""
    result = classify_mitigation(
        status_code=403,
        body="Forbidden",
        headers=None,
        path="/wp-config.php.bak",
    )
    assert result is MitigationClass.ABORT


# ── T3: classify_mitigation — 429 → RATE_LIMIT ───────────────────────────────


def test_429_classifies_rate_limit() -> None:
    """A 429 response → MitigationClass.RATE_LIMIT."""
    result = classify_mitigation(
        status_code=429,
        body="Rate limit exceeded",
        headers=None,
        path="/login",
    )
    assert result is MitigationClass.RATE_LIMIT


# ── T4: classify_mitigation — OK response → None ─────────────────────────────


def test_ok_response_returns_none() -> None:
    """A 200 OK response has no mitigation class (None)."""
    result = classify_mitigation(
        status_code=200,
        body="<html>Hello</html>",
        headers=None,
        path="/",
    )
    assert result is None


# ── T5: LockoutGovernor — ABORT past cap ──────────────────────────────────────


def test_lockout_governor_aborts_past_cap() -> None:
    """After max_escalations, governor denies further escalation."""
    gov = LockoutGovernor(max_escalations=2)
    host = "target.example.com"

    assert gov.may_escalate(host) is True
    gov.record_escalation(host)
    assert gov.may_escalate(host) is True
    gov.record_escalation(host)
    # Now at cap.
    assert gov.may_escalate(host) is False
    assert gov.is_locked_out(host) is True
    assert gov.remaining(host) == 0


# ── T6: DIFFERENTIAL — RATE_LIMIT class → rate_throttle technique ─────────────


def test_differential_rate_limit_produces_rate_throttle() -> None:
    """RATE_LIMIT class drives rate_throttle technique (anti-#11 differential)."""
    gov = LockoutGovernor()
    planner = EvasionPlanner(governor=gov, consecutive_threshold=1)
    host = "a.example.com"

    planner.record_blocked(host)
    proposal = planner.evaluate(host, MitigationClass.RATE_LIMIT, evasion_authorized=True)

    assert proposal is not None
    assert proposal.technique is EvasionTechnique.RATE_THROTTLE
    assert proposal.mitigation_class is MitigationClass.RATE_LIMIT


# ── T7: DIFFERENTIAL — BROWSER class → tls_impersonate technique ─────────────


def test_differential_browser_produces_tls_impersonate() -> None:
    """BROWSER class drives tls_impersonate technique (anti-#11 differential).

    This proves that a DIFFERENT class produces a DIFFERENT technique — the
    selection is class-driven, not a fixed escalation ladder.
    """
    gov = LockoutGovernor()
    planner = EvasionPlanner(governor=gov, consecutive_threshold=1)
    host = "b.example.com"

    planner.record_blocked(host)
    proposal = planner.evaluate(host, MitigationClass.BROWSER, evasion_authorized=True)

    assert proposal is not None
    assert proposal.technique is EvasionTechnique.TLS_IMPERSONATE
    assert proposal.mitigation_class is MitigationClass.BROWSER
    # Anti-#11 proof: different class → different technique.
    assert EvasionTechnique.TLS_IMPERSONATE is not EvasionTechnique.RATE_THROTTLE


# ── T8: Planner — not authorized → None (fail-closed) ────────────────────────


def test_planner_not_authorized_returns_none() -> None:
    """Without evasion_authorized, planner NEVER proposes (fail-closed)."""
    gov = LockoutGovernor()
    planner = EvasionPlanner(governor=gov, consecutive_threshold=1)
    host = "c.example.com"

    planner.record_blocked(host)
    proposal = planner.evaluate(host, MitigationClass.BROWSER, evasion_authorized=False)

    assert proposal is None
    # Governor untouched — no escalation recorded.
    assert gov.remaining(host) == EVASION_MAX_ESCALATIONS_PER_HOST
