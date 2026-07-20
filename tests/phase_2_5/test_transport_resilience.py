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

from agent_alpha.config.constants import (
    EVASION_MAX_ESCALATIONS_PER_HOST,
    TECHNIQUE_FOR_MITIGATION_CLASS,
)
from agent_alpha.recon.transport_resilience import (
    EvasionPlanner,
    EvasionTechnique,
    LockoutGovernor,
    MitigationClass,
    classify_mitigation,
)

# ── T1: classify_mitigation — cf-mitigated challenge header → CHALLENGE ───────


def test_cf_mitigated_challenge_header_classifies_challenge() -> None:
    """A 403 with cf-mitigated: challenge header → MitigationClass.CHALLENGE."""
    result = classify_mitigation(
        status_code=403,
        body="<html>Attention Required</html>",
        headers={"cf-mitigated": "challenge", "server": "cloudflare"},
        path="/api/users",
    )
    assert result is MitigationClass.CHALLENGE


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


# ── T7: CF-managed challenge must never map to TLS impersonation ──────────────


def test_cf_managed_challenge_never_maps_to_tls() -> None:
    """Cloudflare-managed challenge header → CHALLENGE → browser_solve, not TLS.

    Regression: cf-mitigated: challenge must NOT drive tls_impersonate. The
    mitigation class stays CHALLENGE and maps to browser_solve.
    """
    mitigation = classify_mitigation(
        status_code=403,
        body="<html>Attention Required</html>",
        headers={"cf-mitigated": "challenge", "server": "cloudflare"},
        path="/api/users",
    )
    assert mitigation is MitigationClass.CHALLENGE

    gov = LockoutGovernor()
    planner = EvasionPlanner(governor=gov, consecutive_threshold=1)
    host = "b.example.com"

    planner.record_blocked(host)
    proposal = planner.evaluate(host, mitigation, evasion_authorized=True)

    assert proposal is not None
    assert proposal.technique is EvasionTechnique.BROWSER_SOLVE
    assert proposal.technique is not EvasionTechnique.TLS_IMPERSONATE


# ── T8: Planner — not authorized → None (fail-closed) ────────────────────────


def test_planner_not_authorized_returns_none() -> None:
    """Without evasion_authorized, planner NEVER proposes (fail-closed)."""
    gov = LockoutGovernor()
    planner = EvasionPlanner(governor=gov, consecutive_threshold=1)
    host = "c.example.com"

    planner.record_blocked(host)
    proposal = planner.evaluate(host, MitigationClass.FINGERPRINT, evasion_authorized=False)

    assert proposal is None
    # Governor untouched — no escalation recorded.
    assert gov.remaining(host) == EVASION_MAX_ESCALATIONS_PER_HOST


# ── T9: Exhaustiveness — enum & map must be synchronized ──────────────────────


def test_every_mitigation_class_has_a_technique() -> None:
    """Exhaustiveness test: every MitigationClass must map to a valid EvasionTechnique.

    This prevents drift (Lyndon #6/#7) and silent failures (Lyndon #3). If a new
    MitigationClass is added but forgotten in TECHNIQUE_FOR_MITIGATION_CLASS, this
    test fails immediately instead of silently defaulting to NONE at runtime.
    """
    # All enum values must have a mapping key.
    assert set(TECHNIQUE_FOR_MITIGATION_CLASS) == {c.value for c in MitigationClass}

    # All mapped values must be valid EvasionTechnique enum members.
    for v in TECHNIQUE_FOR_MITIGATION_CLASS.values():
        EvasionTechnique(v)  # raises ValueError if v is not a valid technique
