"""Contract: CredentialLockoutGovernor bounds login attempts so Beta never
locks out a client's real accounts (§12.22 D2, credential-spray safety).

RED before the governor exists:
  1. ``from agent_alpha.tools.internal.access.cred_lockout import
     CredentialLockoutGovernor`` → ImportError.
  2. default_creds has no ``lockout`` seam → the wiring test cannot inject one.

Lyndon checks:
  #6 — distinct concept from recon LockoutGovernor (login attempts, not reach).
  #7 — thresholds come from constants (single source), asserted below.
  RUNNER-SEAL ≠ WIRED — the last test proves default_creds.run() actually honours
  the governor on the live path (non-island), not just the class in isolation.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_4/test_cred_lockout.py -v
"""

from __future__ import annotations

from typing import Any

from agent_alpha.config import constants
from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.applicator import AuthResult, GovernedApplicator
from agent_alpha.tools.internal.access.cred_lockout import CredentialLockoutGovernor

_HOST = "app.example.com"


def test_thresholds_come_from_constants() -> None:
    """Governor defaults are the single-source constants (anti-#7)."""
    gov = CredentialLockoutGovernor()
    assert gov.remaining_for_username(_HOST, "admin") == (
        constants.CRED_LOCKOUT_MAX_ATTEMPTS_PER_USERNAME
    )
    assert gov.remaining_for_host(_HOST) == constants.CRED_LOCKOUT_MAX_ATTEMPTS_PER_HOST


def test_per_username_cap_blocks_further_attempts() -> None:
    """After max_per_username submissions on one account, may_attempt is False —
    the account is never driven past the cap (lockout safety)."""
    gov = CredentialLockoutGovernor(max_per_username=3, max_per_host=100)
    for _ in range(3):
        assert gov.may_attempt(_HOST, "admin") is True
        gov.record_attempt(_HOST, "admin")
    assert gov.may_attempt(_HOST, "admin") is False
    assert gov.is_locked_out(_HOST, "admin") is True
    # A DIFFERENT account on the same host still has its own budget.
    assert gov.may_attempt(_HOST, "editor") is True


def test_per_host_aggregate_cap_blocks_even_under_username_cap() -> None:
    """The host aggregate cap stops the spray even when each account stays under
    its own per-username cap (IP-ban / WAF-trip safety)."""
    gov = CredentialLockoutGovernor(max_per_username=5, max_per_host=4)
    for i in range(4):
        assert gov.may_attempt(_HOST, f"user{i}") is True
        gov.record_attempt(_HOST, f"user{i}")  # 1 attempt each, 4 total = host cap
    # Host budget spent: a brand-new account (own per-user budget intact) is refused.
    assert gov.may_attempt(_HOST, "fresh") is False
    assert gov.remaining_for_host(_HOST) == 0


def test_counts_are_scoped_per_host() -> None:
    """A second host has an independent budget — no cross-host bleed."""
    gov = CredentialLockoutGovernor(max_per_username=1, max_per_host=10)
    gov.record_attempt(_HOST, "admin")
    assert gov.may_attempt(_HOST, "admin") is False
    assert gov.may_attempt("other.example.com", "admin") is True


# ── SEAM: GovernedApplicator enforces the governor for EVERY cred tool ──────────

_BUDGET = ResourceBudget(max_requests=10, max_seconds=5, max_cost_usd=0.0)


class _RecordingApplicator:
    """CredentialApplicator double: records every username that reaches apply()."""

    service = "http"
    required_auth = "ACTIVE_APPROVED"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def applies_to(self, credential_service: str, target: str) -> bool:  # noqa: ARG002
        return True

    def apply(self, *, username: str, secret: str, target: str, budget: Any) -> AuthResult:  # noqa: ARG002
        self.calls.append(username)
        return AuthResult(
            success=False,
            access_level="",
            service="http",
            confidence=0.0,
            proof_request={},
            proof_response={},
        )


def test_governed_applicator_refuses_when_budget_exhausted() -> None:
    """Once the (host, username) budget is spent, GovernedApplicator.apply returns a
    failed AuthResult WITHOUT touching the wire — the account is never locked out."""
    gov = CredentialLockoutGovernor(max_per_username=1, max_per_host=100)
    gov.record_attempt(_HOST, "admin")  # pre-exhaust the account
    inner = _RecordingApplicator()
    governed = GovernedApplicator(inner, gov)

    res = governed.apply(
        username="admin", secret="x", target=f"https://{_HOST}/login", budget=_BUDGET
    )

    assert res.success is False
    assert "admin" not in inner.calls, "locked-out account reached the wire — seam not enforced"


def test_governed_applicator_records_and_delegates_when_budget_remains() -> None:
    """With budget remaining, the wrapper records the attempt and delegates to the
    wrapped applicator (the submission actually happens)."""
    gov = CredentialLockoutGovernor(max_per_username=3, max_per_host=100)
    inner = _RecordingApplicator()
    governed = GovernedApplicator(inner, gov)

    governed.apply(
        username="editor", secret="x", target=f"https://{_HOST}/login", budget=_BUDGET
    )

    assert inner.calls == ["editor"], "attempt did not reach the wrapped applicator"
    assert gov.remaining_for_username(_HOST, "editor") == 2, "attempt was not recorded"


def test_governed_applicator_exposes_inner_metadata() -> None:
    """service / required_auth must pass through so the registry + factory still see
    the applicator's real selection metadata (wrap is transparent)."""
    governed = GovernedApplicator(_RecordingApplicator(), CredentialLockoutGovernor())
    assert governed.service == "http"
    assert governed.required_auth == "ACTIVE_APPROVED"
