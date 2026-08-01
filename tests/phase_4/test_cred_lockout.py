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
from agent_alpha.tools.contracts import ResourceBudget, TargetContext
from agent_alpha.tools.internal.access.applicator import AuthResult
from agent_alpha.tools.internal.access.cred_lockout import CredentialLockoutGovernor
from agent_alpha.tools.internal.access.default_creds import DefaultCredsTool

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


# ── RUNNER-SEAL ≠ WIRED: default_creds must honour the governor on the live path ──


class _RecordingApplicator:
    """Records every username that actually reaches the wire (apply()). Returns a
    failed AuthResult so the tool keeps iterating other accounts."""

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


class _Bound:
    def __init__(self, applicator: Any, target: str) -> None:
        self.applicator = applicator
        self.target = target


def test_default_creds_stops_submitting_when_account_locked_out() -> None:
    """Non-island: with a governor already at the per-username cap for 'admin',
    DefaultCredsTool.run() must NOT submit another 'admin' attempt to the wire."""
    gov = CredentialLockoutGovernor(max_per_username=2, max_per_host=100)
    # Pre-exhaust the 'admin' account budget (as if 2 attempts already happened).
    gov.record_attempt(_HOST, "admin")
    gov.record_attempt(_HOST, "admin")

    applicator = _RecordingApplicator()
    tool = DefaultCredsTool(
        applicators=[_Bound(applicator, f"https://{_HOST}")],
        http_client=object(),  # non-None so run() proceeds; wire is the fake applicator
        lockout=gov,
    )
    ctx = TargetContext(engagement_id="eng-lockout", tenant_id=None, target=f"https://{_HOST}")
    budget = ResourceBudget(max_requests=50, max_seconds=5, max_cost_usd=0.0)

    result = tool.run(ctx, budget)

    assert "admin" not in applicator.calls, (
        "default_creds submitted a locked-out 'admin' attempt — governor not wired"
    )
    assert result.success is False
