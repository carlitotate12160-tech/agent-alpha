# agent_alpha/tools/internal/access/cred_lockout.py
"""cred_lockout — CredentialLockoutGovernor: bound login attempts so Beta never
locks out a client's real accounts (§12.22 D2, credential-spray safety).

DISTINCT from ``recon.transport_resilience.LockoutGovernor`` (that bounds REACH
escalations per host). This governs LOGIN attempts keyed by ``(host, username)``
plus a per-host aggregate. One concept per class (anti-#6); thresholds live in
``config.constants`` (single source, anti-#7).

Doctrine: safety-before-capability. Every credential tool (default_creds today;
cred_reuse / odoo_access / username-derived candidates as they wire in) MUST pass
each submission through ``may_attempt`` / ``record_attempt`` so a real account is
never driven into lockout, and total login noise on a host stays bounded.

Event-sourced projection: this class holds the in-memory counters; the caller
persists the underlying attempt events externally (parity with LockoutGovernor).
``may_attempt`` = read side; ``record_attempt`` = write side.
"""

from __future__ import annotations

from agent_alpha.config import constants


class CredentialLockoutGovernor:
    """Bounds login attempts per ``(host, username)`` and per host.

    An attempt is allowed only when BOTH budgets remain: the account has not hit
    ``max_per_username`` AND the host has not hit ``max_per_host``. Once either is
    spent, ``may_attempt`` returns ``False`` and the caller MUST stop submitting.
    """

    def __init__(
        self,
        *,
        max_per_username: int = constants.CRED_LOCKOUT_MAX_ATTEMPTS_PER_USERNAME,
        max_per_host: int = constants.CRED_LOCKOUT_MAX_ATTEMPTS_PER_HOST,
    ) -> None:
        self._max_user = max_per_username
        self._max_host = max_per_host
        self._per_user: dict[tuple[str, str], int] = {}
        self._per_host: dict[str, int] = {}

    def may_attempt(self, host: str, username: str) -> bool:
        """True iff the account AND the host both have attempt budget remaining."""
        if self._per_host.get(host, 0) >= self._max_host:
            return False
        return self._per_user.get((host, username), 0) < self._max_user

    def record_attempt(self, host: str, username: str) -> None:
        """Record one login submission against ``(host, username)`` and *host*."""
        self._per_user[(host, username)] = self._per_user.get((host, username), 0) + 1
        self._per_host[host] = self._per_host.get(host, 0) + 1

    def remaining_for_username(self, host: str, username: str) -> int:
        """Attempts left for *username* on *host* (0 if the host cap is already spent)."""
        if self._per_host.get(host, 0) >= self._max_host:
            return 0
        return max(0, self._max_user - self._per_user.get((host, username), 0))

    def remaining_for_host(self, host: str) -> int:
        """Aggregate attempts left on *host* across all usernames."""
        return max(0, self._max_host - self._per_host.get(host, 0))

    def is_locked_out(self, host: str, username: str) -> bool:
        """True if no further attempt may be made for ``(host, username)``."""
        return not self.may_attempt(host, username)
