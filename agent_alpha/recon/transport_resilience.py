# agent_alpha/recon/transport_resilience.py
"""§12.33 slice-9a — Mitigation-class discriminator, lockout governor, planner
escalation trigger.

Architecture (anti-#11): the MITIGATION CLASS drives the evasion technique, NOT
a fixed escalation ladder. `classify_mitigation` inspects headers/status/path to
determine WHY a request was blocked, then `TECHNIQUE_FOR_MITIGATION_CLASS`
(constants.py, single-source) maps class → technique.

`LockoutGovernor`: per-host bounded escalations; event-sourced via the EventStore.
After `EVASION_MAX_ESCALATIONS_PER_HOST` escalations for a host, any further
escalation request returns ABORT — the agent must NOT burn opsec budget.

`EvasionPlanner`: after N consecutive BLOCKED verdicts (same host) with
`evasion_authorized=True`, proposes the technique for the detected class. Without
authorization or below threshold, records BLOCKED and returns None.

Evasion stays RECON_ONLY — no transport body here (DeepSeek lane: curl_cffi /
camoufox). This module owns the DISCRIMINATOR + GOVERNOR + TRIGGER only.

PURE logic: no I/O, no HTTP calls. Depends only on classify_response (response_
classifier.py) + constants.py.
"""

from __future__ import annotations

import enum

from agent_alpha.config.constants import (
    EVASION_CONSECUTIVE_BLOCKED_N,
    EVASION_MAX_ESCALATIONS_PER_HOST,
    TECHNIQUE_FOR_MITIGATION_CLASS,
)
from agent_alpha.recon.response_classifier import Verdict, classify_response

# ── Enums ─────────────────────────────────────────────────────────────────────


class MitigationClass(enum.StrEnum):
    """WHY the request was blocked — the class drives the technique (anti-#11)."""

    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    FINGERPRINT = "fingerprint"
    RULE_DENY = "rule_deny"
    ABORT = "abort"


class EvasionTechnique(enum.StrEnum):
    """WHAT evasion technique the planner may propose for a given class."""

    RATE_THROTTLE = "rate_throttle"
    BROWSER_SOLVE = "browser_solve"
    TLS_IMPERSONATE = "tls_impersonate"
    NONE = "none"


# ── Discriminator ─────────────────────────────────────────────────────────────

# Path suffixes that indicate a protected backup — escalating evasion on these
# is pointless and burns opsec budget. The target deliberately blocks them.
_ABORT_PATH_SUFFIXES: frozenset[str] = frozenset({".bak", ".save", ".old", ".orig", ".swp", "~"})


def classify_mitigation(
    *,
    status_code: int,
    body: str,
    headers: dict[str, str] | None = None,
    transport_error: bool = False,
    path: str = "",
) -> MitigationClass | None:
    """Classify the mitigation class of a blocked/challenged response.

    Returns None if the response is not blocked/challenged (i.e. no mitigation
    detected). Reuses :func:`classify_response` as the verdict source.

    Classification rules (precedence order):
      1. Path ends with a backup suffix (.bak, .save, etc.) → ABORT.
         Rationale: the target explicitly protects backup files; escalating
         evasion is futile and wastes opsec budget.
      2. status_code == 429 → RATE_LIMIT.
      3. Verdict == CHALLENGE, or headers contain ``cf-mitigated`` with value
         containing "challenge" → CHALLENGE (interactive browser challenge).
      4. Default blocked (403/503 without challenge marker) → FINGERPRINT
         (plain WAF/CDN 403/503 based on TLS fingerprint).
    """
    verdict = classify_response(
        status_code=status_code,
        body=body,
        headers=headers,
        transport_error=transport_error,
    )
    if verdict not in (Verdict.BLOCKED, Verdict.CHALLENGE):
        return None

    # Rule 1: backup path → ABORT (never escalate).
    if path and any(path.rstrip("/").endswith(suffix) for suffix in _ABORT_PATH_SUFFIXES):
        return MitigationClass.ABORT

    # Rule 2: explicit rate limit.
    if status_code == 429:
        return MitigationClass.RATE_LIMIT

    # Rule 3: interactive challenge (body markers or CF-managed challenge).
    if verdict is Verdict.CHALLENGE:
        return MitigationClass.CHALLENGE
    if headers:
        cf_mitigated = headers.get("cf-mitigated", headers.get("Cf-Mitigated", ""))
        if "challenge" in cf_mitigated.lower():
            return MitigationClass.CHALLENGE

    # Rule 4: default blocked (403/503 without challenge marker) → FINGERPRINT.
    return MitigationClass.FINGERPRINT


# ── Lockout Governor ──────────────────────────────────────────────────────────


class EscalationRecord:
    """Per-host escalation counter (in-memory, event-sourced projection)."""

    __slots__ = ("host", "count")

    def __init__(self, host: str) -> None:
        self.host = host
        self.count: int = 0


class LockoutGovernor:
    """Per-host bounded escalation governor (§12.22 Decision 2).

    Tracks how many escalation attempts have been made per host. Once
    `max_escalations` is reached, further attempts return ABORT — the agent
    MUST stop trying on that host.

    Event-sourced: callers persist events externally; this class maintains the
    in-memory projection. `record_escalation` is the write side;
    `may_escalate` is the read side.
    """

    def __init__(self, *, max_escalations: int = EVASION_MAX_ESCALATIONS_PER_HOST) -> None:
        self._max = max_escalations
        self._hosts: dict[str, EscalationRecord] = {}

    def may_escalate(self, host: str) -> bool:
        """Return True if the host has NOT exhausted its escalation budget."""
        rec = self._hosts.get(host)
        if rec is None:
            return True
        return rec.count < self._max

    def record_escalation(self, host: str) -> None:
        """Record one escalation attempt for *host*."""
        rec = self._hosts.get(host)
        if rec is None:
            rec = EscalationRecord(host)
            self._hosts[host] = rec
        rec.count += 1

    def remaining(self, host: str) -> int:
        """Return the number of escalation attempts remaining for *host*."""
        rec = self._hosts.get(host)
        if rec is None:
            return self._max
        return max(0, self._max - rec.count)

    def is_locked_out(self, host: str) -> bool:
        """Return True if *host* is locked out (budget exhausted)."""
        return not self.may_escalate(host)


# ── Planner ───────────────────────────────────────────────────────────────────


class PlannerProposal:
    """A concrete evasion technique proposal from the planner."""

    __slots__ = ("host", "mitigation_class", "technique")

    def __init__(
        self, host: str, mitigation_class: MitigationClass, technique: EvasionTechnique
    ) -> None:
        self.host = host
        self.mitigation_class = mitigation_class
        self.technique = technique

    def __repr__(self) -> str:
        return (
            f"PlannerProposal(host={self.host!r}, "
            f"class={self.mitigation_class.value}, "
            f"technique={self.technique.value})"
        )


class EvasionPlanner:
    """Decides WHEN to propose an evasion technique switch (§12.33 D1).

    Trigger: N consecutive BLOCKED verdicts on the same host AND
    `evasion_authorized` is True. The technique proposed is driven by the
    mitigation class (anti-#11), not a fixed ladder.

    If `evasion_authorized` is False, or the LockoutGovernor says ABORT, the
    planner returns None (record only, never propose).
    """

    def __init__(
        self,
        *,
        governor: LockoutGovernor,
        consecutive_threshold: int = EVASION_CONSECUTIVE_BLOCKED_N,
    ) -> None:
        self._governor = governor
        self._threshold = consecutive_threshold
        # Per-host consecutive BLOCKED counter.
        self._consecutive: dict[str, int] = {}

    def record_blocked(self, host: str) -> None:
        """Record a BLOCKED verdict for *host*."""
        self._consecutive[host] = self._consecutive.get(host, 0) + 1

    def reset(self, host: str) -> None:
        """Reset the consecutive counter for *host* (e.g. on OK verdict)."""
        self._consecutive.pop(host, None)

    @property
    def consecutive_blocked(self) -> dict[str, int]:
        """Read-only view of per-host consecutive blocked counts."""
        return dict(self._consecutive)

    def evaluate(
        self,
        host: str,
        mitigation_class: MitigationClass,
        *,
        evasion_authorized: bool,
    ) -> PlannerProposal | None:
        """Evaluate whether an evasion technique switch should be proposed.

        Returns a `PlannerProposal` if all conditions are met:
          1. Consecutive BLOCKED count >= N (threshold).
          2. `evasion_authorized` is True.
          3. LockoutGovernor allows further escalation on *host*.
          4. The class does NOT map to NONE (ABORT class).

        Otherwise returns None — the caller should only record the BLOCKED
        event without changing transport behavior.
        """
        count = self._consecutive.get(host, 0)

        # Gate 1: below threshold — no action.
        if count < self._threshold:
            return None

        # Gate 2: not authorized — never propose.
        if not evasion_authorized:
            return None

        # Gate 3: governor lockout — ABORT.
        if not self._governor.may_escalate(host):
            return None

        # Gate 4: resolve technique from class (fail-loud: missing key = bug).
        technique_value = TECHNIQUE_FOR_MITIGATION_CLASS[mitigation_class.value]
        technique = EvasionTechnique(technique_value)
        if technique is EvasionTechnique.NONE:
            return None

        # All gates passed — propose and record escalation.
        self._governor.record_escalation(host)
        # Reset counter so the agent gets another N attempts before next proposal.
        self._consecutive[host] = 0

        return PlannerProposal(
            host=host,
            mitigation_class=mitigation_class,
            technique=technique,
        )
