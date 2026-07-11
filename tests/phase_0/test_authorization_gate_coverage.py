"""Auth-gate coverage: fail-closed paths + can_agent_proceed role×state matrix.

The AuthorizationStateMachine is the non-bypassable gate — the crown-jewel
control. These tests target REAL security branches that were uncovered (not a
coverage-number chase):

  1. FAIL-CLOSED: every gate-query method wraps _rebuild in
     ``except Exception: return False`` so a store read failure DENIES rather
     than crashes or allows. If a refactor made that handler re-raise or return
     True, no existing test would catch it.
  2. can_agent_proceed role×state cells that existing tests skip
     (CONDUCTOR / OMEGA / BETA / DELTA / EPSILON, unknown role, unknown engagement).

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_authorization_gate_coverage.py -v
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope, SOWError
from agent_alpha.config.constants import SOW_MAX_FILE_SIZE_MB
from agent_alpha.events.store import EventStore, InMemoryEventStore


def _store() -> InMemoryEventStore:
    return InMemoryEventStore()


def _valid_scope() -> Scope:
    return Scope(ip_ranges=["10.0.0.0/24"], domains=["example.com"], exclusions=["10.0.0.5"])


class _RaisingReadStore:
    """EventStore whose reads fail. Simulates a corrupted/unavailable store so
    we can prove the gate DENIES (fail-closed) instead of crashing."""

    def append(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("append must not be called in a fail-closed query test")

    def get_events(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("simulated event-store read failure")


def _raising_sm() -> AuthorizationStateMachine:
    return AuthorizationStateMachine(event_store=cast(EventStore, _RaisingReadStore()))


def _sm_in(state: int) -> tuple[AuthorizationStateMachine, str]:
    """Return an SM + engagement_id driven to *state* via the real transitions."""
    sm = AuthorizationStateMachine(event_store=_store())
    eid = sm.create_engagement("client_a", "10.0.0.0/24").engagement_id
    if state == a2a_pb2.CREATED:
        return sm, eid
    if state == a2a_pb2.EMERGENCY_STOP:
        sm.emergency_stop(eid, "test")
        return sm, eid
    sm.enable_recon(eid, _valid_scope())
    if state == a2a_pb2.RECON_ONLY:
        return sm, eid
    sm.enable_active(eid)
    if state == a2a_pb2.ACTIVE_APPROVED:
        return sm, eid
    sm.enable_offensive(eid, b"statement of work content")
    return sm, eid  # OFFENSIVE_APPROVED


# ── 1. Fail-closed on store read failure ─────────────────────────────────────


def test_can_agent_proceed_fails_closed_on_store_read_error() -> None:
    assert _raising_sm().can_agent_proceed(a2a_pb2.CONDUCTOR, "eng") is False


def test_is_in_scope_fails_closed_on_store_read_error() -> None:
    assert _raising_sm().is_in_scope("eng", "example.com") is False


def test_owns_fails_closed_on_store_read_error() -> None:
    assert _raising_sm().owns("eng", "tenant_a") is False


def test_is_db_endpoint_in_scope_fails_closed_on_store_read_error() -> None:
    assert _raising_sm().is_db_endpoint_in_scope("eng", "10.0.0.9", 3306) is False


def test_assert_offensive_web_target_fails_closed_on_store_read_error() -> None:
    # domain target -> routes into is_in_scope -> get_events raises -> denied
    assert _raising_sm().assert_offensive_web_target("eng", "https://example.com") is False


# ── 2. Unknown engagement / unknown role -> deny ─────────────────────────────


def test_can_agent_proceed_unknown_engagement_is_denied() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    assert sm.can_agent_proceed(a2a_pb2.CONDUCTOR, "nonexistent") is False


def test_is_in_scope_unknown_engagement_is_false() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    assert sm.is_in_scope("nonexistent", "example.com") is False


def test_owns_unknown_engagement_is_false() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    assert sm.owns("nonexistent", "tenant_a") is False


def test_unknown_agent_role_is_denied_even_when_offensive_approved() -> None:
    sm, eid = _sm_in(a2a_pb2.OFFENSIVE_APPROVED)
    assert sm.can_agent_proceed(9999, eid) is False


def test_owns_none_tenant_bypasses_check() -> None:
    sm, eid = _sm_in(a2a_pb2.CREATED)
    assert sm.owns(eid, None) is True


# ── 3. can_agent_proceed role × state matrix (previously-uncovered cells) ─────

_MATRIX: list[tuple[int, int, bool]] = [
    # CONDUCTOR: allowed in every non-emergency state, denied under EMERGENCY_STOP
    (a2a_pb2.CONDUCTOR, a2a_pb2.CREATED, True),
    (a2a_pb2.CONDUCTOR, a2a_pb2.OFFENSIVE_APPROVED, True),
    (a2a_pb2.CONDUCTOR, a2a_pb2.EMERGENCY_STOP, False),
    # OMEGA (reporting): allowed once recon+; denied at CREATED
    (a2a_pb2.OMEGA, a2a_pb2.CREATED, False),
    (a2a_pb2.OMEGA, a2a_pb2.RECON_ONLY, True),
    (a2a_pb2.OMEGA, a2a_pb2.OFFENSIVE_APPROVED, True),
    # ALPHA: denied at CREATED (completes the ladder)
    (a2a_pb2.ALPHA, a2a_pb2.CREATED, False),
    # BETA (initial access): denied until ACTIVE_APPROVED
    (a2a_pb2.BETA, a2a_pb2.CREATED, False),
    (a2a_pb2.BETA, a2a_pb2.RECON_ONLY, False),
    (a2a_pb2.BETA, a2a_pb2.ACTIVE_APPROVED, True),
    (a2a_pb2.BETA, a2a_pb2.OFFENSIVE_APPROVED, True),
    # DELTA / EPSILON: offensive-only
    (a2a_pb2.DELTA, a2a_pb2.ACTIVE_APPROVED, False),
    (a2a_pb2.DELTA, a2a_pb2.OFFENSIVE_APPROVED, True),
    (a2a_pb2.EPSILON, a2a_pb2.RECON_ONLY, False),
    (a2a_pb2.EPSILON, a2a_pb2.OFFENSIVE_APPROVED, True),
]


@pytest.mark.parametrize(("role", "state", "expected"), _MATRIX)
def test_can_agent_proceed_role_state_matrix(role: int, state: int, expected: bool) -> None:
    sm, eid = _sm_in(state)
    assert sm.can_agent_proceed(role, eid) is expected


# ── 4. Illegal-order transition guards (state-machine ordering enforcement) ───
# These enforce that the offensive escalation ladder cannot be skipped or
# repeated out of order — the core promise of the gate.


def test_enable_recon_rejected_when_already_past_created_or_recon() -> None:
    sm, eid = _sm_in(a2a_pb2.ACTIVE_APPROVED)
    with pytest.raises(ValueError):
        sm.enable_recon(eid, _valid_scope())


def test_enable_offensive_rejected_before_active_approved() -> None:
    sm, eid = _sm_in(a2a_pb2.RECON_ONLY)
    with pytest.raises(ValueError):
        sm.enable_offensive(eid, b"statement of work content")


def test_enable_offensive_rejects_oversized_sow() -> None:
    sm, eid = _sm_in(a2a_pb2.ACTIVE_APPROVED)
    oversized = b"x" * (SOW_MAX_FILE_SIZE_MB * 1024 * 1024 + 1)
    with pytest.raises(SOWError):
        sm.enable_offensive(eid, oversized)
