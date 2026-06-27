"""Contract: Beta (STRIKE / Initial Access) — authorization + scope gate,
A2A handoff discipline, and the false-success guard.  Phase 3.

This is the RED test that DEFINES "done" for the Beta gate before any
offensive body is written (per the per-tool loop — Claude's RED test first,
DeepSeek fills the body, IDE never edits the contract).

What is LOCKED here (must stay green; the offensive body cannot weaken it):
  1. Beta runs ONLY at ACTIVE_APPROVED or OFFENSIVE_APPROVED. At CREATED or
     RECON_ONLY it returns a BLOCKED handoff and NEVER reaches step()
     (no initial-access attempt without authorization).
  2. Beta refuses an out-of-scope entry_point — BLOCKED, before the body.
  3. Every Beta message goes to the CONDUCTOR, never to another agent
     (agents never call agents directly).
  4. False-success guard (anti-Lyndon #3): an empty access result is FAILED,
     never COMPLETE — encoded as a strict-xfail that DeepSeek flips when the
     body records access.

The single RED frontier is Beta.step() (the initial-access technique), which
raises NotImplementedError until DeepSeek authors it.
"""

from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

IN_SCOPE_ENTRY = "http://lab-target.invalid/login"
OUT_OF_SCOPE_ENTRY = "http://not-authorized.invalid/login"


def _scope() -> Scope:
    return Scope(
        ip_ranges=["10.0.0.0/30"],
        domains=["lab-target.invalid"],
        exclusions=[],
    )


def _beta(auth: AuthorizationStateMachine) -> Beta:
    return Beta(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
    )


def _decode(msg: a2a_pb2.A2AMessage) -> a2a_pb2.HandoffPayload:
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    return payload


def _new_auth() -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="c", target="lab-target.invalid")
    return auth, rec.engagement_id


def _advance_to_active(auth: AuthorizationStateMachine, eng: str) -> None:
    auth.enable_recon(eng, _scope())
    auth.enable_active(eng)  # RECON_ONLY + verified scope -> ACTIVE_APPROVED


# ── 1. Gate semantics (documents the role gate the agent relies on) ──────────


def test_beta_gate_is_active_approved_or_higher() -> None:
    auth, eng = _new_auth()
    assert auth.can_agent_proceed(a2a_pb2.BETA, eng) is False  # CREATED
    auth.enable_recon(eng, _scope())
    assert auth.can_agent_proceed(a2a_pb2.BETA, eng) is False  # RECON_ONLY — Alpha's tier
    auth.enable_active(eng)
    assert auth.can_agent_proceed(a2a_pb2.BETA, eng) is True   # ACTIVE_APPROVED


# ── 2. Beta refuses to run unauthorized (no body reached) ────────────────────


def test_blocked_at_created() -> None:
    auth, eng = _new_auth()
    msg = _beta(auth).run_strike(eng, IN_SCOPE_ENTRY)  # must NOT raise
    assert _decode(msg).status == a2a_pb2.BLOCKED


def test_blocked_at_recon_only() -> None:
    auth, eng = _new_auth()
    auth.enable_recon(eng, _scope())
    msg = _beta(auth).run_strike(eng, IN_SCOPE_ENTRY)  # must NOT raise
    assert _decode(msg).status == a2a_pb2.BLOCKED


def test_blocked_out_of_scope_even_when_authorized() -> None:
    auth, eng = _new_auth()
    _advance_to_active(auth, eng)
    msg = _beta(auth).run_strike(eng, OUT_OF_SCOPE_ENTRY)  # scope gate, not body
    assert _decode(msg).status == a2a_pb2.BLOCKED


# ── 3. A2A discipline: handoff targets the Conductor, never an agent ─────────


def test_handoff_addressed_to_conductor() -> None:
    auth, eng = _new_auth()
    msg = _beta(auth).run_strike(eng, IN_SCOPE_ENTRY)
    assert msg.from_agent == a2a_pb2.BETA
    assert msg.to_agent == a2a_pb2.CONDUCTOR
    assert msg.message_type == a2a_pb2.HANDOFF_READY


# ── 4. The RED frontier: gate passes, the offensive body is what's missing ───


def test_authorized_in_scope_reaches_offensive_body() -> None:
    """Proves the gates PASSED (no BLOCKED): control reaches step(), which is
    the DeepSeek lane and raises NotImplementedError until authored."""
    auth, eng = _new_auth()
    _advance_to_active(auth, eng)
    with pytest.raises(NotImplementedError):
        _beta(auth).run_strike(eng, IN_SCOPE_ENTRY)


@pytest.mark.xfail(
    raises=NotImplementedError,
    strict=True,
    reason="Beta.step body is the DeepSeek lane. When access-recording exists, "
    "delete this marker: an empty access result MUST be FAILED, not COMPLETE.",
)
def test_false_success_guard_empty_access_is_failed() -> None:
    auth, eng = _new_auth()
    _advance_to_active(auth, eng)
    msg = _beta(auth).run_strike(eng, IN_SCOPE_ENTRY)
    payload = _decode(msg)
    # Holds once the body runs and records NO credentials/sessions:
    assert payload.status == a2a_pb2.FAILED
    assert payload.findings_count == 0
