"""Contract: Beta (STRIKE / Initial Access) — authorization + scope gate,
A2A handoff discipline, and the false-success guard.  Phase 3.

This is the RED test that DEFINES "done" for the Beta gate before any
offensive body is written (per the per-tool loop — Claude's RED test first,
GLM fills the body, IDE never edits the contract).

What is LOCKED here (must stay green; the offensive body cannot weaken it):
  1. Beta runs ONLY at ACTIVE_APPROVED or OFFENSIVE_APPROVED. At CREATED or
     RECON_ONLY it returns a BLOCKED handoff and NEVER reaches step()
     (no initial-access attempt without authorization).
  2. Beta refuses an out-of-scope entry_point — BLOCKED, before the body.
  3. Every Beta message goes to the CONDUCTOR, never to another agent
     (agents never call agents directly).
  4. False-success guard (anti-Lyndon #3): an empty access result is FAILED,
     never COMPLETE — all default credentials rejected ⇒ FAILED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator

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
        cred_applicators=[HttpFormApplicator(http_client=None)],
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


# ── Test doubles for false-success guard (deps-injected path) ────────────────


@dataclass
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = IN_SCOPE_ENTRY


class _RejectingHttpClient:
    """All default credentials are rejected — no positive auth signal."""

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _Resp:
        return _Resp(401, "<html>login required</html>")

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _Resp:
        return _Resp(403, "<html>forbidden</html>")


class _StubOrchestrator:
    def decide(self, observation: dict[str, Any]) -> Any:
        return type(
            "D",
            (),
            {
                "tool": "default_creds",
                "tier": "rule",
                "technique_id": "T1078",
                "cost_usd": 0.0,
                "reasoning": "",
            },
        )()


# ── 1. Gate semantics (documents the role gate the agent relies on) ──────────


def test_beta_gate_is_active_approved_or_higher() -> None:
    auth, eng = _new_auth()
    assert auth.can_agent_proceed(a2a_pb2.BETA, eng) is False  # CREATED
    auth.enable_recon(eng, _scope())
    assert auth.can_agent_proceed(a2a_pb2.BETA, eng) is False  # RECON_ONLY — Alpha's tier
    auth.enable_active(eng)
    assert auth.can_agent_proceed(a2a_pb2.BETA, eng) is True  # ACTIVE_APPROVED


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


# ── 4. False-success guard (anti-Lyndon #3): no access ⇒ FAILED ─────────────


def test_false_success_guard_empty_access_is_failed() -> None:
    """All default credentials rejected → FAILED, not COMPLETE.

    Injecting a rejecting HTTP client so the body actually runs through
    the live path and no credential produces a positive auth signal.
    """
    auth, eng = _new_auth()
    _advance_to_active(auth, eng)
    beta = Beta(
        cred_applicators=[HttpFormApplicator(http_client=None)],
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
        orchestrator=_StubOrchestrator(),
        http_client=_RejectingHttpClient(),
    )
    msg = beta.run_strike(eng, IN_SCOPE_ENTRY)
    payload = _decode(msg)
    # Holds because the body ran and recorded NO credentials/sessions:
    assert payload.status == a2a_pb2.FAILED
    assert payload.findings_count == 0
