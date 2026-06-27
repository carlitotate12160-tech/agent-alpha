"""Contract: Beta initial-access must be REAL, not proof-theatre (anti-Lyndon #3).

These tests fail against PR #51's step() on purpose — they are the contract that
body must satisfy before merge. The #51 body fetches the entry point 3x with the
SAME url and NEVER applies the credential, so:
  * it can only ever reach FAILED (masking that it never tried), or
  * fabricate access on a nondeterministic server (false positive).

What is pinned here:
  A. SUCCESS requires the credential to be ACTUALLY APPLIED — the transport must
     receive an authenticated request, and access is claimed only when the authed
     response differs from the unauthenticated baseline. (RED on #51.)
  B. A real attempt that is rejected → FAILED via the live path (calls happened),
     NOT via a silent short-circuit. (guard)
  C. Missing deps must FAIL LOUD (run_strike raises), never silently become FAILED
     — "couldn't try" != "tried, no access". (RED until the run_strike precondition
     lands; that precondition is Claude's lane.)
  D. Identical baseline/authed responses ⇒ NO access (a credential that changes
     nothing is not access). (guard against the #51 nondeterminism false-positive.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AttackNode, CredentialProperties, NodeType, node_to_dict

ENTRY = "http://lab-target.invalid/login"
HOST = "lab-target.invalid"
SECRET_REF = "vault://lab-target/admin"


# ── Test doubles ────────────────────────────────────────────────


@dataclass
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ENTRY


class AuthAwareFakeHttpClient:
    """Routes by whether the request carries ANY auth context (headers/cookies/
    data) — mechanism-agnostic, so it works no matter how DeepSeek applies the
    credential (header, cookie, or form POST). Records every call so a test can
    prove the credential was actually applied rather than fabricated."""

    def __init__(self, *, unauth: _Resp, authed: _Resp) -> None:
        self._unauth = unauth
        self._authed = authed
        self.calls: list[dict[str, Any]] = []

    def _route(
        self, method: str, url: str, headers: Any, cookies: Any, data: Any
    ) -> _Resp:
        applied = bool(headers) or bool(cookies) or bool(data)
        self.calls.append({"method": method, "url": url, "auth": applied})
        return self._authed if applied else self._unauth

    def get(
        self, url: str, *, headers: Any = None, cookies: Any = None
    ) -> _Resp:
        return self._route("GET", url, headers, cookies, None)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _Resp:
        return self._route("POST", url, headers, cookies, data or json_body)


class _StubOrchestrator:
    """ORIENT/PLAN double — returns a PlaybookDecision-shaped object."""

    def decide(self, observation: dict[str, Any]) -> Any:
        return type(
            "D",
            (),
            {
                "tool": "http_login",
                "tier": "rule",
                "technique_id": "T1078",
                "cost_usd": 0.0,
                "reasoning": "",
            },
        )()


# ── Fixtures / helpers ──────────────────────────────────────────


def _active_engagement() -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="c", target=HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=["10.0.0.0/30"], domains=[HOST], exclusions=[]))
    auth.enable_active(rec.engagement_id)
    return auth, rec.engagement_id


def _graph_with_credential() -> NetworkXGraphStore:
    gs = NetworkXGraphStore()
    node = AttackNode(
        id=f"cred:{HOST}:admin",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="admin", secret_ref=SECRET_REF, service="http", access_level="user"
        ),
        confidence=0.8,
        agent="alpha",
        timestamp_utc="2026-06-27T00:00:00Z",
        verified=True,
    )
    gs.apply_event("NodeDiscovered", node_to_dict(node))
    return gs


def _beta(auth: AuthorizationStateMachine, gs: NetworkXGraphStore, http: Any) -> Beta:
    return Beta(
        authorization=auth,
        graph_store=gs,
        event_store=InMemoryEventStore(),
        orchestrator=_StubOrchestrator(),
        http_client=http,
    )


def _decode(msg: a2a_pb2.A2AMessage) -> a2a_pb2.HandoffPayload:
    p = a2a_pb2.HandoffPayload()
    p.ParseFromString(msg.payload)
    return p


# ── A. SUCCESS requires the credential to be ACTUALLY APPLIED (RED on #51) ───


def test_success_requires_credential_actually_applied() -> None:
    auth, eng = _active_engagement()
    gs = _graph_with_credential()
    http = AuthAwareFakeHttpClient(
        unauth=_Resp(401, "<html>login required</html>"),
        authed=_Resp(200, "<html>admin dashboard — welcome administrator</html>"),
    )
    msg = _beta(auth, gs, http).run_strike(eng, ENTRY)
    payload = _decode(msg)

    assert payload.status == a2a_pb2.COMPLETE
    assert SECRET_REF in payload.handoff_data.decode()       # provenance: the cred applied
    assert payload.findings_count >= 1
    assert list(payload.proof_artifacts)                     # non-empty proof
    assert any(c["auth"] for c in http.calls), "credential was never applied — theatre"


# ── B. A rejected real attempt → FAILED via the live path (guard) ───────────


def test_rejected_attempt_is_failed_via_live_path() -> None:
    auth, eng = _active_engagement()
    gs = _graph_with_credential()
    http = AuthAwareFakeHttpClient(
        unauth=_Resp(401, "<html>login required</html>"),
        authed=_Resp(403, "<html>forbidden</html>"),  # creds rejected
    )
    msg = _beta(auth, gs, http).run_strike(eng, ENTRY)

    assert _decode(msg).status == a2a_pb2.FAILED
    assert http.calls, "FAILED must come from a real attempt, not a silent short-circuit"


# ── C. Missing deps must FAIL LOUD, not silently become FAILED (RED) ────────


def test_missing_dependencies_fail_loud() -> None:
    """Contract: run_strike must raise when http_client/orchestrator are absent —
    a wiring bug must never read as 'tried, no access'. Requires the run_strike
    dep-precondition (Claude's lane) added after the scope gate."""
    auth, eng = _active_engagement()
    gs = _graph_with_credential()
    beta = Beta(
        authorization=auth,
        graph_store=gs,
        event_store=InMemoryEventStore(),
        orchestrator=None,
        http_client=None,
    )
    with pytest.raises((ValueError, RuntimeError)):
        beta.run_strike(eng, ENTRY)


# ── D. Identical baseline/authed responses ⇒ NO access (guard) ──────────────


def test_identical_responses_is_not_access() -> None:
    auth, eng = _active_engagement()
    gs = _graph_with_credential()
    same = "<html>same page either way</html>"
    http = AuthAwareFakeHttpClient(unauth=_Resp(200, same), authed=_Resp(200, same))
    msg = _beta(auth, gs, http).run_strike(eng, ENTRY)

    assert _decode(msg).status == a2a_pb2.FAILED  # a credential that changes nothing != access
