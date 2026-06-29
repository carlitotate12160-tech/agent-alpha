"""Contract: Beta initial-access must be REAL, not proof-theatre (anti-Lyndon #3).

Beta.step()'s ACT delegates to the default_creds tool (known-defaults). These
tests drive Beta end-to-end and fail against PR #51's step() on purpose — they
are the contract that body must satisfy before merge.

What is pinned here:
  A. SUCCESS requires a default credential to be ACTUALLY APPLIED — the transport
     must receive an authenticated request, and access is claimed only when the
     authed response differs from the unauthenticated baseline. (RED on #51.)
  B. A real attempt that is rejected → FAILED via the live path (calls happened),
     NOT via a silent short-circuit. (guard)
  C. Missing deps must FAIL LOUD (run_strike raises), never silently become FAILED.
     (RED until the run_strike dep-precondition lands — Claude's lane.)
  D. Identical baseline/authed responses ⇒ NO access. (guard against the #51
     nondeterminism false-positive.)

The fake routes by whether a request carries ANY auth context (header/cookie/
data), so it is agnostic to how the offensive body applies the credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

ENTRY = "http://lab-target.invalid/login"
HOST = "lab-target.invalid"


# ── Test doubles ────────────────────────────────────────────────


@dataclass
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ENTRY


class AuthAwareFakeHttpClient:
    """Routes by whether the request carries ANY auth context (headers/cookies/
    data) — mechanism-agnostic. Records every call so a test can prove a default
    credential was actually applied rather than fabricated."""

    def __init__(self, *, unauth: _Resp, authed: _Resp) -> None:
        self._unauth = unauth
        self._authed = authed
        self.calls: list[dict[str, Any]] = []

    def _route(self, method: str, url: str, headers: Any, cookies: Any, data: Any) -> _Resp:
        applied = bool(headers) or bool(cookies) or bool(data)
        self.calls.append({"method": method, "url": url, "auth": applied})
        return self._authed if applied else self._unauth

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _Resp:
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
                "tool": "default_creds",
                "tier": "rule",
                "technique_id": "T1078",
                "cost_usd": 0.0,
                "reasoning": "",
            },
        )()


# ── Helpers ─────────────────────────────────────────────────────


def _active_engagement() -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="c", target=HOST)
    auth.enable_recon(
        rec.engagement_id, Scope(ip_ranges=["10.0.0.0/30"], domains=[HOST], exclusions=[])
    )
    auth.enable_active(rec.engagement_id)
    return auth, rec.engagement_id


def _beta(auth: AuthorizationStateMachine, http: Any) -> Beta:
    return Beta(
        cred_applicators=[HttpFormApplicator(http_client=http)],
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
        orchestrator=_StubOrchestrator(),
        http_client=http,
    )


def _decode(msg: a2a_pb2.A2AMessage) -> a2a_pb2.HandoffPayload:
    p = a2a_pb2.HandoffPayload()
    p.ParseFromString(msg.payload)
    return p


# ── A. SUCCESS requires a default credential ACTUALLY APPLIED (RED on #51) ───


def test_success_requires_credential_actually_applied() -> None:
    auth, eng = _active_engagement()
    http = AuthAwareFakeHttpClient(
        unauth=_Resp(401, "<html>login required</html>"),
        authed=_Resp(
            200,
            "<html>admin dashboard — welcome administrator</html>",
            headers={"set-cookie": "session=abc"},
        ),
    )
    payload = _decode(_beta(auth, http).run_strike(eng, ENTRY))

    assert payload.status == a2a_pb2.COMPLETE
    assert payload.findings_count >= 1
    assert list(payload.proof_artifacts)  # non-empty proof
    assert "credential_refs" in payload.handoff_data.decode()
    assert any(c["auth"] for c in http.calls), "credential never applied — theatre"


# ── B. A rejected real attempt → FAILED via the live path (guard) ───────────


def test_rejected_attempt_is_failed_via_live_path() -> None:
    auth, eng = _active_engagement()
    http = AuthAwareFakeHttpClient(
        unauth=_Resp(401, "<html>login required</html>"),
        authed=_Resp(403, "<html>forbidden</html>"),  # defaults rejected
    )
    msg = _beta(auth, http).run_strike(eng, ENTRY)

    assert _decode(msg).status == a2a_pb2.FAILED
    assert http.calls, "FAILED must come from a real attempt, not a silent short-circuit"


# ── C. Missing deps must FAIL LOUD, not silently become FAILED (RED) ────────


def test_missing_dependencies_fail_loud() -> None:
    """run_strike must raise when http_client/orchestrator are absent — a wiring
    bug must never read as 'tried, no access'. Requires the run_strike
    dep-precondition (Claude's lane) added after the scope gate."""
    auth, eng = _active_engagement()
    beta = Beta(
        cred_applicators=[HttpFormApplicator(http_client=None)],
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
        orchestrator=None,
        http_client=None,
    )
    with pytest.raises((ValueError, RuntimeError)):
        beta.run_strike(eng, ENTRY)


# ── D. Identical baseline/authed responses ⇒ NO access (guard) ──────────────


def test_identical_responses_is_not_access() -> None:
    auth, eng = _active_engagement()
    same = "<html>same page either way</html>"
    http = AuthAwareFakeHttpClient(unauth=_Resp(200, same), authed=_Resp(200, same))
    msg = _beta(auth, http).run_strike(eng, ENTRY)

    assert _decode(msg).status == a2a_pb2.FAILED  # a credential that changes nothing != access


# ── E. Text differs but no POSITIVE auth signal ⇒ NO access (closes the gap) ─


def test_text_differs_without_auth_signal_is_not_access() -> None:
    """A failed-login page also differs from baseline — "text != baseline" is a weak
    signal that would false-positive. Access requires a POSITIVE signal (session
    cookie / authed area), so a differing-but-still-login response with no set-cookie
    MUST be FAILED. This pins the VERIFY contract the offensive body must honour."""
    auth, eng = _active_engagement()
    http = AuthAwareFakeHttpClient(
        unauth=_Resp(200, "<html>please log in</html>"),
        authed=_Resp(200, "<html>invalid password — please log in</html>"),  # differs, no cookie
    )
    msg = _beta(auth, http).run_strike(eng, ENTRY)
    assert _decode(msg).status == a2a_pb2.FAILED
