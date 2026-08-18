"""Contract: a verified Beta access MUST NOT persist the session-token VALUE to the
event store (anti-Lyndon #45 leak). The handoff/tests were green while a Set-Cookie
value sat cleartext in proof_response['headers'] — assert on the STORED artifact,
not just the handoff.

This fails before the redaction fix (raw headers + cookie value persisted) and
passes after (headers dropped, session event stores the cookie NAME only,
proof deep-redacted).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.conductor.applicator_factory import BoundApplicator
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.tools.contracts import ResourceBudget, ToolResult
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator

ENTRY = "http://lab-target.invalid/login"
HOST = "lab-target.invalid"
SECRET = "S3CR3T_SESSION_VALUE_do_not_persist"


@dataclass
class _Resp:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ENTRY


class _Fake:
    """Routes by auth context. Authed response carries a Set-Cookie with SECRET so
    a positive auth signal fires and the token flows into the finding."""

    def __init__(self) -> None:
        self._unauth = _Resp(200, '<html><input type="password"> please log in</html>')
        self._authed = _Resp(
            200,
            "<html>admin dashboard</html>",
            {"set-cookie": f"session={SECRET}; Path=/; HttpOnly", "content-type": "text/html"},
        )
        self.calls: list[str] = []

    def _route(self, headers: Any, cookies: Any, data: Any) -> _Resp:
        self.calls.append("x")
        return self._authed if (headers or cookies or data) else self._unauth

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _Resp:
        return self._route(headers, cookies, None)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _Resp:
        return self._route(headers, cookies, data or json_body)


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


def test_session_token_value_never_persisted_to_event_store() -> None:
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="c", target=HOST)
    auth.enable_recon(
        rec.engagement_id, Scope(ip_ranges=["10.0.0.0/30"], domains=[HOST], exclusions=[])
    )
    auth.enable_active(rec.engagement_id)
    eng = rec.engagement_id

    beta_events = InMemoryEventStore()
    http = _Fake()
    beta = Beta(
        cred_applicators=[BoundApplicator(HttpFormApplicator(http_client=http), ENTRY)],
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=beta_events,
        orchestrator=_StubOrchestrator(),
        http_client=http,
    )

    msg = beta.run_strike(eng, ENTRY)
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    assert payload.status == a2a_pb2.COMPLETE  # success path actually ran + persisted

    persisted = json.dumps([e.payload for e in beta_events.get_events(eng)], default=str)
    assert SECRET not in persisted, "session token value leaked into the event store (#45)"


# ── GAP-116-A: authenticated-session propagation (prerequisite for the 116-B crawl) ──
# The session VALUE must reach Beta in-memory (so the crawl can reuse it) while the
# #45 persistence invariant above stays intact. These pin BOTH halves of that contract.


def _beta_with_session() -> tuple[Beta, str, InMemoryEventStore]:
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="c", target=HOST)
    auth.enable_recon(
        rec.engagement_id, Scope(ip_ranges=["10.0.0.0/30"], domains=[HOST], exclusions=[])
    )
    auth.enable_active(rec.engagement_id)
    beta_events = InMemoryEventStore()
    http = _Fake()
    beta = Beta(
        cred_applicators=[BoundApplicator(HttpFormApplicator(http_client=http), ENTRY)],
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=beta_events,
        orchestrator=_StubOrchestrator(),
        http_client=http,
    )
    return beta, rec.engagement_id, beta_events


def test_won_session_reaches_beta_in_memory_but_never_persists() -> None:
    beta, eng, beta_events = _beta_with_session()

    beta.run_strike(eng, ENTRY)

    # Capability: the live session is available in-memory for the 116-B crawl.
    assert beta._won_session_cookies == {"session": SECRET}, (
        "116-A: the won session must reach Beta in-memory so the authenticated crawl can reuse it"
    )
    # Invariant preserved: holding it in-memory did NOT leak it into the event store.
    persisted = json.dumps([e.payload for e in beta_events.get_events(eng)], default=str)
    assert SECRET not in persisted, (
        "116-A must not regress #45: session value stayed out of storage"
    )


def test_won_session_reinitialised_on_each_run_strike() -> None:
    beta, eng, _ = _beta_with_session()
    # Simulate a prior target's live session lingering on the reused Beta instance.
    beta._won_session_cookies = {"stale": "leftover_from_previous_target"}
    beta.run_strike(eng, ENTRY)
    # run_strike's per-run init must drop the stale session before capturing the new one
    # (no session leaks across sibling targets — the Bug #35 class of state leak).
    assert beta._won_session_cookies == {"session": SECRET}, (
        "116-A: run_strike must re-init the won session (no stale session across targets)"
    )


def test_ephemeral_session_excluded_from_repr_and_findings_surface() -> None:
    r = ToolResult(
        tool="cred_reuse",
        success=True,
        confidence=0.9,
        findings=({"access_level": "admin", "username": "admin"},),
        ephemeral_session={"session": SECRET},
    )
    assert SECRET not in repr(r), (
        "116-A: session value must not appear in ToolResult repr (repr=False)"
    )
    assert SECRET not in json.dumps(r.findings, default=str), (
        "116-A: session value must never enter the findings/persist surface"
    )


def test_applicator_hands_up_live_session_cookies() -> None:
    http = _Fake()
    res = HttpFormApplicator(http_client=http).apply(
        username="admin",
        secret="pw",
        target=ENTRY,
        budget=ResourceBudget(max_requests=5, max_seconds=5, max_cost_usd=0.0),
    )
    assert res.success
    assert res.session_cookies == {"session": SECRET}, (
        "116-A: applicator must return the live session"
    )
    assert SECRET not in repr(res), (
        "116-A: AuthResult repr must not leak the session value (repr=False)"
    )


def test_full_multicookie_session_jar_propagates_not_just_first_cookie() -> None:
    # GAP-116-C: WordPress issues wordpress_logged_in_* AND wordpress_sec_*; the 116-B crawl needs
    # the WHOLE jar. HttpResponse.cookies carries every Set-Cookie; the applicator must hand up all
    # of them, not just the first parsed header cookie.
    jar = {"wordpress_logged_in_x": "AAA", "wordpress_sec_x": "BBB"}

    class _JarResp:
        def __init__(self, text: str, cookies: dict[str, str] | None = None) -> None:
            self.status_code = 200
            self.text = text
            self.url = ENTRY
            self.headers = {"content-type": "text/html"}
            self.cookies = cookies or {}

    class _JarHttp:
        def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _JarResp:
            # authed (with session) → dashboard + full jar; unauth → login form (password field).
            return (
                _JarResp("admin dashboard", jar)
                if cookies
                else _JarResp('<input type="password"> log in')
            )

        def post(
            self,
            url: str,
            *,
            data: Any = None,
            json_body: Any = None,
            headers: Any = None,
            cookies: Any = None,
            allow_redirects: bool = True,
        ) -> _JarResp:
            return _JarResp("admin dashboard", jar)  # no password field → positive auth signal

    res = HttpFormApplicator(http_client=_JarHttp()).apply(
        username="a",
        secret="p",
        target=ENTRY,
        budget=ResourceBudget(max_requests=5, max_seconds=5, max_cost_usd=0.0),
    )
    assert res.success
    assert res.session_cookies == jar, "GAP-116-C: the FULL multi-cookie jar must propagate"

