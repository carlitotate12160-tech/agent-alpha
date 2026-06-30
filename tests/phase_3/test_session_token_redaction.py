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
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
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
    beta = Beta(
        cred_applicators=[HttpFormApplicator(http_client=None)],
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=beta_events,
        orchestrator=_StubOrchestrator(),
        http_client=_Fake(),
    )

    msg = beta.run_strike(eng, ENTRY)
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    assert payload.status == a2a_pb2.COMPLETE  # success path actually ran + persisted

    persisted = json.dumps([e.payload for e in beta_events.get_events(eng)], default=str)
    assert SECRET not in persisted, "session token value leaked into the event store (#45)"
