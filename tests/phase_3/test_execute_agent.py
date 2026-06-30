"""RED tests for the shared agent-execution helper (collapses PR #69 issues 2/3/7/8/9).

FROZEN contract (architect-authored — the IDE implements execute_agent to make these pass;
do NOT edit the assertions). Pins the cardinal safety properties Devin's review found
missing, plus offensive-agent idempotency on retry.

Agreed contract (review of the IDE proposal, 2026-06-29):
  * agent_factory(graph_store) -> Callable[[], ExecOutcome]   (Q2 option A; the closure maps
    the agent's native result to success/failure, helper stays agent-agnostic).
  * graph_rebuilder(event_store, engagement_id) -> graph_store (rebuilt from the event stream).
  * On refuse (tenant/auth) → record a REFUSED event, emit NO HANDOFF_READY, agent NOT run.
  * Idempotent: if a terminal HANDOFF_READY for (engagement, this agent_role) already exists,
    do NOT re-run the agent body (re-running an OFFENSIVE agent on Celery retry is forbidden).

VERIFY: Oracle ARM64 only — `.venv/bin/python3 -m pytest tests/phase_3/test_execute_agent.py`.
"""

from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.execute_agent import ExecOutcome, execute_agent
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import AttackNode, CredentialProperties, NodeType

ENG = "eng_exec01"
TENANT = "tenant_a"


# ── Test doubles ──────────────────────────────────────────────────────────────


class FakeAuth:
    def __init__(self, *, permitted: bool, owner: str | None = TENANT) -> None:
        self._permitted = permitted
        self._owner = owner
        self.proceed_calls: list[int] = []

    def can_agent_proceed(self, agent_role: int, engagement_id: str) -> bool:
        self.proceed_calls.append(agent_role)
        return self._permitted

    def owns(self, engagement_id: str, tenant_id: str | None) -> bool:
        return tenant_id == self._owner


class FakeEvent:
    def __init__(self, event_type: object, payload: dict, sequence: int) -> None:
        self.event_type = event_type
        self.payload = payload
        self.sequence = sequence


class FakeStore:
    def __init__(self, events: list[FakeEvent] | None = None) -> None:
        self._events = list(events or [])
        self._seq = len(self._events)

    def get_events(self, engagement_id: str) -> list[FakeEvent]:
        return list(self._events)

    def append(self, *, event_type: object, engagement_id: str, agent: str, payload: dict) -> None:
        self._seq += 1
        self._events.append(FakeEvent(event_type, payload, self._seq))

    def types(self) -> list[object]:
        return [e.event_type for e in self._events]

    def last_handoff_status(self) -> int | None:
        for e in reversed(self._events):
            if e.event_type == EventType.HANDOFF_READY:
                return int(e.payload.get("status"))
        return None


class FakeAgent:
    """Records that it ran and the graph it was given; returns a controllable outcome.
    Its zero-arg ``run`` is the callable agent_factory returns (Q2 option A)."""

    def __init__(self, *, graph_store, succeed: bool) -> None:
        self.graph_store = graph_store
        self._succeed = succeed
        self.ran = False

    def run(self) -> ExecOutcome:
        self.ran = True
        return ExecOutcome(
            status=a2a_pb2.COMPLETE if self._succeed else a2a_pb2.FAILED,
            next_recommended=a2a_pb2.OMEGA,
            reason="ok" if self._succeed else "strike failed",
        )


def _graph_with_cred() -> object:
    class _Graph:
        def __init__(self) -> None:
            self._nodes = [
                AttackNode(
                    id="cred_alpha_1",
                    type=NodeType.CREDENTIAL,
                    properties=CredentialProperties(
                        username="svc", secret_ref="vault://x",
                        service="database", access_level="db_user",
                    ),
                    confidence=0.9,
                )
            ]

        def nodes_by_type(self, node_type: NodeType) -> list[AttackNode]:
            return [n for n in self._nodes if n.type == node_type]

    return _Graph()


def _rebuilder_with_cred(event_store, engagement_id) -> object:
    """Fake graph_rebuilder: a graph containing Alpha's CREDENTIAL node — proves
    execute_agent replays state rather than handing the agent an empty graph."""
    return _graph_with_cred()


def _empty_rebuilder(event_store, engagement_id) -> object:
    class _Empty:
        def nodes_by_type(self, node_type: NodeType) -> list:
            return []

    return _Empty()


def _run(*, permitted=True, owner=TENANT, succeed=True, rebuilder=_rebuilder_with_cred, seed=None):
    auth = FakeAuth(permitted=permitted, owner=owner)
    store = FakeStore(seed)
    captured: dict = {}

    def agent_factory(graph_store):
        agent = FakeAgent(graph_store=graph_store, succeed=succeed)
        captured["agent"] = agent
        return agent.run  # zero-arg callable -> ExecOutcome (Q2 option A)

    outcome = execute_agent(
        engagement_id=ENG, tenant_id=TENANT, agent_role=a2a_pb2.BETA,
        auth=auth, event_store=store, graph_rebuilder=rebuilder,
        agent_factory=agent_factory, timeout_s=30.0,
    )
    return auth, store, captured.get("agent"), outcome


# ── T1 — anti-#3 false-success (CARDINAL) ────────────────────────────────────────


def test_failed_agent_emits_failed_status_never_complete() -> None:
    _auth, store, agent, _outcome = _run(succeed=False)
    assert agent.ran
    assert store.last_handoff_status() == a2a_pb2.FAILED
    assert store.last_handoff_status() != a2a_pb2.COMPLETE


def test_succeeded_agent_emits_complete() -> None:
    _auth, store, _agent, _outcome = _run(succeed=True)
    assert store.last_handoff_status() == a2a_pb2.COMPLETE


# ── T2 — auth gate re-checked at execution (anti auth-softening, TOCTOU) ──────────


def test_blocked_when_auth_denies_does_not_run_agent() -> None:
    auth, store, agent, _outcome = _run(permitted=False)
    assert auth.proceed_calls == [a2a_pb2.BETA]  # the gate WAS consulted
    assert agent is None or not agent.ran  # agent body never executed
    assert store.last_handoff_status() != a2a_pb2.COMPLETE  # never claims success


# ── T3 — graph replay (chain alive, event-sourced) ───────────────────────────────


def test_agent_receives_replayed_graph_with_alpha_credential() -> None:
    _auth, _store, agent, _outcome = _run(succeed=True, rebuilder=_rebuilder_with_cred)
    creds = agent.graph_store.nodes_by_type(NodeType.CREDENTIAL)
    assert [n.id for n in creds] == ["cred_alpha_1"]  # Beta SEES Alpha's harvested cred


# ── T4 — tenant ownership ─────────────────────────────────────────────────────────


def test_refuses_when_engagement_not_owned_by_tenant() -> None:
    _auth, store, agent, _outcome = _run(owner="tenant_OTHER")
    assert agent is None or not agent.ran
    assert store.last_handoff_status() != a2a_pb2.COMPLETE


# ── T5 — idempotency: never re-run an OFFENSIVE agent on Celery retry ─────────────


def test_does_not_rerun_agent_if_terminal_handoff_already_exists() -> None:
    """If a HANDOFF_READY for (this engagement, this agent_role) already exists, execute_agent
    must NOT re-invoke the agent body — re-running Beta on retry = repeated offensive action."""
    prior = FakeEvent(
        EventType.HANDOFF_READY,
        {"from_agent": a2a_pb2.BETA, "status": a2a_pb2.COMPLETE, "next_recommended": a2a_pb2.OMEGA},
        1,
    )
    _auth, _store, agent, _outcome = _run(seed=[prior])
    assert agent is None or not agent.ran  # agent body NOT re-run


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
