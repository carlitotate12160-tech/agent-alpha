# RED tests — blast-radius approval gate (GAP-005/006 slice-1, ADR §1 / §12.35).
#
# A SECONDARY safety gate on top of the auth-tier gate: an offensive-tier transition
# (GAMMA/DELTA/EPSILON) that is already auth-permitted must ALSO clear a blast-radius
# check; if the graph's worst-case blast severity meets the threshold, the engagement
# PARKS for human opt-in instead of auto-dispatching. This wires the previously
# report-only `calculate_blast_radius` (GAP-006) + PolicyEnforcer (GAP-005) into the
# Conductor decision path. It adds a human checkpoint before high-impact dispatch —
# it removes no capability.
#
# Run on Oracle ARM64 only.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.advance import advance_engagement, decide_advance
from agent_alpha.conductor.blast_gate import assess_blast_gate
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import AssetProperties, AttackNode, NodeType

_TS = "2026-07-13T00:00:00Z"
_GATE = frozenset({"ANCHOR"})  # GAMMA maps to ANCHOR


def _asset(node_id: str) -> AttackNode:
    return AttackNode(
        id=node_id,
        type=NodeType.ASSET,
        properties=AssetProperties(host=node_id),
        confidence=0.5,
        agent="alpha",
        timestamp_utc=_TS,
    )


class FakeStore:
    """Minimal GraphStore surface used by calculate_blast_radius + max_blast_severity."""

    def __init__(self, node_ids: list[str], adjacency: dict[str, list[str]]) -> None:
        self._nodes = {nid: _asset(nid) for nid in node_ids}
        self._adj = adjacency

    def get_node(self, node_id: str) -> AttackNode | None:
        return self._nodes.get(node_id)

    def neighbors(self, node_id: str) -> list[AttackNode]:
        return [self._nodes[n] for n in self._adj.get(node_id, []) if n in self._nodes]

    def nodes_by_type(self, node_type: NodeType) -> list[AttackNode]:
        return [n for n in self._nodes.values() if n.type == node_type]


def _high_blast_store() -> FakeStore:
    # source reaches 5 nodes -> reachable_count 5 -> severity "high"
    return FakeStore(
        [f"asset:h{i}" for i in range(6)],
        {"asset:h0": [f"asset:h{i}" for i in range(1, 6)]},
    )


def _low_blast_store() -> FakeStore:
    return FakeStore(["asset:h0"], {})  # 0 reachable -> "low"


# ── assess_blast_gate (pure over the graph) ─────────────────────────────────


def test_assess_gate_fires_on_high_blast_for_gated_agent() -> None:
    assert (
        assess_blast_gate(
            store=_high_blast_store(),
            gate_before_agents=_GATE,
            next_agent_name="ANCHOR",
            threshold="high",
        )
        is True
    )


def test_assess_gate_silent_on_low_blast() -> None:
    assert (
        assess_blast_gate(
            store=_low_blast_store(),
            gate_before_agents=_GATE,
            next_agent_name="ANCHOR",
            threshold="high",
        )
        is False
    )


def test_assess_gate_never_gates_non_offensive_agent() -> None:
    # Beta/STRIKE is not in blast_radius_gate_before — never gated, even on high blast.
    assert (
        assess_blast_gate(
            store=_high_blast_store(),
            gate_before_agents=_GATE,
            next_agent_name="STRIKE",
            threshold="high",
        )
        is False
    )


# ── decide_advance (pure decision) ──────────────────────────────────────────


def _dispatchable_kwargs() -> dict[str, Any]:
    return dict(
        status=a2a_pb2.COMPLETE,
        from_agent=a2a_pb2.BETA,
        next_recommended=a2a_pb2.GAMMA,
        current_state=a2a_pb2.OFFENSIVE_APPROVED,
        next_permitted=True,
        already_dispatched=False,
    )


def test_decide_parks_when_blast_gate_requires_approval() -> None:
    d = decide_advance(**_dispatchable_kwargs(), blast_gate_requires_approval=True)
    assert d.action == "park_awaiting_approval"
    assert d.next_agent == a2a_pb2.GAMMA


def test_decide_dispatches_when_gate_clear() -> None:
    d = decide_advance(**_dispatchable_kwargs(), blast_gate_requires_approval=False)
    assert d.action == "dispatch"


# ── WIRING: reachable via advance_engagement (non-island) ───────────────────


@dataclass
class FakeEvent:
    event_type: Any
    payload: dict[str, Any]
    sequence: int


class FakeEventStore:
    def __init__(self, events: list[FakeEvent]) -> None:
        self._events = events
        self.appended: list[tuple[Any, ...]] = []

    def get_events(self, engagement_id: str) -> list[FakeEvent]:
        return self._events

    def append(self, *args: Any, **kwargs: Any) -> None:
        self.appended.append((args, kwargs))


class FakeAuth:
    def get_state(self, eid: str) -> int:
        return a2a_pb2.OFFENSIVE_APPROVED

    def can_agent_proceed(self, role: int, eid: str) -> bool:
        return True


class FakePolicy:
    def gate_before_agents(self) -> frozenset[str]:
        return _GATE


@dataclass
class FakeDispatcher:
    calls: list[Any] = field(default_factory=list)

    def dispatch(self, *, engagement_id: str, agent: int) -> None:
        self.calls.append(agent)


def _handoff_events(next_role: int, from_agent: int = a2a_pb2.BETA) -> list[FakeEvent]:
    return [
        FakeEvent(
            EventType.HANDOFF_READY,
            {"from_agent": from_agent, "status": a2a_pb2.COMPLETE, "next_recommended": next_role},
            1,
        )
    ]


def test_advance_parks_offensive_dispatch_on_high_blast() -> None:
    store = _high_blast_store()
    disp = FakeDispatcher()
    decision = advance_engagement(
        engagement_id="eng1",
        auth=FakeAuth(),
        event_store=FakeEventStore(_handoff_events(a2a_pb2.GAMMA)),
        dispatcher=disp,
        policy=FakePolicy(),
        graph_rebuilder=lambda es, eid: store,
    )
    assert decision.action == "park_awaiting_approval"  # reached the gate via advance
    assert disp.calls == []  # NOT dispatched


def test_advance_dispatches_offensive_when_blast_low() -> None:
    store = _low_blast_store()
    disp = FakeDispatcher()
    decision = advance_engagement(
        engagement_id="eng1",
        auth=FakeAuth(),
        event_store=FakeEventStore(_handoff_events(a2a_pb2.GAMMA)),
        dispatcher=disp,
        policy=FakePolicy(),
        graph_rebuilder=lambda es, eid: store,
    )
    assert decision.action == "dispatch"
    assert disp.calls == [a2a_pb2.GAMMA]
