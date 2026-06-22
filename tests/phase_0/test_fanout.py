"""C5 contract: Conductor fan-out interface (§12.13) — degree-1 seam.

Hermetic (injected enqueue stands in for the broker). Asserts the §12.13 invariants
the INTERFACE must hold now (runtime multi-worker concurrency is C6):
  * partition: N targets → N bounded units, order-preserved, empty scope refused;
  * gate never dilutes (#1): a denied role enqueues NOTHING and raises;
  * bounded plan (#2): max_concurrency / wave_count never exceed the per-role cap;
  * deterministic aggregation (#3): every unit lands in ONE monotonic, gapless
    engagement event stream;
  * caps come from the single source of truth (#7).

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_fanout.py -v
"""

from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.fanout import (
    DispatchResult,
    EmptyScopeError,
    FanOutDispatcher,
    FanOutGateError,
    WorkUnit,
    max_workers_for,
    partition_targets,
)
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import EventStore, InMemoryEventStore


class _RecordingEnqueue:
    """Stands in for `run_engagement_task.delay`; records units, returns a task_id."""

    def __init__(self) -> None:
        self.units: list[WorkUnit] = []

    def __call__(self, unit: WorkUnit) -> str:
        self.units.append(unit)
        return f"task-{unit.unit_index}"


def _units(n: int, *, role: str = "alpha") -> list[WorkUnit]:
    return partition_targets(
        [f"10.0.0.{i}" for i in range(n)],
        engagement_id="eng1",
        tenant_id="tenant_a",
        role=role,
        phase="recon",
    )


def _authorized() -> tuple[AuthorizationStateMachine, EventStore, str]:
    """An engagement in RECON_ONLY — ALPHA may proceed."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    eng = auth.create_engagement("client_a", "10.0.0.0/24", tenant_id="tenant_a").engagement_id
    auth.enable_recon(eng, Scope(ip_ranges=["10.0.0.0/24"], domains=[], exclusions=[]))
    assert auth.can_agent_proceed(a2a_pb2.ALPHA, eng) is True
    return auth, store, eng


# ── partition_targets ─────────────────────────────────────────────────


def test_partition_one_unit_per_target_in_order() -> None:
    units = partition_targets(
        ["a", "b", "c"], engagement_id="eng1", tenant_id="t", role="alpha", phase="recon"
    )
    assert [u.target for u in units] == ["a", "b", "c"]
    assert [u.unit_index for u in units] == [0, 1, 2]
    assert {u.unit_total for u in units} == {3}


def test_partition_drops_blanks() -> None:
    units = partition_targets(
        ["a", "", "   ", "b"], engagement_id="eng1", tenant_id=None, role="alpha", phase="recon"
    )
    assert [u.target for u in units] == ["a", "b"]
    assert units[0].unit_total == 2


def test_partition_empty_scope_refused() -> None:
    with pytest.raises(EmptyScopeError):
        partition_targets([], engagement_id="eng1", tenant_id=None, role="alpha", phase="recon")
    with pytest.raises(EmptyScopeError):
        partition_targets(
            ["", "  "], engagement_id="eng1", tenant_id=None, role="alpha", phase="recon"
        )


# ── caps (single source of truth) ─────────────────────────────────────


def test_cap_from_single_source_of_truth() -> None:
    assert max_workers_for("gamma") == constants.MAX_WORKERS_PER_ROLE["gamma"] == 2
    assert max_workers_for("alpha") == 10
    assert max_workers_for("unknown-role") == constants.DEFAULT_MAX_WORKERS


# ── gate never dilutes (#1) ───────────────────────────────────────────


def test_dispatch_denied_enqueues_nothing() -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    eng = auth.create_engagement("client_a", "10.0.0.0/24", tenant_id="tenant_a").engagement_id
    # CREATED state (no recon) → ALPHA not authorized.
    enqueue = _RecordingEnqueue()
    dispatcher = FanOutDispatcher(auth, store, enqueue)

    with pytest.raises(FanOutGateError):
        dispatcher.dispatch(_units(3), role_int=a2a_pb2.ALPHA, engagement_id=eng, cap=4)

    assert enqueue.units == []  # nothing queued on a gate denial
    assert [e for e in store.get_events(eng) if e.event_type == EventType.WORK_UNIT_QUEUED] == []


# ── enqueue + deterministic aggregation (#3) ──────────────────────────


def test_dispatch_enqueues_all_and_aggregates_gaplessly() -> None:
    auth, store, eng = _authorized()
    enqueue = _RecordingEnqueue()
    dispatcher = FanOutDispatcher(auth, store, enqueue)

    units = partition_targets(
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        engagement_id=eng,
        tenant_id="tenant_a",
        role="alpha",
        phase="recon",
    )
    result = dispatcher.dispatch(units, role_int=a2a_pb2.ALPHA, engagement_id=eng, cap=4)

    assert result.units_dispatched == 3
    assert result.task_ids == ("task-0", "task-1", "task-2")
    assert len(enqueue.units) == 3

    queued = [e for e in store.get_events(eng) if e.event_type == EventType.WORK_UNIT_QUEUED]
    assert len(queued) == 3
    # ONE stream, monotonic + gapless across the WHOLE engagement (§12.13 #3).
    seqs = [e.sequence_number for e in store.get_events(eng)]
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))


# ── bounded plan never exceeds the cap (#2) ───────────────────────────


def test_dispatch_plan_bounded_by_cap() -> None:
    auth, store, eng = _authorized()
    dispatcher = FanOutDispatcher(auth, store, _RecordingEnqueue())
    units = partition_targets(
        [f"10.0.0.{i}" for i in range(5)],
        engagement_id=eng,
        tenant_id="tenant_a",
        role="alpha",
        phase="recon",
    )

    tight = dispatcher.dispatch(units, role_int=a2a_pb2.ALPHA, engagement_id=eng, cap=2)
    assert tight.max_concurrency == 2  # never exceeds cap
    assert tight.wave_count == 3  # ceil(5 / 2)

    auth2, store2, eng2 = _authorized()
    d2 = FanOutDispatcher(auth2, store2, _RecordingEnqueue())
    units2 = partition_targets(
        [f"10.0.0.{i}" for i in range(5)],
        engagement_id=eng2,
        tenant_id="tenant_a",
        role="alpha",
        phase="recon",
    )
    wide = d2.dispatch(units2, role_int=a2a_pb2.ALPHA, engagement_id=eng2, cap=10)
    assert wide.max_concurrency == 5  # min(cap, N)
    assert wide.wave_count == 1


def test_dispatch_rejects_bad_cap_and_empty_units() -> None:
    auth, store, eng = _authorized()
    dispatcher = FanOutDispatcher(auth, store, _RecordingEnqueue())
    with pytest.raises(ValueError):
        dispatcher.dispatch(_units(2), role_int=a2a_pb2.ALPHA, engagement_id=eng, cap=0)
    with pytest.raises(ValueError):
        dispatcher.dispatch([], role_int=a2a_pb2.ALPHA, engagement_id=eng, cap=4)


def test_dispatch_result_is_frozen() -> None:
    r = DispatchResult(units_dispatched=1, cap=4, max_concurrency=1, wave_count=1, task_ids=("t",))
    with pytest.raises((AttributeError, TypeError)):
        r.cap = 9  # type: ignore[misc]
