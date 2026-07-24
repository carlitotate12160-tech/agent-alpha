# tests/phase_2/test_scratchpad_loop_wiring.py
"""Pin scratchpad flow + event-sourced snapshot + backward-compat.

RED / GREEN split (before G2 production change):
  t_scratchpad_flows_step_to_step    -- RED  (loop passes {} every step today)
  t_snapshot_event_per_step          -- RED  (loop never calls snapshot today)
  t_no_store_is_backward_compatible  -- GREEN (None path is today behaviour)
  t_tenant_isolation                 -- GREEN (InMemory stores are naturally scoped)

All four tests drive the REAL run_cognitive_loop -- NOT a hand-rolled store unit.
_run_with_store is the single wiring point for session_store.  When G2 adds the
session_store parameter to run_cognitive_loop, only _run_with_store changes;
test bodies stay untouched.

DO NOT TOUCH SEALED: path_probe.py, git/backup/actuator/odoo probes,
  leak_extraction.py, credential_assembly.py, response_classifier.py.
VERIFY ON Oracle ARM64 only (.venv312/bin/python3 -m pytest ...).
"""

from __future__ import annotations

import copy
from typing import Any

from agent_alpha.agents.base import BoundedAutonomy, LoopOutcome, StopReason, run_cognitive_loop
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.memory.session import InMemorySessionStore, SessionRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENG_A = "eng_scratchpad_a001"
_ENG_B = "eng_scratchpad_b002"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(
    engagement_id: str,
    scratchpad: dict | None = None,
) -> SessionRecord:
    """Return a minimal SessionRecord suitable for test use."""
    return SessionRecord(
        engagement_id=engagement_id,
        target_scope={},
        active_agent="scout",
        current_phase="recon",
        current_phase_iteration=0,
        authorization={},
        scratchpad=scratchpad if scratchpad is not None else {},
        ttl_seconds=3600,
    )


def _snapshot_events(event_store: InMemoryEventStore, engagement_id: str) -> list:
    """All SCRATCHPAD_SNAPSHOTTED events for engagement_id, in order."""
    return [
        e
        for e in event_store.get_events(engagement_id)
        if e.event_type == EventType.SCRATCHPAD_SNAPSHOTTED
    ]


# ---------------------------------------------------------------------------
# Fake agents
# ---------------------------------------------------------------------------


class _ScratchpadAccumulatorAgent:
    """Records incoming context each step; appends a note to scratchpad.

    Progress model: discovers 1 node on steps 1..(steps_to_run-1), 0 on the
    last step.  With no_progress_threshold=1 the loop stops after exactly
    steps_to_run iterations.
    """

    def __init__(self, steps_to_run: int = 3) -> None:
        self._steps_to_run = steps_to_run
        self._call_count = 0
        self.received_contexts: list[dict] = []

    def step(self, context: dict) -> dict:
        self._call_count += 1
        self.received_contexts.append(copy.deepcopy(context))

        pad: dict = dict(context.get("scratchpad") or {})
        notes: list = list(pad.get("notes") or [])
        notes.append(f"step{self._call_count}")
        pad["notes"] = notes

        discovered = 1 if self._call_count < self._steps_to_run else 0
        return {
            "discovered_nodes": discovered,
            "cost_usd": 0.001,
            "scratchpad": pad,  # G2: loop reads this and persists it
        }


class _NoOpAgent:
    """Minimal agent: no scratchpad writes, discovers 1 node then stalls."""

    def __init__(self) -> None:
        self._call_count = 0
        self.received_contexts: list[dict] = []

    def step(self, context: dict) -> dict:
        self._call_count += 1
        self.received_contexts.append(copy.deepcopy(context))
        discovered = 1 if self._call_count == 1 else 0
        return {"discovered_nodes": discovered, "cost_usd": 0.0}


# ---------------------------------------------------------------------------
# Loop harness -- the ONLY place that changes when G2 ships
# ---------------------------------------------------------------------------


def _run_with_store(
    agent: Any,
    policy: BoundedAutonomy,
    *,
    session_store: Any,
    engagement_id: str,
    event_store: InMemoryEventStore,
) -> LoopOutcome:
    """Invoke run_cognitive_loop, threading session_store in once G2 lands.

    PRE-G2:  run_cognitive_loop does not accept session_store.  We call it
    with the current real signature (agent, policy).  t1/t2 receive {} at
    every step; their assertions fail -> FAILED (RED).  No TypeError/ERROR.

    POST-G2: Replace the body with:
        return run_cognitive_loop(
            agent, policy,
            session_store=session_store,
            engagement_id=engagement_id,
            event_store=event_store,
        )
    t1/t2 go GREEN; t3 stays GREEN (session_store=None keeps {} path).
    """
    return run_cognitive_loop(
        agent,
        policy,
        session_store=session_store,
        engagement_id=engagement_id,
        event_store=event_store,
    )


# ---------------------------------------------------------------------------
# t1 -- RED until G2
# ---------------------------------------------------------------------------


def test_scratchpad_flows_step_to_step() -> None:
    """RED until G2: scratchpad accumulates across steps via the real loop.

    The loop must load the scratchpad from the session store before each
    step() call and persist the returned scratchpad back after each call.
    Step N incoming context must contain notes written by steps 1..N-1.

    PRE-G2: loop passes {} every step, so step 2 has no note from step 1 ->
    assertion fails -> FAILED (RED).
    """
    event_store = InMemoryEventStore()
    session_store = InMemorySessionStore()
    session_store.set(_make_session(_ENG_A))

    steps_to_run = 3
    agent = _ScratchpadAccumulatorAgent(steps_to_run=steps_to_run)
    policy = BoundedAutonomy(
        max_iterations=50,
        time_budget_s=30.0,
        cost_budget_usd=99.0,
        no_progress_threshold=1,
    )

    _run_with_store(
        agent,
        policy,
        session_store=session_store,
        engagement_id=_ENG_A,
        event_store=event_store,
    )

    assert len(agent.received_contexts) >= steps_to_run, (
        f"Expected >= {steps_to_run} step() calls, got {len(agent.received_contexts)}"
    )

    # Step 1 enters with empty scratchpad (initial state).
    ctx1 = agent.received_contexts[0]
    pad1: dict = ctx1.get("scratchpad") or {}
    assert pad1.get("notes", []) == [], f"Step 1 scratchpad should be empty on entry; got {pad1!r}"

    # Step 2 must contain note written by step 1.
    # RED today -- loop passes {} so scratchpad is absent.
    ctx2 = agent.received_contexts[1]
    pad2: dict = ctx2.get("scratchpad") or {}
    assert "step1" in (pad2.get("notes") or []), (
        f"Scratchpad did not accumulate: step 2 missing note from step 1. "
        f"scratchpad={pad2!r}  (RED until G2)"
    )

    # Step 3 must contain notes from steps 1 and 2.
    ctx3 = agent.received_contexts[2]
    pad3: dict = ctx3.get("scratchpad") or {}
    notes3: list = list(pad3.get("notes") or [])
    assert "step1" in notes3 and "step2" in notes3, (
        f"Scratchpad did not accumulate into step 3: notes={notes3!r}  (RED until G2)"
    )


# ---------------------------------------------------------------------------
# t2 -- RED until G2
# ---------------------------------------------------------------------------


def test_snapshot_event_per_step() -> None:
    """RED until G2: one SCRATCHPAD_SNAPSHOTTED per loop step, isolated copy.

    The loop must call session_store.snapshot_scratchpad_event() after each
    step() and append the result to the EventStore.  The payload is a DEEP
    COPY -- mutating the live scratchpad must NOT change any stored snapshot.

    PRE-G2: loop never calls snapshot_scratchpad_event -> zero events ->
    count assertion fails -> FAILED (RED).
    """
    event_store = InMemoryEventStore()
    session_store = InMemorySessionStore()
    session_store.set(_make_session(_ENG_A))

    steps_to_run = 3
    agent = _ScratchpadAccumulatorAgent(steps_to_run=steps_to_run)
    policy = BoundedAutonomy(
        max_iterations=50,
        time_budget_s=30.0,
        cost_budget_usd=99.0,
        no_progress_threshold=1,
    )

    outcome = _run_with_store(
        agent,
        policy,
        session_store=session_store,
        engagement_id=_ENG_A,
        event_store=event_store,
    )

    # One snapshot per iteration including the final stall step.
    total_iters = outcome.iterations_run
    snaps = _snapshot_events(event_store, _ENG_A)
    assert len(snaps) == total_iters, (
        f"Expected {total_iters} SCRATCHPAD_SNAPSHOTTED events, got {len(snaps)}.  (RED until G2)"
    )

    # Deep-copy isolation: mutating live scratchpad must NOT change snap[0].
    if len(snaps) >= 2:
        notes_at_snap0: list = list(snaps[0].payload.get("notes") or [])

        live = session_store.get(_ENG_A)
        if live is not None:
            live.scratchpad["notes"] = ["INJECTED_MUTATION"]

        snaps_after = _snapshot_events(event_store, _ENG_A)
        notes_after: list = list(snaps_after[0].payload.get("notes") or [])
        assert notes_after == notes_at_snap0, (
            f"Deep-copy contract violated: mutating live scratchpad changed "
            f"a stored snapshot.  before={notes_at_snap0!r} after={notes_after!r}"
        )


# ---------------------------------------------------------------------------
# t3 -- GREEN today
# ---------------------------------------------------------------------------


def test_no_store_is_backward_compatible() -> None:
    """GREEN today: session_store=None -> {} every step, zero snapshot events.

    When no session store is provided the loop behaves EXACTLY as today:
    step({}) every iteration.  All existing callers and tests stay green.
    """
    event_store = InMemoryEventStore()
    agent = _NoOpAgent()
    policy = BoundedAutonomy(
        max_iterations=10,
        time_budget_s=30.0,
        cost_budget_usd=99.0,
        no_progress_threshold=2,
    )

    outcome = _run_with_store(
        agent,
        policy,
        session_store=None,
        engagement_id=_ENG_A,
        event_store=event_store,
    )

    # Every step must receive an empty context dict.
    for i, ctx in enumerate(agent.received_contexts):
        assert ctx == {}, f"step {i + 1}: expected {{}} when session_store=None, got {ctx!r}"

    # Zero snapshot events.
    snaps = _snapshot_events(event_store, _ENG_A)
    assert snaps == [], (
        f"session_store=None must yield zero SCRATCHPAD_SNAPSHOTTED events; got {len(snaps)}"
    )

    # Spot-check outcome shape.
    assert isinstance(outcome, LoopOutcome)
    assert outcome.iterations_run >= 1
    assert outcome.nodes_discovered >= 0
    assert outcome.stop_reason in (
        StopReason.NO_PROGRESS,
        StopReason.MAX_ITERATIONS,
        StopReason.TIME_BUDGET,
        StopReason.COST_BUDGET,
    )


# ---------------------------------------------------------------------------
# t4 -- GREEN today
# ---------------------------------------------------------------------------


def test_tenant_isolation() -> None:
    """GREEN today: two InMemorySessionStore instances never share scratchpad data.

    Each tenant has its own store -- no cross-tenant leakage.  This makes the
    isolation contract explicit so the proof transfers when RedisSessionStore
    is wired in the same per-tenant pattern.
    """
    store_a = InMemorySessionStore()
    store_a.set(_make_session(_ENG_A, scratchpad={"tenant": "alpha"}))

    store_b = InMemorySessionStore()
    store_b.set(_make_session(_ENG_B, scratchpad={"tenant": "beta"}))

    event_store_a = InMemoryEventStore()
    event_store_b = InMemoryEventStore()

    agent_a = _ScratchpadAccumulatorAgent(steps_to_run=2)
    agent_b = _ScratchpadAccumulatorAgent(steps_to_run=2)
    policy = BoundedAutonomy(
        max_iterations=10,
        time_budget_s=30.0,
        cost_budget_usd=99.0,
        no_progress_threshold=1,
    )

    _run_with_store(
        agent_a,
        policy,
        session_store=store_a,
        engagement_id=_ENG_A,
        event_store=event_store_a,
    )
    _run_with_store(
        agent_b,
        policy,
        session_store=store_b,
        engagement_id=_ENG_B,
        event_store=event_store_b,
    )

    # Store A must not contain ENG_B session.
    assert store_a.get(_ENG_B) is None, (
        f"Tenant isolation violated: store_a has session for {_ENG_B!r}"
    )
    # Store B must not contain ENG_A session.
    assert store_b.get(_ENG_A) is None, (
        f"Tenant isolation violated: store_b has session for {_ENG_A!r}"
    )

    # Scratchpad in A must not carry B sentinel.
    record_a = store_a.get(_ENG_A)
    assert record_a is not None
    assert record_a.scratchpad.get("tenant") == "alpha", (
        f"Store A scratchpad contaminated: {record_a.scratchpad!r}"
    )

    # Scratchpad in B must not carry A sentinel.
    record_b = store_b.get(_ENG_B)
    assert record_b is not None
    assert record_b.scratchpad.get("tenant") == "beta", (
        f"Store B scratchpad contaminated: {record_b.scratchpad!r}"
    )

    # Event stores are fully disjoint objects.
    assert event_store_a is not event_store_b
    assert event_store_a.count(_ENG_B) == 0
    assert event_store_b.count(_ENG_A) == 0
