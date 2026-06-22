"""Conductor fan-out interface (§12.13 / C5) — partition → gate → enqueue → aggregate.

The six Greek agents are ROLES, not instances: within a phase, the **Conductor**
partitions the phase's scope into bounded `WorkUnit`s and enqueues them; up to a
per-role cap run concurrently; every result flows back into the one append-only
engagement stream. An agent NEVER enqueues work — only the Conductor does
(§12.13 invariant 4: no direct A2A dispatch).

C5 scope (ADR §12.13 phasing, anti-Lyndon #1): this builds the dispatch INTERFACE
fan-out-aware **at degree 1**. Real multi-worker runtime concurrency is C6 (once the
agent run pipeline exists); building a runtime limiter now would be a machine with no
driver. The cap is therefore expressed as a deterministic bounded PLAN
(`max_concurrency` / `wave_count`) the C6 executor will honour, plus the
gate-before-enqueue + single-stream aggregation invariants which ARE enforced now.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import EventStore


class FanOutGateError(Exception):
    """Dispatch refused because the engagement's authorization state does not permit
    the role to proceed. Raised BEFORE any unit is enqueued (§12.13 invariant 1: a
    unit is enqueued ONLY after the gate validates) — no partial dispatch on a gate
    denial: either the phase is authorized or nothing is queued."""


class EmptyScopeError(ValueError):
    """Refuse to partition an empty scope. An empty fan-out is a no-op masquerading
    as success (anti-Lyndon #3); the caller must handle 'nothing to do' explicitly."""


@dataclass(frozen=True)
class WorkUnit:
    """One bounded, pre-authorized unit of a phase's work — the canonical fan-out
    type (§12.13). Data-parallel: one target slice per unit. Carries its own
    authorization context (engagement + tenant) so a worker never reads auth state."""

    engagement_id: str
    tenant_id: str | None
    role: str
    phase: str
    target: str
    unit_index: int
    unit_total: int


@dataclass(frozen=True)
class DispatchResult:
    """Outcome of a fan-out dispatch + the bounded plan the executor must honour."""

    units_dispatched: int
    cap: int
    max_concurrency: int  # min(cap, N) — never exceeds the per-role cap
    wave_count: int  # ceil(N / cap) — number of bounded waves at degree=cap
    task_ids: tuple[str, ...]


# Hands a unit to the queue, returns its task_id. Injected so the seam is testable
# without a live broker, and so C6 wires `run_engagement_task.delay` here.
EnqueueFn = Callable[["WorkUnit"], str]


def max_workers_for(role: str) -> int:
    """Per-role concurrency cap from the single source of truth (constants, #7)."""
    return constants.MAX_WORKERS_PER_ROLE.get(role.lower(), constants.DEFAULT_MAX_WORKERS)


def partition_targets(
    targets: Sequence[str],
    *,
    engagement_id: str,
    tenant_id: str | None,
    role: str,
    phase: str,
) -> list[WorkUnit]:
    """Partition a phase scope into bounded units — one per target (data-parallel).

    Order-preserving and deterministic. Blanks are dropped; an all-empty scope is
    refused (EmptyScopeError) — a fan-out of zero units is never a silent success.
    """
    cleaned = [t.strip() for t in targets if t and t.strip()]
    if not cleaned:
        raise EmptyScopeError(f"cannot partition an empty scope for engagement {engagement_id!r}")
    total = len(cleaned)
    return [
        WorkUnit(
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            role=role,
            phase=phase,
            target=target,
            unit_index=i,
            unit_total=total,
        )
        for i, target in enumerate(cleaned)
    ]


class FanOutDispatcher:
    """Conductor-owned fan-out seam: gate → bounded enqueue → aggregate.

    NOT an agent capability — only the Conductor constructs/calls this; there is no
    path for one agent to enqueue work for another (§12.13 invariant 4).
    """

    def __init__(
        self, auth: AuthorizationStateMachine, store: EventStore, enqueue: EnqueueFn
    ) -> None:
        self._auth = auth
        self._store = store
        self._enqueue = enqueue

    def dispatch(
        self,
        units: Sequence[WorkUnit],
        *,
        role_int: int,
        engagement_id: str,
        cap: int,
    ) -> DispatchResult:
        """Validate the gate ONCE, then enqueue every unit under a bounded plan.

        Order of effects matters: the gate is checked BEFORE any enqueue, so a denial
        queues nothing (§12.13 #1). Each enqueued unit emits one WORK_UNIT_QUEUED
        event into the single engagement stream — the EventStore serialises appends,
        so the sequence is monotonic + gapless (§12.13 #3 aggregation).

        Raises FanOutGateError on a gate denial (before any enqueue), ValueError on an
        empty unit list or cap < 1.
        """
        if cap < 1:
            raise ValueError(f"cap must be >= 1, got {cap}")
        if not units:
            raise ValueError("no units to dispatch")

        # §12.13 invariant 1 — gate never dilutes: validate BEFORE any enqueue.
        if not self._auth.can_agent_proceed(role_int, engagement_id):
            raise FanOutGateError(
                f"role {role_int} not authorized for engagement {engagement_id!r}; "
                "no units enqueued"
            )

        n = len(units)
        task_ids: list[str] = []
        for unit in units:  # order preserved
            task_id = self._enqueue(unit)
            self._store.append(
                event_type=EventType.WORK_UNIT_QUEUED,
                engagement_id=engagement_id,
                agent="CONDUCTOR",
                payload={
                    "task_id": task_id,
                    "tenant_id": unit.tenant_id,
                    "role": unit.role,
                    "phase": unit.phase,
                    "target": unit.target,
                    "unit_index": unit.unit_index,
                    "unit_total": unit.unit_total,
                },
            )
            task_ids.append(task_id)

        return DispatchResult(
            units_dispatched=n,
            cap=cap,
            max_concurrency=min(cap, n),
            wave_count=(n + cap - 1) // cap,
            task_ids=tuple(task_ids),
        )
