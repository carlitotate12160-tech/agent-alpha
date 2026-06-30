"""RED test for PR #69 issue #4/#15 — the dispatch of advance must NOT be swallowed.

run_engagement_task (Alpha) still wraps advance_engagement_task.delay() in a broad
try/except, so a broker failure is silently eaten → Alpha completes, the handoff is
persisted, but advance never runs → Beta is never dispatched → the chain stalls silently.
That is a #3-family false-success (looks fine, chain is dead).

Fix = factor the "persist handoff THEN enqueue advance" tail into ONE shared helper
emit_handoff_and_advance() (the same step execute_agent already does internally) that:
  * persists HANDOFF_READY BEFORE enqueueing (so a failed enqueue never loses the handoff —
    a retry can pick it up), and
  * does NOT swallow an enqueue failure (re-raises; may also record DISPATCH_FAILED).

Both run_engagement_task and run_agent_task call this helper → #4/#15 fixed in BOTH paths,
one source of truth (#6/#7). This is NOT the full Alpha→execute_agent unification (that
stays a tracked follow-up) — only the emit+advance tail is shared.

VERIFY: Oracle ARM64 only — `.venv/bin/python3 -m pytest tests/phase_3/test_emit_handoff_and_advance.py`.
"""

from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.execute_agent import emit_handoff_and_advance
from agent_alpha.events.event_types import EventType


class FakeEvent:
    def __init__(self, event_type: object, payload: dict, sequence: int) -> None:
        self.event_type = event_type
        self.payload = payload
        self.sequence = sequence


class FakeStore:
    def __init__(self) -> None:
        self._events: list[FakeEvent] = []

    def get_events(self, engagement_id: str) -> list[FakeEvent]:
        return list(self._events)

    def append(self, *, event_type: object, engagement_id: str, agent: str, payload: dict) -> None:
        self._events.append(FakeEvent(event_type, payload, len(self._events) + 1))

    def has(self, event_type: object) -> bool:
        return any(e.event_type == event_type for e in self._events)


def _emit(store: FakeStore, advance_fn) -> None:
    emit_handoff_and_advance(
        event_store=store,
        engagement_id="eng_1",
        tenant_id="tenant_a",
        from_agent=a2a_pb2.ALPHA,
        status=a2a_pb2.COMPLETE,
        next_recommended=a2a_pb2.BETA,
        advance_fn=advance_fn,
    )


def test_happy_path_persists_handoff_and_calls_advance_once() -> None:
    store = FakeStore()
    calls: list[tuple] = []
    _emit(store, lambda engagement_id, tenant_id: calls.append((engagement_id, tenant_id)))
    assert store.has(EventType.HANDOFF_READY)
    assert calls == [("eng_1", "tenant_a")]


def test_dispatch_failure_is_not_swallowed() -> None:
    """The whole point of #4/#15: a broker failure must surface, never be eaten."""
    store = FakeStore()

    def boom(engagement_id: str, tenant_id: str) -> None:
        raise RuntimeError("broker unreachable")

    with pytest.raises(RuntimeError):
        _emit(store, boom)


def test_handoff_is_persisted_before_advance_is_called() -> None:
    """Handoff must be durable BEFORE the enqueue, so a failed enqueue can be retried
    without losing the handoff."""
    store = FakeStore()
    seen: dict = {}

    def check_then_raise(engagement_id: str, tenant_id: str) -> None:
        seen["handoff_present_at_dispatch"] = store.has(EventType.HANDOFF_READY)
        raise RuntimeError("broker down after handoff was persisted")

    with pytest.raises(RuntimeError):
        _emit(store, check_then_raise)
    assert seen["handoff_present_at_dispatch"] is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
