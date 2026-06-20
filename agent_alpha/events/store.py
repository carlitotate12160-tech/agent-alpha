# agent_alpha/events/store.py
# Append-only event store — the backbone of all system state.
# ADR §8o-1: single append-only event stream. Every agent action is an
# immutable event recorded here. All projections (AttackGraph, audit log,
# metrics) are derived from this stream; nothing writes state directly.
# This module defines the EventStore Protocol (one canonical interface) plus
# InMemoryEventStore. A Postgres-backed implementation of the SAME Protocol is
# added in P2 (durable persistence). Sequence numbers are monotonic, gapless,
# and per-engagement.

import dataclasses
import datetime
import typing
import uuid

from agent_alpha.config.constants import (
    EVENT_SEQUENCE_GAP_ALLOWED,
    EVENT_STORE_TABLE,
    MAX_EVENTS_PER_ENGAGEMENT,
)


class EventStoreError(Exception):
    pass


class EventLimitExceededError(EventStoreError):
    pass


class SequenceGapError(EventStoreError):
    pass


class EventNotFoundError(EventStoreError):
    pass


@dataclasses.dataclass(frozen=True)
class AgentEvent:
    event_id: str
    event_type: str
    engagement_id: str
    agent: str
    timestamp_utc: str
    payload: dict[str, object]
    sequence_number: int


def _utcnow() -> str:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"


@typing.runtime_checkable
class EventStore(typing.Protocol):
    """Append-only event store — the durable backbone of all system state.

    One canonical interface, mirroring GraphStore / SessionStore /
    EngagementMemoryStore. Implementations: InMemoryEventStore (below) and a
    Postgres-backed store (P2). Sequence numbers are monotonic, gapless,
    per-engagement; events are immutable once appended.
    """

    def append(
        self,
        event_type: str,
        engagement_id: str,
        agent: str,
        payload: dict[str, object],
    ) -> AgentEvent: ...

    def get_events(self, engagement_id: str, after_sequence: int = 0) -> list[AgentEvent]: ...

    def get_event(self, engagement_id: str, sequence_number: int) -> AgentEvent | None: ...

    def replay(self, engagement_id: str) -> list[AgentEvent]: ...

    def count(self, engagement_id: str) -> int: ...

    def verify_immutability(
        self,
        engagement_id: str,
        sequence_number: int,
        original_event: AgentEvent,
    ) -> bool: ...


class InMemoryEventStore:
    """In-memory EventStore implementation (tests/dev). The Postgres-backed
    implementation of the same Protocol arrives in P2."""

    # Target table for the deferred PostgreSQL backend (Phase 1).
    _table = EVENT_STORE_TABLE

    def __init__(self) -> None:
        self._events: dict[str, list[AgentEvent]] = {}
        self._sequence_counters: dict[str, int] = {}

    def append(
        self,
        event_type: str,
        engagement_id: str,
        agent: str,
        payload: dict[str, object],
    ) -> AgentEvent:
        current_count = len(self._events.get(engagement_id, []))
        if current_count >= MAX_EVENTS_PER_ENGAGEMENT:
            raise EventLimitExceededError(
                f"Engagement '{engagement_id}' has reached the maximum of "
                f"{MAX_EVENTS_PER_ENGAGEMENT} events"
            )

        next_sequence = self._sequence_counters.get(engagement_id, 0) + 1

        event = AgentEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            engagement_id=engagement_id,
            agent=agent,
            timestamp_utc=_utcnow(),
            payload=payload,
            sequence_number=next_sequence,
        )

        self._events.setdefault(engagement_id, []).append(event)
        self._sequence_counters[engagement_id] = next_sequence
        return event

    def get_events(
        self,
        engagement_id: str,
        after_sequence: int = 0,
    ) -> list[AgentEvent]:
        events = self._events.get(engagement_id, [])
        selected = [e for e in events if e.sequence_number > after_sequence]
        return sorted(selected, key=lambda e: e.sequence_number)

    def get_event(
        self,
        engagement_id: str,
        sequence_number: int,
    ) -> AgentEvent | None:
        for event in self._events.get(engagement_id, []):
            if event.sequence_number == sequence_number:
                return event
        return None

    def replay(self, engagement_id: str) -> list[AgentEvent]:
        events = sorted(
            self._events.get(engagement_id, []),
            key=lambda e: e.sequence_number,
        )

        if not EVENT_SEQUENCE_GAP_ALLOWED:
            for index, event in enumerate(events):
                expected_sequence = index + 1
                if event.sequence_number != expected_sequence:
                    raise SequenceGapError(
                        f"Sequence gap detected for engagement "
                        f"'{engagement_id}': expected {expected_sequence}, "
                        f"found {event.sequence_number}"
                    )

        return events

    def count(self, engagement_id: str) -> int:
        return len(self._events.get(engagement_id, []))

    def verify_immutability(
        self,
        engagement_id: str,
        sequence_number: int,
        original_event: AgentEvent,
    ) -> bool:
        stored_event = self.get_event(engagement_id, sequence_number)
        if stored_event is None:
            return False
        return stored_event == original_event
