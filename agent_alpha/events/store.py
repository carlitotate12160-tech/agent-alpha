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
import re
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


class PostgresEventStore:
    """Durable, append-only EventStore backed by PostgreSQL (P2).

    Implements the :class:`EventStore` Protocol; behaviour mirrors
    :class:`InMemoryEventStore`. Tenant-scoped: every query filters on
    ``tenant_id`` so a store instance only sees its own tenant's events
    (Postgres Row-Level Security is the next hardening layer on top of this
    app-level scoping). ``psycopg`` is imported lazily so the hermetic unit
    suite needs no database driver.

    Durability guarantee: ``timestamp_utc`` is stored verbatim as TEXT and the
    payload as JSONB, so ``append`` then a fresh-store ``replay`` returns
    byte-identical :class:`AgentEvent` objects.
    """

    _table = EVENT_STORE_TABLE

    def __init__(self, dsn: str, tenant_id: str) -> None:
        import psycopg  # lazy: unit suite never imports the driver

        if not re.fullmatch(r"[A-Za-z0-9_.-]+", tenant_id):
            raise ValueError(f"invalid tenant_id for RLS connection option: {tenant_id!r}")
        self._psycopg = psycopg
        self._dsn = dsn
        self._tenant_id = tenant_id
        # app.tenant_id is set per-connection so Row-Level Security scopes every
        # query/insert to this tenant (defence-in-depth atop the WHERE filters).
        self._conn_options = f"-c app.tenant_id={tenant_id}"
        self._ensure_schema()

    # ── schema (idempotent) ───────────────────────────────────

    def _connect(self) -> typing.Any:
        """Connection with app.tenant_id set so RLS scopes it to this tenant."""
        return self._psycopg.connect(self._dsn, options=self._conn_options)

    def _ensure_schema(self) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._table} (
                    tenant_id       text    NOT NULL,
                    event_id        text    NOT NULL,
                    event_type      text    NOT NULL,
                    engagement_id   text    NOT NULL,
                    agent           text    NOT NULL,
                    timestamp_utc   text    NOT NULL,
                    payload         jsonb   NOT NULL,
                    sequence_number integer NOT NULL,
                    PRIMARY KEY (tenant_id, engagement_id, sequence_number)
                )
                """
            )
            cur.execute(
                """
                CREATE OR REPLACE FUNCTION agent_alpha_events_append_only()
                RETURNS trigger AS $func$
                BEGIN
                    RAISE EXCEPTION 'event store is append-only: % not permitted', TG_OP;
                END;
                $func$ LANGUAGE plpgsql
                """
            )
            cur.execute(f"DROP TRIGGER IF EXISTS agent_alpha_events_no_mutate ON {self._table}")
            cur.execute(
                f"""
                CREATE TRIGGER agent_alpha_events_no_mutate
                    BEFORE UPDATE OR DELETE ON {self._table}
                    FOR EACH ROW EXECUTE FUNCTION agent_alpha_events_append_only()
                """
            )
            cur.execute(f"ALTER TABLE {self._table} ENABLE ROW LEVEL SECURITY")
            cur.execute(f"ALTER TABLE {self._table} FORCE ROW LEVEL SECURITY")
            cur.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {self._table}")
            cur.execute(
                f"""
                CREATE POLICY tenant_isolation ON {self._table}
                    USING (tenant_id = current_setting('app.tenant_id', true))
                    WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
                """
            )
            conn.commit()

    # ── helpers ───────────────────────────────────────────────

    @staticmethod
    def _row_to_event(row: tuple[typing.Any, ...]) -> AgentEvent:
        return AgentEvent(
            event_id=str(row[0]),
            event_type=str(row[1]),
            engagement_id=str(row[2]),
            agent=str(row[3]),
            timestamp_utc=str(row[4]),
            payload=dict(row[5]),  # JSONB -> dict
            sequence_number=int(row[6]),
        )

    _SELECT_COLS = (
        "event_id, event_type, engagement_id, agent, timestamp_utc, payload, sequence_number"
    )

    # ── EventStore Protocol ───────────────────────────────────

    def append(
        self,
        event_type: str,
        engagement_id: str,
        agent: str,
        payload: dict[str, object],
    ) -> AgentEvent:
        from psycopg.types.json import Json

        with self._connect() as conn, conn.cursor() as cur:
            # Serialise concurrent appends for this engagement -> gapless sequence.
            # The lock is transaction-scoped (released on commit/rollback).
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"{self._tenant_id}:{engagement_id}",),
            )
            cur.execute(
                f"SELECT COUNT(*) FROM {self._table} WHERE tenant_id = %s AND engagement_id = %s",
                (self._tenant_id, engagement_id),
            )
            count_row = cur.fetchone()
            current_count = int(count_row[0]) if count_row else 0
            if current_count >= MAX_EVENTS_PER_ENGAGEMENT:
                raise EventLimitExceededError(
                    f"Engagement '{engagement_id}' has reached the maximum of "
                    f"{MAX_EVENTS_PER_ENGAGEMENT} events"
                )

            cur.execute(
                f"SELECT COALESCE(MAX(sequence_number), 0) FROM {self._table} "
                "WHERE tenant_id = %s AND engagement_id = %s",
                (self._tenant_id, engagement_id),
            )
            max_row = cur.fetchone()
            next_sequence = (int(max_row[0]) if max_row else 0) + 1

            event = AgentEvent(
                event_id=str(uuid.uuid4()),
                event_type=event_type,
                engagement_id=engagement_id,
                agent=agent,
                timestamp_utc=_utcnow(),
                payload=payload,
                sequence_number=next_sequence,
            )
            cur.execute(
                f"INSERT INTO {self._table} (tenant_id, event_id, event_type, "
                "engagement_id, agent, timestamp_utc, payload, sequence_number) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    self._tenant_id,
                    event.event_id,
                    event.event_type,
                    event.engagement_id,
                    event.agent,
                    event.timestamp_utc,
                    Json(event.payload),
                    event.sequence_number,
                ),
            )
            conn.commit()
            return event

    def get_events(self, engagement_id: str, after_sequence: int = 0) -> list[AgentEvent]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"SELECT {self._SELECT_COLS} FROM {self._table} "
                "WHERE tenant_id = %s AND engagement_id = %s AND sequence_number > %s "
                "ORDER BY sequence_number",
                (self._tenant_id, engagement_id, after_sequence),
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def get_event(self, engagement_id: str, sequence_number: int) -> AgentEvent | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"SELECT {self._SELECT_COLS} FROM {self._table} "
                "WHERE tenant_id = %s AND engagement_id = %s AND sequence_number = %s",
                (self._tenant_id, engagement_id, sequence_number),
            )
            row = cur.fetchone()
            return self._row_to_event(row) if row else None

    def replay(self, engagement_id: str) -> list[AgentEvent]:
        events = self.get_events(engagement_id, after_sequence=0)
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
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) FROM {self._table} WHERE tenant_id = %s AND engagement_id = %s",
                (self._tenant_id, engagement_id),
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0

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
