# agent_alpha/memory/session.py
# SessionMemory: Redis-backed live state store for genuinely volatile (not
# event-sourced) data during active engagements.
#
# ADR §12.11: "anything reconstructable from the event log MAY be volatile"
# — SessionMemory IS that volatile layer. Source of truth is itself while
# the engagement is running, NOT a projection of the event log.
#
# CRITICAL ARCHITECTURAL DISTINCTION:
# - EngagementMemory = projection of events (PostgreSQL), never written
#   directly, immutable read-model.
# - SessionMemory = genuinely volatile live state (Redis), read/written
#   directly by Conductor + agents, mutable, disposable.
#
# This file defines SessionStore Protocol + InMemorySessionStore test double
# and RedisSessionStore for production use.

from __future__ import annotations

import copy
import dataclasses
import json
import typing

from agent_alpha.events.event_types import EventType

# ── Exceptions ───────────────────────────────────────────────────────


class SessionNotFoundError(Exception):
    """Raised when attempting to update a session that doesn't exist."""

    def __init__(self, engagement_id: str) -> None:
        super().__init__(
            f"Session not found for engagement_id={engagement_id!r}. "
            f"Caller must set() a full SessionRecord first."
        )
        self.engagement_id = engagement_id


# ── Live state record ────────────────────────────────────────────────


@dataclasses.dataclass
class SessionRecord:
    """Mutable live state for an active engagement.

    Unlike EngagementMemoryRecord (which is frozen), SessionRecord is
    intentionally mutable — it's updated in-place during the engagement's
    Cognitive Loop. Per K3 schema, ADR §12.11.
    """

    engagement_id: str
    target_scope: dict[str, object]
    active_agent: str
    current_phase: str
    current_phase_iteration: int
    authorization: dict[str, object]
    scratchpad: dict[str, object]
    ttl_seconds: int


# ── Store protocol ───────────────────────────────────────────────────


@typing.runtime_checkable
class SessionStore(typing.Protocol):
    """Read/write interface for volatile engagement session state.

    Mirrors ``graph/store.py``'s ``GraphStore`` Protocol in style, but
    for genuinely volatile (not event-sourced) data. The store is
    read/written directly; it is NOT a projection of the event log.
    """

    def get(self, engagement_id: str) -> SessionRecord | None:
        """Return the session record, or ``None`` if not found."""
        ...

    def set(self, record: SessionRecord) -> None:
        """Persist *record*, overwriting any prior record for the same
        ``engagement_id``."""
        ...

    def update_scratchpad(self, engagement_id: str, scratchpad: dict[str, object]) -> None:
        """Update only the scratchpad field for the given engagement.

        This is a convenience method for the highest-frequency write path
        (Cognitive Loop ORIENT/PLAN steps writing scratchpad notes).

        Raises:
            SessionNotFoundError: if *engagement_id* doesn't exist yet.
                Callers must ``set()`` a full SessionRecord first.
        """
        ...

    def delete(self, engagement_id: str) -> None:
        """Remove the session record for *engagement_id*.

        Idempotent: does not raise if *engagement_id* doesn't exist.
        Mirrors EmergencyStopHandler's idempotency style.
        """
        ...

    def exists(self, engagement_id: str) -> bool:
        """Return ``True`` if a session exists for *engagement_id*,
        ``False`` otherwise."""
        ...

    def snapshot_scratchpad_event(self, engagement_id: str) -> tuple[str, dict[str, object]]:
        """Return a tuple the CALLER appends to the EventStore.

        Returns:
            A tuple ``(EventType.SCRATCHPAD_SNAPSHOTTED, scratchpad_copy)``
            where ``scratchpad_copy`` is an ISOLATED deep copy, frozen at
            the moment this method is called. Implementations MUST NOT
            return a live reference to the record's scratchpad dict — a
            later mutation of the live scratchpad (via update_scratchpad()
            or direct access) must never retroactively change a snapshot
            already returned by this method. This matters because the
            caller (Conductor) may not call EventStore.append() with this
            payload immediately; the gap between "snapshot taken" and
            "event durably appended" must not be a window where the
            payload can silently drift.

        Raises:
            SessionNotFoundError: if *engagement_id* doesn't exist yet.

        Notes:
            This file does NOT import or depend on EventStore — checkpointing
            is the Conductor's job. This method just exposes the data; it
            doesn't orchestrate the checkpoint.
        """
        ...


# ── In-memory store (for testing) ────────────────────────────────────


class InMemorySessionStore:
    """Minimal dict-backed ``SessionStore`` for unit tests.

    Mirrors how ``InMemoryEngagementMemoryStore`` implements
    ``EngagementMemoryStore`` — a lightweight, zero-dependency concrete
    store. No Redis, no TTL enforcement (TTL is a Redis-specific concern,
    irrelevant for the in-memory test double).
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    def get(self, engagement_id: str) -> SessionRecord | None:
        return self._sessions.get(engagement_id)

    def set(self, record: SessionRecord) -> None:
        self._sessions[record.engagement_id] = record

    def update_scratchpad(self, engagement_id: str, scratchpad: dict[str, object]) -> None:
        record = self._sessions.get(engagement_id)
        if record is None:
            raise SessionNotFoundError(engagement_id)
        record.scratchpad = scratchpad

    def delete(self, engagement_id: str) -> None:
        self._sessions.pop(engagement_id, None)

    def exists(self, engagement_id: str) -> bool:
        return engagement_id in self._sessions

    def snapshot_scratchpad_event(self, engagement_id: str) -> tuple[str, dict[str, object]]:
        record = self._sessions.get(engagement_id)
        if record is None:
            raise SessionNotFoundError(engagement_id)
        # deepcopy is deliberate, not defensive paranoia: returning a live
        # reference here means a later in-place mutation of record.scratchpad
        # (e.g. via get(...).scratchpad["k"] = v, bypassing update_scratchpad)
        # silently rewrites a snapshot the caller may have already queued for
        # EventStore.append() — proven via reproduction, not theoretical.
        return (EventType.SCRATCHPAD_SNAPSHOTTED, copy.deepcopy(record.scratchpad))


# ── Redis-backed store (for production) ────────────────────────────────


class RedisSessionStore:
    """Redis-backed :class:`SessionStore` — durable, TTL-enforcing volatile state.

    Mirrors :class:`InMemorySessionStore` semantics, but persists each
    :class:`SessionRecord` as a JSON value under a tenant-namespaced key with a
    native Redis TTL (the volatile layer's whole point). ``redis`` is imported
    lazily so the hermetic unit suite needs no driver.
    """

    def __init__(self, redis_url: str, tenant_id: str) -> None:
        import redis  # lazy: unit suite never imports the driver

        self._redis: typing.Any = redis.Redis.from_url(redis_url, decode_responses=True)
        self._tenant_id = tenant_id

    def _key(self, engagement_id: str) -> str:
        return f"session:{self._tenant_id}:{engagement_id}"

    @staticmethod
    def _serialise(record: SessionRecord) -> str:
        return json.dumps(dataclasses.asdict(record))

    @staticmethod
    def _deserialise(raw: str) -> SessionRecord:
        return SessionRecord(**json.loads(raw))

    def get(self, engagement_id: str) -> SessionRecord | None:
        raw = self._redis.get(self._key(engagement_id))
        return self._deserialise(raw) if raw is not None else None

    def set(self, record: SessionRecord) -> None:
        ttl = record.ttl_seconds if record.ttl_seconds > 0 else None
        self._redis.set(self._key(record.engagement_id), self._serialise(record), ex=ttl)

    def update_scratchpad(self, engagement_id: str, scratchpad: dict[str, object]) -> None:
        record = self.get(engagement_id)
        if record is None:
            raise SessionNotFoundError(engagement_id)
        record.scratchpad = scratchpad
        # KEEPTTL: a scratchpad write must not silently extend the session's life.
        self._redis.set(self._key(engagement_id), self._serialise(record), keepttl=True)

    def delete(self, engagement_id: str) -> None:
        self._redis.delete(self._key(engagement_id))  # idempotent (DEL of absent key = 0)

    def exists(self, engagement_id: str) -> bool:
        return bool(self._redis.exists(self._key(engagement_id)))

    def snapshot_scratchpad_event(self, engagement_id: str) -> tuple[str, dict[str, object]]:
        record = self.get(engagement_id)
        if record is None:
            raise SessionNotFoundError(engagement_id)
        # get() already returns a fresh deserialised dict, but deepcopy keeps the
        # contract explicit + identical to InMemorySessionStore.
        return (EventType.SCRATCHPAD_SNAPSHOTTED, copy.deepcopy(record.scratchpad))
