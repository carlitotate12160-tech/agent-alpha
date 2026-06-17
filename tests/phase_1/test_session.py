# tests/phase_1/test_session.py
# Unit tests for SessionMemory (Redis-backed live state store).
# Uses InMemorySessionStore as test fixture — mirrors
# tests/phase_1/test_engagement_memory.py style.

from __future__ import annotations

import pytest

from agent_alpha.events.event_types import EventType
from agent_alpha.memory.session import (
    InMemorySessionStore,
    SessionNotFoundError,
    SessionRecord,
)


# ── helpers ──────────────────────────────────────────────────────────

ENG_ID = "sess-001"


def make_session_record(
    engagement_id: str = ENG_ID,
    scratchpad: dict[str, object] | None = None,
) -> SessionRecord:
    """Helper factory for SessionRecord instances with sensible defaults."""
    return SessionRecord(
        engagement_id=engagement_id,
        target_scope={"hosts": ["10.0.0.1"], "ports": [80, 443]},
        active_agent="recon-agent",
        current_phase="RECON",
        current_phase_iteration=1,
        authorization={"state": "ACTIVE", "constraints": []},
        scratchpad=scratchpad if scratchpad is not None else {},
        ttl_seconds=3600,
    )


# ── Test 1: set() + get() roundtrip ─────────────────────────────────


def test_set_and_get_roundtrip() -> None:
    """set() a new SessionRecord, then get() returns an equal record."""
    store = InMemorySessionStore()
    record = make_session_record()

    store.set(record)
    retrieved = store.get(ENG_ID)

    assert retrieved is not None
    assert retrieved == record
    assert retrieved.engagement_id == ENG_ID
    assert retrieved.target_scope == {"hosts": ["10.0.0.1"], "ports": [80, 443]}
    assert retrieved.active_agent == "recon-agent"
    assert retrieved.current_phase == "RECON"
    assert retrieved.current_phase_iteration == 1
    assert retrieved.scratchpad == {}
    assert retrieved.ttl_seconds == 3600


# ── Test 2: get() on nonexistent session ───────────────────────────


def test_get_nonexistent_returns_none() -> None:
    """get() on a nonexistent engagement_id returns None (not an exception)."""
    store = InMemorySessionStore()

    result = store.get("nonexistent-engagement")

    assert result is None


# ── Test 3: update_scratchpad() on existing session ────────────────


def test_update_scratchpad_existing_session() -> None:
    """update_scratchpad() on an existing session updates only the
    scratchpad field, leaving all other fields unchanged."""
    store = InMemorySessionStore()
    record = make_session_record(scratchpad={"initial": "data"})
    store.set(record)

    new_scratchpad = {"updated": "notes", "phase": "exploit"}
    store.update_scratchpad(ENG_ID, new_scratchpad)

    retrieved = store.get(ENG_ID)
    assert retrieved is not None
    assert retrieved.scratchpad == new_scratchpad
    assert retrieved.engagement_id == ENG_ID
    assert retrieved.active_agent == "recon-agent"
    assert retrieved.current_phase == "RECON"
    assert retrieved.current_phase_iteration == 1
    assert retrieved.target_scope == {"hosts": ["10.0.0.1"], "ports": [80, 443]}
    assert retrieved.authorization == {"state": "ACTIVE", "constraints": []}
    assert retrieved.ttl_seconds == 3600


# ── Test 4: update_scratchpad() on nonexistent session ─────────────


def test_update_scratchpad_nonexistent_raises() -> None:
    """update_scratchpad() on a NONEXISTENT engagement_id raises
    SessionNotFoundError."""
    store = InMemorySessionStore()

    with pytest.raises(
        SessionNotFoundError,
        match=r"Session not found for engagement_id='nonexistent'",
    ):
        store.update_scratchpad("nonexistent", {"foo": "bar"})


# ── Test 5: delete() idempotency ────────────────────────────────────


def test_delete_idempotent() -> None:
    """delete() on an existing session removes it (subsequent get()
    returns None); delete() on a nonexistent session does not raise
    (idempotent)."""
    store = InMemorySessionStore()
    record = make_session_record()
    store.set(record)

    assert store.get(ENG_ID) is not None

    store.delete(ENG_ID)

    assert store.get(ENG_ID) is None

    store.delete(ENG_ID)


# ── Test 6: exists() checks ─────────────────────────────────────────


def test_exists_returns_correct_status() -> None:
    """exists() returns True after set(), False after delete()."""
    store = InMemorySessionStore()

    assert store.exists(ENG_ID) is False

    record = make_session_record()
    store.set(record)

    assert store.exists(ENG_ID) is True

    store.delete(ENG_ID)

    assert store.exists(ENG_ID) is False


# ── Test 7: snapshot_scratchpad_event() ────────────────────────────


def test_snapshot_scratchpad_event() -> None:
    """snapshot_scratchpad_event() returns a tuple whose second element
    equals the current scratchpad dict exactly (not a copy with
    extra/missing keys), and whose first element equals
    EventType.SCRATCHPAD_SNAPSHOTTED."""
    store = InMemorySessionStore()
    scratchpad_data = {"phase": "EXPLOIT", "notes": "SQLi successful"}
    record = make_session_record(scratchpad=scratchpad_data)
    store.set(record)

    event_type, payload = store.snapshot_scratchpad_event(ENG_ID)

    assert event_type == EventType.SCRATCHPAD_SNAPSHOTTED
    assert payload == scratchpad_data
    assert payload == {"phase": "EXPLOIT", "notes": "SQLi successful"}
    assert "phase" in payload
    assert "notes" in payload
    assert len(payload) == 2


def test_snapshot_scratchpad_event_nonexistent_raises() -> None:
    """snapshot_scratchpad_event() on a nonexistent engagement_id raises
    SessionNotFoundError."""
    store = InMemorySessionStore()

    with pytest.raises(
        SessionNotFoundError,
        match=r"Session not found for engagement_id='nonexistent'",
    ):
        store.snapshot_scratchpad_event("nonexistent")
