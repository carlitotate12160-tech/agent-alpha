# tests/phase_1/test_engagement_memory.py
# Integration tests for EngagementMemoryProjector.
# Uses real EventStore (Phase 0) + InMemoryEngagementMemoryStore
# as test fixtures — mirrors tests/phase_1/test_projectors.py style.

from __future__ import annotations

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import EventStore
from agent_alpha.memory.engagement import (
    EngagementMemoryProjector,
    EngagementMemoryRecord,
    InMemoryEngagementMemoryStore,
)

# ── helpers ──────────────────────────────────────────────────────────

ENG_ID = "eng-mem-001"


# ── Test 1: empty event stream ──────────────────────────────────────


def test_project_empty_stream() -> None:
    """project() on engagement with 0 events -> all list/dict fields
    empty, last_sequence_number == 0."""
    es = EventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    record = projector.project(ENG_ID)

    assert record.engagement_id == ENG_ID
    assert record.event_stream_id == ENG_ID
    assert record.confirmed_exploits == []
    assert record.failed_attempts == []
    assert record.time_to_exploit_per_phase == {}
    assert record.tool_success_rates == {}
    assert record.proof_artifacts == []
    assert record.scratchpad_snapshot == {}
    assert record.last_sequence_number == 0


# ── Test 2: single ScratchpadSnapshotted ────────────────────────────


def test_project_single_scratchpad_snapshot() -> None:
    """Append one SCRATCHPAD_SNAPSHOTTED event -> scratchpad_snapshot
    equals its payload."""
    es = EventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(
        EventType.SCRATCHPAD_SNAPSHOTTED,
        ENG_ID,
        "system",
        {"notes": "test"},
    )

    record = projector.project(ENG_ID)

    assert record.scratchpad_snapshot == {"notes": "test"}
    assert record.last_sequence_number == 1


# ── Test 3: latest scratchpad wins, no merge ────────────────────────


def test_project_latest_scratchpad_wins() -> None:
    """Append two SCRATCHPAD_SNAPSHOTTED events with different payloads ->
    scratchpad_snapshot equals ONLY the higher-sequence-number event."""
    es = EventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(
        EventType.SCRATCHPAD_SNAPSHOTTED,
        ENG_ID,
        "system",
        {"notes": "first"},
    )
    es.append(
        EventType.SCRATCHPAD_SNAPSHOTTED,
        ENG_ID,
        "system",
        {"notes": "second", "extra": "data"},
    )

    record = projector.project(ENG_ID)

    assert record.scratchpad_snapshot == {"notes": "second", "extra": "data"}
    assert "first" not in str(record.scratchpad_snapshot)


# ── Test 4: idempotency ─────────────────────────────────────────────


def test_project_idempotent() -> None:
    """project() called twice on the same event stream -> both returned
    records are equal (dataclass equality), second upsert does not raise."""
    es = EventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(
        EventType.SCRATCHPAD_SNAPSHOTTED,
        ENG_ID,
        "system",
        {"notes": "idempotent"},
    )
    es.append(
        EventType.EXPLOIT_CONFIRMED,
        ENG_ID,
        "exploit-agent",
        {"cve": "CVE-2024-0001", "host": "10.0.0.1"},
    )

    record1 = projector.project(ENG_ID)
    record2 = projector.project(ENG_ID)

    assert record1 == record2
    assert record1.confirmed_exploits == record2.confirmed_exploits
    assert record1.scratchpad_snapshot == record2.scratchpad_snapshot
    assert record1.last_sequence_number == record2.last_sequence_number


# ── Test 5: drift detection ─────────────────────────────────────────


def test_verify_projection_detects_drift() -> None:
    """After project(), manually corrupt the stored record ->
    verify_projection() returns False.  Without corruption, returns True."""
    es = EventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(
        EventType.SCRATCHPAD_SNAPSHOTTED,
        ENG_ID,
        "system",
        {"notes": "original"},
    )

    projector.project(ENG_ID)

    # Before corruption: should be consistent
    assert (
        projector.verify_projection(
            ENG_ID,
            fresh_store_factory=InMemoryEngagementMemoryStore,
        )
        is True
    )

    # Corrupt the stored record by replacing it with a tampered copy
    corrupted = EngagementMemoryRecord(
        engagement_id=ENG_ID,
        confirmed_exploits=[{"fake": "exploit"}],
        failed_attempts=[],
        time_to_exploit_per_phase={},
        tool_success_rates={},
        proof_artifacts=[],
        scratchpad_snapshot={"notes": "corrupted"},
        event_stream_id=ENG_ID,
        last_sequence_number=999,
    )
    ms.upsert(corrupted)

    # After corruption: drift detected
    assert (
        projector.verify_projection(
            ENG_ID,
            fresh_store_factory=InMemoryEngagementMemoryStore,
        )
        is False
    )


# ── Test 6: engagement_id filtering ─────────────────────────────────


def test_project_filters_by_engagement_id() -> None:
    """Append events with engagement_id "eng_A" and "eng_B" interleaved
    in the same EventStore -> project("eng_A") only reflects "eng_A"
    events."""
    es = EventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    eng_a = "eng_A"
    eng_b = "eng_B"

    # Interleave events for both engagements
    es.append(
        EventType.EXPLOIT_CONFIRMED,
        eng_a,
        "exploit-agent",
        {"cve": "CVE-A-001", "host": "10.0.0.1"},
    )
    es.append(
        EventType.EXPLOIT_CONFIRMED,
        eng_b,
        "exploit-agent",
        {"cve": "CVE-B-001", "host": "10.0.0.2"},
    )
    es.append(
        EventType.SCRATCHPAD_SNAPSHOTTED,
        eng_a,
        "system",
        {"notes": "eng_A notes"},
    )
    es.append(
        EventType.EXPLOIT_FAILED,
        eng_b,
        "exploit-agent",
        {"cve": "CVE-B-002", "error": "timeout"},
    )
    es.append(
        EventType.PROOF_ARTIFACT_RECORDED,
        eng_a,
        "exploit-agent",
        {"artifact_type": "screenshot", "path": "/tmp/proof.png"},
    )

    record_a = projector.project(eng_a)
    record_b = projector.project(eng_b)

    # eng_A assertions
    assert record_a.engagement_id == eng_a
    assert len(record_a.confirmed_exploits) == 1
    assert record_a.confirmed_exploits[0]["cve"] == "CVE-A-001"
    assert record_a.scratchpad_snapshot == {"notes": "eng_A notes"}
    assert len(record_a.proof_artifacts) == 1
    assert record_a.failed_attempts == []

    # eng_B assertions — should NOT contain eng_A data
    assert record_b.engagement_id == eng_b
    assert len(record_b.confirmed_exploits) == 1
    assert record_b.confirmed_exploits[0]["cve"] == "CVE-B-001"
    assert len(record_b.failed_attempts) == 1
    assert record_b.scratchpad_snapshot == {}
    assert record_b.proof_artifacts == []
