"""RED tests for time_to_first_proof_s and time_to_first_exploit_s metrics.

These tests verify that the EngagementMemoryProjector correctly derives
the "proved in X minutes" and "exploited in X minutes" metrics from the
event stream. 7 tests cover the key scenarios."""

from __future__ import annotations

from unittest import mock

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.memory.engagement import (
    EngagementMemoryProjector,
    InMemoryEngagementMemoryStore,
)

ENG_ID = "eng-time-metrics-001"


def test_time_to_first_proof_computed_from_created_to_first_proof() -> None:
    """ENGAGEMENT_CREATED at T0, PROOF_ARTIFACT_RECORDED at T+60s -> time_to_first_proof_s = 60.0."""
    es = InMemoryEventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    with mock.patch("agent_alpha.events.store._utcnow") as mock_utcnow:
        mock_utcnow.side_effect = [
            "2024-01-01T00:00:00Z",  # ENGAGEMENT_CREATED
            "2024-01-01T00:01:00Z",  # PROOF_ARTIFACT_RECORDED
        ]
        es.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})
        es.append(
            EventType.PROOF_ARTIFACT_RECORDED, ENG_ID, "alpha", {"artifact_type": "screenshot"}
        )

    record = projector.project(ENG_ID)
    assert record.time_to_first_proof_s == 60.0


def test_time_to_first_exploit_computed_from_created_to_first_exploit() -> None:
    """ENGAGEMENT_CREATED at T0, EXPLOIT_CONFIRMED at T+120s -> time_to_first_exploit_s = 120.0."""
    es = InMemoryEventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    with mock.patch("agent_alpha.events.store._utcnow") as mock_utcnow:
        mock_utcnow.side_effect = [
            "2024-01-01T00:00:00Z",  # ENGAGEMENT_CREATED
            "2024-01-01T00:02:00Z",  # EXPLOIT_CONFIRMED
        ]
        es.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})
        es.append(EventType.EXPLOIT_CONFIRMED, ENG_ID, "beta", {"cve": "CVE-2024-0001"})

    record = projector.project(ENG_ID)
    assert record.time_to_first_exploit_s == 120.0


def test_time_to_first_proof_none_when_created_missing() -> None:
    """No ENGAGEMENT_CREATED event -> time_to_first_proof_s = None."""
    es = InMemoryEventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(EventType.PROOF_ARTIFACT_RECORDED, ENG_ID, "alpha", {"artifact_type": "screenshot"})

    record = projector.project(ENG_ID)
    assert record.time_to_first_proof_s is None


def test_time_to_first_proof_none_when_proof_missing() -> None:
    """ENGAGEMENT_CREATED exists but no PROOF_ARTIFACT_RECORDED -> time_to_first_proof_s = None."""
    es = InMemoryEventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})

    record = projector.project(ENG_ID)
    assert record.time_to_first_proof_s is None


def test_time_to_first_exploit_none_when_created_missing() -> None:
    """No ENGAGEMENT_CREATED event -> time_to_first_exploit_s = None."""
    es = InMemoryEventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(EventType.EXPLOIT_CONFIRMED, ENG_ID, "beta", {"cve": "CVE-2024-0001"})

    record = projector.project(ENG_ID)
    assert record.time_to_first_exploit_s is None


def test_time_to_first_exploit_none_when_exploit_missing() -> None:
    """ENGAGEMENT_CREATED exists but no EXPLOIT_CONFIRMED -> time_to_first_exploit_s = None."""
    es = InMemoryEventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    es.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})

    record = projector.project(ENG_ID)
    assert record.time_to_first_exploit_s is None


def test_first_timestamp_used_not_subsequent() -> None:
    """Multiple PROOF_ARTIFACT_RECORDED events -> time_to_first_proof_s uses the FIRST timestamp."""
    es = InMemoryEventStore()
    ms = InMemoryEngagementMemoryStore()
    projector = EngagementMemoryProjector(es, ms)

    with mock.patch("agent_alpha.events.store._utcnow") as mock_utcnow:
        mock_utcnow.side_effect = [
            "2024-01-01T00:00:00Z",  # ENGAGEMENT_CREATED
            "2024-01-01T00:01:00Z",  # First PROOF_ARTIFACT_RECORDED
            "2024-01-01T00:05:00Z",  # Second PROOF_ARTIFACT_RECORDED
        ]
        es.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})
        es.append(
            EventType.PROOF_ARTIFACT_RECORDED, ENG_ID, "alpha", {"artifact_type": "screenshot"}
        )
        es.append(EventType.PROOF_ARTIFACT_RECORDED, ENG_ID, "alpha", {"artifact_type": "log"})

    record = projector.project(ENG_ID)
    assert record.time_to_first_proof_s == 60.0  # Uses first proof at 60s, not 300s
