# tests/phase_0/test_event_store.py
import dataclasses

import pytest

from agent_alpha.config.constants import MAX_EVENTS_PER_ENGAGEMENT
from agent_alpha.events.store import (
    AgentEvent,
    EventStore,
    EventLimitExceededError,
    SequenceGapError,
)


def test_append_sets_event_type_and_agent():
    store = EventStore()
    event = store.append("EngagementCreated", "eng_A", "conductor", {"k": "v"})
    assert event.event_type == "EngagementCreated"
    assert event.agent == "conductor"
    assert event.engagement_id == "eng_A"
    assert event.payload == {"k": "v"}


def test_append_sequence_starts_at_one_and_increments():
    store = EventStore()
    e1 = store.append("A", "eng_A", "conductor", {})
    e2 = store.append("B", "eng_A", "conductor", {})
    e3 = store.append("C", "eng_A", "conductor", {})
    assert (e1.sequence_number, e2.sequence_number, e3.sequence_number) == (1, 2, 3)


def test_append_returns_frozen_event():
    store = EventStore()
    event = store.append("A", "eng_A", "conductor", {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.event_type = "tampered"


def test_get_events_returns_sequence_order():
    store = EventStore()
    for i in range(5):
        store.append(f"E{i}", "eng_A", "conductor", {})
    events = store.get_events("eng_A")
    assert [e.sequence_number for e in events] == [1, 2, 3, 4, 5]


def test_get_events_after_sequence():
    store = EventStore()
    for i in range(5):
        store.append(f"E{i}", "eng_A", "conductor", {})
    events = store.get_events("eng_A", after_sequence=2)
    assert [e.sequence_number for e in events] == [3, 4, 5]


def test_get_events_unknown_engagement_returns_empty():
    store = EventStore()
    assert store.get_events("missing") == []


def test_replay_returns_all_in_order():
    store = EventStore()
    for i in range(10):
        store.append(f"E{i}", "eng_A", "conductor", {})
    events = store.replay("eng_A")
    assert len(events) == 10
    assert [e.sequence_number for e in events] == list(range(1, 11))


def test_replay_validates_no_gap():
    store = EventStore()
    for i in range(10):
        store.append(f"E{i}", "eng_A", "conductor", {})
    assert len(store.replay("eng_A")) == 10


def test_replay_detects_gap():
    store = EventStore()
    for i in range(3):
        store.append(f"E{i}", "eng_A", "conductor", {})
    corrupted = store._events["eng_A"]
    corrupted[1] = dataclasses.replace(corrupted[1], sequence_number=5)
    with pytest.raises(SequenceGapError):
        store.replay("eng_A")


def test_count_returns_correct_count():
    store = EventStore()
    for i in range(4):
        store.append(f"E{i}", "eng_A", "conductor", {})
    assert store.count("eng_A") == 4


def test_count_unknown_engagement_returns_zero():
    store = EventStore()
    assert store.count("missing") == 0


def test_verify_immutability_identical_true():
    store = EventStore()
    event = store.append("A", "eng_A", "conductor", {"x": 1})
    assert store.verify_immutability("eng_A", event.sequence_number, event) is True


def test_verify_immutability_tampered_false():
    store = EventStore()
    event = store.append("A", "eng_A", "conductor", {"x": 1})
    tampered = dataclasses.replace(event, payload={"x": 999})
    assert store.verify_immutability("eng_A", event.sequence_number, tampered) is False


def test_independent_sequence_counters():
    store = EventStore()
    for _ in range(5):
        store.append("A", "eng_A", "conductor", {})
    for _ in range(3):
        store.append("B", "eng_B", "conductor", {})
    assert store.count("eng_A") == 5
    assert store.count("eng_B") == 3
    assert store.get_events("eng_A")[-1].sequence_number == 5
    assert store.get_events("eng_B")[-1].sequence_number == 3


def test_append_limit_exceeded():
    store = EventStore()
    store._events["eng_A"] = [
        AgentEvent("id", "A", "eng_A", "conductor", "t", {}, i + 1)
        for i in range(MAX_EVENTS_PER_ENGAGEMENT)
    ]
    store._sequence_counters["eng_A"] = MAX_EVENTS_PER_ENGAGEMENT
    with pytest.raises(EventLimitExceededError):
        store.append("A", "eng_A", "conductor", {})


def test_get_event_by_sequence():
    store = EventStore()
    for i in range(5):
        store.append(f"E{i}", "eng_A", "conductor", {})
    event = store.get_event("eng_A", 3)
    assert event is not None
    assert event.sequence_number == 3


def test_get_event_nonexistent_sequence_returns_none():
    store = EventStore()
    store.append("A", "eng_A", "conductor", {})
    assert store.get_event("eng_A", 99) is None
