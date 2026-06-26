"""RED contract: cross-process inner-monologue streaming to the USER channel.

The Phase-2 exit criterion "inner monologue streamed to user in real-time" is NOT met
by the sink abstraction alone (NullSink discards; CollectingSink is test-only). Frames
must cross the Celery-worker → FastAPI boundary to a real user — tenant-scoped and
redacted. This pins that contract.

Authored by Claude. RED until RedisMonologueSink.emit + stream_monologue are implemented.
Hermetic: a fake pub/sub stands in for Redis; the real redis-py adapter + WS endpoint are
the operational layer (verified on Oracle).

Run on Oracle ARM64:
  .venv/bin/python3 -m pytest tests/phase_2/test_monologue_streaming.py -v
"""

from __future__ import annotations

import collections
import typing

from agent_alpha.agents.monologue import ThoughtFrame
from agent_alpha.agents.monologue_stream import (
    RedisMonologueSink,
    channel_for,
    stream_monologue,
)


class _FakePublisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []

    def publish(self, channel: str, payload: str) -> None:
        self.published.append((channel, payload))


class _FakeSubscriber:
    """Replays whatever a _FakePublisher recorded, per channel, in arrival order."""

    def __init__(self, published: list[tuple[str, str]]) -> None:
        self._by_channel: dict[str, list[str]] = collections.defaultdict(list)
        for channel, payload in published:
            self._by_channel[channel].append(payload)

    def listen(self, channel: str) -> typing.Iterator[str]:
        yield from self._by_channel.get(channel, [])


def _frame(eng: str, msg: str, phase: str = "ORIENT") -> ThoughtFrame:
    return ThoughtFrame(
        engagement_id=eng,
        agent="alpha",
        phase=phase,
        message=msg,
        timestamp_utc="2026-06-26T00:00:00Z",
        reasoning="",
    )


# ── channel SSOT (passes now — it is the contract, not a body) ───────────


def test_channel_is_tenant_and_engagement_scoped() -> None:
    a = channel_for("tenant_a", "eng_1")
    b = channel_for("tenant_b", "eng_1")
    assert a != b
    assert "tenant_a" in a and "eng_1" in a


# ── RED until emit()/stream_monologue() are implemented ──────────────────


def test_emit_publishes_redacted_frame_to_the_scoped_channel() -> None:
    pub = _FakePublisher()
    sink = RedisMonologueSink(pub, tenant_id="t1", engagement_id="eng_1")
    sink.emit(_frame("eng_1", "reasoning leaked DB_PASSWORD=TEST_FIXTURE_SECRET here"))
    assert len(pub.published) == 1
    channel, payload = pub.published[0]
    assert channel == channel_for("t1", "eng_1")
    assert "TEST_FIXTURE_SECRET" not in payload  # redacted before leaving the process
    assert "eng_1" in payload  # frame still carries its identity


def test_emit_preserves_order() -> None:
    pub = _FakePublisher()
    sink = RedisMonologueSink(pub, tenant_id="t1", engagement_id="eng_1")
    for i in range(3):
        sink.emit(_frame("eng_1", f"step {i}", phase="ACT"))
    msgs = [p for _, p in pub.published]
    assert len(msgs) == 3
    assert all(f"step {i}" in msgs[i] for i in range(3))


def test_tenant_cannot_read_another_tenants_stream() -> None:
    pub = _FakePublisher()
    RedisMonologueSink(pub, tenant_id="t1", engagement_id="eng_1").emit(
        _frame("eng_1", "tenant-one-only ops")
    )
    sub = _FakeSubscriber(pub.published)
    leaked = list(stream_monologue(sub, tenant_id="t2", engagement_id="eng_1"))
    assert leaked == []  # different tenant -> different channel -> nothing


def test_stream_round_trips_frames_in_order() -> None:
    pub = _FakePublisher()
    sink = RedisMonologueSink(pub, tenant_id="t1", engagement_id="eng_1")
    sink.emit(_frame("eng_1", "first", phase="OBSERVE"))
    sink.emit(_frame("eng_1", "second", phase="PERSIST"))
    sub = _FakeSubscriber(pub.published)
    frames = list(stream_monologue(sub, tenant_id="t1", engagement_id="eng_1"))
    assert [f.message for f in frames] == ["first", "second"]
    assert [f.phase for f in frames] == ["OBSERVE", "PERSIST"]
    assert all(isinstance(f, ThoughtFrame) for f in frames)
