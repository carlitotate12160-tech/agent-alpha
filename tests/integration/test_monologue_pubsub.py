"""Integration: inner-monologue frames cross processes via Redis pub/sub, tenant-scoped.

Proves the REAL transport the hermetic suite stubs: a frame published to
monologue:{tenant}:{eng} is received by a subscriber on that EXACT channel, redacted,
and NOT by a subscriber on another tenant's channel.

Skips when no Redis is reachable — same policy as the other integration tests
(a skip is NOT a pass).

Run on Oracle ARM64 (Redis up):
  .venv/bin/python3 -m pytest tests/integration/test_monologue_pubsub.py -v
"""

from __future__ import annotations

import json
import os

import pytest

try:
    import redis
except ImportError:
    pytest.skip("redis not installed", allow_module_level=True)

from agent_alpha.agents.monologue import ThoughtFrame
from agent_alpha.agents.monologue_stream import RedisMonologueSink, channel_for
from agent_alpha.conductor.monologue_transport import RedisPublisher

_URL = os.environ.get("AGENT_ALPHA_REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def redis_client():
    client = redis.Redis.from_url(_URL)
    try:
        client.ping()
    except Exception:
        pytest.skip("no Redis reachable — integration skipped (NOT passed)")
    return client


def _frame(msg: str) -> ThoughtFrame:
    return ThoughtFrame(
        engagement_id="eng_1",
        agent="alpha",
        phase="ACT",
        message=msg,
        timestamp_utc="2026-06-26T00:00:00Z",
    )


def test_frame_reaches_same_tenant_channel_redacted(redis_client) -> None:
    sub = redis.Redis.from_url(_URL).pubsub()
    sub.subscribe(channel_for("t1", "eng_1"))
    assert sub.get_message(timeout=2.0)["type"] == "subscribe"  # subscribe ack

    RedisMonologueSink(RedisPublisher(redis_client), "t1", "eng_1").emit(
        _frame("reasoning leaked DB_PASSWORD=TEST_FIXTURE_SECRET here")
    )

    msg = sub.get_message(timeout=2.0, ignore_subscribe_messages=True)
    sub.close()
    assert msg is not None, "subscriber on the engagement channel received nothing"
    raw = msg["data"].decode() if isinstance(msg["data"], bytes) else str(msg["data"])
    assert "TEST_FIXTURE_SECRET" not in raw  # redacted before it left the worker
    body = json.loads(raw)
    assert body["engagement_id"] == "eng_1"
    assert body["phase"] == "ACT"


def test_other_tenant_channel_receives_nothing(redis_client) -> None:
    sub = redis.Redis.from_url(_URL).pubsub()
    sub.subscribe(channel_for("t2", "eng_1"))  # DIFFERENT tenant, same engagement id
    assert sub.get_message(timeout=2.0)["type"] == "subscribe"

    RedisMonologueSink(RedisPublisher(redis_client), "t1", "eng_1").emit(
        _frame("tenant-one-only operational detail")
    )

    msg = sub.get_message(timeout=1.0, ignore_subscribe_messages=True)
    sub.close()
    assert msg is None, "cross-tenant leak: t2 received t1's monologue"
