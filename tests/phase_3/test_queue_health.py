"""Phase 3 — A7 observability (slice A7-c): broker queue-depth + worker health.

Contract for build_queue_health (pure assembler) and RedisCeleryProbe (thin
adapter). No live Redis: fakes make this identical on Oracle and in pre-flight.

Run on Oracle ARM64:
    .venv312/bin/python3 -m pytest tests/phase_3/test_queue_health.py -v

Core invariant (anti Lyndon #3): a DOWN broker is degraded with UNKNOWN depth —
never "queue_depth 0 / healthy". A false-empty health signal is worse than none.
"""

from __future__ import annotations

import dataclasses
import datetime

from agent_alpha.conductor.health import (
    QueueHealth,
    RedisCeleryProbe,
    build_queue_health,
)


class _FakeProbe:
    def __init__(self, *, reachable: bool, depth: int = 0, workers: int | None = 0) -> None:
        self._reachable = reachable
        self._depth = depth
        self._workers = workers

    def broker_reachable(self) -> bool:
        return self._reachable

    def queue_depth(self) -> int:
        return self._depth

    def worker_count(self) -> int | None:
        return self._workers


_FIXED = datetime.datetime(2026, 7, 5, 0, 0, 0, tzinfo=datetime.UTC)


def _clock() -> datetime.datetime:
    return _FIXED


# ── assembler ──────────────────────────────────────────────────────────
def test_healthy_broker_up_workers_present() -> None:
    health = build_queue_health(_FakeProbe(reachable=True, depth=5, workers=2), clock=_clock)
    assert health.broker_reachable is True
    assert health.queue_depth == 5
    assert health.worker_count == 2
    assert health.degraded is False
    assert health.checked_at_utc == _FIXED.isoformat()


def test_broker_down_is_degraded_with_unknown_depth() -> None:
    """anti-#3: down broker must NOT read as depth 0 / healthy."""
    health = build_queue_health(_FakeProbe(reachable=False), clock=_clock)
    assert health.broker_reachable is False
    assert health.queue_depth is None  # UNKNOWN, not 0
    assert health.worker_count is None
    assert health.degraded is True


def test_broker_up_no_workers_is_degraded_but_depth_surfaced() -> None:
    health = build_queue_health(_FakeProbe(reachable=True, depth=3, workers=0), clock=_clock)
    assert health.degraded is True  # queued work can't drain
    assert health.queue_depth == 3  # depth still reported honestly
    assert health.worker_count == 0


def test_broker_up_workers_unknown_is_degraded() -> None:
    health = build_queue_health(_FakeProbe(reachable=True, depth=0, workers=None), clock=_clock)
    assert health.degraded is True
    assert health.worker_count is None


def test_no_dead_field_structural_guard() -> None:
    health = build_queue_health(_FakeProbe(reachable=True, depth=1, workers=1), clock=_clock)
    fields = {f.name for f in dataclasses.fields(QueueHealth)}
    assert fields == {
        "broker_reachable",
        "queue_depth",
        "worker_count",
        "degraded",
        "checked_at_utc",
    }
    assert health.checked_at_utc  # populated, not empty


# ── adapter (fakes, no Redis) ──────────────────────────────────────────
class _FakeRedis:
    def __init__(self, *, lists: dict[str, list[object]], ping_ok: bool = True) -> None:
        self._lists = lists
        self._ping_ok = ping_ok

    def ping(self) -> bool:
        if not self._ping_ok:
            raise ConnectionError("broker down")
        return True

    def scan_iter(self, *, match: str, count: int = 100):  # noqa: ARG002
        prefix = match.rstrip("*")
        return [k for k in self._lists if k.startswith(prefix)]

    def llen(self, key: str) -> int:
        return len(self._lists[key])


class _FakeInspect:
    def __init__(self, replies: dict[str, object] | None) -> None:
        self._replies = replies

    def ping(self) -> dict[str, object] | None:
        return self._replies


class _FakeControl:
    def __init__(self, replies: dict[str, object] | None) -> None:
        self._replies = replies

    def inspect(self, timeout: float = 1.0) -> _FakeInspect:  # noqa: ARG002
        return _FakeInspect(self._replies)


class _FakeCelery:
    def __init__(self, replies: dict[str, object] | None) -> None:
        self.control = _FakeControl(replies)


def _probe(redis: _FakeRedis, celery: _FakeCelery) -> RedisCeleryProbe:
    return RedisCeleryProbe(redis_client=redis, celery_app=celery, queue_prefix="engagement_")


def test_adapter_sums_depth_across_prefixed_queues() -> None:
    redis = _FakeRedis(
        lists={
            "engagement_default": [1, 2, 3],
            "engagement_tenant_a": [1],
            "celery-task-meta-xyz": [1, 1, 1, 1],  # NOT a queue — must be ignored
        }
    )
    probe = _probe(redis, _FakeCelery({"w1": {}}))
    assert probe.queue_depth() == 4  # 3 + 1, meta key excluded by prefix


def test_adapter_broker_unreachable_returns_false_not_raise() -> None:
    redis = _FakeRedis(lists={}, ping_ok=False)
    probe = _probe(redis, _FakeCelery(None))
    assert probe.broker_reachable() is False  # swallowed, not raised


def test_adapter_worker_count_none_when_no_replies() -> None:
    probe = _probe(_FakeRedis(lists={}), _FakeCelery(None))
    assert probe.worker_count() == 0  # broker up, zero workers


def test_adapter_worker_count_counts_replies() -> None:
    probe = _probe(_FakeRedis(lists={}), _FakeCelery({"w1": {}, "w2": {}}))
    assert probe.worker_count() == 2


def test_adapter_feeds_assembler_end_to_end_degraded_when_down() -> None:
    """Adapter + assembler compose: unreachable broker -> degraded, depth None."""
    probe = _probe(_FakeRedis(lists={"engagement_default": [1]}, ping_ok=False), _FakeCelery(None))
    health = build_queue_health(probe, clock=_clock)
    assert health.degraded is True
    assert health.queue_depth is None


# ── endpoint wiring (anti-#2: probe is live code) ──────────────────────
import os  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agent_alpha.conductor.main import app  # noqa: E402

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")
_jwt = pytest.importorskip("jwt")


def _auth() -> dict[str, str]:
    tok = str(
        _jwt.encode(
            {"tenant_id": "test-tenant", "sub": "op"},
            os.environ["AGENT_ALPHA_JWT_SECRET"],
            algorithm="HS256",
        )
    )
    return {"Authorization": f"Bearer {tok}"}


def test_health_endpoint_returns_shape() -> None:
    """GET /health/queue → 200 with all fields. Env-independent: with no broker
    it reports degraded/unreachable (still 200), never crashes."""
    client = TestClient(app)
    resp = client.get("/health/queue", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert set(data) == {
        "broker_reachable",
        "queue_depth",
        "worker_count",
        "degraded",
        "checked_at_utc",
    }
    assert isinstance(data["degraded"], bool)
    assert data["checked_at_utc"]


def test_health_endpoint_requires_auth() -> None:
    client = TestClient(app)
    resp = client.get("/health/queue")
    assert resp.status_code == 401
