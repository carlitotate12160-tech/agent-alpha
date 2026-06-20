"""Integration contract: RedisSessionStore (P2 — durable volatile session layer).

Runs ONLY against a real Redis (infra/ compose). Skips if AGENT_ALPHA_REDIS_URL
is unset, the redis driver is absent, or Redis is unreachable. SessionMemory is
the volatile layer (its own source of truth while running, NOT an event
projection) — but it must survive a reconnect within a run and enforce TTL
natively.

Setup:
    cd infra && docker-compose up -d
    export AGENT_ALPHA_REDIS_URL="redis://:<pw>@127.0.0.1:16379/0"
    .venv/bin/python3 -m pytest tests/integration/test_redis_session_store.py -q
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_alpha.memory.session import SessionNotFoundError, SessionRecord, SessionStore

pytest.importorskip("redis")

pytestmark = pytest.mark.integration

_URL = os.environ.get("AGENT_ALPHA_REDIS_URL")
_TENANT = "tenant_integration_test"


def _new_store():
    if not _URL:
        pytest.skip("AGENT_ALPHA_REDIS_URL not set — Redis integration skipped")
    from agent_alpha.memory.session import RedisSessionStore

    try:
        store = RedisSessionStore(redis_url=_URL, tenant_id=_TENANT)
        store._redis.ping()
    except Exception as exc:  # noqa: BLE001 — any connect failure -> skip, not fail
        pytest.skip(f"Redis unreachable: {exc}")
    return store


@pytest.fixture
def store():
    return _new_store()


def _record(engagement_id, scratchpad=None):
    return SessionRecord(
        engagement_id=engagement_id,
        target_scope={"domains": ["x.invalid"]},
        active_agent="alpha",
        current_phase="recon",
        current_phase_iteration=1,
        authorization={"state": "RECON_ONLY"},
        scratchpad=scratchpad if scratchpad is not None else {"note": "hi"},
        ttl_seconds=100,
    )


def _eng():
    return "eng_redis_" + uuid.uuid4().hex[:10]


def test_protocol_conformance(store):
    assert isinstance(store, SessionStore)


def test_set_get_survives_reconnect(store):
    eng = _eng()
    rec = _record(eng)
    store.set(rec)
    reborn = _new_store()  # fresh client = a reconnect
    assert reborn.get(eng) == rec
    reborn.delete(eng)


def test_update_scratchpad_missing_raises(store):
    with pytest.raises(SessionNotFoundError):
        store.update_scratchpad(_eng(), {"k": "v"})


def test_update_scratchpad(store):
    eng = _eng()
    store.set(_record(eng))
    store.update_scratchpad(eng, {"updated": True})
    got = store.get(eng)
    assert got is not None and got.scratchpad == {"updated": True}
    store.delete(eng)


def test_delete_is_idempotent(store):
    eng = _eng()
    store.set(_record(eng))
    store.delete(eng)
    store.delete(eng)  # again -> no error
    assert store.exists(eng) is False


def test_snapshot_is_isolated_from_later_mutation(store):
    eng = _eng()
    store.set(_record(eng, scratchpad={"v": 1}))
    _evt, snap = store.snapshot_scratchpad_event(eng)
    store.update_scratchpad(eng, {"v": 2})
    assert snap == {"v": 1}  # snapshot frozen at capture time
    store.delete(eng)


def test_ttl_is_applied(store):
    eng = _eng()
    store.set(_record(eng))  # ttl_seconds=100
    ttl = store._redis.ttl(store._key(eng))
    assert 0 < ttl <= 100
    store.delete(eng)
