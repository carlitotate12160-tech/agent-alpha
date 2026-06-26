# tests/integration/test_postgres_event_store.py
"""Integration contract (RED): PostgresEventStore — P2 durable persistence.

Runs ONLY against a real Postgres (the infra/ compose). SKIPS cleanly when
AGENT_ALPHA_PG_DSN is unset, psycopg is absent, or the DB is unreachable — the
hermetic unit suite never needs a database.

Headline guarantee: write events -> "restart" (a fresh store / new connection)
-> replay -> the events come back BYTE-IDENTICAL. That is what makes the
event-sourced audit log real instead of an in-memory illusion.

Set up before running:
    cd infra && docker-compose up -d
    export AGENT_ALPHA_PG_DSN="postgresql://agent_alpha:<pw>@127.0.0.1:15432/agent_alpha"
    .venv/bin/python3 -m pytest tests/integration/ -q
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_alpha.config.constants import EVENT_STORE_TABLE
from agent_alpha.events.store import AgentEvent, EventStore

psycopg = pytest.importorskip("psycopg")  # skip the whole module if driver absent

pytestmark = pytest.mark.integration

_DSN = os.environ.get("AGENT_ALPHA_PG_DSN")
_TENANT = "tenant_integration_test"


def _new_store():
    """Construct a PostgresEventStore or skip if the DB is unreachable."""
    if not _DSN:
        pytest.skip("AGENT_ALPHA_PG_DSN not set — Postgres integration skipped")
    from agent_alpha.events.store import PostgresEventStore

    try:
        return PostgresEventStore(dsn=_DSN, tenant_id=_TENANT)
    except Exception as exc:  # noqa: BLE001 — any connect failure -> skip, not fail
        pytest.skip(f"Postgres unreachable: {exc}")


@pytest.fixture
def pg_store():
    return _new_store()


def _unique_engagement() -> str:
    return "eng_it_" + uuid.uuid4().hex[:10]


# ── 1. Protocol conformance ───────────────────────────────────────────


def test_postgres_store_satisfies_event_store_protocol(pg_store) -> None:
    assert isinstance(pg_store, EventStore)


# ── 2. HEADLINE: restart -> replay -> byte-identical ──────────────────


def test_restart_replay_is_byte_identical(pg_store) -> None:
    engagement_id = _unique_engagement()

    appended: list[AgentEvent] = []
    for i in range(10):
        appended.append(pg_store.append("NODE_DISCOVERED", engagement_id, "alpha", {"i": i}))

    # "Restart": a brand-new store object + fresh connection to the same DB.
    reborn = _new_store()
    replayed = reborn.replay(engagement_id)

    assert replayed == appended  # identical AgentEvents (ids, timestamps, seq, payload)


# ── 3. Append-only enforced at the DB layer (not just the app) ────────


def test_append_only_rejected_by_db(pg_store) -> None:
    engagement_id = _unique_engagement()
    pg_store.append("NODE_DISCOVERED", engagement_id, "alpha", {"k": "v"})

    # A raw UPDATE on a past event row must be rejected by the database itself.
    with psycopg.connect(_DSN, options=f"-c app.tenant_id={_TENANT}") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.Error):
            cur.execute(
                f"UPDATE {EVENT_STORE_TABLE} SET agent = 'tampered' WHERE engagement_id = %s",
                (engagement_id,),
            )
        conn.rollback()

    with psycopg.connect(_DSN, options=f"-c app.tenant_id={_TENANT}") as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.Error):
            cur.execute(
                f"DELETE FROM {EVENT_STORE_TABLE} WHERE engagement_id = %s",
                (engagement_id,),
            )
        conn.rollback()


# ── 4. Sequence numbers are monotonic + gapless per engagement ────────


def test_sequence_is_monotonic_and_gapless(pg_store) -> None:
    engagement_id = _unique_engagement()
    events = [
        pg_store.append("NODE_DISCOVERED", engagement_id, "alpha", {"i": i}) for i in range(5)
    ]
    assert [e.sequence_number for e in events] == [1, 2, 3, 4, 5]
    # replay enforces no-gap and returns them in order.
    assert [e.sequence_number for e in pg_store.replay(engagement_id)] == [1, 2, 3, 4, 5]


def test_rls_isolates_tenants(pg_store) -> None:
    """FORCE RLS: tenant B cannot see tenant A's events even on the same DB."""
    from agent_alpha.events.store import PostgresEventStore

    engagement_id = _unique_engagement()
    store_a = PostgresEventStore(dsn=_DSN, tenant_id="tenant_rls_A")
    store_b = PostgresEventStore(dsn=_DSN, tenant_id="tenant_rls_B")

    store_a.append("NODE_DISCOVERED", engagement_id, "alpha", {"x": 1})

    assert store_a.count(engagement_id) == 1  # owner sees its own
    assert store_b.replay(engagement_id) == []  # other tenant sees nothing
    assert store_b.count(engagement_id) == 0
