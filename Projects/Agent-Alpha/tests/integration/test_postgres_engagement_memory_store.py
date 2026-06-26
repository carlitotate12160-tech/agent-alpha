"""Integration contract: PostgresEngagementMemoryStore (P2 durable read-model).

EngagementMemory is a PROJECTION of the event stream — upsert is an idempotent
overwrite (not an append), so unlike the event store there is no append-only
trigger. Runs ONLY against a real Postgres; skips without AGENT_ALPHA_PG_DSN.
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_alpha.memory.engagement import EngagementMemoryRecord, EngagementMemoryStore

pytest.importorskip("psycopg")

pytestmark = pytest.mark.integration

_DSN = os.environ.get("AGENT_ALPHA_PG_DSN")
_TENANT = "tenant_integration_test"


def _new_store():
    if not _DSN:
        pytest.skip("AGENT_ALPHA_PG_DSN not set — Postgres integration skipped")
    from agent_alpha.memory.engagement import PostgresEngagementMemoryStore

    try:
        return PostgresEngagementMemoryStore(dsn=_DSN, tenant_id=_TENANT)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Postgres unreachable: {exc}")


@pytest.fixture
def store():
    return _new_store()


def _record(engagement_id: str, last_seq: int = 7) -> EngagementMemoryRecord:
    return EngagementMemoryRecord(
        engagement_id=engagement_id,
        confirmed_exploits=[{"id": "e1"}],
        failed_attempts=[],
        time_to_exploit_per_phase={"recon": 1.5},
        tool_success_rates={"nmap": 0.9},
        proof_artifacts=[{"ref": "p1"}],
        scratchpad_snapshot={"note": "x"},
        event_stream_id=engagement_id,
        last_sequence_number=last_seq,
    )


def _eng() -> str:
    return "eng_em_" + uuid.uuid4().hex[:10]


def test_protocol_conformance(store) -> None:
    assert isinstance(store, EngagementMemoryStore)


def test_upsert_get_survives_reconnect(store) -> None:
    eng = _eng()
    rec = _record(eng)
    store.upsert(rec)
    reborn = _new_store()  # fresh connection
    assert reborn.get(eng) == rec


def test_upsert_is_idempotent_overwrite(store) -> None:
    eng = _eng()
    store.upsert(_record(eng, last_seq=1))
    store.upsert(_record(eng, last_seq=99))  # same engagement, newer projection
    got = store.get(eng)
    assert got is not None and got.last_sequence_number == 99


def test_get_missing_returns_none(store) -> None:
    assert store.get(_eng()) is None


def test_rls_isolates_tenants() -> None:
    """FORCE RLS: tenant B cannot read tenant A's engagement record."""
    if not _DSN:
        pytest.skip("AGENT_ALPHA_PG_DSN not set — Postgres integration skipped")
    from agent_alpha.memory.engagement import PostgresEngagementMemoryStore

    eng = _eng()
    store_a = PostgresEngagementMemoryStore(dsn=_DSN, tenant_id="tenant_rls_A")
    store_b = PostgresEngagementMemoryStore(dsn=_DSN, tenant_id="tenant_rls_B")

    store_a.upsert(_record(eng))
    assert store_a.get(eng) is not None  # owner sees its own
    assert store_b.get(eng) is None  # other tenant sees nothing
