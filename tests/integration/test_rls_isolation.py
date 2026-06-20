"""Integration contract: Row-Level Security actually isolates tenants.

WHY THIS FILE EXISTS
--------------------
The other integration tests all run under a SINGLE tenant
(`tenant_integration_test`). They pass identically whether RLS works or is a
complete no-op — they never open a second tenant and check it is blocked.
That is Lyndon failure #3 (false success): RLS code exists, but its critical
path is never executed by a test.

These three tests exercise that path. If RLS were disabled, removed, or the
table were not FORCE'd, AT LEAST ONE of these MUST go red. The negative-control
test (#3) specifically fails if the suite is only "green because the DB is
empty" — it proves two tenants' rows coexist in ONE table, separated solely by
RLS, not by separate tables or PK collisions.

Runs ONLY against a real Postgres on Oracle ARM64; skips without
AGENT_ALPHA_PG_DSN. Never accept local/Windows results (Lyndon #9).
"""

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip("psycopg")

pytestmark = pytest.mark.integration

_DSN = os.environ.get("AGENT_ALPHA_PG_DSN")


# ── store factories (one per tenant, same DSN, same physical table) ───


def _event_store(tenant_id: str):
    if not _DSN:
        pytest.skip("AGENT_ALPHA_PG_DSN not set — Postgres integration skipped")
    from agent_alpha.events.store import PostgresEventStore

    try:
        return PostgresEventStore(dsn=_DSN, tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001 — connect failure -> skip, not fail
        pytest.skip(f"Postgres unreachable: {exc}")


def _engagement_store(tenant_id: str):
    if not _DSN:
        pytest.skip("AGENT_ALPHA_PG_DSN not set — Postgres integration skipped")
    from agent_alpha.memory.engagement import PostgresEngagementMemoryStore

    try:
        return PostgresEngagementMemoryStore(dsn=_DSN, tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Postgres unreachable: {exc}")


def _two_tenants() -> tuple[str, str]:
    suffix = uuid.uuid4().hex[:8]
    return f"rls_tenant_a_{suffix}", f"rls_tenant_b_{suffix}"


def _eng() -> str:
    return "eng_rls_" + uuid.uuid4().hex[:10]


# ── 1. HEADLINE: event-store reads are tenant-scoped by RLS ───────────


def test_event_store_rls_blocks_cross_tenant_reads() -> None:
    """Tenant B must NOT see events written by tenant A.

    If RLS is a no-op, B.replay() returns A's event and this goes red.
    """
    tenant_a, tenant_b = _two_tenants()
    engagement_id = _eng()

    store_a = _event_store(tenant_a)
    store_b = _event_store(tenant_b)

    store_a.append("NODE_DISCOVERED", engagement_id, "alpha", {"secret": "tenant_a_only"})

    # A sees its own write.
    a_events = store_a.replay(engagement_id)
    assert len(a_events) == 1
    assert a_events[0].payload == {"secret": "tenant_a_only"}

    # B, using the SAME engagement_id on the SAME table, sees nothing.
    assert store_b.replay(engagement_id) == []
    assert store_b.count(engagement_id) == 0


# ── 2. Engagement-memory reads are tenant-scoped by RLS ───────────────


def test_engagement_memory_rls_blocks_cross_tenant_reads() -> None:
    """Tenant B must NOT read tenant A's engagement record."""
    from agent_alpha.memory.engagement import EngagementMemoryRecord

    tenant_a, tenant_b = _two_tenants()
    engagement_id = _eng()

    store_a = _engagement_store(tenant_a)
    store_b = _engagement_store(tenant_b)

    record = EngagementMemoryRecord(
        engagement_id=engagement_id,
        confirmed_exploits=[{"id": "tenant_a_exploit"}],
        failed_attempts=[],
        time_to_exploit_per_phase={"recon": 1.5},
        tool_success_rates={"nmap": 0.9},
        proof_artifacts=[{"ref": "p1"}],
        scratchpad_snapshot={"note": "tenant_a"},
        event_stream_id=engagement_id,
        last_sequence_number=7,
    )
    store_a.upsert(record)

    assert store_a.get(engagement_id) == record  # A sees its own.
    assert store_b.get(engagement_id) is None  # B is blocked by RLS.


# ── 3. NEGATIVE CONTROL: same engagement_id coexists, RLS is the wall ──


def test_event_store_rls_negative_control_rows_coexist_in_one_table() -> None:
    """Both tenants write the SAME engagement_id; each sees ONLY its own row.

    This fails if RLS is off (each tenant would see BOTH rows -> count == 2),
    AND it fails if the suite were only passing because the DB is empty
    (it explicitly asserts a row IS present, count == 1, for each tenant).
    Proves the two rows live in one physical table, separated solely by RLS.
    """
    tenant_a, tenant_b = _two_tenants()
    engagement_id = _eng()  # SAME id for both tenants on purpose.

    store_a = _event_store(tenant_a)
    store_b = _event_store(tenant_b)

    store_a.append("NODE_DISCOVERED", engagement_id, "alpha", {"owner": "a"})
    store_b.append("NODE_DISCOVERED", engagement_id, "alpha", {"owner": "b"})

    a_events = store_a.replay(engagement_id)
    b_events = store_b.replay(engagement_id)

    # Each tenant sees exactly one row — its own — never the other's.
    assert store_a.count(engagement_id) == 1
    assert store_b.count(engagement_id) == 1
    assert a_events[0].payload == {"owner": "a"}
    assert b_events[0].payload == {"owner": "b"}
