"""Integration contract: Postgres Row-Level Security is the REAL tenant backstop.

WHY THIS FILE WAS REWRITTEN
---------------------------
The first version of these tests only called the store's public API
(`replay`, `count`, `get`). But EVERY query in the store already carries an
explicit ``WHERE tenant_id = %s`` (events/store.py get_events/count/append,
engagement.py get). So those assertions pass even if RLS is dropped entirely —
they prove the APPLICATION filter works, not RLS. That is a false-success trap
(Lyndon #3): the defence-in-depth layer was never exercised.

RLS only earns its keep when a query FORGETS the tenant filter (a new code
path, an admin query, an ORM, or SQLi that controls engagement_id). This file
probes exactly that: it issues RAW SQL with NO tenant_id predicate, under a
connection scoped to tenant B, and asserts the database itself refuses to
return tenant A's rows. If RLS were off — or the connection role bypasses RLS
(superuser / BYPASSRLS) — these go RED.

Two layers are tested explicitly and kept separate:
  * APP layer  : store API is tenant-scoped (the WHERE filter).
  * RLS layer  : raw, unfiltered SQL still cannot cross tenants.
Plus a guard that FAILS (not skips) if the DSN role can bypass RLS, because
under such a role the entire isolation guarantee is void.

Runs ONLY against a real Postgres on Oracle ARM64; skips without
AGENT_ALPHA_PG_DSN (Lyndon #9 — Oracle is the only valid env).
"""

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip("psycopg")
import psycopg  # noqa: E402 — after importorskip on purpose

from agent_alpha.config.constants import (  # noqa: E402
    ENGAGEMENT_MEMORY_TABLE,
    EVENT_STORE_TABLE,
)

pytestmark = pytest.mark.integration

_DSN = os.environ.get("AGENT_ALPHA_PG_DSN")


def _require_dsn() -> str:
    if not _DSN:
        pytest.skip("AGENT_ALPHA_PG_DSN not set — Postgres integration skipped")
    return _DSN


def _event_store(tenant_id: str):
    from agent_alpha.events.store import PostgresEventStore

    try:
        return PostgresEventStore(dsn=_require_dsn(), tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001 — connect failure -> skip, not fail
        pytest.skip(f"Postgres unreachable: {exc}")


def _engagement_store(tenant_id: str):
    from agent_alpha.memory.engagement import PostgresEngagementMemoryStore

    try:
        return PostgresEngagementMemoryStore(dsn=_require_dsn(), tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Postgres unreachable: {exc}")


def _raw_conn(tenant_id: str):
    """A raw connection scoped to one tenant exactly as production scopes it:
    app.tenant_id is set per-connection so RLS applies. No app WHERE filter is
    used by the callers below — the DB is the only thing standing between
    tenants here."""
    return psycopg.connect(_require_dsn(), options=f"-c app.tenant_id={tenant_id}")


def _two_tenants() -> tuple[str, str]:
    s = uuid.uuid4().hex[:8]
    return f"rls_a_{s}", f"rls_b_{s}"


def _eng() -> str:
    return "eng_rls_" + uuid.uuid4().hex[:10]


# ── 0. GUARD: the DSN role must NOT be able to bypass RLS ─────────────
# If this fails, every other RLS assertion is meaningless and tenant
# isolation in production is silently void. Fail loudly, do not skip.


def test_dsn_role_cannot_bypass_rls() -> None:
    _require_dsn()
    with psycopg.connect(_require_dsn()) as conn, conn.cursor() as cur:
        cur.execute("SELECT current_setting('is_superuser')")
        is_superuser = cur.fetchone()[0]
        cur.execute(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        bypass_rls = cur.fetchone()[0]

    assert is_superuser == "off", (
        "DSN role is a SUPERUSER — it bypasses Row-Level Security even with "
        "FORCE. Tenant isolation is NOT enforced by the database. Use a "
        "dedicated NOSUPERUSER NOBYPASSRLS role for the app/CI DSN."
    )
    assert bypass_rls is False, (
        "DSN role has BYPASSRLS — RLS provides no protection. "
        "Use a NOBYPASSRLS role."
    )


# ── 1. APP layer: store API is tenant-scoped (the WHERE filter) ───────


def test_app_layer_store_api_is_tenant_scoped() -> None:
    tenant_a, tenant_b = _two_tenants()
    eng = _eng()
    store_a, store_b = _event_store(tenant_a), _event_store(tenant_b)

    store_a.append("NODE_DISCOVERED", eng, "alpha", {"owner": "a"})

    assert store_a.count(eng) == 1
    assert store_b.replay(eng) == []  # app WHERE filter (NOT proof of RLS)


# ── 2. RLS layer: raw, UNFILTERED read still cannot cross tenants ─────
# This is the real test. The SELECT has NO tenant_id predicate; only RLS
# stands between tenant B and tenant A's row.


def test_rls_blocks_unfiltered_cross_tenant_read_event_store() -> None:
    tenant_a, tenant_b = _two_tenants()
    eng = _eng()
    _event_store(tenant_a).append("NODE_DISCOVERED", eng, "alpha", {"owner": "a"})

    # As tenant B, query WITHOUT a tenant_id filter. RLS must hide A's row.
    with _raw_conn(tenant_b) as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT count(*) FROM {EVENT_STORE_TABLE} WHERE engagement_id = %s",
            (eng,),
        )
        seen_by_b = cur.fetchone()[0]

    # As tenant A, the same unfiltered query DOES see its own row.
    with _raw_conn(tenant_a) as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT count(*) FROM {EVENT_STORE_TABLE} WHERE engagement_id = %s",
            (eng,),
        )
        seen_by_a = cur.fetchone()[0]

    assert seen_by_b == 0, "RLS FAILED: tenant B read tenant A's event via unfiltered SQL"
    assert seen_by_a == 1


def test_rls_blocks_unfiltered_cross_tenant_read_engagement_memory() -> None:
    from agent_alpha.memory.engagement import EngagementMemoryRecord

    tenant_a, tenant_b = _two_tenants()
    eng = _eng()
    _engagement_store(tenant_a).upsert(
        EngagementMemoryRecord(
            engagement_id=eng,
            confirmed_exploits=[],
            failed_attempts=[],
            time_to_exploit_per_phase={},
            tool_success_rates={},
            proof_artifacts=[],
            scratchpad_snapshot={"owner": "a"},
            event_stream_id=eng,
            last_sequence_number=0,
        )
    )

    with _raw_conn(tenant_b) as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT count(*) FROM {ENGAGEMENT_MEMORY_TABLE} WHERE engagement_id = %s",
            (eng,),
        )
        seen_by_b = cur.fetchone()[0]

    assert seen_by_b == 0, "RLS FAILED: tenant B read tenant A's engagement record"


# ── 3. RLS WITH CHECK: a tenant cannot forge a row for another tenant ─


def test_rls_with_check_blocks_forged_tenant_insert() -> None:
    tenant_a, tenant_b = _two_tenants()
    eng = _eng()
    # Ensure the table exists with RLS applied.
    _event_store(tenant_a)

    # As tenant B, try to INSERT a row LABELLED as tenant A. WITH CHECK must
    # reject it — you cannot write outside your own tenant.
    with _raw_conn(tenant_b) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.Error):
            cur.execute(
                f"INSERT INTO {EVENT_STORE_TABLE} "
                "(tenant_id, event_id, event_type, engagement_id, agent, "
                " timestamp_utc, payload, sequence_number) "
                "VALUES (%s, %s, 'X', %s, 'alpha', '2026-01-01T00:00:00Z', '{}', 1)",
                (tenant_a, str(uuid.uuid4()), eng),
            )
        conn.rollback()
