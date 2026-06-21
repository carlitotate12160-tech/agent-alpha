# tests/integration/test_cross_process_auth.py
"""Integration: cross-process AuthorizationStateMachine reconstruction (C1.0).

The HEADLINE test for C1.0: SM1 creates + transitions an engagement through
the full lifecycle (incl. scope, sow_hash, EMERGENCY_STOP) via a
PostgresEventStore. SM2 = a **fresh PostgresEventStore connection to the same
DSN** (a genuinely independent instance, simulating a separate Celery worker
process). SM2 reconstructs via rebuild_engagement — and gets the identical
EngagementRecord.

This is the real cross-process proof. The in-memory tests (phase_0) prove
reducer correctness; this proves durable reconstruction across connections.

Set up before running:
    cd infra && docker-compose up -d
    export AGENT_ALPHA_PG_DSN="postgresql://agent_alpha:<pw>@127.0.0.1:15432/agent_alpha"
    .venv/bin/python3 -m pytest tests/integration/test_cross_process_auth.py -v
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import (
    AuthorizationStateMachine,
    Scope,
)
from agent_alpha.conductor.engagement_reducer import rebuild_engagement
from agent_alpha.config.constants import SOW_HASH_ALGORITHM

psycopg = pytest.importorskip("psycopg")

pytestmark = pytest.mark.integration

_DSN = os.environ.get("AGENT_ALPHA_PG_DSN")
_TENANT = "tenant_cross_process_" + uuid.uuid4().hex[:6]


def _new_store():
    """Construct a PostgresEventStore or skip if unreachable."""
    if not _DSN:
        pytest.skip("AGENT_ALPHA_PG_DSN not set — cross-process test skipped")
    from agent_alpha.events.store import PostgresEventStore

    try:
        return PostgresEventStore(dsn=_DSN, tenant_id=_TENANT)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Postgres unreachable: {exc}")


# ── HEADLINE: cross-process reconstruction ────────────────────────────


def test_cross_process_reconstruction_postgres() -> None:
    """SM1 runs the full lifecycle. SM2 (fresh connection) reconstructs
    the identical EngagementRecord from durable events."""

    # ── SM1: "API process" ────────────────────────────────────────
    store1 = _new_store()
    sm1 = AuthorizationStateMachine(event_store=store1)

    scope = Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=["example.com"],
        exclusions=["10.0.0.5"],
    )
    sow_bytes = b"signed statement of work"
    sow_hash = hashlib.new(SOW_HASH_ALGORITHM, sow_bytes).digest()

    rec = sm1.create_engagement("client_cross", "10.0.0.0/24", tenant_id=_TENANT)
    eid = rec.engagement_id

    sm1.enable_recon(eid, scope)
    sm1.enable_active(eid)
    sm1.enable_offensive(eid, sow_bytes)
    sm1.emergency_stop(eid, "cross-process test halt")

    sm1_record = sm1.get_record(eid)

    # ── SM2: "Celery worker" — genuinely independent store connection ─
    store2 = _new_store()
    events = store2.get_events(eid)
    assert len(events) >= 5, f"Expected ≥5 events, got {len(events)}"

    rebuilt = rebuild_engagement(events)
    assert rebuilt is not None

    # Core assertions: the rebuilt record matches SM1's view.
    assert rebuilt.engagement_id == eid
    assert rebuilt.client_id == sm1_record.client_id
    assert rebuilt.target == sm1_record.target
    assert rebuilt.state == a2a_pb2.EMERGENCY_STOP
    assert rebuilt.stopped_reason == "cross-process test halt"

    # Scope roundtrip through Postgres JSONB.
    assert rebuilt.scope is not None
    assert rebuilt.scope.ip_ranges == scope.ip_ranges
    assert rebuilt.scope.domains == scope.domains
    assert rebuilt.scope.exclusions == scope.exclusions
    assert rebuilt.scope.verified is True

    # sow_hash roundtrip through hex encoding + JSONB.
    assert rebuilt.sow_hash == sow_hash

    # SM2 can also be used as a full AuthorizationStateMachine.
    sm2 = AuthorizationStateMachine(event_store=store2)
    assert sm2.get_state(eid) == a2a_pb2.EMERGENCY_STOP
    assert sm2.can_agent_proceed(a2a_pb2.ALPHA, eid) is False
    assert sm2.is_in_scope(eid, "10.0.0.42") is True
    assert sm2.is_in_scope(eid, "10.0.0.5") is False  # excluded


def test_cross_process_scope_enables_active_on_rebuilt_sm() -> None:
    """A Celery worker SM (fresh connection) can continue transitions
    where the API process left off — specifically, enable_active requires
    a verified scope that only exists via event-sourced rebuild."""

    store1 = _new_store()
    sm1 = AuthorizationStateMachine(event_store=store1)

    rec = sm1.create_engagement("client_scope", "10.0.0.0/24")
    eid = rec.engagement_id
    sm1.enable_recon(
        eid,
        Scope(
            ip_ranges=["10.0.0.0/24"],
            domains=["example.com"],
            exclusions=[],
        ),
    )
    assert sm1.get_state(eid) == a2a_pb2.RECON_ONLY

    # SM2: fresh connection, simulating a Celery worker.
    store2 = _new_store()
    sm2 = AuthorizationStateMachine(event_store=store2)

    # enable_active requires RECON_ONLY state + verified scope — both
    # must come from the event stream (not in-memory state).
    assert sm2.enable_active(eid) is True
    assert sm2.get_state(eid) == a2a_pb2.ACTIVE_APPROVED

    # SM1 sees the transition too (shared Postgres).
    assert sm1.get_state(eid) == a2a_pb2.ACTIVE_APPROVED


def test_unknown_engagement_raises_not_found_on_fresh_sm() -> None:
    """SM2 (fresh connection) queries an unknown engagement → not-found, no crash."""
    store1 = _new_store()
    sm1 = AuthorizationStateMachine(event_store=store1)

    rec = sm1.create_engagement("client_unknown", "10.0.0.0/24")
    known_eid = rec.engagement_id

    # SM2: fresh connection, simulating a separate process.
    store2 = _new_store()
    sm2 = AuthorizationStateMachine(event_store=store2)

    # Query the known engagement on SM2 → should work.
    assert sm2.get_state(known_eid) == a2a_pb2.CREATED

    # Query an unknown engagement on SM2 → should raise, not crash.
    from agent_alpha.conductor.authorization import EngagementNotFoundError

    with pytest.raises(EngagementNotFoundError):
        sm2.get_state("eng_unknown_99999")

    with pytest.raises(EngagementNotFoundError):
        sm2.get_record("eng_unknown_99999")
