"""GAP B contract: emergency-stop audit events route to the TENANT store.

Today EmergencyStopHandler appends EMERGENCY_STOP_EXECUTED to the legacy
single-tenant event_store (emergency.py:88), so a tenant's own stop event lands
in the "default" store instead of its own RLS-scoped store 
(an audit-isolation gap: stop is a safety-critical, legally-auditable action).

This test is RED until the handler resolves the engagement's tenant and writes
to that tenant's store. Deterministic + no DB (forces in-memory via monkeypatch).

CONTRACT KNOB: assumes the fix passes a StoreProvider as `store_provider=` and
the handler resolves tenant via auth.get_record(engagement_id).tenant_id. If the
implementation wires tenant-resolution differently, adapt the construction
below 
— the BEHAVIOUR asserted (event → tenant store, NOT legacy) is the contract.
"""

from __future__ import annotations

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.emergency import EmergencyStopHandler
from agent_alpha.config.stores import StoreProvider
from agent_alpha.events.store import InMemoryEventStore


def test_emergency_stop_event_routes_to_tenant_store(monkeypatch) -> None:
    # Force the in-memory backend so the test is deterministic regardless of
    # whether a Postgres DSN is set in the environment (e.g. in CI).
    monkeypatch.delenv("AGENT_ALPHA_PG_DSN", raising=False)

    legacy = InMemoryEventStore()
    provider = StoreProvider()
    auth_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=auth_store)
    handler = EmergencyStopHandler(auth, legacy, store_provider=provider)

    record = auth.create_engagement("client-x", "10.0.0.0/24", tenant_id="tenant_gapb")
    result = handler.execute(record.engagement_id, reason="drill", issued_by="tester")
    assert result.success is True

    # The audit event must be in the tenant's own store …
    assert provider.for_tenant("tenant_gapb").count(record.engagement_id) == 1
    # … and NOT in the legacy single-tenant store.
    assert legacy.count(record.engagement_id) == 0


def test_emergency_stop_falls_back_to_legacy_when_no_tenant(monkeypatch) -> None:
    """Engagements with no tenant_id (legacy/tests) still get an audit event —
    the routing must not silently drop events when tenant_id is None."""
    monkeypatch.delenv("AGENT_ALPHA_PG_DSN", raising=False)

    legacy = InMemoryEventStore()
    provider = StoreProvider()
    auth_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=auth_store)
    handler = EmergencyStopHandler(auth, legacy, store_provider=provider)

    record = auth.create_engagement("client-x", "10.0.0.0/24")  # no tenant_id
    handler.execute(record.engagement_id, reason="drill", issued_by="tester")

    assert legacy.count(record.engagement_id) == 1
