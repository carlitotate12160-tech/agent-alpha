# agent_alpha/config/stores.py
"""Environment-driven store selection.

Returns the real durable backend when configured, the in-memory store
otherwise. This is what keeps the durable adapters WIRED into the live path
(anti-Lyndon #2) without forcing a database on the unit suite or local dev.

  AGENT_ALPHA_PG_DSN     set -> PostgresEventStore, else InMemoryEventStore
  AGENT_ALPHA_TENANT_ID  tenant for the durable store (default "default").
                         Per-engagement tenant routing is a Phase 3 concern
                         (the Conductor orchestrator); this is single-tenant
                         operation for now.
"""

from __future__ import annotations

import os

from agent_alpha.events.store import EventStore, InMemoryEventStore

PG_DSN_ENV = "AGENT_ALPHA_PG_DSN"
TENANT_ENV = "AGENT_ALPHA_TENANT_ID"


def build_event_store() -> EventStore:
    """Select the event store from the environment (Postgres if a DSN is set)."""
    dsn = os.environ.get(PG_DSN_ENV)
    if not dsn:
        return InMemoryEventStore()

    from agent_alpha.events.store import PostgresEventStore

    tenant_id = os.environ.get(TENANT_ENV, "default")
    return PostgresEventStore(dsn=dsn, tenant_id=tenant_id)
