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
import threading

from agent_alpha.events.store import EventStore, InMemoryEventStore

PG_DSN_ENV = "AGENT_ALPHA_PG_DSN"
TENANT_ENV = "AGENT_ALPHA_TENANT_ID"


def build_event_store() -> EventStore:
    """Select the event store from the environment (Postgres if a DSN is set).

    This is the legacy single-tenant entry point used by older call sites and
    unit tests. New multi-tenant callers should use :class:`StoreProvider`
    instead so each tenant is routed to its own EventStore instance.
    """

    dsn = os.environ.get(PG_DSN_ENV)
    if not dsn:
        return InMemoryEventStore()

    from agent_alpha.events.store import PostgresEventStore

    tenant_id = os.environ.get(TENANT_ENV, "default")
    return PostgresEventStore(dsn=dsn, tenant_id=tenant_id)


class StoreProvider:
    """Per-tenant EventStore provider.

    Lazily creates and caches one EventStore per tenant. When a Postgres DSN is
    configured, each tenant gets its own :class:`PostgresEventStore` instance
    scoped via Row-Level Security. When no DSN is set, each tenant is routed to
    an independent :class:`InMemoryEventStore`, keeping tenants isolated even in
    local/dev runs.
    """

    def __init__(self, dsn: str | None = None) -> None:
        self._dsn = dsn or os.environ.get(PG_DSN_ENV)
        self._stores: dict[str, EventStore] = {}
        self._lock = threading.Lock()

    def for_tenant(self, tenant_id: str) -> EventStore:
        if not tenant_id:
            raise ValueError("tenant_id must be non-empty")

        with self._lock:
            existing = self._stores.get(tenant_id)
            if existing is not None:
                return existing

            if not self._dsn:
                store: EventStore = InMemoryEventStore()
            else:
                from agent_alpha.events.store import PostgresEventStore

                store = PostgresEventStore(dsn=self._dsn, tenant_id=tenant_id)

            self._stores[tenant_id] = store
            return store
