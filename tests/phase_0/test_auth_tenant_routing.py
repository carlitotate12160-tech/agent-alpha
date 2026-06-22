"""C3 contract: auth-event tenant routing through the synchronous API path.

GAP (C1.0 regression, named in main.py): the worker (`run_engagement_task`) was
made tenant-aware in C1.6 — it reconstructs the SM over `store_provider.for_tenant
(tenant_id)`. But the SYNCHRONOUS API routes (create / recon / sow / run / stop /
state) still operate through the module-global `auth`, which is bound to the single
default `event_store`. That split is not just an audit-isolation gap — it is a
FUNCTIONAL break for any real tenant:

  * `create_engagement` writes ENGAGEMENT_CREATED + state events to the DEFAULT store.
  * the worker reads the engagement from the TENANT store → finds nothing →
    refuses a legitimately-authorized run with "not_found".

The existing dispatch tests miss this because they mock `.delay` (the worker never
runs) and only assert run-status events, which the run route happens to write to the
tenant store. These tests exercise the full lifecycle end-to-end and are RED until
every auth-event write/read is routed to the engagement's own tenant store.

CONTRACT KNOB: the fix is expected to introduce a single resolver
`main.auth_for(tenant_id)` used by every route (and an `emergency_for` for /stop),
so one tenant == one store. The BEHAVIOUR asserted below (lifecycle events land in
the tenant store, default stays empty, worker finds the record) is the contract,
not the helper name.

Deterministic + no DB: relies on the in-memory backend (no AGENT_ALPHA_PG_DSN).
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from agent_alpha.conductor import main as m
from agent_alpha.events.store import InMemoryEventStore

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")

jwt = pytest.importorskip("jwt")


def _token(tenant_id: str, sub: str = "tester") -> str:
    return str(
        jwt.encode(
            {"tenant_id": tenant_id, "sub": sub},
            os.environ["AGENT_ALPHA_JWT_SECRET"],
            algorithm="HS256",
        )
    )


def _auth(tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(tenant_id)}"}


@pytest.fixture(autouse=True)
def _require_inmemory() -> None:
    """These assertions read the module stores directly; they are only meaningful
    on the in-memory backend (a Postgres-backed run isolates via RLS, not object
    identity). Skip rather than give a false result if a DSN is configured."""
    if not isinstance(m.event_store, InMemoryEventStore):
        pytest.skip("auth-tenant-routing assertions require the in-memory backend")


def _create(client: TestClient, tenant: str) -> str:
    resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(tenant),
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["engagement_id"])


def test_create_routes_lifecycle_events_to_tenant_store() -> None:
    """ENGAGEMENT_CREATED must land in the tenant's own store, NOT the default."""
    client = TestClient(app=m.app)
    eid = _create(client, "tenant_a")

    assert m.store_provider.for_tenant("tenant_a").count(eid) >= 1
    assert m.event_store.count(eid) == 0  # legacy default store must be untouched


def test_recon_transition_also_lands_in_tenant_store() -> None:
    """A subsequent state transition (enable_recon) must stay in the same tenant
    store — proving the whole lifecycle is consistent, not just creation."""
    client = TestClient(app=m.app)
    eid = _create(client, "tenant_a")

    resp = client.post(
        f"/engagements/{eid}/recon",
        json={"ip_ranges": ["10.0.0.0/24"], "domains": [], "exclusions": []},
        headers=_auth("tenant_a"),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "RECON_ONLY"
    assert m.event_store.count(eid) == 0  # nothing leaked to the default store


def test_second_tenant_cannot_see_first_tenants_events() -> None:
    """Tenant isolation: tenant_b's store holds none of tenant_a's events."""
    client = TestClient(app=m.app)
    eid = _create(client, "tenant_a")

    assert m.store_provider.for_tenant("tenant_b").count(eid) == 0


def test_worker_finds_engagement_created_via_api(celery_eager_config: None) -> None:
    """End-to-end consistency: an engagement created + recon-enabled through the
    API must be visible to the worker reading the SAME tenant store. Pre-fix the
    worker reads the tenant store while create wrote to the default store, so the
    run is refused 'not_found' — the split-brain this contract closes."""
    client = TestClient(app=m.app)
    eid = _create(client, "tenant_a")
    client.post(
        f"/engagements/{eid}/recon",
        json={"ip_ranges": ["10.0.0.0/24"], "domains": [], "exclusions": []},
        headers=_auth("tenant_a"),
    )

    # Invoke the task body directly (eager, no broker); RECON_ONLY lets ALPHA proceed.
    result = m.run_engagement_task(eid, "tenant_a")

    assert result["status"] != "refused", (
        "worker refused an engagement it should find on the tenant store "
        "(split-brain: create wrote to default store, worker reads tenant store)"
    )
    assert result["status"] == "started"
