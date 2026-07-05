"""Phase 3 — A7 observability (slice A7-a) WIRING contract.

Proves ``project_engagement_trace`` is a LIVE read model, not dead code
(anti Lyndon #2): the ``GET /engagements/{id}/trace`` endpoint consumes it,
enforces the same tenant-isolation 404 and auth 401 as ``/run-status``, and
serializes a non-empty trace over HTTP.

Run on Oracle ARM64:
    .venv312/bin/python3 -m pytest tests/phase_3/test_trace_endpoint.py -v
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor import main as m
from agent_alpha.conductor.main import app
from agent_alpha.events.event_types import EventType

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


def _auth(tenant_id: str = "test-tenant") -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(tenant_id)}"}


def _create(client: TestClient, tenant: str = "test-tenant") -> str:
    resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(tenant),
    )
    assert resp.status_code in (200, 201), resp.text
    return str(resp.json()["engagement_id"])


def test_trace_endpoint_empty_after_create() -> None:
    """Fresh engagement (no outcome events yet) → 200 with an empty, well-formed
    trace. Empty is a valid read, not an error."""
    client = TestClient(app)
    engagement_id = _create(client)

    resp = client.get(f"/engagements/{engagement_id}/trace", headers=_auth())

    assert resp.status_code == 200
    data = resp.json()
    assert data["engagement_id"] == engagement_id
    assert data["steps"] == []
    assert data["total_latency_s"] == 0.0
    assert "last_sequence_number" in data


def test_trace_endpoint_serializes_outcome_step() -> None:
    """A HANDOFF_READY(COMPLETE) in the engagement's store surfaces as one
    serialized step through the endpoint — proves the projection is wired end
    to end, not just unit-tested in isolation. Backend-agnostic: appended
    through the SAME resolver the endpoint reads (store_provider.for_tenant),
    so it runs on Postgres (Oracle) too — no isinstance skip that would drop
    the only non-empty proof on the valid environment (anti Lyndon #9)."""

    client = TestClient(app)
    engagement_id = _create(client)

    # Inject an agent outcome into the SAME tenant store the endpoint reads.
    store = m.store_provider.for_tenant("test-tenant")
    store.append(
        event_type=EventType.HANDOFF_READY,
        engagement_id=engagement_id,
        agent=a2a_pb2.AgentRole.Name(a2a_pb2.ALPHA),
        payload={"from_agent": a2a_pb2.ALPHA, "status": a2a_pb2.COMPLETE},
    )

    resp = client.get(f"/engagements/{engagement_id}/trace", headers=_auth())

    assert resp.status_code == 200
    steps = resp.json()["steps"]
    assert len(steps) == 1
    assert steps[0]["agent"] == a2a_pb2.AgentRole.Name(a2a_pb2.ALPHA)
    assert steps[0]["outcome"] == "complete"
    assert steps[0]["event_type"] == EventType.HANDOFF_READY


def test_trace_endpoint_cross_tenant_returns_404() -> None:
    """Same tenant-isolation boundary as /run-status: tenant-b cannot read
    tenant-a's trace."""
    client = TestClient(app)
    engagement_id = _create(client, tenant="tenant-a")

    resp = client.get(f"/engagements/{engagement_id}/trace", headers=_auth("tenant-b"))
    assert resp.status_code == 404


def test_trace_endpoint_without_token_returns_401() -> None:
    client = TestClient(app)
    engagement_id = _create(client)

    resp = client.get(f"/engagements/{engagement_id}/trace")
    assert resp.status_code == 401


def test_trace_endpoint_unknown_engagement_returns_404() -> None:
    client = TestClient(app)
    resp = client.get("/engagements/does-not-exist/trace", headers=_auth())
    assert resp.status_code == 404
