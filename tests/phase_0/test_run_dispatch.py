"""Phase 0 — Celery dispatch endpoint test contract.

Tests the /engagements/{id}/run endpoint behavior:
- Endpoint enqueues task and returns immediately (non-blocking)
- Auth/ownership enforcement
- Celery configuration (JSON serializer, time limits from constants)

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_run_dispatch.py -v
"""

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from agent_alpha.config import constants
from agent_alpha.conductor.main import app, celery_app

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")

jwt = pytest.importorskip("jwt")


def _token(tenant_id: str, sub: str = "tester") -> str:
    return jwt.encode({"tenant_id": tenant_id, "sub": sub}, os.environ["AGENT_ALPHA_JWT_SECRET"], algorithm="HS256")


def _auth(tenant_id: str = "test-tenant") -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(tenant_id)}"}


def test_run_endpoint_returns_202_and_task_id() -> None:
    """C1.1: endpoint enqueues + returns immediately with task_id."""
    client = TestClient(app)

    # Create an engagement first
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    engagement_id = create_resp.json()["engagement_id"]

    # Mock .delay to verify it's called without actually running the task
    mock_task = MagicMock()
    mock_task.id = "test-task-id-123"
    mock_task.delay.return_value = mock_task

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        response = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )

    assert response.status_code == 202
    data = response.json()
    assert data["engagement_id"] == engagement_id
    assert data["task_id"] == "test-task-id-123"

    # Verify .delay was called once with correct arguments
    mock_task.delay.assert_called_once_with(engagement_id, "test-tenant")


def test_run_endpoint_without_token_returns_401() -> None:
    """C1.1 auth: no token → 401."""
    client = TestClient(app)

    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    engagement_id = create_resp.json()["engagement_id"]

    response = client.post(f"/engagements/{engagement_id}/run")
    assert response.status_code == 401


def test_run_endpoint_cross_tenant_returns_404() -> None:
    """C1.1 ownership: token for another tenant → 404."""
    client = TestClient(app)

    # Create engagement as tenant-a
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth("tenant-a"),
    )
    engagement_id = create_resp.json()["engagement_id"]

    # Try to run as tenant-b
    mock_task = MagicMock()
    mock_task.id = "test-task-id-123"
    mock_task.delay.return_value = mock_task

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        response = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth("tenant-b"),
        )

    assert response.status_code == 404
    # .delay should NOT be called for cross-tenant access
    mock_task.delay.assert_not_called()


def test_run_endpoint_nonexistent_engagement_returns_404() -> None:
    """C1.1: engagement not found → 404."""
    client = TestClient(app)

    mock_task = MagicMock()
    mock_task.id = "test-task-id-123"
    mock_task.delay.return_value = mock_task

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        response = client.post(
            "/engagements/eng_does_not_exist/run",
            headers=_auth(),
        )

    assert response.status_code == 404
    mock_task.delay.assert_not_called()


def test_celery_serializer_is_json_only() -> None:
    """C1.7: assert celery_app.conf uses JSON serializer."""
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.accept_content == ["json"]
    assert celery_app.conf.result_serializer == "json"


def test_celery_time_limits_from_constants() -> None:
    """C1.7/C1.5: time limits come from constants."""
    assert celery_app.conf.task_soft_time_limit == constants.CELERY_TASK_SOFT_LIMIT_SEC
    assert celery_app.conf.task_time_limit == constants.CELERY_TASK_HARD_LIMIT_SEC


def test_run_status_queryable_after_dispatch() -> None:
    """C1.2: after POST /run, GET /run-status → "queued" + task_id."""
    client = TestClient(app)

    # Create an engagement
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    engagement_id = create_resp.json()["engagement_id"]

    # Dispatch the task
    mock_task = MagicMock()
    mock_task.id = "test-task-id-123"
    mock_task.delay.return_value = mock_task

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        run_resp = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )

    assert run_resp.status_code == 202
    task_id = run_resp.json()["task_id"]

    # Query status
    status_resp = client.get(
        f"/engagements/{engagement_id}/run-status",
        headers=_auth(),
    )

    assert status_resp.status_code == 200
    data = status_resp.json()
    assert data["status"] == "queued"
    assert data["task_id"] == task_id
    assert data["engagement_id"] == engagement_id


def test_run_status_cross_tenant_returns_404() -> None:
    """C1.2: cross-tenant GET /run-status → 404."""
    client = TestClient(app)

    # Create engagement as tenant-a
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth("tenant-a"),
    )
    engagement_id = create_resp.json()["engagement_id"]

    # Try to query status as tenant-b
    status_resp = client.get(
        f"/engagements/{engagement_id}/run-status",
        headers=_auth("tenant-b"),
    )

    assert status_resp.status_code == 404


def test_run_status_without_token_returns_401() -> None:
    """C1.2: no token → 401."""
    client = TestClient(app)

    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    engagement_id = create_resp.json()["engagement_id"]

    status_resp = client.get(f"/engagements/{engagement_id}/run-status")
    assert status_resp.status_code == 401


def test_idempotent_dispatch_returns_existing_task_id() -> None:
    """C1.3: two POST /run for same engagement → .delay called once, second returns existing task_id."""
    client = TestClient(app)

    # Create an engagement
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    engagement_id = create_resp.json()["engagement_id"]

    # Mock .delay
    mock_task = MagicMock()
    mock_task.id = "test-task-id-123"
    mock_task.delay.return_value = mock_task

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        # First POST /run
        first_resp = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )
        assert first_resp.status_code == 202
        first_task_id = first_resp.json()["task_id"]

        # Second POST /run (idempotent)
        second_resp = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )
        assert second_resp.status_code == 200
        second_task_id = second_resp.json()["task_id"]

    # .delay should be called exactly once
    mock_task.delay.assert_called_once()

    # Second response should return the same task_id
    assert second_task_id == first_task_id


def test_re_runnable_after_completion() -> None:
    """C1.3: once status is done/failed/refused, new POST /run is accepted."""
    client = TestClient(app)

    # Create an engagement
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    engagement_id = create_resp.json()["engagement_id"]

    # Mock .delay
    mock_task = MagicMock()
    mock_task.id = "test-task-id-123"
    mock_task.delay.return_value = mock_task

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        # First dispatch
        first_resp = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )
        assert first_resp.status_code == 202

    # Simulate completion by emitting COMPLETED event (via direct store access)
    from agent_alpha.conductor import main as conductor_main
    from agent_alpha.events.event_types import EventType

    store = conductor_main.store_provider.for_tenant("test-tenant")
    store.append(
        event_type=EventType.ENGAGEMENT_RUN_STARTED,
        engagement_id=engagement_id,
        agent="WORKER",
        payload={},
    )
    store.append(
        event_type=EventType.ENGAGEMENT_RUN_COMPLETED,
        engagement_id=engagement_id,
        agent="WORKER",
        payload={},
    )

    # New dispatch should be accepted after completion
    mock_task.id = "test-task-id-456"
    mock_task.delay.reset_mock()

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        second_resp = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )
        assert second_resp.status_code == 202
        # Should get a new task_id
        assert second_resp.json()["task_id"] == "test-task-id-456"


def test_failed_run_is_re_runnable() -> None:
    """C1.3 interplay: after status "failed", new POST /run is accepted."""
    client = TestClient(app)

    # Create an engagement
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    engagement_id = create_resp.json()["engagement_id"]

    # Mock .delay
    mock_task = MagicMock()
    mock_task.id = "test-task-id-123"
    mock_task.delay.return_value = mock_task

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        # First dispatch
        first_resp = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )
        assert first_resp.status_code == 202

    # Simulate failure by emitting FAILED event (via direct store access)
    from agent_alpha.conductor import main as conductor_main
    from agent_alpha.events.event_types import EventType

    store = conductor_main.store_provider.for_tenant("test-tenant")
    store.append(
        event_type=EventType.ENGAGEMENT_RUN_STARTED,
        engagement_id=engagement_id,
        agent="WORKER",
        payload={},
    )
    store.append(
        event_type=EventType.ENGAGEMENT_RUN_FAILED,
        engagement_id=engagement_id,
        agent="WORKER",
        payload={"reason": "simulated failure"},
    )

    # New dispatch should be accepted after failure
    mock_task.id = "test-task-id-456"
    mock_task.delay.reset_mock()

    with patch("agent_alpha.conductor.main.run_engagement_task.delay", mock_task.delay):
        second_resp = client.post(
            f"/engagements/{engagement_id}/run",
            headers=_auth(),
        )
        assert second_resp.status_code == 202
        # Should get a new task_id
        assert second_resp.json()["task_id"] == "test-task-id-456"
