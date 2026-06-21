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
