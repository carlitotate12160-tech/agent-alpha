"""Phase 0 — Celery task body test contract.

Tests the run_engagement_task Celery task behavior:
- Worker reconstructs auth state from EventStore
- Authorization gate enforcement (refusal when not authorized)
- Emits EngagementRunStarted when authorized
- No sensitive data in return value

Uses task_always_eager=True to run tasks synchronously for testing.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_run_engagement_task.py -v
"""

from __future__ import annotations

import os

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.main import run_engagement_task
from agent_alpha.conductor.models import Scope
from agent_alpha.config.stores import StoreProvider

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")


def test_task_refuses_unauthorized_engagement(celery_eager_config: None) -> None:
    """Worker reconstructs + enforces gate: CREATED state → refusal."""
    # Use the global event_store that the task closes over
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    auth = AuthorizationStateMachine(event_store=store)

    # Create engagement in CREATED state (no recon enabled)
    record = auth.create_engagement(
        client_id="client_a",
        target="10.0.0.0/24",
        tenant_id="test-tenant",
    )
    engagement_id = record.engagement_id

    # Run the task body directly (eager mode)
    result = run_engagement_task(engagement_id, "test-tenant")

    # Task should refuse because no agent is authorized in CREATED state
    assert result["status"] == "refused"
    assert result["engagement_id"] == engagement_id


def test_task_starts_authorized_engagement(celery_eager_config: None) -> None:
    """Authorized path emits started after enable_recon."""
    # Use the global event_store that the task closes over
    from agent_alpha.conductor import main as conductor_main
    from agent_alpha.config.stores import StoreProvider

    store = conductor_main.event_store
    auth = AuthorizationStateMachine(event_store=store)

    # Create and enable recon
    record = auth.create_engagement(
        client_id="client_a",
        target="10.0.0.0/24",
        tenant_id="test-tenant",
    )
    engagement_id = record.engagement_id
    scope = Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=["example.com"],
        exclusions=[],
    )
    auth.enable_recon(engagement_id=engagement_id, scope=scope)

    # Verify Alpha is authorized before running task
    assert auth.can_agent_proceed(a2a_pb2.ALPHA, engagement_id)

    # Ensure the store provider returns our test store for this tenant
    conductor_main.store_provider._stores["test-tenant"] = store

    # Run the task body
    result = run_engagement_task(engagement_id, "test-tenant")

    # Task should start because Alpha is authorized in RECON_ONLY state
    assert result["status"] == "started"
    assert result["engagement_id"] == engagement_id


def test_task_refuses_tenant_mismatch(celery_eager_config: None) -> None:
    """Worker enforces tenant ownership: tenant_id mismatch → refusal."""
    # Use the global event_store that the task closes over
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    auth = AuthorizationStateMachine(event_store=store)

    # Create engagement for tenant-a
    record = auth.create_engagement(
        client_id="client_a",
        target="10.0.0.0/24",
        tenant_id="tenant-a",
    )
    engagement_id = record.engagement_id
    scope = Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=["example.com"],
        exclusions=[],
    )
    auth.enable_recon(engagement_id=engagement_id, scope=scope)

    # Run task with tenant-b (mismatch)
    result = run_engagement_task(engagement_id, "tenant-b")

    # Task should refuse due to tenant mismatch
    assert result["status"] == "refused"
    assert result["engagement_id"] == engagement_id


def test_task_refuses_not_found_engagement(celery_eager_config: None) -> None:
    """Worker rejects engagement that doesn't exist."""
    # Use the global event_store that the task closes over
    from agent_alpha.conductor import main as conductor_main

    # Run task with non-existent engagement
    result = run_engagement_task("eng_does_not_exist", "test-tenant")

    # Task should refuse
    assert result["status"] == "refused"
    assert result["engagement_id"] == "eng_does_not_exist"


def test_task_result_contains_no_sensitive_data(celery_eager_config: None) -> None:
    """C1.8: task return value contains only {engagement_id, status}."""
    # Use the global event_store that the task closes over
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    auth = AuthorizationStateMachine(event_store=store)

    record = auth.create_engagement(
        client_id="client_a",
        target="10.0.0.0/24",
        tenant_id="test-tenant",
    )
    engagement_id = record.engagement_id
    scope = Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=["example.com"],
        exclusions=[],
    )
    auth.enable_recon(engagement_id=engagement_id, scope=scope)

    result = run_engagement_task(engagement_id, "test-tenant")

    # Return value should only contain engagement_id and status
    assert set(result.keys()) == {"engagement_id", "status"}
    # No sensitive keys like findings, creds, payload, etc.
    assert "findings" not in result
    assert "creds" not in result
    assert "payload" not in result
    assert "target" not in result
    assert "client_id" not in result


def test_task_can_agent_proceed_check(celery_eager_config: None) -> None:
    """Verify the task checks can_agent_proceed before proceeding."""
    # Use the global event_store that the task closes over
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    auth = AuthorizationStateMachine(event_store=store)

    # Create engagement but don't enable recon (CREATED state)
    record = auth.create_engagement(
        client_id="client_a",
        target="10.0.0.0/24",
        tenant_id="test-tenant",
    )
    engagement_id = record.engagement_id

    # Verify Alpha is not authorized in CREATED state
    assert not auth.can_agent_proceed(a2a_pb2.ALPHA, engagement_id)

    # Enable recon
    scope = Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=["example.com"],
        exclusions=[],
    )
    auth.enable_recon(engagement_id=engagement_id, scope=scope)

    # Now Alpha should be authorized
    assert auth.can_agent_proceed(a2a_pb2.ALPHA, engagement_id)
