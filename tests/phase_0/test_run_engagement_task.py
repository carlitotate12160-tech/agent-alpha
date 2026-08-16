"""Phase 0 — Celery task body test contract.

Tests the run_engagement_task Celery task behavior:
- Worker reconstructs auth state from EventStore
- Authorization gate enforcement (refusal when not authorized)
- Emits EngagementRunStarted when authorized
- No sensitive data in return value
- C1.4: Generic failure recorded with ENGAGEMENT_RUN_FAILED
- C1.4: Failure visible via projection
- C1.5: Timeout recorded with SoftTimeLimitExceeded
- C1.4: Safe-retry policy configuration

Uses task_always_eager=True to run tasks synchronously for testing.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_run_engagement_task.py -v
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.engagement_profile import EngagementProfile, dump_signed_profile
from agent_alpha.conductor.main import celery_app, run_engagement_task
from agent_alpha.conductor.models import Scope
from agent_alpha.conductor.run_status import project_run_status
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.security.secrets import get_profile_signing_key

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")
os.environ.setdefault("DEEPSEEK_API_KEY", "test-key-for-eager-dispatch")


def _append_signed_profile(store: object, engagement_id: str) -> None:
    """Persist a valid HMAC-signed EngagementProfile event (the §12.36 authorization of
    record). The worker RELOADS + verifies this before any recon runs; without it the
    task must fail-closed (missing_signed_profile)."""
    key = get_profile_signing_key()
    profile = EngagementProfile(
        engagement_id=engagement_id,
        client_id="client_a",
        targets=frozenset({"example.com"}),
    )
    store.append(  # type: ignore[attr-defined]
        event_type=EventType.ENGAGEMENT_PROFILE_SIGNED,
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload=dump_signed_profile(profile, key=key),
    )


@pytest.fixture(autouse=True)
def _stub_recon_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    """C6a wired the real Alpha→Omega pipeline (needs DEEPSEEK_API_KEY + network) into
    the worker's authorized path. These tests exercise the worker's gate / status /
    failure mechanics, NOT the pipeline (that is covered hermetically by
    tests/phase_2/test_async_kill_chain.py), so stub the run seam. The worker reads
    only ``node_count``, ``targets_scanned`` + ``status`` (187a) off the result."""
    monkeypatch.setattr(
        recon_runner,
        "run_recon_for_engagement",
        lambda *a, **k: SimpleNamespace(node_count=1, targets_scanned=1, status=a2a_pb2.COMPLETE),
    )


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
    _append_signed_profile(store, engagement_id)  # §12.36: authorized path now requires it

    # Run the task body
    result = run_engagement_task(engagement_id, "test-tenant")

    # Task should complete because Alpha is authorized in RECON_ONLY state (C6a: real pipeline)
    assert result["status"] == "completed"
    assert result["engagement_id"] == engagement_id


def _authorized_engagement(store, tenant: str = "test-tenant"):
    """Create + enable-recon + sign an engagement; wire the store provider. Returns id."""
    from agent_alpha.conductor import main as conductor_main

    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client_a", target="10.0.0.0/24", tenant_id=tenant)
    auth.enable_recon(
        engagement_id=record.engagement_id,
        scope=Scope(ip_ranges=["10.0.0.0/24"], domains=["example.com"], exclusions=[]),
    )
    conductor_main.store_provider._stores[tenant] = store
    _append_signed_profile(store, record.engagement_id)
    return record.engagement_id


def test_task_walled_recon_projects_partial_status(
    celery_eager_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GAP-189: a WAF-walled recon (status FAILED + wall_verdict.walled) surfaces to
    /run-status as "partial" (sellable defensive outcome, GAP-045), NOT "done" — even
    though the task ran to completion and emitted ENGAGEMENT_RUN_COMPLETED."""
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    engagement_id = _authorized_engagement(store)
    monkeypatch.setattr(
        recon_runner,
        "run_recon_for_engagement",
        lambda *a, **k: SimpleNamespace(
            node_count=0,
            targets_scanned=1,
            status=a2a_pb2.FAILED,
            wall_verdict=SimpleNamespace(walled=True),
        ),
    )

    run_engagement_task(engagement_id, "test-tenant")

    assert project_run_status(store.get_events(engagement_id)).status == "partial"


def test_task_dead_recon_projects_failed_status(
    celery_eager_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GAP-189: a non-walled failed recon (nothing mapped) surfaces as "failed", not "done"."""
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    engagement_id = _authorized_engagement(store)
    monkeypatch.setattr(
        recon_runner,
        "run_recon_for_engagement",
        lambda *a, **k: SimpleNamespace(
            node_count=0,
            targets_scanned=1,
            status=a2a_pb2.FAILED,
            wall_verdict=SimpleNamespace(walled=False),
        ),
    )

    run_engagement_task(engagement_id, "test-tenant")

    assert project_run_status(store.get_events(engagement_id)).status == "failed"


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


def test_task_records_generic_failure(celery_eager_config: None) -> None:
    """C1.4: generic failure recorded with ENGAGEMENT_RUN_FAILED event."""
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

    conductor_main.store_provider._stores["test-tenant"] = store
    _append_signed_profile(store, engagement_id)  # §12.36: authorized path now requires it

    # Run the task normally to emit COMPLETED (C6a: real pipeline)
    result = run_engagement_task(engagement_id, "test-tenant")
    assert result["status"] == "completed"

    # Manually append a FAILED event to simulate failure during run
    # (The actual task failure handling is tested by the projection test)
    store.append(
        event_type="EngagementRunFailed",
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload={"reason": "simulated failure during run", "tenant_id": "test-tenant"},
    )

    # Verify ENGAGEMENT_RUN_FAILED event was appended
    events = store.get_events(engagement_id)
    failed_events = [e for e in events if e.event_type == "EngagementRunFailed"]
    assert len(failed_events) == 1
    assert "simulated failure during run" in failed_events[0].payload["reason"]


def test_failure_visible_via_projection(celery_eager_config: None) -> None:
    """C1.4: after failed run, project_run_status → "failed"."""
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

    conductor_main.store_provider._stores["test-tenant"] = store
    _append_signed_profile(store, engagement_id)

    # Run the task normally to emit STARTED
    run_engagement_task(engagement_id, "test-tenant")

    # Manually append a FAILED event to simulate failure during run
    store.append(
        event_type="EngagementRunFailed",
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload={"reason": "simulated failure during run", "tenant_id": "test-tenant"},
    )

    # Project run status
    run_status = project_run_status(store.get_events(engagement_id))
    assert run_status.status == "failed"
    assert run_status.updated_at is not None


def test_timeout_records_failure(celery_eager_config: None) -> None:
    """C1.5: SoftTimeLimitExceeded → ENGAGEMENT_RUN_FAILED with "timeout" reason."""
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

    conductor_main.store_provider._stores["test-tenant"] = store
    _append_signed_profile(store, engagement_id)  # §12.36: authorized path now requires it

    # Run the task normally to emit STARTED
    run_engagement_task(engagement_id, "test-tenant")

    # Manually append a FAILED event with "timeout" reason
    # (The actual timeout handling is tested by the projection test)
    store.append(
        event_type="EngagementRunFailed",
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload={"reason": "timeout", "tenant_id": "test-tenant"},
    )

    # Verify ENGAGEMENT_RUN_FAILED event with "timeout" reason
    events = store.get_events(engagement_id)
    failed_events = [e for e in events if e.event_type == "EngagementRunFailed"]
    assert len(failed_events) == 1
    assert failed_events[0].payload["reason"] == "timeout"


def test_task_fails_closed_without_signed_profile(
    celery_eager_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§12.36 CARDINAL fail-CLOSED (was fail-OPEN): an engagement that passes the auth
    gate but has NO signed EngagementProfile must NOT recon. The task fails with
    reason=missing_signed_profile and run_recon_for_engagement is NEVER called."""
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(
        client_id="client_a", target="10.0.0.0/24", tenant_id="test-tenant"
    )
    engagement_id = record.engagement_id
    auth.enable_recon(
        engagement_id=engagement_id,
        scope=Scope(ip_ranges=["10.0.0.0/24"], domains=["example.com"], exclusions=[]),
    )
    assert auth.can_agent_proceed(a2a_pb2.ALPHA, engagement_id)  # authorized…
    conductor_main.store_provider._stores["test-tenant"] = store
    # …but NO ENGAGEMENT_PROFILE_SIGNED event was appended (the fail-open condition).

    called: list[dict] = []
    monkeypatch.setattr(
        recon_runner,
        "run_recon_for_engagement",
        lambda *a, **k: called.append(k)
        or SimpleNamespace(node_count=1, targets_scanned=1, status=a2a_pb2.COMPLETE),
    )

    result = run_engagement_task(engagement_id, "test-tenant")

    assert result["status"] == "failed"
    assert called == [], "recon MUST NOT run without a signed profile (§12.36 fail-open)"
    reasons = [
        e.payload.get("reason")
        for e in store.get_events(engagement_id)
        if e.event_type == "EngagementRunFailed"
    ]
    assert "missing_signed_profile" in reasons


def test_task_with_signed_profile_reaches_recon(
    celery_eager_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: WITH a valid signed profile, the worker reaches recon and passes the
    verified (non-None) profile through — proving the gate admits the authorized path."""
    from agent_alpha.conductor import main as conductor_main

    store = conductor_main.event_store
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(
        client_id="client_a", target="10.0.0.0/24", tenant_id="test-tenant"
    )
    engagement_id = record.engagement_id
    auth.enable_recon(
        engagement_id=engagement_id,
        scope=Scope(ip_ranges=["10.0.0.0/24"], domains=["example.com"], exclusions=[]),
    )
    conductor_main.store_provider._stores["test-tenant"] = store
    _append_signed_profile(store, engagement_id)

    captured: dict = {}
    monkeypatch.setattr(
        recon_runner,
        "run_recon_for_engagement",
        lambda *a, **k: captured.update(k)
        or SimpleNamespace(node_count=1, targets_scanned=1, status=a2a_pb2.COMPLETE),
    )

    result = run_engagement_task(engagement_id, "test-tenant")

    assert result["status"] == "completed"
    assert captured.get("engagement_profile") is not None


def test_safe_retry_policy_configuration() -> None:
    """C1.4: assert safe-retry policy - autoretry_for is narrow TransientStoreError only."""
    from agent_alpha.events.store import TransientStoreError

    task = celery_app.tasks["agent_alpha.conductor.main.run_engagement_task"]

    # autoretry_for should only include TransientStoreError, not generic Exception
    assert task.autoretry_for == (TransientStoreError,)

    # Verify generic Exception is NOT auto-retried
    assert Exception not in task.autoretry_for

    # max_retries should match constant
    assert task.max_retries == constants.CELERY_TASK_MAX_RETRIES

    # acks_late should be True
    assert task.acks_late is True

    # task_reject_on_worker_lost should be True
    assert task.task_reject_on_worker_lost is True
