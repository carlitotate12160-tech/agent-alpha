# agent_alpha/conductor/main.py
# Phase 0 — FastAPI + Celery skeleton wiring all Phase 0 components.
#
# ADR §8a: non-blocking, chat-while-task-runs. Celery workers run engagements
# in background. Phase 0: Celery task is a no-op placeholder (real agent logic
# Phase 2+). All Phase 0 components wired here as singletons.

import hashlib
import logging
import os
from typing import Annotated, Any

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response, UploadFile

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.api_auth import Principal, require_principal
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.emergency import EmergencyStopHandler
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.conductor.run_status import project_run_status
from agent_alpha.config.constants import (
    CELERY_QUEUE_PREFIX,
    CELERY_RESULT_EXPIRES_SEC,
    CELERY_TASK_HARD_LIMIT_SEC,
    CELERY_TASK_MAX_RETRIES,
    CELERY_TASK_SOFT_LIMIT_SEC,
    SOW_MAX_FILE_SIZE_MB,
)
from agent_alpha.config.stores import StoreProvider, build_event_store
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import TransientStoreError
from agent_alpha.security.secrets import LogScrubber, SecretsManager

_log = logging.getLogger(__name__)

event_store = build_event_store()
store_provider = StoreProvider()

policy = PolicyEnforcer()
secrets_mgr = SecretsManager()
log_scrubber = LogScrubber()
log_scrubber.install_logging_filter()


# C3: single source of truth for auth-event routing. Every synchronous route AND
# the worker build their AuthorizationStateMachine through auth_for(), so an
# engagement's entire lifecycle — create, scope, SOW, run, stop — is read from and
# written to ONE store per tenant. This closes the C1.0 split-brain where the API
# wrote auth events to the default store while the worker read the tenant store
# (a functional break for real tenants, not merely an audit-isolation gap).
# tenant_id is the JWT-verified claim (API) or the propagated task arg (worker);
# None routes to the legacy single-tenant default store (no-tenant ops / tests).
def auth_for(tenant_id: str | None) -> AuthorizationStateMachine:
    store = store_provider.for_tenant(tenant_id) if tenant_id else event_store
    return AuthorizationStateMachine(event_store=store)


def emergency_for(tenant_id: str | None) -> EmergencyStopHandler:
    store = store_provider.for_tenant(tenant_id) if tenant_id else event_store
    # celery_revoker stays None until C4 wires the real revoker.
    return EmergencyStopHandler(auth_for(tenant_id), store, store_provider=store_provider)


_redis_url = os.environ.get("AGENT_ALPHA_REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery(
    "agent_alpha",
    broker=_redis_url,
    backend=_redis_url,
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_soft_time_limit=CELERY_TASK_SOFT_LIMIT_SEC,
    task_time_limit=CELERY_TASK_HARD_LIMIT_SEC,
    result_expires=CELERY_RESULT_EXPIRES_SEC,
    task_default_queue=f"{CELERY_QUEUE_PREFIX}default",
)

app = FastAPI(title="Agent-Alpha Conductor", version="0.1.0")

engagements = APIRouter(
    prefix="/engagements",
    dependencies=[Depends(require_principal)],
)

# ── Celery task (Phase 3 placeholder: gate + status only) ────────────


@celery_app.task(
    bind=True,
    acks_late=True,
    task_reject_on_worker_lost=True,
    autoretry_for=(TransientStoreError,),
    retry_backoff=True,
    max_retries=CELERY_TASK_MAX_RETRIES,
)  # type: ignore[untyped-decorator]
def run_engagement_task(self: Any, engagement_id: str, tenant_id: str | None) -> dict[str, Any]:
    """Run an engagement in a worker process, enforcing the auth gate.

    C1.6 design-now: the task is tenant-aware. The worker reconstructs the
    AuthorizationStateMachine over the correct EventStore instance and enforces
    the gate locally before any agent logic runs.

    C1.8: The return value (and thus the Celery result backend) carries only
    opaque status — never findings, creds, or payloads. Domain data flows
    through the tenant-scoped event store instead.
    """

    target_store = event_store

    def _record_failure(reason: str) -> None:
        try:
            target_store.append(
                event_type=EventType.ENGAGEMENT_RUN_FAILED,
                engagement_id=engagement_id,
                agent="CONDUCTOR",
                payload={"reason": reason, "tenant_id": tenant_id},
            )
        except Exception:  # noqa: BLE001
            _log.exception("Failed to append EngagementRunFailed event for %s", engagement_id)

    try:
        if tenant_id is not None:
            try:
                target_store = store_provider.for_tenant(tenant_id)
            except TransientStoreError:
                raise
            except Exception:  # noqa: BLE001 — fallback to default store
                _log.exception("Failed to resolve tenant store for tenant_id=%s", tenant_id)

        worker_auth = AuthorizationStateMachine(event_store=target_store)

        def _record_refusal(reason: str) -> None:
            try:
                target_store.append(
                    event_type=EventType.ENGAGEMENT_RUN_REFUSED,
                    engagement_id=engagement_id,
                    agent="CONDUCTOR",
                    payload={"reason": reason, "tenant_id": tenant_id},
                )
            except Exception:  # noqa: BLE001 — refusal audit must not crash the task
                _log.exception("Failed to append EngagementRunRefused event for %s", engagement_id)

        try:
            record = worker_auth.get_record(engagement_id)
        except TransientStoreError:
            raise
        except Exception:  # noqa: BLE001 — not found / unauthorized
            _record_refusal("not_found")
            return {"engagement_id": engagement_id, "status": "refused"}

        # Enforce tenant ownership in-worker when a tenant_id is provided.
        if tenant_id is not None and record.tenant_id is not None and record.tenant_id != tenant_id:
            _record_refusal("tenant_mismatch")
            return {"engagement_id": engagement_id, "status": "refused"}

        # Authorization gate: if no agent is allowed to proceed, refuse.
        if not worker_auth.can_agent_proceed(a2a_pb2.ALPHA, engagement_id):
            _record_refusal("not_authorized")
            return {"engagement_id": engagement_id, "status": "refused"}

    except SoftTimeLimitExceeded:
        _record_failure("timeout")
        return {"engagement_id": engagement_id, "status": "failed"}
    except TransientStoreError:
        if self.request.retries >= self.max_retries:
            _record_failure("transient_store_error_exhausted")
            return {"engagement_id": engagement_id, "status": "failed"}
        raise
    except Exception as exc:  # noqa: BLE001
        _log.exception("Unexpected exception during engagement run setup")
        _record_failure(str(exc))
        return {"engagement_id": engagement_id, "status": "failed"}

    # --- OFFENSIVE RUN (NO RETRIES) ---
    try:
        # TODO (C6): real agent run pipeline goes here once implemented.
        # For C1.x we only prove that a worker process can reconstruct auth state
        # from the shared EventStore and apply the gate.

        # Emit a "run started" audit event; name kept generic to avoid schema churn.
        try:
            target_store.append(
                event_type=EventType.ENGAGEMENT_RUN_STARTED,
                engagement_id=engagement_id,
                agent="CONDUCTOR",
                payload={"tenant_id": record.tenant_id},
            )
        except Exception:  # noqa: BLE001 — failure to audit must not crash the task
            _log.exception("Failed to append EngagementRunStarted event for %s", engagement_id)

        return {"engagement_id": engagement_id, "status": "started"}

    except SoftTimeLimitExceeded:
        _record_failure("timeout")
        return {"engagement_id": engagement_id, "status": "failed"}
    except Exception as exc:  # noqa: BLE001
        _log.exception("Unexpected exception during offensive run")
        _record_failure(str(exc))
        return {"engagement_id": engagement_id, "status": "failed"}


# ── Endpoints ────────────────────────────────────────────────────────


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@engagements.post("")
def create_engagement(
    body: dict[str, str],
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, str]:
    try:
        client_id = body["client_id"]
        target = body["target"]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="client_id and target required") from exc

    record = auth_for(principal.tenant_id).create_engagement(
        client_id, target, tenant_id=principal.tenant_id
    )
    return {
        "engagement_id": record.engagement_id,
        "state": a2a_pb2.EngagementState.Name(record.state),
    }


@engagements.post("/{engagement_id}/recon")
def enable_recon(
    engagement_id: str,
    body: dict[str, list[str]],
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, str]:
    try:
        ip_ranges = body["ip_ranges"]
        domains = body["domains"]
        exclusions = body["exclusions"]
    except KeyError as exc:
        raise HTTPException(
            status_code=400, detail="ip_ranges, domains, and exclusions required"
        ) from exc

    scope = Scope(ip_ranges=ip_ranges, domains=domains, exclusions=exclusions)
    sm = auth_for(principal.tenant_id)
    try:
        record = sm.get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    try:
        sm.enable_recon(engagement_id, scope)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    state = sm.get_state(engagement_id)
    return {"engagement_id": engagement_id, "state": a2a_pb2.EngagementState.Name(state)}


@engagements.post("/{engagement_id}/sow")
def upload_sow(
    engagement_id: str,
    file: UploadFile,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, str]:
    max_bytes = SOW_MAX_FILE_SIZE_MB * 1024 * 1024
    content = file.file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"SOW exceeds {SOW_MAX_FILE_SIZE_MB}MB limit",
        )

    try:
        record = auth_for(principal.tenant_id).get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    sow_hash = hashlib.sha256(content).hexdigest()
    return {"engagement_id": engagement_id, "sow_hash": sow_hash}


@engagements.post("/{engagement_id}/run", status_code=202)
def run_engagement(
    engagement_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    response: Response,
) -> dict[str, Any]:
    try:
        record = auth_for(principal.tenant_id).get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    target_store = (
        store_provider.for_tenant(principal.tenant_id) if principal.tenant_id else event_store
    )
    run_status = project_run_status(target_store.get_events(engagement_id))

    if run_status.status in ("queued", "running"):
        response.status_code = 200
        return {"engagement_id": engagement_id, "task_id": run_status.task_id}

    # Non-blocking dispatch: enqueue the task and return immediately.
    task = run_engagement_task.delay(engagement_id, principal.tenant_id)

    target_store.append(
        event_type=EventType.ENGAGEMENT_RUN_QUEUED,
        engagement_id=engagement_id,
        agent="API",
        payload={"task_id": task.id, "tenant_id": principal.tenant_id},
    )

    return {
        "engagement_id": engagement_id,
        "task_id": task.id,
    }


@engagements.get("/{engagement_id}/run-status")
def get_run_status(
    engagement_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    try:
        record = auth_for(principal.tenant_id).get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    target_store = (
        store_provider.for_tenant(principal.tenant_id) if principal.tenant_id else event_store
    )
    run_status = project_run_status(target_store.get_events(engagement_id))

    return {
        "engagement_id": engagement_id,
        "status": run_status.status,
        "task_id": run_status.task_id,
        "updated_at": run_status.updated_at,
    }


@engagements.post("/{engagement_id}/stop")
def emergency_stop(
    engagement_id: str,
    body: dict[str, str],
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    try:
        reason = body["reason"]
        issued_by = body["issued_by"]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="reason and issued_by required") from exc

    try:
        record = auth_for(principal.tenant_id).get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    result = emergency_for(principal.tenant_id).execute(engagement_id, reason, issued_by)
    return {
        "engagement_id": result.engagement_id,
        "success": result.success,
        "tasks_revoked": result.tasks_revoked,
        "elapsed_ms": result.elapsed_ms,
        "reason": result.reason,
        "timestamp_utc": result.timestamp_utc,
    }


@engagements.get("/{engagement_id}/state")
def get_state(
    engagement_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    try:
        record = auth_for(principal.tenant_id).get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    state = record.state

    return {
        "engagement_id": engagement_id,
        "state": a2a_pb2.EngagementState.Name(state),
        "state_value": state,
    }


app.include_router(engagements)
