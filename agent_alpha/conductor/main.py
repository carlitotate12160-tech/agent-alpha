# agent_alpha/conductor/main.py
# Phase 0 — FastAPI + Celery skeleton wiring all Phase 0 components.
#
# ADR §8a: non-blocking, chat-while-task-runs. Celery workers run engagements
# in background. Phase 0: Celery task is a no-op placeholder (real agent logic
# Phase 2+). All Phase 0 components wired here as singletons.

import hashlib
import logging
import os
import typing
from typing import Annotated, Any

from celery import Celery
from fastapi import APIRouter, Depends, FastAPI, HTTPException, UploadFile

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.api_auth import Principal, require_principal
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.emergency import EmergencyStopHandler
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.config.constants import SOW_MAX_FILE_SIZE_MB
from agent_alpha.config.stores import StoreProvider, build_event_store
from agent_alpha.security.secrets import LogScrubber, SecretsManager

_log = logging.getLogger(__name__)

# ── Singletons (module-level, initialized once) ─────────────────────

event_store = build_event_store()
store_provider = StoreProvider()


def _event_callback(event_type: str, payload: dict[str, Any]) -> None:
    """Append events to the appropriate tenant store.

    For legacy callers/tests where no tenant_id is present on the payload,
    events are written to the legacy single-tenant ``event_store``.
    """

    engagement_id = typing.cast(str, payload["engagement_id"])
    tenant_id = typing.cast(str | None, payload.get("tenant_id"))
    if tenant_id:
        store = store_provider.for_tenant(tenant_id)
    else:
        store = event_store

    store.append(
        event_type=event_type,
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload=payload,
    )


auth = AuthorizationStateMachine(event_callback=_event_callback)
policy = PolicyEnforcer()
secrets_mgr = SecretsManager()
log_scrubber = LogScrubber()
log_scrubber.install_logging_filter()
emergency = EmergencyStopHandler(auth, event_store, store_provider=store_provider)

_redis_url = os.environ.get("AGENT_ALPHA_REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery(
    "agent_alpha",
    broker=_redis_url,
    backend=_redis_url,
)

app = FastAPI(title="Agent-Alpha Conductor", version="0.1.0")

engagements = APIRouter(
    prefix="/engagements",
    dependencies=[Depends(require_principal)],
)

# ── Celery task (placeholder) ────────────────────────────────────────


@celery_app.task  # type: ignore[untyped-decorator]
def run_engagement_task(engagement_id: str) -> dict[str, Any]:
    return {"engagement_id": engagement_id, "status": "placeholder"}


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

    record = auth.create_engagement(client_id, target, tenant_id=principal.tenant_id)
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
    try:
        record = auth.get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    try:
        auth.enable_recon(engagement_id, scope)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    state = auth.get_state(engagement_id)
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
        record = auth.get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    sow_hash = hashlib.sha256(content).hexdigest()
    return {"engagement_id": engagement_id, "sow_hash": sow_hash}


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
        record = auth.get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    result = emergency.execute(engagement_id, reason, issued_by)
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
        record = auth.get_record(engagement_id)
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
