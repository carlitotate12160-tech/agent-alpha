# agent_alpha/conductor/main.py
# Phase 0 — FastAPI + Celery skeleton wiring all Phase 0 components.
#
# ADR §8a: non-blocking, chat-while-task-runs. Celery workers run engagements
# in background. Phase 0: Celery task is a no-op placeholder (real agent logic
# Phase 2+). All Phase 0 components wired here as singletons.

import hashlib
import logging
from typing import Any

from celery import Celery
from fastapi import FastAPI, HTTPException, UploadFile

from agent_alpha.a2a import a2a_pb2
from agent_alpha.config.constants import SOW_MAX_FILE_SIZE_MB
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.emergency import EmergencyStopHandler
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.events.store import EventStore
from agent_alpha.security.secrets import LogScrubber, SecretsManager

_log = logging.getLogger(__name__)

# ── Singletons (module-level, initialized once) ─────────────────────

event_store = EventStore()
auth = AuthorizationStateMachine(event_callback=event_store.append)
policy = PolicyEnforcer()
secrets_mgr = SecretsManager()
log_scrubber = LogScrubber()
log_scrubber.install_logging_filter()
emergency = EmergencyStopHandler(auth, event_store)

celery_app = Celery(
    "agent_alpha",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
)

app = FastAPI(title="Agent-Alpha Conductor", version="0.1.0")

# ── Celery task (placeholder) ────────────────────────────────────────


@celery_app.task
def run_engagement_task(engagement_id: str) -> dict[str, Any]:
    return {"engagement_id": engagement_id, "status": "placeholder"}

# ── Endpoints ────────────────────────────────────────────────────────


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.post("/engagements")
def create_engagement(body: dict[str, str]) -> dict[str, str]:
    try:
        client_id = body["client_id"]
        target = body["target"]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="client_id and target required") from exc

    record = auth.create_engagement(client_id, target)
    return {"engagement_id": record.engagement_id, "state": a2a_pb2.EngagementState.Name(record.state)}


@app.post("/engagements/{engagement_id}/recon")
def enable_recon(engagement_id: str, body: dict[str, list[str]]) -> dict[str, str]:
    try:
        ip_ranges = body["ip_ranges"]
        domains = body["domains"]
        exclusions = body["exclusions"]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="ip_ranges, domains, and exclusions required") from exc

    scope = Scope(ip_ranges=ip_ranges, domains=domains, exclusions=exclusions)
    try:
        auth.enable_recon(engagement_id, scope)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    state = auth.get_state(engagement_id)
    return {"engagement_id": engagement_id, "state": a2a_pb2.EngagementState.Name(state)}


@app.post("/engagements/{engagement_id}/sow")
def upload_sow(engagement_id: str, file: UploadFile) -> dict[str, str]:
    max_bytes = SOW_MAX_FILE_SIZE_MB * 1024 * 1024
    content = file.file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"SOW exceeds {SOW_MAX_FILE_SIZE_MB}MB limit",
        )

    sow_hash = hashlib.sha256(content).hexdigest()
    return {"engagement_id": engagement_id, "sow_hash": sow_hash}


@app.post("/engagements/{engagement_id}/stop")
def emergency_stop(engagement_id: str, body: dict[str, str]) -> dict[str, Any]:
    try:
        reason = body["reason"]
        issued_by = body["issued_by"]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="reason and issued_by required") from exc

    result = emergency.execute(engagement_id, reason, issued_by)
    return {
        "engagement_id": result.engagement_id,
        "success": result.success,
        "tasks_revoked": result.tasks_revoked,
        "elapsed_ms": result.elapsed_ms,
        "reason": result.reason,
        "timestamp_utc": result.timestamp_utc,
    }


@app.get("/engagements/{engagement_id}/state")
def get_state(engagement_id: str) -> dict[str, Any]:
    try:
        state = auth.get_state(engagement_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    return {
        "engagement_id": engagement_id,
        "state": a2a_pb2.EngagementState.Name(state),
        "state_value": state,
    }
