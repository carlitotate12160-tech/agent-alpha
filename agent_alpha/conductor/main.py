# agent_alpha/conductor/main.py
# Phase 0 — FastAPI + Celery skeleton wiring all Phase 0 components.
#
# ADR §8a: non-blocking, chat-while-task-runs. Celery workers run engagements
# in background. Phase 0: Celery task is a no-op placeholder (real agent logic
# Phase 2+). All Phase 0 components wired here as singletons.

import hashlib
import logging
import os
import pathlib
import secrets as stdlib_secrets
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Annotated, Any
from urllib.parse import urlparse

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response, UploadFile
from pydantic import BaseModel, ConfigDict, model_validator

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor import recon_runner, routes_monologue
from agent_alpha.conductor.advance import Dispatcher, advance_engagement
from agent_alpha.conductor.api_auth import Principal, require_principal, valid_engagement_id
from agent_alpha.conductor.applicator_factory import (
    beta_web_applicators,
    build_applicators_for_engagement,
)
from agent_alpha.conductor.authorization import (
    AuthorizationStateMachine,
    ConsentRequiredError,
    Scope,
    authorize_engagement,
)
from agent_alpha.conductor.domain_verification import DnspythonResolver, DomainOwnershipError
from agent_alpha.conductor.emergency import EmergencyStopHandler
from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    GuardrailError,
    ProfileSignatureError,
    assert_not_guardrailed,
    dump_signed_profile,
    load_signed_profile_from_dict,
)
from agent_alpha.conductor.execute_agent import (
    ExecOutcome,
    emit_handoff_and_advance,
    execute_agent,
    rebuild_graph_from_events,
)
from agent_alpha.conductor.health import RedisCeleryProbe, build_queue_health
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.conductor.reporting import build_engagement_report
from agent_alpha.conductor.revoker import CeleryTaskRevoker
from agent_alpha.conductor.router import select_strike_entry
from agent_alpha.conductor.run_status import project_run_status
from agent_alpha.conductor.verification import verify_access_nodes
from agent_alpha.config.constants import (
    CELERY_QUEUE_PREFIX,
    CELERY_RESULT_EXPIRES_SEC,
    CELERY_TASK_HARD_LIMIT_SEC,
    CELERY_TASK_MAX_RETRIES,
    CELERY_TASK_SOFT_LIMIT_SEC,
    MAX_STRIKE_CANDIDATES,
    SOW_MAX_FILE_SIZE_MB,
)
from agent_alpha.config.stores import SecretsVaultProvider, StoreProvider, build_event_store
from agent_alpha.events.event_types import EventType
from agent_alpha.events.reachability import unreachable_hosts
from agent_alpha.events.store import TransientStoreError
from agent_alpha.events.trace import project_engagement_trace
from agent_alpha.live_fire.browser_solve import DeepSeekBrowserSolve
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.llm.routing import resolve_reasoning_provider
from agent_alpha.memory.session import InMemorySessionStore, RedisSessionStore, SessionRecord
from agent_alpha.recon.origin_discovery import (
    CompositeOriginDiscovery,
    OriginDiscovery,
    StaticOriginDiscovery,
)
from agent_alpha.recon.origin_resolver import LiveOriginDiscovery
from agent_alpha.security.secrets import (
    LogScrubber,
    SecretsManager,
    SecretsVault,
    get_profile_signing_key,
)
from agent_alpha.tools.internal.access.cred_lockout import CredentialLockoutGovernor
from agent_alpha.tools.playbook import PlaybookEngine

_log = logging.getLogger(__name__)


event_store = build_event_store()
store_provider = StoreProvider()

policy = PolicyEnforcer()
secrets_mgr = SecretsManager()  # module default for the no-tenant path (in-memory, no key)
secrets_provider = SecretsVaultProvider()  # per-tenant, lazy — mirrors store_provider
log_scrubber = LogScrubber()
log_scrubber.install_logging_filter()

_in_memory_session_store = InMemorySessionStore()


def session_store_for(tenant_id: str | None) -> Any:
    if tenant_id and os.environ.get("AGENT_ALPHA_PG_DSN"):
        return RedisSessionStore(_redis_url, tenant_id)
    return _in_memory_session_store


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
    # C4: the real revoker reads this tenant's store for all queued task_ids and
    # broadcasts a Celery revoke for each. The auth-state flip (handler, synchronous)
    # remains the authoritative "no agent proceeds" guarantee; revoke is best-effort.
    revoker = CeleryTaskRevoker(celery_app.control, store)
    return EmergencyStopHandler(
        auth_for(tenant_id), store, celery_revoker=revoker, store_provider=store_provider
    )


def _normalise_domain(d: str) -> str:
    return d.strip().lower().rstrip(".")


class OwnershipChallengeBody(BaseModel):
    domain: str


class AuthorizeBody(BaseModel):
    domains: list[str]
    consent_items: list[str] = []
    signed_by: str = ""
    signed_at: str = ""
    authorization_level: str = "RECON_ONLY"
    allow_evasion: bool = False
    allow_origin_discovery: bool = False
    allow_subdomain_enum: bool = False
    opsec_stealth: bool = False
    authorized_origins: list[str] | None = None  # manual override (dev/cooperative)
    verification_mode: str = (
        "cooperative"  # "cooperative" (default, SOW-based) | "dns_txt" (strict)
    )


class EnableReconBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def reject_stale_body(cls, data: Any) -> Any:
        if isinstance(data, dict) and data:
            raise ValueError(
                "scope is derived from the signed profile; do not send ip_ranges/domains/exclusions"
            )
        return data


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

# ── Celery task: auth gate + status, then runs the real Alpha→Omega recon ──
# pipeline in-worker (recon_runner.run_recon_for_engagement). Non-blocking.


def _ensure_session(
    engagement_id: str, tenant_id: str | None, phase: str = "recon", agent: str = "alpha"
) -> Any:
    """Create a SessionRecord if one does not yet exist for this engagement."""
    store = session_store_for(tenant_id)
    if not store.exists(engagement_id):
        store.set(
            SessionRecord(
                engagement_id=engagement_id,
                target_scope={},
                active_agent=agent,
                current_phase=phase,
                current_phase_iteration=0,
                authorization={},
                scratchpad={},
                ttl_seconds=86400,
            )
        )
    return store


def _record_run_failure(
    target_store: Any,
    engagement_id: str,
    tenant_id: str | None,
    reason: str,
    *,
    agent_role: int | None = None,
) -> None:
    """Append an ENGAGEMENT_RUN_FAILED audit event. Never crashes the caller."""
    payload: dict[str, Any] = {"reason": reason, "tenant_id": tenant_id}
    if agent_role is not None:
        payload["agent_role"] = agent_role
    try:
        target_store.append(
            event_type=EventType.ENGAGEMENT_RUN_FAILED,
            engagement_id=engagement_id,
            agent="CONDUCTOR",
            payload=payload,
        )
    except Exception:  # noqa: BLE001 — failure audit must not crash the task
        _log.exception("Failed to append ENGAGEMENT_RUN_FAILED for %s", engagement_id)


def _load_task_profile(
    target_store: Any, engagement_id: str
) -> tuple[EngagementProfile | None, str | None]:
    """Load + HMAC-verify the signed EngagementProfile for an engagement.

    Returns ``(profile, None)`` on success, or ``(None, reason)`` where reason is one of
    ``missing_signed_profile`` / ``profile_signature_invalid`` / ``profile_load_error``.
    Callers decide the gate (Alpha: always required; Beta: required for the offensive run).
    ``TransientStoreError`` propagates — a transient store failure is not a missing profile.
    """
    try:
        signing_key = get_profile_signing_key()
        events = target_store.get_events(engagement_id)
        envelope = next(
            (e for e in reversed(events) if e.event_type == EventType.ENGAGEMENT_PROFILE_SIGNED),
            None,
        )
        if not envelope or not envelope.payload:
            return None, "missing_signed_profile"
        return load_signed_profile_from_dict(envelope.payload, key=signing_key), None
    except ProfileSignatureError:
        return None, "profile_signature_invalid"
    except TransientStoreError:
        raise
    except Exception:  # noqa: BLE001 — any other load failure = no verified profile
        _log.exception("Failed to load signed EngagementProfile for %s", engagement_id)
        return None, "profile_load_error"


@celery_app.task(
    bind=True,
    acks_late=True,
    task_reject_on_worker_lost=True,
    autoretry_for=(TransientStoreError,),
    retry_backoff=True,
    max_retries=CELERY_TASK_MAX_RETRIES,
)  # type: ignore[untyped-decorator]
def run_engagement_task(self: Any, engagement_id: str, tenant_id: str | None) -> dict[str, Any]:  # noqa: C901
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

        session_store = _ensure_session(engagement_id, tenant_id)

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
        # Emit a "run started" audit event.
        try:
            target_store.append(
                event_type=EventType.ENGAGEMENT_RUN_STARTED,
                engagement_id=engagement_id,
                agent="CONDUCTOR",
                payload={"tenant_id": record.tenant_id},
            )
        except Exception:  # noqa: BLE001 — failure to audit must not crash the task
            _log.exception("Failed to append EngagementRunStarted event for %s", engagement_id)

        # C6a (Shape B): run the real Alpha→Omega recon pipeline for this engagement.
        # Heavy deps are built inside the seam (json-only Celery args, C1.7). Per-unit
        # fan-out execution + live-fire FP gate are C6b.
        task_secrets: SecretsVault = secrets_mgr
        if tenant_id is not None:
            try:
                task_secrets = secrets_provider.for_tenant(tenant_id)
            except Exception:  # noqa: BLE001 — vault failure must not crash the task
                _log.exception("Failed to resolve tenant vault for tenant_id=%s", tenant_id)

        # §12.36 CARDINAL wiring: load the signed EngagementProfile from the
        # ENGAGEMENT_PROFILE_SIGNED event and verify its HMAC. The profile is
        # the SINGLE source of scope + capability authorization for the recon
        # pipeline. If no profile is found or HMAC fails → fail the task loudly
        # (never recon with an unverified or missing profile).
        try:
            signing_key = get_profile_signing_key()
        except Exception as exc:
            raise ValueError(f"signing key unavailable: {exc}") from exc

        engagement_profile: EngagementProfile | None = None
        try:
            events = target_store.get_events(engagement_id)
            profile_envelope = next(
                (
                    e
                    for e in reversed(events)
                    if e.event_type == EventType.ENGAGEMENT_PROFILE_SIGNED
                ),
                None,
            )
            # §12.36 fail-CLOSED (anti-downgrade): a missing signed profile is NOT
            # recon-able — the profile is the SINGLE source of scope + capability
            # authorization. NEVER null-and-continue (that was a fail-OPEN: recon would
            # proceed on record-derived scope without the signed authorization of record).
            if not profile_envelope or not profile_envelope.payload:
                _record_failure("missing_signed_profile")
                return {"engagement_id": engagement_id, "status": "failed"}
            # Load and verify the signature using the single source of truth key.
            engagement_profile = load_signed_profile_from_dict(
                profile_envelope.payload, key=signing_key
            )
        except ProfileSignatureError as exc:
            # Invalid HMAC → fail loud (anti-downgrade); never recon on an unverified profile.
            _log.warning("Signed EngagementProfile HMAC invalid for %s: %s", engagement_id, exc)
            _record_failure("profile_signature_invalid")
            return {"engagement_id": engagement_id, "status": "failed"}
        except TransientStoreError:
            raise  # offensive-run is no-retry; the outer handler records + fails
        except Exception:  # noqa: BLE001 — any other load failure = no valid authz = fail-closed
            _log.exception("Failed to load signed EngagementProfile for %s", engagement_id)
            _record_failure("profile_load_error")
            return {"engagement_id": engagement_id, "status": "failed"}
        # engagement_profile is GUARANTEED non-None past this point (fail-closed above).

        # Build origin_discovery from authorized_origins in the signed profile.
        # This wires origin-direct reach: when a probe hits WAF/CF, Alpha can
        # bypass to the origin IP (authorized in the profile).
        task_origin_discovery: OriginDiscovery | None = None
        if engagement_profile is not None:
            profile_origins = getattr(engagement_profile, "authorized_origins", None)
            if profile_origins:
                # Cooperative path: client pre-signed origin IPs (StaticOriginDiscovery).
                task_origin_discovery = StaticOriginDiscovery(list(profile_origins))
            elif getattr(engagement_profile, "allow_origin_discovery", False):
                # §12.46 Slice B external-vantage path: no pre-signed IPs but the
                # signed profile consented to origin discovery → real CT/DNS
                # resolution. Consent-gated here; candidates() only ACTS inside
                # resolve_and_bind_origin (re-checks the capability) + the binding
                # proof + composed gate. Fail-closed if nothing binds.
                task_origin_discovery = LiveOriginDiscovery(engagement_id, worker_auth)

        # GAP-017 consumer: union OTX origin_ip_candidates (event-sourced, §12.48
        # slice-5) into the binding candidate list. Only when origin discovery is
        # already consented (task_origin_discovery is not None) — OTX IPs must NOT
        # be probed without the origin-discovery capability. Each is still PROVEN by
        # verify_origin_binding (candidate ≠ authorization).
        if task_origin_discovery is not None:
            task_origin_discovery = CompositeOriginDiscovery(
                task_origin_discovery, target_store, engagement_id
            )

        # ── §12.41: wire browser_solve when the signed profile consents to evasion ──
        task_browser_solve = None
        task_browser_solve_viable = False
        if engagement_profile is not None and getattr(engagement_profile, "allow_evasion", False):
            task_browser_solve = DeepSeekBrowserSolve.from_env()
            task_browser_solve_viable = task_browser_solve is not None

        # §12.48 slice-5: OTX source injected only when a key is configured
        # (build_otx_client returns None otherwise → OTX enrichment skipped).
        task_otx = recon_runner.build_otx_client(engagement_id)
        # §12.48 slice-2 (VT): VirusTotal source injected only when a key is
        # configured (build_virustotal_client returns None otherwise → VT
        # enrichment skipped). VT finds origin IPs + grey-cloud subdomains that
        # crt.sh/OTX miss.
        task_vt = recon_runner.build_virustotal_client(engagement_id)

        run_result = recon_runner.run_recon_for_engagement(
            engagement_id,
            tenant_id,
            worker_auth,
            target_store,
            record,
            secrets_manager=task_secrets,
            session_store=session_store,
            policy=policy,
            engagement_profile=engagement_profile,
            origin_discovery=task_origin_discovery,
            browser_solve=task_browser_solve,
            browser_solve_viable=task_browser_solve_viable,
            otx_client=task_otx,
            vt_client=task_vt,
        )

        # C1.8: only OPAQUE metadata leaves to the event store — never the report
        # narrative (it can carry a leaked secret) and never the Celery result backend.
        try:
            target_store.append(
                event_type=EventType.ENGAGEMENT_RUN_COMPLETED,
                engagement_id=engagement_id,
                agent="CONDUCTOR",
                payload={
                    "tenant_id": record.tenant_id,
                    "node_count": run_result.node_count,
                    "targets_scanned": run_result.targets_scanned,
                    "report_generated": True,
                },
            )
        except Exception:  # noqa: BLE001 — failure to audit must not crash the task
            _log.exception("Failed to append EngagementRunCompleted event for %s", engagement_id)

        # Emit handoff + advance — NOT swallowed (#4/#15)
        emit_handoff_and_advance(
            event_store=target_store,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            from_agent=a2a_pb2.ALPHA,
            status=a2a_pb2.COMPLETE,
            next_recommended=a2a_pb2.CONDUCTOR,
            advance_fn=lambda eid, tid: advance_engagement_task.delay(eid, tid),
        )

        return {"engagement_id": engagement_id, "status": "completed"}

    except SoftTimeLimitExceeded:
        _record_failure("timeout")
        return {"engagement_id": engagement_id, "status": "failed"}
    except Exception as exc:  # noqa: BLE001
        _log.exception("Unexpected exception during offensive run")
        _record_failure(str(exc))
        return {"engagement_id": engagement_id, "status": "failed"}


class CeleryDispatcher(Dispatcher):
    def __init__(self, tenant_id: str | None) -> None:
        self.tenant_id = tenant_id

    def dispatch(self, *, engagement_id: str, agent: int) -> None:
        run_agent_task.delay(engagement_id, self.tenant_id, agent)


@celery_app.task(
    bind=True,
    acks_late=True,
    task_reject_on_worker_lost=True,
    autoretry_for=(TransientStoreError,),
    retry_backoff=True,
    max_retries=CELERY_TASK_MAX_RETRIES,
)  # type: ignore[untyped-decorator]
def advance_engagement_task(self: Any, engagement_id: str, tenant_id: str | None) -> dict[str, Any]:
    try:
        target_store = store_provider.for_tenant(tenant_id) if tenant_id else event_store
        auth = AuthorizationStateMachine(event_store=target_store)
        dispatcher = CeleryDispatcher(tenant_id=tenant_id)
        decision = advance_engagement(
            engagement_id=engagement_id,
            auth=auth,
            event_store=target_store,
            dispatcher=dispatcher,
        )
        return {
            "engagement_id": engagement_id,
            "action": decision.action,
            "next_agent": decision.next_agent,
            "reason": decision.reason,
        }
    except Exception:
        _log.exception("Failed to advance engagement %s", engagement_id)
        raise


@celery_app.task(
    bind=True,
    acks_late=True,
    task_reject_on_worker_lost=True,
    autoretry_for=(TransientStoreError,),
    retry_backoff=True,
    max_retries=CELERY_TASK_MAX_RETRIES,
)  # type: ignore[untyped-decorator]
def run_agent_task(
    self: Any, engagement_id: str, tenant_id: str | None, agent_role: int
) -> dict[str, Any]:
    try:
        target_store = store_provider.for_tenant(tenant_id) if tenant_id else event_store
        auth = AuthorizationStateMachine(event_store=target_store)
        record = auth.get_record(engagement_id)

        session_store = _ensure_session(engagement_id, tenant_id, phase="execution", agent="agent")

        task_secrets: SecretsVault = secrets_mgr
        if tenant_id is not None:
            task_secrets = secrets_provider.for_tenant(tenant_id)

        playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
        http_client = HttpClient(engagement_id=engagement_id)
        provider = resolve_reasoning_provider(api_key=os.environ["DEEPSEEK_API_KEY"])
        orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(playbook_dir), provider)

        # Load + verify the signed EngagementProfile (ENGAGEMENT_PROFILE_SIGNED event).
        # For Beta it enables §12.46 origin-direct routing; the fail-CLOSED gate below
        # enforces §12.36 for the offensive run.
        _task_profile, _profile_error = _load_task_profile(target_store, engagement_id)

        # §12.36 fail-CLOSED for the OFFENSIVE Beta run: initial access must NOT proceed
        # without a verified signed profile (the authorization of record) — initial access
        # is MORE invasive than recon, so this mirrors run_engagement_task (Alpha).
        # Beta's authz/scope gates are enforced independently, but §12.36 mandates the
        # signed authorization for ANY offensive run (defence-in-depth + consistency).
        # Omega (reporting) does NOT attack and does NOT use the profile → stays fail-open.
        # (Gamma joins this gate when it is built; it is STOP-gated today.)
        if agent_role == a2a_pb2.BETA and _task_profile is None:
            _record_run_failure(
                target_store,
                engagement_id,
                tenant_id,
                _profile_error or "missing_signed_profile",
                agent_role=agent_role,
            )
            return {"engagement_id": engagement_id, "status": "failed"}

        def agent_factory(
            graph_store: Any, session_store: Any = None, _profile: Any = _task_profile
        ) -> Callable[[], ExecOutcome]:
            if agent_role == a2a_pb2.BETA:
                # §12.46 Slice 2: wrap HttpClient with OriginAwareHttpClient so Beta's
                # offensive POSTs (login, XML-RPC) go origin-direct when a proven-bound
                # origin exists — bypassing CF WAF. Fail-closed: fronted host with no
                # binding + allow_origin_discovery → refuse (don't burn technique at edge).
                # Alpha recon does NOT use this wrapper (it has origin_direct_fetch).
                beta_http: Any = http_client
                if _profile is not None:
                    from agent_alpha.agents.origin_aware_client import OriginAwareHttpClient

                    beta_http = OriginAwareHttpClient(
                        http_client,
                        profile=_profile,
                        event_store=target_store,
                        engagement_id=engagement_id,
                    )
                # GAP-034: demote strike-dead hosts (HOST_ABANDONED) so the
                # bounded budget prefers reachable auth-surfaces.
                strike_entry_selection = select_strike_entry(
                    graph_store,
                    default_target=record.target,
                    unreachable_hosts=unreachable_hosts(target_store.get_events(engagement_id)),
                )
                strike_entry = strike_entry_selection.selected_entry
                # Emit observability event BEFORE building applicators + running strike
                target_store.append(
                    event_type=EventType.STRIKE_ENTRY_SELECTED,
                    engagement_id=engagement_id,
                    agent="CONDUCTOR",
                    payload={
                        "selected_entry": strike_entry,
                        "matched_label": strike_entry_selection.matched_label,
                        "fallback_to_default": strike_entry_selection.fallback_to_default,
                        "candidates_considered": strike_entry_selection.candidates_considered,
                    },
                )
                # GAP-035: strike EVERY in-scope ranked auth-surface, not just the top
                # one. The loop lives HERE at the dispatch seam — Beta's single-entry
                # run_strike contract is untouched (anti #8/#10). Fallback (no ranked
                # auth-surface) -> single default entry, back-compat.
                ranked_candidates = strike_entry_selection.ranked_entries

                def run_beta() -> ExecOutcome:
                    if ranked_candidates:
                        plan = [(c.entry_url, c.host) for c in ranked_candidates]
                    else:
                        plan = [
                            (
                                strike_entry,
                                urlparse(strike_entry).hostname or urlparse(strike_entry).netloc,
                            )
                        ]

                    # #1: ONE credential-lockout governor for the whole engagement
                    # (§12.22 D2). Shared across every candidate so the failed-login
                    # budget is engagement-wide, NOT reset per candidate.
                    engagement_lockout = CredentialLockoutGovernor()

                    # #3: MAX_STRIKE_CANDIDATES caps IN-SCOPE strikes. Router returns the
                    # full ranked list; the Conductor scope gate runs FIRST, then we stop
                    # after MAX in-scope candidates — so out-of-scope entries ranked high
                    # never consume the budget and starve in-scope surfaces.
                    complete_next: int | None = None
                    blocked_next: int | None = None
                    struck = 0
                    for entry_url, host in plan:
                        if struck >= MAX_STRIKE_CANDIDATES:
                            break
                        # Per-host authoritative in-scope gate (stays in Conductor).
                        if host and not auth.is_in_scope(engagement_id, host):
                            target_store.append(
                                event_type=EventType.STRIKE_CANDIDATE_SKIPPED,
                                engagement_id=engagement_id,
                                agent="CONDUCTOR",
                                payload={
                                    "entry": entry_url,
                                    "host": host,
                                    "reason": "out_of_scope",
                                },
                            )
                            continue
                        target_store.append(
                            event_type=EventType.STRIKE_CANDIDATE_ATTEMPTED,
                            engagement_id=engagement_id,
                            agent="CONDUCTOR",
                            payload={"entry": entry_url, "host": host},
                        )
                        # Slice-B: roster resolved PER-HOST so SpaLoginApplicator binds
                        # this host's harvested login endpoint (fail-closed if none).
                        applicator_candidates = beta_web_applicators(
                            beta_http,
                            events=target_store.get_events(engagement_id),
                            host=host,
                        )
                        applicators = build_applicators_for_engagement(
                            engagement_id=engagement_id,
                            auth=auth,
                            graph_store=graph_store,
                            web_target=entry_url,
                            candidates=applicator_candidates,
                            lockout=engagement_lockout,
                        )
                        beta = Beta(
                            authorization=auth,
                            graph_store=graph_store,
                            event_store=target_store,
                            orchestrator=orchestrator,
                            http_client=beta_http,
                            secrets_manager=task_secrets,
                            cred_applicators=applicators,
                            session_store=session_store,
                        )
                        handoff_msg = beta.run_strike(engagement_id, entry_url)
                        handoff_payload = a2a_pb2.HandoffPayload()
                        handoff_payload.ParseFromString(handoff_msg.payload)
                        struck += 1
                        if handoff_payload.status == a2a_pb2.COMPLETE:
                            verify_access_nodes(graph_store, target_store, engagement_id)
                            # First COMPLETE (highest-ranked surface) drives the chain.
                            if complete_next is None:
                                complete_next = handoff_payload.next_recommended
                        elif handoff_payload.status == a2a_pb2.BLOCKED:
                            if blocked_next is None:
                                blocked_next = handoff_payload.next_recommended

                    if struck == 0:
                        return ExecOutcome(
                            status=a2a_pb2.FAILED,
                            next_recommended=a2a_pb2.OMEGA,
                            reason="beta_no_in_scope_candidate",
                        )
                    # #2: status precedence COMPLETE > BLOCKED > FAILED. BLOCKED must
                    # survive (execute_agent suppresses advance on BLOCKED) — never
                    # collapse an all-blocked run into FAILED.
                    if complete_next is not None:
                        return ExecOutcome(
                            status=a2a_pb2.COMPLETE, next_recommended=complete_next, reason="ok"
                        )
                    if blocked_next is not None:
                        return ExecOutcome(
                            status=a2a_pb2.BLOCKED,
                            next_recommended=blocked_next,
                            reason="beta_blocked",
                        )
                    return ExecOutcome(
                        status=a2a_pb2.FAILED, next_recommended=a2a_pb2.OMEGA, reason="beta_failed"
                    )

                return run_beta
            elif agent_role == a2a_pb2.OMEGA:

                def run_omega() -> ExecOutcome:
                    build_engagement_report(
                        graph_store, target_store, engagement_id, style="technical"
                    )
                    return ExecOutcome(
                        status=a2a_pb2.COMPLETE,
                        next_recommended=a2a_pb2.CONDUCTOR,
                        reason="report_generated",
                    )

                return run_omega
            else:
                raise ValueError(f"Unknown agent role: {agent_role}")

        execute_agent(
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            agent_role=agent_role,
            auth=auth,
            event_store=target_store,
            graph_rebuilder=rebuild_graph_from_events,
            agent_factory=agent_factory,
            timeout_s=300.0,
            advance_fn=lambda eid, tid: advance_engagement_task.delay(eid, tid),
            session_store=session_store,
        )

        return {"engagement_id": engagement_id, "status": "completed"}
    except Exception:
        _log.exception("Failed to run agent task %s for agent_role %s", engagement_id, agent_role)
        raise


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


@engagements.post("/{engagement_id}/ownership/challenge")
def ownership_challenge(
    body: OwnershipChallengeBody,
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
) -> dict[str, str]:
    """Mint a DNS-TXT ownership challenge token for a domain.

    The operator places the returned TXT record in public DNS, then calls
    ``/authorize`` which drives ``authorize_engagement`` — the SINGLE
    verify+sign point.

    Token = ``secrets.token_urlsafe(32)`` (random, NOT HMAC-derived from
    the signing key — D2). The token is public (placed in DNS) and is NOT
    a secret.
    """
    domain = _normalise_domain(body.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="domain must be non-empty")

    # Guardrail check — reject bank/gov/big-tech TLDs early.
    try:
        assert_not_guardrailed(domain)
    except GuardrailError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    sm = auth_for(principal.tenant_id)
    try:
        record = sm.get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    token = stdlib_secrets.token_urlsafe(32)

    target_store = (
        store_provider.for_tenant(principal.tenant_id) if principal.tenant_id else event_store
    )
    target_store.append(
        event_type=EventType.OWNERSHIP_CHALLENGE_ISSUED,
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload={"domain": domain, "token": token},
    )

    return {
        "record_name": domain,
        "record_type": "TXT",
        "record_value": f"agent-alpha={token}",
    }


@engagements.post("/{engagement_id}/authorize")
def authorize_engagement_endpoint(
    body: AuthorizeBody,
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
) -> dict[str, str]:
    """Authorize an engagement via §12.36: DNS-TXT ownership + consent + HMAC sign.

    Delegates to ``authorize_engagement()`` — the SINGLE verify+sign point.
    verify_domain_ownership is called ONLY inside authorize_engagement (D1).
    This endpoint NEVER calls it directly (anti double-verify #6).
    """
    if not body.domains:
        raise HTTPException(status_code=400, detail="domains required")

    sm = auth_for(principal.tenant_id)
    try:
        record = sm.get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    target_store = (
        store_provider.for_tenant(principal.tenant_id) if principal.tenant_id else event_store
    )

    # Recover challenge tokens from OWNERSHIP_CHALLENGE_ISSUED events.
    ownership_tokens: dict[str, str] = {}
    for evt in target_store.get_events(engagement_id):
        if evt.event_type == EventType.OWNERSHIP_CHALLENGE_ISSUED:
            d = str(evt.payload.get("domain", ""))
            t = str(evt.payload.get("token", ""))
            if d:
                norm_d = _normalise_domain(d)
                ownership_tokens[norm_d] = f"dns-txt:agent-alpha={t}"

    skip_verification = os.environ.get("AGENT_ALPHA_SKIP_DOMAIN_VERIFICATION", "").lower() in (
        "1",
        "true",
        "yes",
    )
    # Opso C: cooperative verification mode — operator explicitly chooses SOW-based
    # verification (no DNS-TXT). Recorded in the signed profile + event payload for
    # audit trail. When business is ready to tighten, default back to "dns_txt" only.
    cooperative_mode = body.verification_mode == "cooperative"
    if cooperative_mode:
        skip_verification = True

    for domain in body.domains:
        normalized = _normalise_domain(domain)
        if normalized not in ownership_tokens:
            if skip_verification:
                # Auto-mint challenge token when verification is skipped.
                token = stdlib_secrets.token_urlsafe(32)
                target_store.append(
                    event_type=EventType.OWNERSHIP_CHALLENGE_ISSUED,
                    engagement_id=engagement_id,
                    agent="CONDUCTOR",
                    payload={"domain": normalized, "token": token},
                )
                ownership_tokens[normalized] = f"dns-txt:agent-alpha={token}"
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"no ownership challenge issued for domain {normalized!r}; "
                    f"call /ownership/challenge first",
                )
        # Defense-in-depth: guardrail check before authorize_engagement.
        try:
            assert_not_guardrailed(normalized)
        except GuardrailError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    # Auto-fill consent + signer when domain verification is skipped (dev/cooperative).
    if skip_verification:
        if not body.consent_items:
            body.consent_items = ["recon_only", "subdomain_enum", "origin_discovery", "evasion"]
        if not body.signed_by:
            body.signed_by = "operator"
        if not body.signed_at:
            body.signed_at = datetime.now(timezone.utc).isoformat()  # noqa: UP017

    # Origin IPs: ONLY from explicit client input. A discovered IP is NEVER
    # auto-authorized here (§12.38 collateral risk: a shared-host / co-tenant IP
    # found via passive DNS is not proven to serve the client's domain). Per-IP
    # origin authorization is a RUNTIME two-proof decision (§12.46 origin-binding),
    # not an authorize-time guess. Absent client-named IPs, authorized_origins
    # stays empty → fail-closed (origin-direct simply does not fire).
    authorized_origins: frozenset[str] | None = (
        frozenset(body.authorized_origins) if body.authorized_origins else None
    )

    signing_key = get_profile_signing_key()

    try:
        profile = authorize_engagement(
            engagement_id=engagement_id,
            client_id=record.client_id,
            targets=body.domains,
            ownership_tokens=ownership_tokens,
            dns_resolver=DnspythonResolver(),
            skip_domain_verification=skip_verification,
            verification_mode=body.verification_mode,
            authorized_origins=authorized_origins,
            consent_items=frozenset(body.consent_items) if body.consent_items else None,
            signed_by=body.signed_by,
            signed_at=body.signed_at,
            authorization_level=body.authorization_level,
            allow_evasion=body.allow_evasion,
            allow_origin_discovery=body.allow_origin_discovery,
            allow_subdomain_enum=body.allow_subdomain_enum,
            opsec_stealth=body.opsec_stealth,
            event_store=target_store,
            key=signing_key,
        )
    except ConsentRequiredError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DomainOwnershipError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GuardrailError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Persist the signed envelope so run_engagement_task can reload it.
    envelope = dump_signed_profile(profile, key=signing_key)
    target_store.append(
        event_type=EventType.ENGAGEMENT_PROFILE_SIGNED,
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload=envelope,
    )

    profile_hash = profile.sign(signing_key)
    return {"engagement_id": engagement_id, "profile_hash": profile_hash}


@engagements.post("/{engagement_id}/recon")
def enable_recon(
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
    body: EnableReconBody | None = None,
) -> dict[str, str]:
    """Enable recon for an authorized engagement.

    §12.36 HARD CUT (D4): scope comes from the signed EngagementProfile
    ONLY — the old free-form {ip_ranges, domains, exclusions} body is
    removed. The profile is the SINGLE scope source (anti-Lyndon #6).
    """
    sm = auth_for(principal.tenant_id)
    try:
        record = sm.get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    target_store = (
        store_provider.for_tenant(principal.tenant_id) if principal.tenant_id else event_store
    )

    # Require a signed-profile envelope event for this engagement.
    signing_key = get_profile_signing_key()
    profile: EngagementProfile | None = None
    for evt in reversed(target_store.get_events(engagement_id)):
        if evt.event_type == EventType.ENGAGEMENT_PROFILE_SIGNED:
            try:
                profile = load_signed_profile_from_dict(evt.payload, key=signing_key)
            except ProfileSignatureError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"signed profile integrity check failed: {exc}",
                ) from exc
            break

    if profile is None:
        raise HTTPException(
            status_code=400,
            detail="no signed EngagementProfile found; call /authorize first",
        )

    # Defense-in-depth: re-check guardrails on every scope_target even though
    # authorize_engagement already checked. Prevents a stale signed profile
    # from bypassing a guardrail added after authorization.
    for target in profile.scope_targets:
        try:
            assert_not_guardrailed(target)
        except GuardrailError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    # Derive Scope from the signed profile's scope_targets (SINGLE source).
    # Wire allow_subdomain_enum from the profile → Scope.allow_subdomains so
    # is_in_scope() accepts subdomains (Strategy B: side-door target expansion).
    scope = Scope(
        ip_ranges=[],
        domains=sorted(profile.scope_targets),
        exclusions=[],
        allow_subdomains=profile.allow_subdomain_enum,
    )

    try:
        sm.enable_recon(engagement_id, scope)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    state = sm.get_state(engagement_id)
    return {"engagement_id": engagement_id, "state": a2a_pb2.EngagementState.Name(state)}


@engagements.post("/{engagement_id}/sow")
def upload_sow(
    file: UploadFile,
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
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
    principal: Annotated[Principal, Depends(require_principal)],
    response: Response,
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
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
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
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


@engagements.get("/{engagement_id}/trace")
def get_engagement_trace(
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
) -> dict[str, Any]:
    """A7 observability (slice A7-a): the per-engagement run trace.

    Read-only consumer of ``project_engagement_trace`` — mirrors
    ``get_run_status`` exactly, including the tenant-isolation 404. Wiring this
    endpoint is what makes the projection a live read model rather than dead
    code (anti Lyndon #2). Zero writes.
    """
    try:
        record = auth_for(principal.tenant_id).get_record(engagement_id)
    except Exception:
        raise HTTPException(status_code=404, detail="engagement not found") from None

    if record.tenant_id is not None and record.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")

    target_store = (
        store_provider.for_tenant(principal.tenant_id) if principal.tenant_id else event_store
    )
    trace = project_engagement_trace(engagement_id, target_store.get_events(engagement_id))

    return {
        "engagement_id": trace.engagement_id,
        "steps": [
            {
                "agent": step.agent,
                "outcome": step.outcome,
                "event_type": step.event_type,
                "sequence_number": step.sequence_number,
                "timestamp_utc": step.timestamp_utc,
                "latency_s": step.latency_s,
            }
            for step in trace.steps
        ],
        "total_latency_s": trace.total_latency_s,
        "last_sequence_number": trace.last_sequence_number,
    }


@app.get("/health/queue")
def get_queue_health(
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    """A7 observability (slice A7-c): live broker queue-depth + worker health.

    System-level operational signal (not per-engagement, not event-sourced) —
    the read-only consumer that makes the health probe live code (anti Lyndon
    #2). NOTE: returns GLOBAL queue depth; an authenticated tenant can see
    aggregate system load. Acceptable for an operator signal at this stage;
    per-tenant scoping is a later refinement, tracked, not silently ignored.
    """
    probe = RedisCeleryProbe.from_url(_redis_url, celery_app, CELERY_QUEUE_PREFIX)
    health = build_queue_health(probe)
    return {
        "broker_reachable": health.broker_reachable,
        "queue_depth": health.queue_depth,
        "worker_count": health.worker_count,
        "degraded": health.degraded,
        "checked_at_utc": health.checked_at_utc,
    }


@engagements.post("/{engagement_id}/stop")
def emergency_stop(
    body: dict[str, str],
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
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
    principal: Annotated[Principal, Depends(require_principal)],
    engagement_id: Annotated[str, Depends(valid_engagement_id)],
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
app.include_router(routes_monologue.router)
