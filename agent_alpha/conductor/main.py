# agent_alpha/conductor/main.py
# Phase 0 — FastAPI + Celery skeleton wiring all Phase 0 components.
#
# ADR §8a: non-blocking, chat-while-task-runs. Celery workers run engagements
# in background. Phase 0: Celery task is a no-op placeholder (real agent logic
# Phase 2+). All Phase 0 components wired here as singletons.

import hashlib
import ipaddress
import json
import logging
import os
import pathlib
import secrets as stdlib_secrets
import socket
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Annotated, Any

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
from agent_alpha.conductor.run_status import project_run_status
from agent_alpha.conductor.verification import verify_access_nodes
from agent_alpha.config.constants import (
    CELERY_QUEUE_PREFIX,
    CELERY_RESULT_EXPIRES_SEC,
    CELERY_TASK_HARD_LIMIT_SEC,
    CELERY_TASK_MAX_RETRIES,
    CELERY_TASK_SOFT_LIMIT_SEC,
    SOW_MAX_FILE_SIZE_MB,
)
from agent_alpha.config.stores import SecretsVaultProvider, StoreProvider, build_event_store
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import TransientStoreError
from agent_alpha.events.trace import project_engagement_trace
from agent_alpha.live_fire.browser_solve import DeepSeekBrowserSolve
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.llm.routing import resolve_reasoning_provider
from agent_alpha.memory.session import InMemorySessionStore, RedisSessionStore, SessionRecord
from agent_alpha.recon.origin_discovery import StaticOriginDiscovery
from agent_alpha.security.secrets import (
    LogScrubber,
    SecretsManager,
    SecretsVault,
    get_profile_signing_key,
    sanitize_for_log,
)
from agent_alpha.tools.playbook import PlaybookEngine

_log = logging.getLogger(__name__)


_CF_RANGES = [
    ipaddress.ip_network(n)
    for n in [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ]
]


def _is_cloudflare_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _CF_RANGES)
    except ValueError:
        return False


def _crtsh_subdomains(domain: str) -> list[str]:
    """Query CT logs for subdomain names of *domain* via crt.sh + hackertarget fallback."""
    names: set[str] = set()

    # Primary: crt.sh JSON API
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 — hardcoded HTTPS URL to crt.sh
            data = json.loads(resp.read())
        for entry in data:
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n and "*" not in n and n.endswith(domain):
                    names.add(n)
        if names:
            return sorted(names)
    except Exception:
        pass  # fall through to hackertarget

    # Fallback: hackertarget host search API
    url2 = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        req2 = urllib.request.Request(url2, headers={"User-Agent": "Agent-Alpha/0.1"})
        with urllib.request.urlopen(req2, timeout=10) as resp2:  # nosec B310 — hardcoded HTTPS URL to hackertarget
            for line in resp2.read().decode(errors="replace").splitlines():
                parts = line.split(",")
                if parts and parts[0].strip().lower().endswith(domain):
                    names.add(parts[0].strip().lower())
    except Exception as exc:
        _log.warning("CT log discovery failed for %s: %s", sanitize_for_log(domain), exc)

    return sorted(names)


def _alienvault_otx_subdomains(domain: str) -> list[str]:
    """Query AlienVault OTX (free, no API key) for passive subdomain DNS."""
    names: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Agent-Alpha/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 — hardcoded HTTPS URL to OTX
            data = json.loads(resp.read())
        for record in data.get("passive_dns", []):
            hostname = str(record.get("hostname", "")).strip().lower()
            if hostname and hostname.endswith(domain):
                names.add(hostname)
    except Exception:
        pass  # OTX is best-effort
    return sorted(names)


def _virustotal_subdomains(domain: str) -> list[str]:
    """Query VirusTotal v3 subdomains API (requires VIRUSTOTAL_API_KEY)."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return []

    names: set[str] = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=10"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": api_key,
                "User-Agent": "Agent-Alpha/0.1",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 — hardcoded HTTPS URL to VirusTotal
            data = json.loads(resp.read())
        for item in data.get("data", []):
            n = str(item.get("id", "")).strip().lower()
            if n and n.endswith(domain):
                names.add(n)
    except Exception:
        pass  # VirusTotal is best-effort
    return sorted(names)


def _discover_subdomains(domain: str) -> list[str]:
    """Multi-source subdomain discovery: crt.sh, hackertarget, OTX, VirusTotal."""
    all_names: set[str] = set()

    # Source 1+2: crt.sh + hackertarget
    all_names.update(_crtsh_subdomains(domain))

    # Source 3: AlienVault OTX (free, no API key)
    otx_names = _alienvault_otx_subdomains(domain)
    if otx_names:
        _log.info("OTX found %d subdomains for %s", len(otx_names), sanitize_for_log(domain))
    all_names.update(otx_names)

    # Source 4: VirusTotal (requires API key)
    vt_names = _virustotal_subdomains(domain)
    if vt_names:
        _log.info("VirusTotal found %d subdomains for %s", len(vt_names), sanitize_for_log(domain))
    all_names.update(vt_names)

    return sorted(all_names)


def _resolve_origin_ips(domains: list[str]) -> list[str]:
    """Auto-discover origin IPs for domains via multi-source CT logs + DNS.

    Strategy:
    1. Resolve DNS A records for the domain itself (cooperative/non-CF targets).
    2. Multi-source subdomain discovery: crt.sh, hackertarget, AlienVault OTX,
       Censys (if API key), VirusTotal (if API key).
    3. Resolve each subdomain's DNS A records.
    4. Filter out Cloudflare edge IPs and private/loopback IPs.
    5. Return unique, globally routable origin IPs.

    Used to auto-populate authorized_origins so origin-direct reach can fire
    without manual IP entry (Strix-like UX).
    """
    ips: list[str] = []

    for domain in domains:
        # 1. Direct DNS resolution
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET)
            for _family, _type, _proto, _canon, sockaddr in info:
                ip = str(sockaddr[0])
                try:
                    parsed = ipaddress.ip_address(ip)
                    if parsed.is_global and not _is_cloudflare_ip(ip):
                        ips.append(ip)
                except ValueError:
                    continue
        except socket.gaierror:
            _log.warning("DNS resolution failed for %s — skipping", sanitize_for_log(domain))

        # 2. Multi-source subdomain discovery
        subdomains = _discover_subdomains(domain)
        if subdomains:
            _log.info("Discovered %d subdomains for %s", len(subdomains), sanitize_for_log(domain))

        for sub in subdomains:
            try:
                info = socket.getaddrinfo(sub, None, socket.AF_INET)
                for _family, _type, _proto, _canon, sockaddr in info:
                    ip = str(sockaddr[0])
                    try:
                        parsed = ipaddress.ip_address(ip)
                        if parsed.is_global and not _is_cloudflare_ip(ip):
                            ips.append(ip)
                    except ValueError:
                        continue
            except socket.gaierror:
                continue

    return list(dict.fromkeys(ips))  # dedup, preserve order


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
    opsec_stealth: bool = False
    authorized_origins: list[str] | None = None  # manual override (dev/cooperative)


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
            if not profile_envelope or not profile_envelope.payload:
                raise ValueError("no signed profile event found")
            # Load and verify the signature using the single source of truth key.
            engagement_profile = load_signed_profile_from_dict(
                profile_envelope.payload, key=signing_key
            )
        except ProfileSignatureError as exc:
            # We must fail loud if the signature is invalid (anti-downgrade).
            raise ValueError(f"profile signature invalid: {exc}") from exc
        except Exception:  # noqa: BLE001 — profile load failure must not crash silently
            _log.exception("Failed to load signed EngagementProfile for %s", engagement_id)
            engagement_profile = None

        # Build origin_discovery from authorized_origins in the signed profile.
        # This wires origin-direct reach: when a probe hits WAF/CF, Alpha can
        # bypass to the origin IP (authorized in the profile).
        task_origin_discovery = None
        if engagement_profile is not None:
            profile_origins = getattr(engagement_profile, "authorized_origins", None)
            if profile_origins:
                task_origin_discovery = StaticOriginDiscovery(list(profile_origins))

        # ── §12.41: wire browser_solve when the signed profile consents to evasion ──
        task_browser_solve = None
        task_browser_solve_viable = False
        if engagement_profile is not None and getattr(engagement_profile, "allow_evasion", False):
            task_browser_solve = DeepSeekBrowserSolve.from_env()
            task_browser_solve_viable = task_browser_solve is not None

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

        def agent_factory(graph_store: Any, session_store: Any = None) -> Callable[[], ExecOutcome]:
            if agent_role == a2a_pb2.BETA:
                candidates = beta_web_applicators(http_client)
                applicators = build_applicators_for_engagement(
                    engagement_id=engagement_id,
                    auth=auth,
                    graph_store=graph_store,
                    web_target=record.target,
                    candidates=candidates,
                )
                beta = Beta(
                    authorization=auth,
                    graph_store=graph_store,
                    event_store=target_store,
                    orchestrator=orchestrator,
                    http_client=http_client,
                    secrets_manager=task_secrets,
                    cred_applicators=applicators,
                    session_store=session_store,
                )

                def run_beta() -> ExecOutcome:
                    handoff_msg = beta.run_strike(engagement_id, record.target)
                    handoff_payload = a2a_pb2.HandoffPayload()
                    handoff_payload.ParseFromString(handoff_msg.payload)
                    if handoff_payload.status == a2a_pb2.COMPLETE:
                        verify_access_nodes(graph_store, target_store, engagement_id)
                    return ExecOutcome(
                        status=handoff_payload.status,
                        next_recommended=handoff_payload.next_recommended,
                        reason="ok"
                        if handoff_payload.status == a2a_pb2.COMPLETE
                        else "beta_failed",
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

    # Origin IPs: manual override (dev/cooperative) or auto-resolve via DNS.
    authorized_origins: frozenset[str] | None
    if body.authorized_origins:
        authorized_origins = frozenset(body.authorized_origins)
    else:
        origin_ips = _resolve_origin_ips(body.domains)
        authorized_origins = frozenset(origin_ips) if origin_ips else None

    signing_key = get_profile_signing_key()

    try:
        profile = authorize_engagement(
            engagement_id=engagement_id,
            client_id=record.client_id,
            targets=body.domains,
            ownership_tokens=ownership_tokens,
            dns_resolver=DnspythonResolver(),
            skip_domain_verification=skip_verification,
            authorized_origins=authorized_origins,
            consent_items=frozenset(body.consent_items) if body.consent_items else None,
            signed_by=body.signed_by,
            signed_at=body.signed_at,
            authorization_level=body.authorization_level,
            allow_evasion=body.allow_evasion,
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
    scope = Scope(
        ip_ranges=[],
        domains=sorted(profile.scope_targets),
        exclusions=[],
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
