# agent_alpha/conductor/authorization.py
# Phase 0 — Non-bypassable authorization gate (ADR §1 + §9).
#
# C1.0: state = projection of the append-only event stream (§8o-1, §12.11).
# Any process (API server, Celery worker) with access to the same EventStore
# reconstructs the same engagement/auth state. The in-memory _cache is a perf
# optimization only — never the source of truth.
#
# This module is the ONLY place in the entire codebase that reads or writes
# EngagementState. Agents may query state via the Conductor RPC surface, but
# they NEVER hold an instance of AuthorizationStateMachine and NEVER write
# state directly. Only the Conductor owns an instance.

import hashlib
import ipaddress
import logging
import secrets

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.domain_verification import (
    DNSResolver,
    DomainOwnershipError,
    verify_domain_ownership,
)
from agent_alpha.conductor.engagement_profile import (
    ConsentRecord,
    EngagementProfile,
    assert_not_guardrailed,
)
from agent_alpha.conductor.engagement_reducer import rebuild_engagement
from agent_alpha.conductor.models import (
    EngagementNotFoundError,
    EngagementRecord,
    InvalidScopeError,
    Scope,
    SOWError,
    _coerce_address,
    _ParsedAddress,
)
from agent_alpha.config.constants import (
    EMERGENCY_STOP_TIMEOUT_SEC,
    SOW_HASH_ALGORITHM,
    SOW_MAX_FILE_SIZE_MB,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent, EventStore

# Explicit re-exports for backward compatibility (mypy requires __all__ or
# redundant aliases to treat a re-export as public).
__all__ = [
    "AuthorizationStateMachine",
    "EngagementNotFoundError",
    "EngagementRecord",
    "InvalidScopeError",
    "SOWError",
    "Scope",
    "STATE_RANK",
]

_log = logging.getLogger(__name__)

# The single canonical authorization-tier ladder (anti-Lyndon #7). Higher = more authority.
# Consumers (applicator_factory, recon.db_service_probe) import THIS — never re-declare.
STATE_RANK: dict[int, int] = {
    a2a_pb2.CREATED: 0,
    a2a_pb2.RECON_ONLY: 1,
    a2a_pb2.ACTIVE_APPROVED: 2,
    a2a_pb2.OFFENSIVE_APPROVED: 3,
}


# ── State machine ─────────────────────────────────────────────


class AuthorizationStateMachine:
    """The single, non-bypassable authorization gate.

    C1.0: state is a projection of the durable event stream. The constructor
    takes an injected ``EventStore`` (read + append). Transition methods
    validate against the folded current state, then append the transition
    event. Any process with access to the same ``EventStore`` reconstructs
    the identical engagement/auth state.

    The ``_cache`` dict is a per-process performance optimization only —
    never the source of truth. ``_rebuild`` refreshes it from events.

    NOTE (C3 deferral): auth events currently write to the single injected
    ``EventStore``. Per-tenant store routing is deferred to C3, which will
    inject the resolved per-tenant ``EventStore`` — the SM already takes an
    injected store, so C3 = inject the right store, no redesign.

    Only the Conductor instantiates and owns this object. The engagement
    registry is private; no public attribute access is permitted.
    """

    def __init__(
        self,
        event_store: EventStore,
    ) -> None:
        self._event_store = event_store
        # Performance cache — rebuilt from events on every read. NEVER the
        # source of truth (Lyndon #2/#3: events are the source of truth).
        self._cache: dict[str, EngagementRecord] = {}

    # ── Private helpers ───────────────────────────────────────

    def _append_event(
        self,
        event_type: str,
        engagement_id: str,
        payload: dict[str, object],
    ) -> AgentEvent:
        """Append an event to the store. Returns the persisted AgentEvent."""
        return self._event_store.append(
            event_type=event_type,
            engagement_id=engagement_id,
            agent="CONDUCTOR",
            payload=payload,
        )

    def _rebuild(self, engagement_id: str) -> None:
        """Rebuild the cached EngagementRecord from the event stream.

        This is the canonical projection path — any process calling this
        with access to the same EventStore converges to the same state.
        """
        events = self._event_store.get_events(engagement_id)
        record = rebuild_engagement(events)
        if record is not None:
            self._cache[engagement_id] = record
        else:
            self._cache.pop(engagement_id, None)

    def _get(self, engagement_id: str) -> EngagementRecord:
        self._rebuild(engagement_id)
        record = self._cache.get(engagement_id)
        if record is None:
            raise EngagementNotFoundError(engagement_id)
        return record

    # ── State transitions ─────────────────────────────────────

    def create_engagement(
        self,
        client_id: str,
        target: str,
        tenant_id: str | None = None,
    ) -> EngagementRecord:
        engagement_id = "eng_" + secrets.token_hex(4)
        payload: dict[str, object] = {
            "client_id": client_id,
            "target": target,
            "state": a2a_pb2.CREATED,
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        self._append_event(
            EventType.ENGAGEMENT_CREATED,
            engagement_id,
            payload,
        )
        self._rebuild(engagement_id)
        return self._cache[engagement_id]

    def enable_recon(self, engagement_id: str, scope: Scope) -> bool:
        record = self._get(engagement_id)
        if record.state not in (a2a_pb2.CREATED, a2a_pb2.RECON_ONLY):
            raise ValueError(
                f"enable_recon requires CREATED or RECON_ONLY state, found {record.state}"
            )
        try:
            scope.validate()
        except ValueError as exc:
            raise InvalidScopeError(str(exc)) from exc

        scope.verified = True
        previous = record.state
        # Gate-critical (C1.0 Rev 1): persist the full scope in the event
        # payload so any process can reconstruct it from the event stream.
        # Without this, is_in_scope() and enable_active break after rebuild.
        self._append_event(
            EventType.STATE_TRANSITIONED,
            engagement_id,
            {
                "from_state": previous,
                "to_state": a2a_pb2.RECON_ONLY,
                "scope": {
                    "ip_ranges": scope.ip_ranges,
                    "domains": scope.domains,
                    "exclusions": scope.exclusions,
                    "verified": scope.verified,
                    "db_endpoints": scope.db_endpoints,
                },
            },
        )
        self._rebuild(engagement_id)
        return True

    def enable_active(self, engagement_id: str) -> bool:
        record = self._get(engagement_id)
        if record.state != a2a_pb2.RECON_ONLY:
            raise ValueError(f"enable_active requires RECON_ONLY state, found {record.state}")
        if record.scope is None or not record.scope.verified:
            raise ValueError("enable_active requires a verified scope")

        previous = record.state
        self._append_event(
            EventType.STATE_TRANSITIONED,
            engagement_id,
            {"from_state": previous, "to_state": a2a_pb2.ACTIVE_APPROVED},
        )
        self._rebuild(engagement_id)
        return True

    def enable_offensive(self, engagement_id: str, sow_bytes: bytes) -> bool:
        record = self._get(engagement_id)
        if record.state != a2a_pb2.ACTIVE_APPROVED:
            raise ValueError(
                f"enable_offensive requires ACTIVE_APPROVED state, found {record.state}"
            )
        if not sow_bytes:
            raise SOWError("sow_bytes must be non-empty")
        max_bytes = SOW_MAX_FILE_SIZE_MB * 1024 * 1024
        if len(sow_bytes) > max_bytes:
            raise SOWError(
                f"SOW size {len(sow_bytes)} bytes exceeds "
                f"SOW_MAX_FILE_SIZE_MB={SOW_MAX_FILE_SIZE_MB}"
            )

        sow_hash = hashlib.new(SOW_HASH_ALGORITHM, sow_bytes).digest()
        previous = record.state
        # sow_hash stored as hex string for JSON/JSONB serializability.
        self._append_event(
            EventType.STATE_TRANSITIONED,
            engagement_id,
            {
                "from_state": previous,
                "to_state": a2a_pb2.OFFENSIVE_APPROVED,
                "sow_hash": sow_hash.hex(),
            },
        )
        self._rebuild(engagement_id)
        return True

    def emergency_stop(self, engagement_id: str, reason: str) -> bool:
        """Force ANY state to EMERGENCY_STOP. Idempotent, never raises."""
        record = self._get(engagement_id)
        previous = record.state
        self._append_event(
            EventType.EMERGENCY_STOP,
            engagement_id,
            {
                "from_state": previous,
                "to_state": a2a_pb2.EMERGENCY_STOP,
                "reason": reason,
                "timeout_sec": EMERGENCY_STOP_TIMEOUT_SEC,
            },
        )
        self._rebuild(engagement_id)
        return True

    # ── Queries ───────────────────────────────────────────────

    def can_agent_proceed(self, agent_role: int, engagement_id: str) -> bool:
        """Return whether the given agent role may proceed. Never raises."""
        try:
            self._rebuild(engagement_id)
        except Exception:  # noqa: BLE001 — gate query must never crash
            return False
        record = self._cache.get(engagement_id)
        if record is None:
            return False

        # EMERGENCY_STOP halts everyone, including the Conductor.
        if record.state == a2a_pb2.EMERGENCY_STOP:
            return False

        if agent_role == a2a_pb2.CONDUCTOR:
            return True

        if agent_role in (a2a_pb2.ALPHA, a2a_pb2.OMEGA):
            return bool(
                record.state
                in (
                    a2a_pb2.RECON_ONLY,
                    a2a_pb2.ACTIVE_APPROVED,
                    a2a_pb2.OFFENSIVE_APPROVED,
                )
            )

        if agent_role == a2a_pb2.BETA:
            return bool(
                record.state
                in (
                    a2a_pb2.ACTIVE_APPROVED,
                    a2a_pb2.OFFENSIVE_APPROVED,
                )
            )

        if agent_role in (a2a_pb2.GAMMA, a2a_pb2.DELTA, a2a_pb2.EPSILON):
            return bool(record.state == a2a_pb2.OFFENSIVE_APPROVED)

        return False

    def owns(self, engagement_id: str, tenant_id: str | None) -> bool:
        """Return whether the engagement is owned by the tenant."""
        try:
            self._rebuild(engagement_id)
        except Exception:  # noqa: BLE001
            return False
        record = self._cache.get(engagement_id)
        if record is None:
            return False
        # None tenant_id means bypassing tenant checks for tests or legacy paths
        if tenant_id is None:
            return True
        return record.tenant_id == tenant_id

    def get_state(self, engagement_id: str) -> int:
        return self._get(engagement_id).state

    def get_record(self, engagement_id: str) -> EngagementRecord:
        """Return the full EngagementRecord or raise EngagementNotFoundError."""
        return self._get(engagement_id)

    def is_in_scope(self, engagement_id: str, target: str) -> bool:
        """Return whether target is within scope and not excluded. Never raises."""
        try:
            self._rebuild(engagement_id)
        except Exception:  # noqa: BLE001 — scope query must never crash
            return False
        record = self._cache.get(engagement_id)
        if record is None or record.scope is None:
            return False

        scope = record.scope
        parsed = _coerce_address(target)

        # Exclusions take precedence.
        for exclusion in scope.exclusions:
            if self._matches(parsed, exclusion):
                return False

        if parsed.kind == "domain":
            assert isinstance(parsed.value, str)
            return any(parsed.value == domain.strip().lower() for domain in scope.domains)

        for cidr in scope.ip_ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if (
                parsed.kind == "address"
                and isinstance(parsed.value, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                and parsed.value in network
            ):
                return True
            if parsed.kind == "network" and isinstance(
                parsed.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)
            ):
                if type(parsed.value) is type(network):
                    if isinstance(parsed.value, ipaddress.IPv4Network) and isinstance(
                        network, ipaddress.IPv4Network
                    ):
                        return parsed.value.subnet_of(network)
                    if isinstance(parsed.value, ipaddress.IPv6Network) and isinstance(
                        network, ipaddress.IPv6Network
                    ):
                        return parsed.value.subnet_of(network)
        return False

    def is_db_endpoint_in_scope(self, engagement_id: str, host: str, port: int) -> bool:
        """True iff "host:port" is an explicit db_endpoints entry in the verified SOW
        scope. Exact host match + exact port. Never raises (gate query)."""
        try:
            self._rebuild(engagement_id)
        except Exception:  # noqa: BLE001 — scope query must never crash
            return False
        record = self._cache.get(engagement_id)
        if record is None or record.scope is None:
            return False
        return f"{host}:{port}" in set(record.scope.db_endpoints)

    def assert_offensive_web_target(self, engagement_id: str, target: str) -> bool:
        """Default-DENY gate for offensive web actions on shared hosting.

        Returns True ONLY when ``target``'s hostname parses as a **domain** AND
        ``is_in_scope`` is True. A bare IP literal is always rejected — on
        shared hosting (Cloudways, cPanel) a bare-IP HTTP request hits the
        default vhost / an arbitrary co-tenant app, NOT deterministically the
        owned domain. Bare-IP offensive targeting = out-of-SOW third-party
        access. Never raises (gate query).
        """
        from urllib.parse import urlparse

        # Extract hostname from URL if target is a full URL.
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname or target

        parsed = _coerce_address(hostname)
        if parsed.kind == "address":
            return False  # bare IP is never a valid offensive web target
        return self.is_in_scope(engagement_id, hostname)

    def assert_pivot_target(self, engagement_id: str, target: str) -> bool:
        """Default-DENY gate Epsilon MUST pass before ANY lateral / co-host pivot.

        THE CO-HOST TRAP: on shared hosting, a domain discovered on a compromised
        host frequently resolves to an IP that is already inside the engagement's
        ``ip_ranges`` — but that co-hosted domain has a DIFFERENT owner and is
        almost always OUT of SOW. Touching it is unauthorized third-party access.
        A DOMAIN pivot target is therefore authorized ONLY by explicit presence in
        ``scope.domains``; it is NEVER upgraded to allowed because its resolved IP
        falls in an in-scope range. Bare-IP pivots (internal lateral movement) are
        allowed only when the IP is explicitly within an in-scope range.

        CALLER CONTRACT (non-bypassable intent): pass the discovered HOSTNAME,
        never a pre-resolved IP — resolving a co-host domain to its shared IP and
        passing that IP would defeat the domain rule. This gate is the single
        sanctioned entry for pivot authorization; Epsilon must not re-derive scope.

        Non-raising (gate query). Fail-closed: unparseable, unscoped, or excluded
        targets return False. Reuses ``is_in_scope`` as the single source of scope
        truth (anti-Lyndon #7) — the domain/IP split + exclusions + fail-closed
        rebuild live there, never duplicated here.
        """
        from urllib.parse import urlparse

        parsed_url = urlparse(target)
        hostname = parsed_url.hostname or target
        if not hostname:
            return False
        return self.is_in_scope(engagement_id, hostname)

    @staticmethod
    def _matches(parsed: _ParsedAddress, candidate: str) -> bool:
        """Return whether a parsed target matches a candidate exclusion entry."""
        cand = _coerce_address(candidate)
        if parsed.kind == "domain":
            return cand.kind == "domain" and parsed.value == cand.value
        if cand.kind == "address":
            return parsed.kind == "address" and parsed.value == cand.value
        if cand.kind == "network":
            if (
                parsed.kind == "address"
                and isinstance(parsed.value, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                and isinstance(cand.value, (ipaddress.IPv4Network, ipaddress.IPv6Network))
            ):
                return parsed.value in cand.value
            if (
                parsed.kind == "network"
                and isinstance(parsed.value, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                and isinstance(cand.value, (ipaddress.IPv4Network, ipaddress.IPv6Network))
            ):
                if type(parsed.value) is type(cand.value):
                    if isinstance(parsed.value, ipaddress.IPv4Network) and isinstance(
                        cand.value, ipaddress.IPv4Network
                    ):
                        return parsed.value.subnet_of(cand.value)
                    if isinstance(parsed.value, ipaddress.IPv6Network) and isinstance(
                        cand.value, ipaddress.IPv6Network
                    ):
                        return parsed.value.subnet_of(cand.value)
        return False


# ── §12.36 Signed EngagementProfile authorization ──────────────


def authorize_engagement(
    *,
    engagement_id: str,
    client_id: str,
    targets: list[str],
    scope_mode: str = "single",
    authorized_origins: frozenset[str] | None = None,
    allow_subdomain_enum: bool = False,
    opsec_stealth: bool = False,
    allow_evasion: bool = False,
    include_root: bool = False,
    authorization_level: str = "RECON_ONLY",
    consent_items: frozenset[str] | None = None,
    signed_by: str = "",
    signed_at: str = "",
    ownership_tokens: dict[str, str] | None = None,
    dns_resolver: DNSResolver | None = None,
    event_store: EventStore | None = None,
) -> tuple[EngagementProfile, str]:
    """Build, sign, and (optionally) persist a §12.36 EngagementProfile.

    REQUIRES DNS-TXT ownership verification for every target. Fail-closed:
    if any target fails ownership → raise, no profile.

    Steps:
    1. Guardrail check on every target (overrides consent).
    2. DNS-TXT ownership verification for every target.
    3. Construct EngagementProfile with all fields.
    4. Sign (canonical_json → sha256).
    5. Emit ENGAGEMENT_AUTHORIZED event (if event_store provided).

    Parameters
    ----------
    ownership_tokens : dict[str, str] | None
        Mapping of target → expected DNS-TXT token (e.g. {"example.com": "dns-txt:agent-alpha=abc123"}).
        Every target MUST have an entry. Missing entry → raise.
    dns_resolver : DNSResolver | None
        Injectable DNS resolver. MUST be provided — None raises DomainOwnershipError.
    event_store : EventStore | None
        If provided, emits an ENGAGEMENT_AUTHORIZED event for audit trail.

    Returns
    -------
    tuple[EngagementProfile, str]
        The signed profile and its sha256 hash.

    Raises
    ------
    GuardrailViolation
        If any target is in a guarded TLD/domain.
    DomainOwnershipError
        If DNS-TXT ownership is not proven for a target, or no resolver injected.
    ValueError
        If targets is empty or ownership_tokens is missing a target.
    """
    if not targets:
        raise ValueError("authorize_engagement: targets must be non-empty")

    if ownership_tokens is None:
        ownership_tokens = {}

    # Step 1 — guardrail check on every target (overrides consent).
    for target in targets:
        assert_not_guardrailed(target)

    # Step 2 — DNS-TXT ownership verification for every target.
    verified_targets: list[str] = []
    for target in targets:
        token = ownership_tokens.get(target)
        if token is None:
            raise ValueError(
                f"authorize_engagement: no ownership token provided for {target!r}"
            )
        if not verify_domain_ownership(target, token, dns_resolver=dns_resolver):
            raise DomainOwnershipError(
                f"authorize_engagement: DNS-TXT ownership not proven for {target!r} "
                f"(expected token: {token!r}). Target NOT added to scope."
            )
        verified_targets.append(target)

    # Step 3 — construct EngagementProfile.
    consent = ConsentRecord(
        accepted_items=consent_items or frozenset(),
        signed_by=signed_by,
        signed_at=signed_at,
    )

    profile = EngagementProfile(
        engagement_id=engagement_id,
        client_id=client_id,
        targets=frozenset(verified_targets),
        authorized_origins=authorized_origins or frozenset(),
        allow_evasion=allow_evasion,
        scope_targets=frozenset(verified_targets),
        scope_mode=scope_mode,
        allow_subdomain_enum=allow_subdomain_enum,
        opsec_stealth=opsec_stealth,
        include_root=include_root,
        authorization_level=authorization_level,
        consent=consent,
    )

    # Step 4 — sign.
    profile_hash = profile.sha256()

    # Step 5 — emit event (if event_store provided).
    if event_store is not None:
        event_store.append(
            event_type=EventType.ENGAGEMENT_AUTHORIZED,
            engagement_id=engagement_id,
            agent="CONDUCTOR",
            payload={
                "sha256": profile_hash,
                "consent": consent.to_dict(),
                "verified_targets": verified_targets,
                "authorization_level": authorization_level,
                "capabilities": {
                    "allow_subdomain_enum": allow_subdomain_enum,
                    "opsec_stealth": opsec_stealth,
                    "allow_evasion": allow_evasion,
                    "include_root": include_root,
                },
                "scope_mode": scope_mode,
            },
        )

    _log.info(
        "authorize_engagement: %s — %d targets verified, level=%s, hash=%s",
        engagement_id,
        len(verified_targets),
        authorization_level,
        profile_hash[:16],
    )

    return profile, profile_hash
