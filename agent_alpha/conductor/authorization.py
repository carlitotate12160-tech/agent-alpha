# agent_alpha/conductor/authorization.py
# Phase 0 — Non-bypassable authorization gate (ADR §1 + §9).
#
# This module is the ONLY place in the entire codebase that reads or writes
# EngagementState. Agents may query state via the Conductor RPC surface, but
# they NEVER hold an instance of AuthorizationStateMachine and NEVER write
# state directly. Only the Conductor owns an instance.

import dataclasses
import datetime
import hashlib
import ipaddress
import logging
import secrets
import typing
from dataclasses import dataclass

from agent_alpha.config.constants import (
    EMERGENCY_STOP_TIMEOUT_SEC,
    MAX_SCOPE_IPS,
    SOW_MAX_FILE_SIZE_MB,
    SOW_HASH_ALGORITHM,
)
from agent_alpha.a2a import a2a_pb2

_log = logging.getLogger(__name__)


# ── Custom exceptions ─────────────────────────────────────────


class InvalidScopeError(ValueError):
    """Raised when an engagement scope fails validation."""


class SOWError(ValueError):
    """Raised when a Statement-of-Work payload is invalid."""


class EngagementNotFoundError(KeyError):
    """Raised when an engagement_id is not present in the state machine."""


# ── Helpers ───────────────────────────────────────────────────


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with a 'Z' suffix."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def _coerce_address(value: str):
    """Parse a string as an ip_address, ip_network, or fall back to a domain.

    Returns a tuple (kind, parsed) where kind is one of 'address', 'network',
    or 'domain'. Domains are normalised to lower-case.
    """
    try:
        return ("address", ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        return ("network", ipaddress.ip_network(value, strict=False))
    except ValueError:
        pass
    return ("domain", value.strip().lower())


# ── Dataclasses ───────────────────────────────────────────────


@dataclass
class Scope:
    ip_ranges: list[str]            # CIDR notation
    domains: list[str]
    exclusions: list[str]           # IPs/domains explicitly out of scope
    verified: bool = False

    def validate(self) -> None:
        """Validate the scope. Raises ValueError on any problem."""
        if not self.ip_ranges:
            raise ValueError("scope.ip_ranges must not be empty")

        total_ips = 0
        for cidr in self.ip_ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR in ip_ranges: {cidr!r}") from exc
            total_ips += network.num_addresses

        if total_ips > MAX_SCOPE_IPS:
            raise ValueError(
                f"scope spans {total_ips} IPs, exceeds MAX_SCOPE_IPS={MAX_SCOPE_IPS}"
            )

        for exclusion in self.exclusions:
            kind, _ = _coerce_address(exclusion)
            if kind == "domain" and not exclusion.strip():
                raise ValueError(f"unparseable exclusion: {exclusion!r}")


@dataclass
class EngagementRecord:
    engagement_id: str
    client_id: str
    target: str
    state: int                      # a2a_pb2.EngagementState value
    scope: Scope | None
    sow_hash: bytes | None
    created_at: str                 # ISO 8601 UTC
    updated_at: str                 # ISO 8601 UTC
    stopped_reason: str | None      # set on EMERGENCY_STOP


# ── State machine ─────────────────────────────────────────────


class AuthorizationStateMachine:
    """The single, non-bypassable authorization gate.

    Only the Conductor instantiates and owns this object. The engagement
    registry is private; no public attribute access is permitted.
    """

    def __init__(
        self,
        event_callback: typing.Optional[
            typing.Callable[[str, dict], None]
        ] = None,
    ) -> None:
        self._event_callback = event_callback
        self._engagements: dict[str, EngagementRecord] = {}

    # ── Private helpers ───────────────────────────────────────

    def _emit_event(
        self, event_type: str, engagement_id: str, payload: dict
    ) -> None:
        """Emit an event to the configured callback. Never raises."""
        if self._event_callback is None:
            return
        enriched = dict(payload)
        enriched["event_type"] = event_type
        enriched["engagement_id"] = engagement_id
        enriched["timestamp_utc"] = _utc_now_iso()
        try:
            self._event_callback(event_type, enriched)
        except Exception:  # noqa: BLE001 — event emission must never break the gate
            _log.exception("event_callback failed for event_type=%s", event_type)

    def _get(self, engagement_id: str) -> EngagementRecord:
        try:
            return self._engagements[engagement_id]
        except KeyError as exc:
            raise EngagementNotFoundError(engagement_id) from exc

    # ── State transitions ─────────────────────────────────────

    def create_engagement(self, client_id: str, target: str) -> EngagementRecord:
        engagement_id = "eng_" + secrets.token_hex(4)
        now = _utc_now_iso()
        record = EngagementRecord(
            engagement_id=engagement_id,
            client_id=client_id,
            target=target,
            state=a2a_pb2.CREATED,
            scope=None,
            sow_hash=None,
            created_at=now,
            updated_at=now,
            stopped_reason=None,
        )
        self._engagements[engagement_id] = record
        self._emit_event(
            "EngagementCreated",
            engagement_id,
            {"client_id": client_id, "target": target, "state": a2a_pb2.CREATED},
        )
        return record

    def enable_recon(self, engagement_id: str, scope: Scope) -> bool:
        record = self._get(engagement_id)
        if record.state != a2a_pb2.CREATED:
            raise ValueError(
                f"enable_recon requires CREATED state, found {record.state}"
            )
        try:
            scope.validate()
        except ValueError as exc:
            raise InvalidScopeError(str(exc)) from exc

        scope.verified = True
        record.scope = scope
        previous = record.state
        record.state = a2a_pb2.RECON_ONLY
        record.updated_at = _utc_now_iso()
        self._emit_event(
            "StateTransitioned",
            engagement_id,
            {"from_state": previous, "to_state": a2a_pb2.RECON_ONLY},
        )
        return True

    def enable_active(self, engagement_id: str) -> bool:
        record = self._get(engagement_id)
        if record.state != a2a_pb2.RECON_ONLY:
            raise ValueError(
                f"enable_active requires RECON_ONLY state, found {record.state}"
            )
        if record.scope is None or not record.scope.verified:
            raise ValueError("enable_active requires a verified scope")

        previous = record.state
        record.state = a2a_pb2.ACTIVE_APPROVED
        record.updated_at = _utc_now_iso()
        self._emit_event(
            "StateTransitioned",
            engagement_id,
            {"from_state": previous, "to_state": a2a_pb2.ACTIVE_APPROVED},
        )
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
        record.sow_hash = sow_hash
        previous = record.state
        record.state = a2a_pb2.OFFENSIVE_APPROVED
        record.updated_at = _utc_now_iso()
        self._emit_event(
            "StateTransitioned",
            engagement_id,
            {
                "from_state": previous,
                "to_state": a2a_pb2.OFFENSIVE_APPROVED,
                "sow_hash": sow_hash,
            },
        )
        return True

    def emergency_stop(self, engagement_id: str, reason: str) -> bool:
        """Force ANY state to EMERGENCY_STOP. Idempotent, never raises."""
        record = self._get(engagement_id)
        previous = record.state
        record.state = a2a_pb2.EMERGENCY_STOP
        record.stopped_reason = reason
        record.updated_at = _utc_now_iso()
        self._emit_event(
            "EmergencyStop",
            engagement_id,
            {
                "from_state": previous,
                "to_state": a2a_pb2.EMERGENCY_STOP,
                "reason": reason,
                "timeout_sec": EMERGENCY_STOP_TIMEOUT_SEC,
            },
        )
        return True

    # ── Queries ───────────────────────────────────────────────

    def can_agent_proceed(self, agent_role: int, engagement_id: str) -> bool:
        """Return whether the given agent role may proceed. Never raises."""
        record = self._engagements.get(engagement_id)
        if record is None:
            return False

        # EMERGENCY_STOP halts everyone, including the Conductor.
        if record.state == a2a_pb2.EMERGENCY_STOP:
            return False

        if agent_role == a2a_pb2.CONDUCTOR:
            return True

        if agent_role in (a2a_pb2.ALPHA, a2a_pb2.OMEGA):
            return record.state in (
                a2a_pb2.RECON_ONLY,
                a2a_pb2.ACTIVE_APPROVED,
                a2a_pb2.OFFENSIVE_APPROVED,
            )

        if agent_role == a2a_pb2.BETA:
            return record.state in (
                a2a_pb2.ACTIVE_APPROVED,
                a2a_pb2.OFFENSIVE_APPROVED,
            )

        if agent_role in (a2a_pb2.GAMMA, a2a_pb2.DELTA, a2a_pb2.EPSILON):
            return record.state == a2a_pb2.OFFENSIVE_APPROVED

        return False

    def get_state(self, engagement_id: str) -> int:
        return self._get(engagement_id).state

    def is_in_scope(self, engagement_id: str, target: str) -> bool:
        """Return whether target is within scope and not excluded. Never raises."""
        record = self._engagements.get(engagement_id)
        if record is None or record.scope is None:
            return False

        scope = record.scope
        kind, parsed = _coerce_address(target)

        # Exclusions take precedence.
        for exclusion in scope.exclusions:
            if self._matches(kind, parsed, exclusion):
                return False

        if kind == "domain":
            return any(
                parsed == domain.strip().lower() for domain in scope.domains
            )

        for cidr in scope.ip_ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if kind == "address" and parsed in network:
                return True
            if kind == "network" and parsed.subnet_of(network):
                return True
        return False

    @staticmethod
    def _matches(kind: str, parsed, candidate: str) -> bool:
        """Return whether a parsed target matches a candidate exclusion entry."""
        cand_kind, cand_parsed = _coerce_address(candidate)
        if kind == "domain":
            return cand_kind == "domain" and parsed == cand_parsed
        if cand_kind == "address":
            return kind == "address" and parsed == cand_parsed
        if cand_kind == "network":
            if kind == "address":
                return parsed in cand_parsed
            if kind == "network":
                return parsed.subnet_of(cand_parsed)
        return False
