# agent_alpha/conductor/models.py
# Shared data types for the conductor package — extracted to break the
# circular import between authorization.py and engagement_reducer.py.
#
# Both modules import from here; authorization.py re-exports for backward
# compatibility so existing `from agent_alpha.conductor.authorization import ...`
# continues to work unchanged.

import ipaddress
from dataclasses import dataclass, field

from agent_alpha.config.constants import MAX_SCOPE_IPS

# ── Custom exceptions ─────────────────────────────────────────


class InvalidScopeError(ValueError):
    """Raised when an engagement scope fails validation."""


class SOWError(ValueError):
    """Raised when a Statement-of-Work payload is invalid."""


class EngagementNotFoundError(KeyError):
    """Raised when an engagement_id is not present in the state machine."""


# ── Helper types ──────────────────────────────────────────────


@dataclass
class _ParsedAddress:
    kind: str
    value: (
        ipaddress.IPv4Address
        | ipaddress.IPv6Address
        | ipaddress.IPv4Network
        | ipaddress.IPv6Network
        | str
    )


def _coerce_address(value: str) -> _ParsedAddress:
    """Parse a string as an ip_address, ip_network, or fall back to a domain.

    Returns a _ParsedAddress where kind is one of 'address', 'network',
    or 'domain'. Domains are normalised to lower-case.
    """
    try:
        return _ParsedAddress("address", ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        return _ParsedAddress("network", ipaddress.ip_network(value, strict=False))
    except ValueError:
        pass
    return _ParsedAddress("domain", value.strip().lower())


# ── Dataclasses ───────────────────────────────────────────────


@dataclass
class Scope:
    ip_ranges: list[str]  # CIDR notation
    domains: list[str]
    exclusions: list[str]  # IPs/domains explicitly out of scope
    verified: bool = False
    db_endpoints: list[str] = field(default_factory=list)

    def validate(self) -> None:
        """Validate the scope. Raises ValueError on any problem."""
        if not self.ip_ranges:
            raise InvalidScopeError("scope.ip_ranges must not be empty")

        total_ips = 0
        for cidr in self.ip_ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise InvalidScopeError(f"invalid CIDR in ip_ranges: {cidr!r}") from exc
            total_ips += network.num_addresses

        if total_ips > MAX_SCOPE_IPS:
            raise InvalidScopeError(
                f"scope spans {total_ips} IPs, exceeds MAX_SCOPE_IPS={MAX_SCOPE_IPS}"
            )

        for exclusion in self.exclusions:
            parsed = _coerce_address(exclusion)
            if parsed.kind == "domain" and not exclusion.strip():
                raise InvalidScopeError(f"unparseable exclusion: {exclusion!r}")

        for endpoint in self.db_endpoints:
            host, sep, port_str = endpoint.rpartition(":")
            if sep == "" or not host:
                raise InvalidScopeError(f"invalid db_endpoint: {endpoint!r}")
            try:
                port = int(port_str)
            except ValueError as exc:
                raise InvalidScopeError(f"invalid db_endpoint: {endpoint!r}") from exc
            if port < 1 or port > 65535:
                raise InvalidScopeError(f"invalid db_endpoint port: {endpoint!r}")


@dataclass
class EngagementRecord:
    engagement_id: str
    client_id: str
    target: str
    state: int  # a2a_pb2.EngagementState value
    scope: Scope | None
    sow_hash: bytes | None
    created_at: str  # ISO 8601 UTC
    updated_at: str  # ISO 8601 UTC
    stopped_reason: str | None  # set on EMERGENCY_STOP
    tenant_id: str | None = None  # owning tenant (None for legacy/tests)
