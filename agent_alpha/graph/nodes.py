from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


def merge_tech_stack(existing: list[str] | None, incoming: list[str]) -> list[str]:
    """Order-preserving union — the ONE place asset tech_stack is combined."""
    return list(dict.fromkeys([*(existing or []), *incoming]))


class NodeType(StrEnum):
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    SERVICE = "service"
    DATA = "data"
    ACCESS_LEVEL = "access_level"
    USER = "user"


class VerificationTier(StrEnum):
    UNVERIFIED = "unverified"
    SELF_VERIFIED = "self_verified"
    CROSS_VERIFIED = "cross_verified"


class RelationshipType(StrEnum):
    EXPLOITS = "exploits"
    ENABLES = "enables"
    REQUIRES = "requires"
    LEADS_TO = "leads_to"
    LATERAL_MOVE_TO = "lateral_move_to"
    PIVOTS_VIA = "pivots_via"
    CONFIRMS = "confirms"


@dataclass
class ProofArtifact:
    artifact_id: str
    type: str
    storage_ref: str
    description: str
    captured_at: str
    agent: str
    subject_ref: str = ""
    target: str = ""
    access_level: str = ""


@dataclass
class AssetProperties:
    host: str
    ip: str | None = None
    cf_protected: bool = False
    # GAP-197: behaviourally proven behind a CDN/WAF edge — set when the agent
    # PROVES a hidden origin serves the owned host (ORIGIN_BINDING_PROVEN: we only
    # origin-bind once the edge blocked/killed the front door, so the binding IS proof
    # the edge exists). Vendor UNCONFIRMED — distinct from cf_protected (NS-hint ==
    # Cloudflare). Honest reporting must never read edge_fronted as "not protected" for
    # a flanked host (anti-#3).
    edge_fronted: bool = False
    tech_stack: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    # REST route surface (WordPress /wp-json/ index). DETECT-only inventory:
    # capped at constants.WP_REST_ROUTES_CAP; when the real surface is larger,
    # rest_routes holds the first CAP entries, rest_routes_truncated is True, and
    # rest_routes_total_count records the full count. A route surface is reach,
    # NOT a payable finding (anti-#3).
    rest_routes: list[str] = field(default_factory=list)
    rest_routes_total_count: int = 0
    rest_routes_truncated: bool = False


@dataclass
class VulnerabilityProperties:
    cve_id: str | None = None
    cvss_score: float = 0.0
    affected_service: str = ""
    exploit_available: bool = False


@dataclass
class CredentialProperties:
    username: str
    secret_ref: str
    service: str
    access_level: str


@dataclass
class ServiceProperties:
    name: str
    version: str = ""
    port: int = 0
    protocol: str = "tcp"
    banner: str = ""


@dataclass
class DataProperties:
    data_type: str
    sensitivity: str
    size_estimate: str = ""
    location: str = ""


@dataclass
class AccessLevelProperties:
    level: str
    user_context: str = ""
    shell_type: str = ""
    interactive: bool = False


@dataclass
class UserProperties:
    """An enumerated username (e.g. a WordPress REST user slug).

    DETECT-derived identity, NOT a credential: it carries no secret. It is the
    cred-reuse INPUT — a username to pair with harvested secrets downstream.
    """

    username: str
    source: str = ""


@dataclass
class AttackNode:
    id: str
    type: NodeType
    properties: (
        AssetProperties
        | VulnerabilityProperties
        | CredentialProperties
        | ServiceProperties
        | DataProperties
        | AccessLevelProperties
        | UserProperties
    )
    confidence: float
    proof_artifacts: list[ProofArtifact] = field(default_factory=list)
    agent: str = ""
    timestamp_utc: str = ""
    verified: bool = False
    verification: VerificationTier = VerificationTier.UNVERIFIED

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        # Legacy sync: verified=True without explicit tier → SELF_VERIFIED (tool
        # self-report).  CROSS_VERIFIED is oracle-exclusive: it may ONLY originate
        # from a provenance-checked NodeVerified event emitted by
        # run_verification_pass.  Mapping legacy verified=True → CROSS_VERIFIED
        # would auto-promote self-reports (theater).
        if self.verified and self.verification == VerificationTier.UNVERIFIED:
            object.__setattr__(self, "verification", VerificationTier.SELF_VERIFIED)
        # Derive verified from verification (single source of truth).
        object.__setattr__(self, "verified", self.verification == VerificationTier.CROSS_VERIFIED)


@dataclass
class AttackEdge:
    source_id: str
    target_id: str
    relationship: RelationshipType
    confidence: float
    technique_id: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


_PROPERTY_TYPE_MAP: dict[NodeType, type] = {
    NodeType.ASSET: AssetProperties,
    NodeType.VULNERABILITY: VulnerabilityProperties,
    NodeType.CREDENTIAL: CredentialProperties,
    NodeType.SERVICE: ServiceProperties,
    NodeType.DATA: DataProperties,
    NodeType.ACCESS_LEVEL: AccessLevelProperties,
    NodeType.USER: UserProperties,
}


def node_to_dict(node: AttackNode) -> dict[str, Any]:
    return {
        "id": node.id,
        "type": node.type.value,
        "properties": asdict(node.properties),
        "confidence": node.confidence,
        "proof_artifacts": [asdict(a) for a in node.proof_artifacts],
        "agent": node.agent,
        "timestamp_utc": node.timestamp_utc,
        "verified": node.verified,
        "verification": node.verification.value,
    }


def _reconstruct_node(raw: dict[str, Any]) -> AttackNode:
    raw_type = raw.get("type")
    if not isinstance(raw_type, str):
        raise KeyError(f"Unknown node type: {raw_type}")
    try:
        node_type = NodeType(raw_type)
    except ValueError as exc:
        raise KeyError(f"Unknown node type: {raw_type}") from exc

    try:
        properties_type = _PROPERTY_TYPE_MAP[node_type]
    except KeyError as exc:
        raise KeyError(f"Unknown node type: {raw_type}") from exc

    properties_data = raw.get("properties", {})
    properties = properties_type(**properties_data)

    proof_artifacts_data = raw.get("proof_artifacts", [])
    proof_artifacts = [ProofArtifact(**a) for a in proof_artifacts_data]

    verification_raw = raw.get("verification")
    if verification_raw:
        verification = VerificationTier(verification_raw)
    elif raw.get("verified", False):
        # Legacy payload: verified=True but no verification tier → SELF_VERIFIED
        # (tool self-report).  NEVER CROSS_VERIFIED — that is oracle-exclusive.
        verification = VerificationTier.SELF_VERIFIED
    else:
        verification = VerificationTier.UNVERIFIED

    return AttackNode(
        id=raw["id"],
        type=node_type,
        properties=properties,
        confidence=raw["confidence"],
        proof_artifacts=proof_artifacts,
        agent=raw.get("agent", ""),
        timestamp_utc=raw.get("timestamp_utc", ""),
        verified=raw.get("verified", False),
        verification=verification,
    )
