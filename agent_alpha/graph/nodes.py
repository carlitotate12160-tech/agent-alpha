from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class NodeType(StrEnum):
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    SERVICE = "service"
    DATA = "data"
    ACCESS_LEVEL = "access_level"


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


@dataclass
class AssetProperties:
    host: str
    ip: str | None = None
    cf_protected: bool = False
    tech_stack: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)


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
    )
    confidence: float
    proof_artifacts: list[ProofArtifact] = field(default_factory=list)
    agent: str = ""
    timestamp_utc: str = ""
    verified: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


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

    return AttackNode(
        id=raw["id"],
        type=node_type,
        properties=properties,
        confidence=raw["confidence"],
        proof_artifacts=proof_artifacts,
        agent=raw.get("agent", ""),
        timestamp_utc=raw.get("timestamp_utc", ""),
        verified=raw.get("verified", False),
    )
