from __future__ import annotations

import dataclasses
import typing

from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
)
from agent_alpha.graph.store import GraphStore


@dataclasses.dataclass(frozen=True)
class BlastRadius:
    from_node_id: str
    reachable_node_ids: list[str]
    reachable_count: int
    high_value_targets: list[str]
    severity: str


@dataclasses.dataclass(frozen=True)
class AttackChain:
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    impact_score: float
    chain_length: int


_HIGH_VALUE_ACCESS_LEVELS: set[str] = {"root", "domain_admin", "db_root"}
_SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def find_critical_paths(
    store: GraphStore,
    source_types: list[NodeType] | None = None,
    target_types: list[NodeType] | None = None,
) -> list[list[AttackNode]]:
    if source_types is None:
        effective_source_types: list[NodeType] = [NodeType.ASSET]
    else:
        effective_source_types = list(source_types)

    if target_types is None:
        effective_target_types: list[NodeType] = [NodeType.DATA, NodeType.ACCESS_LEVEL]
    else:
        effective_target_types = list(target_types)

    source_nodes: list[AttackNode] = []
    for node_type in effective_source_types:
        source_nodes.extend(store.nodes_by_type(node_type))

    target_nodes: list[AttackNode] = []
    for node_type in effective_target_types:
        target_nodes.extend(store.nodes_by_type(node_type))

    if not source_nodes or not target_nodes:
        return []

    paths_by_signature: dict[tuple[str, ...], list[AttackNode]] = {}

    for source in source_nodes:
        for target in target_nodes:
            raw_paths = store.find_paths(source.id, target.id)
            for path in raw_paths:
                signature = tuple(node.id for node in path)
                if signature not in paths_by_signature:
                    paths_by_signature[signature] = path

    return list(paths_by_signature.values())


def calculate_blast_radius(store: GraphStore, from_node_id: str) -> BlastRadius:
    start_node = store.get_node(from_node_id)
    if start_node is None:
        return BlastRadius(
            from_node_id=from_node_id,
            reachable_node_ids=[],
            reachable_count=0,
            high_value_targets=[],
            severity="low",
        )

    visited: set[str] = {from_node_id}
    queue: list[str] = [from_node_id]
    reachable_ids: list[str] = []
    reachable_nodes: dict[str, AttackNode] = {}

    while queue:
        current_id = queue.pop(0)
        for neighbor in store.neighbors(current_id):
            neighbor_id = neighbor.id
            if neighbor_id not in visited:
                visited.add(neighbor_id)
                queue.append(neighbor_id)
                reachable_ids.append(neighbor_id)
                reachable_nodes[neighbor_id] = neighbor

    high_value_ids: list[str] = []
    for node_id in reachable_ids:
        node = reachable_nodes[node_id]
        if node.type == NodeType.DATA:
            high_value_ids.append(node_id)
        elif node.type == NodeType.ACCESS_LEVEL and isinstance(
            node.properties, AccessLevelProperties
        ):
            if node.properties.level in _HIGH_VALUE_ACCESS_LEVELS:
                high_value_ids.append(node_id)

    reachable_count = len(reachable_ids)

    if reachable_count == 0:
        severity = "low"
    elif high_value_ids or reachable_count >= 15:
        severity = "critical"
    elif reachable_count >= 5:
        severity = "high"
    else:
        severity = "medium"

    return BlastRadius(
        from_node_id=from_node_id,
        reachable_node_ids=reachable_ids,
        reachable_count=reachable_count,
        high_value_targets=high_value_ids,
        severity=severity,
    )


def _compute_impact_score(edges: list[AttackEdge], chain_length: int) -> float:
    if not edges:
        return 0.0
    avg_confidence = sum(edge.confidence for edge in edges) / float(len(edges))
    return avg_confidence * (1.0 + 0.1 * float(chain_length))


def find_attack_chains(store: GraphStore) -> list[AttackChain]:
    critical_paths = find_critical_paths(store)
    chains: list[AttackChain] = []

    for path in critical_paths:
        if not path:
            continue

        edges: list[AttackEdge] = []
        valid = True
        for i in range(len(path) - 1):
            source_node = path[i]
            target_node = path[i + 1]
            edge = store.get_edge(source_node.id, target_node.id)
            if edge is None:
                valid = False
                break
            edges.append(edge)

        if not valid:
            continue

        chain_length = len(path)
        impact_score = _compute_impact_score(edges, chain_length)
        chains.append(
            AttackChain(
                nodes=path,
                edges=edges,
                impact_score=impact_score,
                chain_length=chain_length,
            )
        )

    return chains


def highest_impact_chain(store: GraphStore) -> AttackChain | None:
    chains = find_attack_chains(store)
    if not chains:
        return None

    return max(chains, key=lambda c: c.impact_score)


def to_narrative(
    store: GraphStore,
    style: typing.Literal["executive", "technical", "remediation"],
) -> str:
    if style not in {"executive", "technical", "remediation"}:
        raise ValueError(f"Unknown narrative style: {style}")

    if style == "executive":
        return _to_executive_narrative(store)
    if style == "technical":
        return _to_technical_narrative(store)
    return _to_remediation_narrative(store)


def _to_executive_narrative(store: GraphStore) -> str:
    assets = store.nodes_by_type(NodeType.ASSET)
    total_assets = len(assets)

    critical_paths = find_critical_paths(store)
    total_critical_paths = len(critical_paths)

    highest_severity = "low"
    for asset in sorted(assets, key=lambda n: n.id):
        radius = calculate_blast_radius(store, asset.id)
        if _SEVERITY_ORDER[radius.severity] > _SEVERITY_ORDER[highest_severity]:
            highest_severity = radius.severity

    lines: list[str] = []
    lines.append("Executive summary")
    lines.append(f"Total assets discovered: {total_assets}")
    lines.append(f"Total critical paths found: {total_critical_paths}")
    lines.append(f"Highest severity blast radius: {highest_severity}")

    if critical_paths:
        lines.append("Critical paths:")
        for idx, path in enumerate(critical_paths, start=1):
            hops = max(len(path) - 1, 0)
            lines.append(f"- Path {idx}: {hops} hops")

    return "\n".join(lines)


def _to_technical_narrative(store: GraphStore) -> str:
    lines: list[str] = []
    lines.append("Technical summary")
    lines.append("Nodes by type:")

    for node_type in NodeType:
        nodes = store.nodes_by_type(node_type)
        if not nodes:
            continue
        lines.append(f"{node_type.value}:")
        for node in sorted(nodes, key=lambda n: n.id):
            lines.append(f"  - {node.id} (confidence={node.confidence:.2f})")

    lines.append("")
    lines.append("Edges by relationship:")
    for relationship in RelationshipType:
        edges = store.edges_by_relationship(relationship)
        if not edges:
            continue
        lines.append(f"{relationship.value}:")
        for edge in sorted(edges, key=lambda e: (e.source_id, e.target_id)):
            lines.append(
                f"  - {edge.source_id} -> {edge.target_id} "
                f"(confidence={edge.confidence:.2f})"
            )

    chain = highest_impact_chain(store)
    lines.append("")
    lines.append("Highest impact chain:")
    if chain is None:
        lines.append("  (no attack chains found)")
    else:
        node_sequence = " -> ".join(node.id for node in chain.nodes)
        lines.append(f"  Nodes: {node_sequence}")
        lines.append(f"  Impact score: {chain.impact_score:.4f}")

    return "\n".join(lines)


def _to_remediation_narrative(store: GraphStore) -> str:
    lines: list[str] = []
    lines.append("Remediation summary")

    vulnerabilities = store.nodes_by_type(NodeType.VULNERABILITY)
    lines.append("Vulnerabilities:")
    for node in sorted(vulnerabilities, key=lambda n: n.id):
        vuln_props = typing.cast(VulnerabilityProperties, node.properties)
        if vuln_props.cve_id:
            lines.append(f"  - {node.id}: {vuln_props.cve_id}")
        else:
            lines.append(f"  - {node.id}: (no cve_id)")

    credentials = store.nodes_by_type(NodeType.CREDENTIAL)
    lines.append("")
    lines.append("Credentials:")
    for node in sorted(credentials, key=lambda n: n.id):
        cred_props = typing.cast(CredentialProperties, node.properties)
        lines.append(f"  - {node.id}: access_level={cred_props.access_level}")

    return "\n".join(lines)
