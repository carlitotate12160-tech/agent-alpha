# agent_alpha/agents/omega/roaster.py
"""Omega (ROASTER) — reporting agent.

READ-ONLY: reads the AttackGraph and produces a report (narrative +
MITRE ATT&CK techniques + PDF).  Never mutates the graph.

Reuses the existing narrative builder ``agent_alpha.graph.narrative.to_narrative``
(anti-Lyndon #6: do not write a new narrative engine).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from agent_alpha.config import constants
from agent_alpha.graph.narrative import (
    BlastRadius,
    ChainFinding,
    find_critical_paths,
    summarize_chain_finding,
    to_narrative,
)
from agent_alpha.graph.nodes import AttackEdge
from agent_alpha.graph.store import GraphStore

logger = logging.getLogger(__name__)


def format_duration(seconds: float | None) -> str | None:
    """Human-readable duration for the "proved in X" headline. None-safe."""
    if seconds is None:
        return None
    total = int(round(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    return f"{minutes}m {secs:02d}s"


@dataclass(frozen=True)
class PathStep:
    """Thin view struct for a single step on the critical path.

    Reuses canonical graph types; NOT a new domain type (anti-#6).
    """

    from_node: str
    edge_technique_id: str
    to_node: str
    node_kind: str


@dataclass(frozen=True)
class EvidenceItem:
    """Thin view struct for evidence backing a risk claim.

    Data comes straight from the redacted ProofArtifact. The vault holds
    the raw secret; this carries only the ref + description (anti-#3).
    """

    technique_id: str
    description: str
    artifact_ref: str
    sha256: str
    captured_at: str


@dataclass(frozen=True)
class Report:
    """Immutable report produced by :class:`Omega`."""

    narrative: str
    mitre_techniques: list[str]
    mitre_attack_version: str
    chain_finding: ChainFinding | None = None
    time_to_first_proof_s: float | None = None
    blocked_hosts: tuple[str, ...] = ()
    critical_path: tuple[PathStep, ...] = ()
    evidence: tuple[EvidenceItem, ...] = ()
    blast_radius: BlastRadius | None = None
    attack_flow_mermaid: str = ""

    # Slice C: PDF export lives in omega_report_contract.md (narrative + flow + evidence).

    def time_to_proof_headline(self) -> str | None:
        """Sellable headline string, or None when no proof was produced."""
        return format_duration(self.time_to_first_proof_s)


class Omega:
    """Reporting agent — the last agent in the Phase 2 path.

    Read-only: only calls query methods on *graph_store*; never mutates it.
    """

    def __init__(self, graph_store: GraphStore) -> None:
        self.graph_store = graph_store

    def generate_report(
        self,
        style: str,
        *,
        time_to_first_proof_s: float | None = None,
        blocked_hosts: tuple[str, ...] = (),
    ) -> Report:
        """Generate a :class:`Report` from the current graph state.

        *style* is one of ``"executive"``, ``"technical"``, or
        ``"remediation"`` — passed directly to
        :func:`~agent_alpha.graph.narrative.to_narrative`.
        """
        narrative = to_narrative(self.graph_store, style)  # type: ignore[arg-type]

        if blocked_hosts:
            blocked_line = "WAF/CF blocked (not assessed): " + ", ".join(blocked_hosts)
            narrative = narrative + "\n" + blocked_line

        # Collect unique, non-empty technique IDs from all edges.
        mitre_techniques = sorted(
            {e.technique_id for e in self.graph_store.all_edges() if e.technique_id}
        )

        # Slice A: critical path + evidence bundle
        critical_paths = find_critical_paths(self.graph_store)
        critical_path_steps: list[PathStep] = []
        evidence_items: list[EvidenceItem] = []
        blast_radius_result: BlastRadius | None = None

        if critical_paths:
            # Choose the highest-impact critical path by longest chain length.
            non_empty_paths = [p for p in critical_paths if p]
            if non_empty_paths:
                non_empty_paths.sort(key=len, reverse=True)
                path = non_empty_paths[0]

                incoming_edges: dict[str, AttackEdge] = {}
                edges_along_path: list[AttackEdge] = []

                for i in range(len(path) - 1):
                    from_node = path[i]
                    to_node = path[i + 1]
                    edge = self.graph_store.get_edge(from_node.id, to_node.id)
                    if edge is None:
                        logger.debug(
                            "Omega.generate_report: missing edge between %s and %s on critical path",
                            from_node.id,
                            to_node.id,
                        )
                        continue
                    edges_along_path.append(edge)
                    if edge.technique_id:
                        incoming_edges[to_node.id] = edge
                    critical_path_steps.append(
                        PathStep(
                            from_node=from_node.id,
                            edge_technique_id=edge.technique_id or "",
                            to_node=to_node.id,
                            node_kind=to_node.type.value,
                        )
                    )

                if path and path[0].id not in incoming_edges and edges_along_path:
                    # Attribute entry-node artifacts to the first edge on the path.
                    incoming_edges[path[0].id] = edges_along_path[0]

                seen_hashes: set[str] = set()
                for node in path:
                    incoming_edge = incoming_edges.get(node.id)
                    technique_id = incoming_edge.technique_id if incoming_edge else ""
                    for artifact in node.proof_artifacts:
                        # SHA-256 of the storage_ref for deduplication
                        sha256 = hashlib.sha256(artifact.storage_ref.encode()).hexdigest()
                        if sha256 in seen_hashes:
                            continue
                        seen_hashes.add(sha256)
                        evidence_items.append(
                            EvidenceItem(
                                technique_id=technique_id,
                                description=artifact.description,
                                artifact_ref=artifact.storage_ref,
                                sha256=sha256,
                                captured_at=artifact.captured_at,
                            )
                        )

                # Compute blast radius from the entry node
                if path:
                    blast_radius_result = self._compute_blast_radius(path[0].id)

        return Report(
            narrative=narrative,
            mitre_techniques=mitre_techniques,
            mitre_attack_version=constants.MITRE_ATTACK_VERSION,
            chain_finding=summarize_chain_finding(self.graph_store),
            time_to_first_proof_s=time_to_first_proof_s,
            blocked_hosts=blocked_hosts,
            critical_path=tuple(critical_path_steps),
            evidence=tuple(evidence_items),
            blast_radius=blast_radius_result,
            attack_flow_mermaid="",  # Slice B: to be implemented
        )

    def _compute_blast_radius(self, from_node_id: str) -> BlastRadius:
        """Compute blast radius from a node using the narrative module."""
        from agent_alpha.graph.narrative import calculate_blast_radius

        return calculate_blast_radius(self.graph_store, from_node_id)
