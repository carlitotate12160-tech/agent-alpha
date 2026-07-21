# agent_alpha/agents/omega/roaster.py
"""Omega (ROASTER) — reporting agent.

READ-ONLY: reads the AttackGraph and produces a report (narrative +
MITRE ATT&CK techniques + PDF).  Never mutates the graph.

Reuses the existing narrative builder ``agent_alpha.graph.narrative.to_narrative``
(anti-Lyndon #6: do not write a new narrative engine).
"""

from __future__ import annotations

import hashlib
import pathlib
from dataclasses import dataclass
from typing import Any

from agent_alpha.config import constants
from agent_alpha.graph.narrative import (
    BlastRadius,
    ChainFinding,
    find_critical_paths,
    summarize_chain_finding,
    to_narrative,
)
from agent_alpha.graph.nodes import ProofArtifact
from agent_alpha.graph.store import GraphStore


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
    critical_path: list[PathStep] = ()
    evidence: list[EvidenceItem] = ()
    blast_radius: BlastRadius | None = None
    attack_flow_mermaid: str = ""

    def time_to_proof_headline(self) -> str | None:
        """Sellable headline string, or None when no proof was produced."""
        return format_duration(self.time_to_first_proof_s)

    def export_pdf(self, path: str | pathlib.Path) -> pathlib.Path:
        """Render :attr:`narrative` to a PDF at *path* and return the path.

        Uses reportlab so there is no system-level dependency on LaTeX or
        wkhtmltopdf.  The resulting file is always non-empty.
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

        out = pathlib.Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(out),
            pagesize=A4,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        story: list[object] = []

        # ── Title ───────────────────────────────────────────────
        story.append(Paragraph("Agent-Alpha Report", styles["Title"]))
        story.append(Spacer(1, 6 * mm))

        # ── Time-to-proof headline (sellable metric) ────────────
        headline = self.time_to_proof_headline()
        if headline is not None:
            story.append(Paragraph(f"Time to proof: {headline}", styles["Heading2"]))
            story.append(Spacer(1, 4 * mm))

        # ── MITRE ATT&CK section ───────────────────────────────
        if self.mitre_techniques:
            story.append(
                Paragraph(
                    f"MITRE ATT&amp;CK ({self.mitre_attack_version}): "
                    f"{', '.join(self.mitre_techniques)}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 4 * mm))

        # ── Key finding (cred-reuse chain) ──────────────────────
        if self.chain_finding is not None:
            cf = self.chain_finding
            story.append(
                Paragraph(f"Key finding — severity: {cf.severity.upper()}", styles["Heading2"])
            )
            story.append(Paragraph(cf.rationale, styles["Normal"]))
            story.append(Spacer(1, 4 * mm))

        # ── Narrative body ──────────────────────────────────────
        for line in self.narrative.splitlines():
            if line.strip():
                story.append(Paragraph(line, styles["Normal"]))
                story.append(Spacer(1, 2 * mm))

        doc.build(story)
        return out


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
            # Use the first critical path (highest impact)
            path = critical_paths[0]
            for i in range(len(path) - 1):
                from_node = path[i]
                to_node = path[i + 1]
                edge = self.graph_store.get_edge(from_node.id, to_node.id)
                if edge is None:
                    continue
                critical_path_steps.append(
                    PathStep(
                        from_node=from_node.id,
                        edge_technique_id=edge.technique_id or "",
                        to_node=to_node.id,
                        node_kind=to_node.type.value,
                    )
                )
                # Collect ProofArtifacts from both endpoint nodes
                for node in (from_node, to_node):
                    for artifact in node.proof_artifacts:
                        # SHA-256 of the storage_ref for deduplication
                        sha256 = hashlib.sha256(artifact.storage_ref.encode()).hexdigest()
                        evidence_items.append(
                            EvidenceItem(
                                technique_id=edge.technique_id or "",
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
