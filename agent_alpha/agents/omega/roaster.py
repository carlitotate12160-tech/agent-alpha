# agent_alpha/agents/omega/roaster.py
"""Omega (ROASTER) — reporting agent.

READ-ONLY: reads the AttackGraph and produces a report (narrative +
MITRE ATT&CK techniques + PDF).  Never mutates the graph.

Reuses the existing narrative builder ``agent_alpha.graph.narrative.to_narrative``
(anti-Lyndon #6: do not write a new narrative engine).
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

from agent_alpha.config import constants
from agent_alpha.graph.narrative import ChainFinding, summarize_chain_finding, to_narrative
from agent_alpha.graph.store import GraphStore


@dataclass(frozen=True)
class Report:
    """Immutable report produced by :class:`Omega`."""

    narrative: str
    mitre_techniques: list[str]
    mitre_attack_version: str
    chain_finding: ChainFinding | None = None

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
                Paragraph(
                    f"Key finding — severity: {cf.severity.upper()}", styles["Heading2"]
                )
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

    def generate_report(self, style: str) -> Report:
        """Generate a :class:`Report` from the current graph state.

        *style* is one of ``"executive"``, ``"technical"``, or
        ``"remediation"`` — passed directly to
        :func:`~agent_alpha.graph.narrative.to_narrative`.
        """
        narrative = to_narrative(self.graph_store, style)  # type: ignore[arg-type]

        # Collect unique, non-empty technique IDs from all edges.
        mitre_techniques = sorted(
            {e.technique_id for e in self.graph_store.all_edges() if e.technique_id}
        )

        return Report(
            narrative=narrative,
            mitre_techniques=mitre_techniques,
            mitre_attack_version=constants.MITRE_ATTACK_VERSION,
            chain_finding=summarize_chain_finding(self.graph_store),
        )
