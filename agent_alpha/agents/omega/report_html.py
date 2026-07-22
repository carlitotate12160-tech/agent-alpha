# agent_alpha/agents/omega/report_html.py
"""HTML report renderer for Omega (ROASTER).

Renders a self-contained HTML client deliverable matching agent_alpha_report_reference.html.
Features:
- Cover page with Agent-Alpha logo (monoline apex-A mark), classification tag, engagement metadata.
- Section 1: Executive summary (narrative prose + severity summary table).
- Section 2: Attack path (STATIC inline SVG generated dynamically from critical_path).
- Section 3: Findings and proof blocks with monospace artifact refs & hashes.
- Section 4: Impact and blast radius.
- Section 5: Recommendations.
- Footer with Agent-Alpha branding and confidentiality metadata.
"""

from __future__ import annotations

import html
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_alpha.agents.omega.roaster import PathStep, Report


AGENT_ALPHA_LOGO_SVG = """<svg width="40" height="40" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M 50 12 L 15 88 L 34 88 L 50 50 L 66 88 L 85 88 Z" fill="none" stroke="#1f3a5f" stroke-width="5" stroke-linejoin="round"/>
  <path d="M 33 65 L 67 65" stroke="#1f3a5f" stroke-width="5" stroke-linecap="round"/>
  <circle cx="50" cy="28" r="4" fill="#1f3a5f"/>
</svg>"""


def _infer_node_kind(node_id: str) -> str:
    """Infer node kind for nodes that never appeared as a to_node (e.g. entry node)."""
    parts = re.split(r"[-_:]", node_id)
    if parts and parts[0]:
        candidate = parts[0].lower()
        if candidate in {
            "asset",
            "credential",
            "vulnerability",
            "access_level",
            "data",
            "host",
            "target",
            "service",
        }:
            return candidate
    return "asset"


def render_attack_path_svg(critical_path: tuple[PathStep, ...] | list[PathStep]) -> str:
    """Render a static inline SVG attack path diagram from critical_path steps.

    Deterministic and self-contained (zero external requests, no Mermaid/JS).
    Renders a variable node count N = len(critical_path) + 1 (2..N nodes).
    Node positions are spread evenly across SVG width.
    Terminal node is marked red / COMPROMISED.
    """
    path_tuple = tuple(critical_path)
    if not path_tuple:
        return (
            '<svg viewBox="0 0 680 120" width="100%" style="display:block; margin:14px 0;" role="img" aria-label="Attack path diagram">\n'
            '  <rect x="0" y="0" width="680" height="120" rx="12" fill="#0f1620"/>\n'
            '  <text x="340" y="65" font-family="monospace" font-size="12" fill="#5b6779" text-anchor="middle">No critical attack path available.</text>\n'
            "</svg>"
        )

    # Extract distinct nodes in order
    node_ids: list[str] = [path_tuple[0].from_node]
    node_kinds: list[str] = [_infer_node_kind(path_tuple[0].from_node)]

    for step in path_tuple:
        node_ids.append(step.to_node)
        node_kinds.append(step.node_kind or _infer_node_kind(step.to_node))

    n_nodes = len(node_ids)

    # Dynamic positioning calculation
    svg_width = 680
    svg_height = 250
    margin_x = 70
    max_x = 610

    if n_nodes == 1:
        x_coords = [340]
    else:
        step_x = (max_x - margin_x) / (n_nodes - 1)
        x_coords = [int(round(margin_x + i * step_x)) for i in range(n_nodes)]

    svg_lines = [
        f'<svg viewBox="0 0 {svg_width} {svg_height}" width="100%" style="display:block; margin:14px 0;" role="img" aria-label="Attack path diagram">',
        f'  <rect x="0" y="0" width="{svg_width}" height="{svg_height}" rx="12" fill="#0f1620"/>',
        f'  <line x1="44" y1="30" x2="{svg_width - 40}" y2="30" stroke="#26303f" stroke-width="1"/>',
        '  <g font-family="monospace" font-size="10" fill="#5b6779" text-anchor="middle">',
    ]

    # Render timeline top markers
    for i, x in enumerate(x_coords):
        color = "#c0392b" if i == n_nodes - 1 else "#3a4557"
        label = f"Step {i + 1}" if i > 0 else "Entry"
        svg_lines.append(
            f'    <circle cx="{x}" cy="30" r="2" fill="{color}"/><text x="{x}" y="20">{label}</text>'
        )
    svg_lines.append("  </g>")

    # Render connector edges with technique labels
    for i, step in enumerate(path_tuple):
        x1 = x_coords[i]
        x2 = x_coords[i + 1]
        mid_x = (x1 + x2) // 2
        tech_id = html.escape(step.edge_technique_id.strip() or "leads_to")

        if i % 2 == 0:
            cy1, cy2 = 180, 180
            text_y = 198
            path_d = (
                f"M{x1},150 C{x1 + (x2 - x1) // 3},{cy1} {x1 + 2 * (x2 - x1) // 3},{cy2} {x2},150"
            )
            stroke_color = "#5d7cae" if i == 0 else "#4a5568"
        else:
            cy1, cy2 = 120, 120
            text_y = 114
            path_d = (
                f"M{x1},150 C{x1 + (x2 - x1) // 3},{cy1} {x1 + 2 * (x2 - x1) // 3},{cy2} {x2},150"
            )
            stroke_color = "#4a5568"

        tech_color = (
            "#c79a4b" if "T1552" in tech_id else ("#c76b5b" if "T1078" in tech_id else "#89a3c9")
        )

        svg_lines.append(
            f'  <path d="{path_d}" fill="none" stroke="{stroke_color}" stroke-width="2"/>'
        )
        svg_lines.append(
            f'  <text x="{mid_x}" y="{text_y}" font-family="monospace" font-size="11" fill="{tech_color}" text-anchor="middle">{tech_id}</text>'
        )

    # Render node circles and labels
    for i, (node_id, kind) in enumerate(zip(node_ids, node_kinds, strict=True)):
        x = x_coords[i]
        node_id_esc = html.escape(node_id)
        kind_esc = html.escape(kind)

        if i == n_nodes - 1:
            # Terminal node (COMPROMISED)
            svg_lines.extend(
                [
                    f'  <circle cx="{x}" cy="150" r="28" fill="#241416" stroke="#c0392b" stroke-width="2"/>',
                    f'  <rect x="{x - 7}" y="151" width="14" height="11" rx="1.5" fill="none" stroke="#e5776a" stroke-width="1.5"/>',
                    f'  <path d="M{x - 4},151 v-3 a4,4 0 0 1 8,0" fill="none" stroke="#e5776a" stroke-width="1.5"/>',
                    f'  <circle cx="{x}" cy="156" r="1.4" fill="#e5776a"/>',
                    f'  <text x="{x}" y="194" font-size="12" fill="#f0d0cb" text-anchor="middle" font-weight="500">{node_id_esc}</text>',
                    f'  <text x="{x}" y="207" font-size="10" fill="#c0392b" text-anchor="middle" font-weight="600" letter-spacing="0.5">COMPROMISED</text>',
                ]
            )
        else:
            # Intermediate / Entry node
            stroke_col = (
                "#5d6b80"
                if i == 0
                else ("#c79a4b" if "cred" in kind or "vuln" in kind else "#5d7cae")
            )
            bg_fill = "#1e1c14" if "cred" in kind or "vuln" in kind else "#16202e"
            svg_lines.extend(
                [
                    f'  <circle cx="{x}" cy="150" r="26" fill="{bg_fill}" stroke="{stroke_col}" stroke-width="2"/>',
                    f'  <circle cx="{x}" cy="150" r="8" fill="none" stroke="#aeb9c9" stroke-width="1.4"/>',
                    f'  <text x="{x}" y="192" font-size="12" fill="#e6eaf0" text-anchor="middle">{node_id_esc}</text>',
                    f'  <text x="{x}" y="206" font-size="11" fill="#7f8a9c" text-anchor="middle">{kind_esc}</text>',
                ]
            )

    # Node-type legend at bottom of panel
    svg_lines.extend(
        [
            '  <g font-family="sans-serif" font-size="10" fill="#7f8a9c">',
            '    <circle cx="50" cy="235" r="4" fill="#5d6b80"/><text x="58" y="238">Entry</text>',
            '    <circle cx="120" cy="235" r="4" fill="#c79a4b"/><text x="128" y="238">Credential / Vuln</text>',
            '    <circle cx="230" cy="235" r="4" fill="#5d7cae"/><text x="238" y="238">Asset / Pivot</text>',
            '    <circle cx="330" cy="235" r="4" fill="#c0392b"/><text x="338" y="238">Objective (Compromised)</text>',
            "  </g>",
            "</svg>",
        ]
    )

    return "\n".join(svg_lines)


def render_report_html(report: Report) -> str:
    """Render a Report instance into a single, self-contained HTML client deliverable string.

    Deterministic: identical Report input produces byte-identical HTML.
    HTML-escapes all field interpolations to prevent markup breakages/XSS.
    Matching agent_alpha_report_reference.html structure & styling.
    """
    # 1. Executive Summary & Narrative
    if report.narrative:
        narrative_p = f'<p class="lead">{html.escape(report.narrative)}</p>'
    else:
        narrative_p = '<p class="no-data">No narrative available.</p>'

    # Summary table rows for Section 1
    sev_table_rows: list[str] = []
    if report.evidence:
        for item in report.evidence:
            tech_esc = html.escape(item.technique_id or "N/A")
            desc_esc = html.escape(item.description or "Evidence item recorded")
            sev_tag = '<span class="sev-tag high">High</span>'
            sev_table_rows.append(
                f'    <tr><td>{desc_esc}</td><td class="mono">{tech_esc}</td><td>{sev_tag}</td></tr>'
            )
    elif report.mitre_techniques:
        for tech in report.mitre_techniques:
            tech_esc = html.escape(tech)
            sev_table_rows.append(
                f'    <tr><td>ATT&amp;CK Technique verified</td><td class="mono">{tech_esc}</td><td><span class="sev-tag high">High</span></td></tr>'
            )

    if sev_table_rows:
        sev_table_html = (
            '  <table class="sev">\n'
            "    <thead><tr><th>Finding</th><th>Technique</th><th>Severity</th></tr></thead>\n"
            "    <tbody>\n" + "\n".join(sev_table_rows) + "\n    </tbody>\n"
            "  </table>"
        )
    else:
        sev_table_html = '<p class="no-data">No findings recorded in summary table.</p>'

    # 2. Attack Path SVG
    attack_path_svg = render_attack_path_svg(report.critical_path)

    # 3. Findings and Proof Blocks
    if report.evidence:
        finding_blocks: list[str] = []
        for idx, item in enumerate(report.evidence, start=1):
            tech_esc = html.escape(item.technique_id or "N/A")
            desc_esc = html.escape(item.description or "Proof artifact captured")
            ref_esc = html.escape(item.artifact_ref)
            sha_esc = html.escape(item.sha256)
            finding_blocks.append(
                f'  <div class="finding high">\n'
                f'    <div class="hd"><h3>3.{idx} &nbsp; {desc_esc}</h3><span class="id sev-tag high">High</span></div>\n'
                f"    <p>{desc_esc}</p>\n"
                f'    <div class="proof mono">Technique {tech_esc} · Proof: {ref_esc} · sha256 {sha_esc}</div>\n'
                f"  </div>"
            )
        findings_html = "\n".join(finding_blocks)
    else:
        findings_html = '  <p class="no-data">No evidence collected.</p>'

    # 4. Blast Radius
    if report.blast_radius:
        b = report.blast_radius
        from_node = html.escape(b.from_node_id)
        sev_label = html.escape(b.severity.capitalize())
        sev_class = b.severity.lower()
        count = b.reachable_count
        hvt_str = html.escape(", ".join(b.high_value_targets)) if b.high_value_targets else "None"
        reachable_str = (
            html.escape(", ".join(b.reachable_node_ids)) if b.reachable_node_ids else "None"
        )

        blast_html = (
            '  <div class="two">\n'
            "    <div>\n"
            "      <h3>Reachable from this access</h3>\n"
            f'      <p>Severity <span class="sev-tag {sev_class}">{sev_label}</span>. '
            f'{count} node(s) reachable from entry point <span class="mono">{from_node}</span>. '
            f'High-value targets: <span class="mono">{hvt_str}</span>. '
            f'Reachable nodes: <span class="mono">{reachable_str}</span>.</p>\n'
            "    </div>\n"
            "    <div>\n"
            "      <h3>Business impact</h3>\n"
            "      <p>An administrative or critical foothold on the application exposes all data and "
            "functions controlled by that role. Validated access paths bypass edge mitigations "
            "and present direct risk to backend assets.</p>\n"
            "    </div>\n"
            "  </div>"
        )
    else:
        blast_html = '  <p class="no-data">No blast radius calculated.</p>'

    # Metadata extraction for cover
    # Use real engagement metadata if provided; fall back to derivation from graph internals
    target_host = report.target if report.target else "target-assessment"
    if not report.target:
        if report.critical_path and report.critical_path[0].from_node:
            target_host = report.critical_path[0].from_node
        elif report.blast_radius and report.blast_radius.from_node_id:
            target_host = report.blast_radius.from_node_id

    target_host_esc = html.escape(target_host)
    engagement_id = report.engagement_id if report.engagement_id else "agent-alpha-engagement"
    if not report.engagement_id:
        if report.chain_finding and report.chain_finding.credential_id:
            engagement_id = f"eng-{report.chain_finding.credential_id}"
    engagement_id_esc = html.escape(engagement_id)
    assessed_at = report.assessed_at if report.assessed_at else "21 July 2026"
    assessed_at_esc = html.escape(assessed_at)

    time_headline = report.time_to_proof_headline()
    time_str = f" · Time to first proof: {html.escape(time_headline)}" if time_headline else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent-Alpha — Red Team Engagement Report</title>
<style>
  :root {{
    --ink: #16191f;
    --muted: #5b6472;
    --faint: #8a919c;
    --line: #dce0e6;
    --accent: #1f3a5f;
    --paper: #ffffff;
    --panel: #f7f8fa;
    --sev-high: #a12525;
    --sev-med: #9a6a12;
    --sev-low: #2f6d47;
  }}
  * {{ box-sizing: border-box; }}
  html {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  body {{
    margin: 0; background: #eceef1; color: var(--ink);
    font-family: "Helvetica Neue", Arial, "Segoe UI", sans-serif;
    font-size: 14px; line-height: 1.6;
  }}
  .page {{
    max-width: 820px; margin: 24px auto; background: var(--paper);
    padding: 56px 64px; border: 1px solid var(--line);
  }}
  .mono {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; font-size: 12.5px; }}
  h1 {{ font-size: 23px; font-weight: 600; letter-spacing: .2px; margin: 0; }}
  h2 {{
    font-size: 15px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px;
    color: var(--accent); margin: 38px 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--accent);
  }}
  h3 {{ font-size: 14px; font-weight: 600; margin: 20px 0 4px; }}
  p {{ margin: 8px 0; }}
  .cover {{ border-bottom: 1px solid var(--line); padding-bottom: 20px; }}
  .wordmark {{ font-size: 13px; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; color: var(--accent); }}
  .subtitle {{ font-size: 14px; color: var(--muted); margin-top: 2px; }}
  .classif {{
    float: right; font-size: 11px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase;
    color: var(--sev-high); border: 1px solid var(--sev-high); padding: 3px 8px;
  }}
  table.meta {{ border-collapse: collapse; margin-top: 16px; font-size: 13px; }}
  table.meta td {{ padding: 3px 24px 3px 0; color: var(--ink); vertical-align: top; }}
  table.meta td.k {{ color: var(--muted); width: 150px; }}
  .lead {{ font-size: 14px; white-space: pre-wrap; }}
  table.sev {{ border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 13px; }}
  table.sev th, table.sev td {{ border: 1px solid var(--line); padding: 7px 10px; text-align: left; }}
  table.sev th {{ background: var(--panel); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); }}
  .sev-tag {{ font-weight: 600; font-size: 12px; }}
  .sev-tag.high, .sev-tag.critical {{ color: var(--sev-high); }}
  .sev-tag.med, .sev-tag.medium {{ color: var(--sev-med); }}
  .sev-tag.low {{ color: var(--sev-low); }}
  .finding {{ border: 1px solid var(--line); border-left: 3px solid var(--line); margin: 12px 0; padding: 12px 14px; }}
  .finding.high, .finding.critical {{ border-left-color: var(--sev-high); }}
  .finding.med, .finding.medium {{ border-left-color: var(--sev-med); }}
  .finding.low {{ border-left-color: var(--sev-low); }}
  .finding .hd {{ display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }}
  .finding .id {{ color: var(--faint); font-size: 12px; }}
  .proof {{ background: var(--panel); border: 1px solid var(--line); padding: 8px 10px; margin-top: 8px; color: var(--muted); word-break: break-all; }}
  .two {{ display: flex; gap: 20px; }}
  .two > div {{ flex: 1; }}
  .no-data {{ color: var(--muted); font-style: italic; }}
  footer {{
    max-width: 820px; margin: 0 auto 40px; padding: 10px 64px; color: var(--faint); font-size: 11px;
    display: flex; justify-content: space-between;
  }}
  @media print {{
    body {{ background: #fff; }}
    .page {{ border: none; margin: 0; max-width: none; padding: 28mm 22mm; }}
    footer {{ padding: 0 22mm; }}
    h2 {{ break-after: avoid; }}
    .finding, .flow {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="page">

  <div class="cover">
    <span class="classif">Confidential</span>
    <div style="display:flex; align-items:center; gap:16px;">
      {AGENT_ALPHA_LOGO_SVG}
      <div>
        <div class="wordmark">Agent-Alpha</div>
        <div style="font-size:11px; color:var(--faint); letter-spacing:.3px;">prove exploitability, not just risk</div>
      </div>
    </div>
    <h1 style="margin-top:14px;">Red team engagement report</h1>
    <div class="subtitle">Authorized security assessment — external attack surface{time_str}</div>
    <table class="meta">
      <tr><td class="k">Target</td><td class="mono">{target_host_esc}</td></tr>
      <tr><td class="k">Engagement ID</td><td class="mono">{engagement_id_esc}</td></tr>
      <tr><td class="k">Assessment date</td><td>{assessed_at_esc}</td></tr>
      <tr><td class="k">Overall risk</td><td><span class="sev-tag high">High</span></td></tr>
      <tr><td class="k">Prepared by</td><td>Agent-Alpha autonomous red-team platform</td></tr>
    </table>
  </div>

  <h2>1 &nbsp; Executive summary</h2>
{narrative_p}
{sev_table_html}

  <h2>2 &nbsp; Attack path</h2>
  <p>The verified attack path established during the assessment:</p>
{attack_path_svg}

  <h2>3 &nbsp; Findings and proof</h2>
{findings_html}

  <h2>4 &nbsp; Impact and blast radius</h2>
{blast_html}

  <h2>5 &nbsp; Recommendations</h2>
  <p>1. Restrict origin server access to authorized entry points only.</p>
  <p>2. Rotate leaked credentials and secrets immediately.</p>
  <p>3. Remove hardcoded secrets from client-delivered JavaScript and assets.</p>
  <p>4. Re-test after remediation to confirm the attack chain is broken.</p>

</div>
<footer>
  <span>Agent-Alpha — Confidential</span>
  <span>Engagement {engagement_id_esc} · {target_host_esc}</span>
</footer>
</body>
</html>
"""
