# agent_alpha/agents/omega/report_html.py
"""HTML report renderer for Omega (ROASTER).

Renders a self-contained HTML client deliverable containing all report sections:
(a) Narrative
(b) Attack-flow diagram (Mermaid)
(c) Evidence bundle table
(d) Blast radius summary
(e) MITRE techniques + chain finding + time to proof headline

Note:
  - Known limitation: Mermaid CDN requires internet access for browser diagram rendering.
  - PDF export is deferred as a follow-up: mermaid->SVG pre-rendering (fixes offline viewing
    and enables PDF export embedding).
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_alpha.agents.omega.roaster import Report


def render_report_html(report: Report) -> str:
    """Render a Report instance into a single, self-contained HTML string.

    Deterministic: identical Report input produces byte-identical HTML.
    HTML-escapes all field interpolations to prevent markup breakages/XSS.
    """
    narrative_html = (
        f'<div class="narrative-content"><pre class="narrative-text">{html.escape(report.narrative)}</pre></div>'
        if report.narrative
        else '<p class="no-data">No narrative available.</p>'
    )

    if report.attack_flow_mermaid:
        mermaid_html = f'<pre class="mermaid">{html.escape(report.attack_flow_mermaid)}</pre>'
    else:
        mermaid_html = '<p class="no-data">No attack flow data available.</p>'

    if report.evidence:
        rows: list[str] = []
        for item in report.evidence:
            tech = html.escape(item.technique_id)
            desc = html.escape(item.description)
            ref = html.escape(item.artifact_ref)
            sha = html.escape(item.sha256)
            captured = html.escape(item.captured_at)
            rows.append(
                f"            <tr>\n"
                f"                <td>{tech}</td>\n"
                f"                <td>{desc}</td>\n"
                f"                <td>{ref}</td>\n"
                f"                <td><code>{sha}</code></td>\n"
                f"                <td>{captured}</td>\n"
                f"            </tr>"
            )
        evidence_html = (
            '        <table class="evidence-table">\n'
            "            <thead>\n"
            "                <tr>\n"
            "                    <th>Technique ID</th>\n"
            "                    <th>Description</th>\n"
            "                    <th>Artifact Reference</th>\n"
            "                    <th>SHA256</th>\n"
            "                    <th>Captured At</th>\n"
            "                </tr>\n"
            "            </thead>\n"
            "            <tbody>\n" + "\n".join(rows) + "\n"
            "            </tbody>\n"
            "        </table>"
        )
    else:
        evidence_html = '        <p class="no-data">No evidence collected.</p>'

    if report.blast_radius:
        b = report.blast_radius
        from_node = html.escape(b.from_node_id)
        severity = html.escape(b.severity.upper())
        count = b.reachable_count
        hvt = html.escape(", ".join(b.high_value_targets)) if b.high_value_targets else "None"
        reachable = html.escape(", ".join(b.reachable_node_ids)) if b.reachable_node_ids else "None"
        blast_html = (
            '        <div class="blast-radius-summary">\n'
            f"            <p><strong>Entry Node:</strong> {from_node}</p>\n"
            f'            <p><strong>Severity:</strong> <span class="severity-{b.severity.lower()}">{severity}</span></p>\n'
            f"            <p><strong>Reachable Nodes Count:</strong> {count}</p>\n"
            f"            <p><strong>High Value Targets:</strong> {hvt}</p>\n"
            f"            <p><strong>Reachable Node IDs:</strong> {reachable}</p>\n"
            "        </div>"
        )
    else:
        blast_html = '        <p class="no-data">No blast radius calculated.</p>'

    time_to_proof = report.time_to_proof_headline()
    if time_to_proof:
        headline_html = f'<p class="headline"><strong>Time to First Proof:</strong> {html.escape(time_to_proof)}</p>'
    else:
        headline_html = '<p class="headline"><strong>Time to First Proof:</strong> N/A</p>'

    if report.mitre_techniques:
        version_esc = html.escape(report.mitre_attack_version)
        tech_items = "".join(f"<li>{html.escape(t)}</li>" for t in report.mitre_techniques)
        mitre_html = f'<div class="mitre-techniques"><p><strong>MITRE ATT&amp;CK Techniques ({version_esc}):</strong></p><ul>{tech_items}</ul></div>'
    else:
        mitre_html = '<div class="mitre-techniques"><p><strong>MITRE ATT&amp;CK Techniques:</strong></p><p class="no-data">No MITRE techniques recorded.</p></div>'

    if report.chain_finding:
        cf = report.chain_finding
        cf_sev = html.escape(cf.severity.upper())
        cf_cred = html.escape(cf.credential_id)
        cf_acc = html.escape(cf.access_id)
        cf_level = html.escape(cf.access_level)
        cf_downstream = "Yes" if cf.downstream_mapped else "No"
        cf_rat = html.escape(cf.rationale)
        chain_html = (
            '        <div class="chain-finding">\n'
            "            <p><strong>Chain Finding Summary:</strong></p>\n"
            "            <ul>\n"
            f'                <li><strong>Severity:</strong> <span class="severity-{cf.severity.lower()}">{cf_sev}</span></li>\n'
            f"                <li><strong>Credential ID:</strong> {cf_cred}</li>\n"
            f"                <li><strong>Access ID:</strong> {cf_acc}</li>\n"
            f"                <li><strong>Access Level:</strong> {cf_level}</li>\n"
            f"                <li><strong>Downstream Mapped:</strong> {cf_downstream}</li>\n"
            f"                <li><strong>Rationale:</strong> {cf_rat}</li>\n"
            "            </ul>\n"
            "        </div>"
        )
    else:
        chain_html = '        <div class="chain-finding"><p><strong>Chain Finding Summary:</strong></p><p class="no-data">No verified chain finding.</p></div>'

    mitre_summary_html = (
        '        <div class="findings-summary">\n'
        f"            {headline_html}\n"
        f"            {mitre_html}\n"
        f"            {chain_html}\n"
        "        </div>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --accent-blue: #38bdf8;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --accent-green: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }}
        h1 {{
            color: var(--accent-blue);
            margin: 0 0 0.5rem 0;
            font-size: 2rem;
        }}
        section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        h2 {{
            color: var(--accent-blue);
            margin-top: 0;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
            font-size: 1.4rem;
        }}
        .narrative-text {{
            white-space: pre-wrap;
            font-family: inherit;
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}
        pre.mermaid {{
            background: #ffffff;
            color: #000000;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            text-align: center;
        }}
        .evidence-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        .evidence-table th, .evidence-table td {{
            border: 1px solid var(--border-color);
            padding: 0.75rem;
            text-align: left;
        }}
        .evidence-table th {{
            background-color: var(--bg-primary);
            color: var(--accent-blue);
        }}
        .evidence-table td code {{
            font-size: 0.85rem;
            color: var(--accent-blue);
        }}
        .no-data {{
            color: var(--text-secondary);
            font-style: italic;
        }}
        .severity-critical {{ color: var(--accent-red); font-weight: bold; }}
        .severity-high {{ color: var(--accent-amber); font-weight: bold; }}
        .severity-medium {{ color: var(--accent-amber); }}
        .severity-low {{ color: var(--accent-green); }}
        ul {{ margin-top: 0.5rem; padding-left: 1.5rem; }}
        li {{ margin-bottom: 0.25rem; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>mermaid.initialize({{startOnLoad: true}});</script>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
        </header>

        <section id="narrative">
            <h2>Executive / Technical Narrative</h2>
            {narrative_html}
        </section>

        <section id="attack-flow">
            <h2>Attack Flow Diagram</h2>
            {mermaid_html}
        </section>

        <section id="evidence">
            <h2>Evidence Bundle</h2>
{evidence_html}
        </section>

        <section id="blast-radius">
            <h2>Blast Radius Summary</h2>
{blast_html}
        </section>

        <section id="mitre-summary">
            <h2>MITRE ATT&amp;CK &amp; Findings Summary</h2>
{mitre_summary_html}
        </section>
    </div>
</body>
</html>
"""
