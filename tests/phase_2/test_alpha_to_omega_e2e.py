"""Contract: Alpha -> Omega end-to-end (the Phase 2 headline exit criterion).

scan target -> graph projection -> narrative report. One real flow across the
two agents, joined only by the AttackGraph + event stream — never by a direct
agent-to-agent call (anti-bypass; everything routes conceptually via state).

Omega is READ-ONLY: it must not mutate the graph. The report must be grounded
in graph facts (a fabricated narrative with an empty graph is a failure),
carry MITRE ATT&CK technique ids, and export to PDF.
"""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.omega.roaster import Omega
from agent_alpha.config import constants
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"


class _StubProvider:
    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object):
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "deepseek-v4-pro"})()


@pytest.fixture
def populated_graph(recon_engagement, http_client, graph_store, event_store, laravel_target_url):
    """Drive the real Alpha so the graph is populated by an actual scan,
    not hand-built — this is what makes the test end-to-end."""
    auth, engagement_id = recon_engagement
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR), provider=_StubProvider()
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
    )
    alpha.run_recon(engagement_id, laravel_target_url)
    assert graph_store.node_count() >= 1, "Alpha must populate the graph before Omega runs"
    return graph_store


def test_omega_generates_grounded_narrative(populated_graph):
    omega = Omega(populated_graph)
    before = populated_graph.node_count()

    report = omega.generate_report(style="technical")

    assert report.narrative.strip()  # non-empty
    assert "laravel" in report.narrative.lower()  # grounded in the finding
    assert populated_graph.node_count() == before  # read-only: no mutation


def test_report_is_mitre_mapped(populated_graph):
    report = Omega(populated_graph).generate_report(style="technical")
    assert report.mitre_techniques  # non-empty
    assert "T1592.002" in report.mitre_techniques  # technique from the probe
    assert report.mitre_attack_version == constants.MITRE_ATTACK_VERSION


def test_report_exports_pdf(populated_graph, tmp_path: pathlib.Path):
    report = Omega(populated_graph).generate_report(style="executive")
    out = report.export_pdf(tmp_path / "report.pdf")
    assert out.exists()
    assert out.stat().st_size > 0
    assert "pdf" in constants.REPORT_FORMATS


def test_all_three_narrative_styles_render(populated_graph):
    omega = Omega(populated_graph)
    for style in ("executive", "technical", "remediation"):
        assert omega.generate_report(style=style).narrative.strip()
