# tests/phase_2/test_live_fire_runner.py
"""Live-fire runner tests (hermetic — no live network).

Two tests:
1. load_engagement_config: parse a sample YAML → EngagementConfig dataclass.
2. run_live_fire: fake HTTP client drives Alpha through two targets;
   score_findings produces (1,0,0,1), fp_rate 0.0, passed True.
"""

from __future__ import annotations

import pathlib
import textwrap

import pytest

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import EventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.runner import (
    EngagementConfig,
    TargetSpec,
    ground_truth_from_config,
    load_engagement_config,
    run_live_fire,
)
from agent_alpha.live_fire.scoring import score_findings
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

from .conftest import FakeHttpClient, FakeHttpResponse, HARDENED_BODY, LARAVEL_DEBUG_BODY


class _StubProvider:
    """Stub LLM provider for the SINGLE_LLM fallback tier.

    Returns a generic_http_probe decision so observations that miss
    every playbook rule still get a valid PlaybookDecision.
    """

    def complete(self, *a: object, **k: object):  # noqa: ANN204
        return type(
            "R", (), {
                "text": '{"tool": "generic_http_probe"}',
                "usage_cost_usd": 0.0,
                "model": "deepseek-v4-pro",
            },
        )()


# ── Fixtures ──────────────────────────────────────────────────────────

SAMPLE_YAML = textwrap.dedent("""\
    client_id: client_lab
    scope:
      ip_ranges:
        - "10.0.0.0/30"
      domains:
        - lab-target.invalid
        - hardened.invalid
    targets:
      - url: "https://lab-target.invalid/trigger-error"
        host: lab-target.invalid
        ground_truth_vulnerable: true
      - url: "https://hardened.invalid/trigger-error"
        host: hardened.invalid
        ground_truth_vulnerable: false
""")


@pytest.fixture
def sample_yaml_path(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "engagement.yaml"
    p.write_text(SAMPLE_YAML)
    return p


@pytest.fixture
def playbook_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / "fixtures" / "playbooks"


# ── Tests ─────────────────────────────────────────────────────────────


def test_load_engagement_config(sample_yaml_path: pathlib.Path) -> None:
    """load_engagement_config parses YAML correctly."""
    config = load_engagement_config(sample_yaml_path)

    assert config.client_id == "client_lab"
    assert config.scope_domains == ["lab-target.invalid", "hardened.invalid"]
    assert len(config.targets) == 2

    laravel_target = config.targets[0]
    assert laravel_target.host == "lab-target.invalid"
    assert laravel_target.ground_truth_vulnerable is True

    hardened_target = config.targets[1]
    assert hardened_target.host == "hardened.invalid"
    assert hardened_target.ground_truth_vulnerable is False


def test_run_live_fire(
    sample_yaml_path: pathlib.Path,
    playbook_dir: pathlib.Path,
) -> None:
    """run_live_fire with FakeHttpClient: lab-target predicted True,
    hardened predicted False; score -> (1,0,0,1), fp_rate 0.0, passed True."""
    config = load_engagement_config(sample_yaml_path)

    # Build fakes
    http_client = FakeHttpClient({
        "https://lab-target.invalid/trigger-error": FakeHttpResponse(
            status_code=500,
            text=LARAVEL_DEBUG_BODY,
            headers={"server": "nginx", "x-powered-by": "PHP/8.2.4"},
            url="https://lab-target.invalid/trigger-error",
        ),
        "https://hardened.invalid/trigger-error": FakeHttpResponse(
            status_code=500,
            text=HARDENED_BODY,
            headers={"server": "nginx"},
            url="https://hardened.invalid/trigger-error",
        ),
    })

    auth = AuthorizationStateMachine()
    graph_store = NetworkXGraphStore()
    event_store = EventStore()

    # Build orchestrator from the test fixtures playbook dir (no LLM needed)
    playbook_engine = PlaybookEngine.from_directory(playbook_dir)
    orchestrator = LLMOrchestrator(playbook_engine, provider=_StubProvider())

    results = run_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
    )

    # Verify per-target predictions
    results_by_host = {r.host: r for r in results}
    assert results_by_host["lab-target.invalid"].predicted_vulnerable is True
    assert results_by_host["hardened.invalid"].predicted_vulnerable is False

    # Score
    gt = ground_truth_from_config(config)
    score = score_findings(results, gt)
    assert (score.tp, score.fp, score.fn, score.tn) == (1, 0, 0, 1)
    assert score.fp_rate_of_findings == 0.0
    assert score.passed is True
