"""Contract: live-fire runner (testable core).

The runner has two layers:
  - run_live_fire(config, *injected deps) -> list[TargetResult]   (HERMETIC, tested
    here with the FakeHttpClient — proves the full Alpha→prediction→score pipeline)
  - main()/CLI that builds the REAL HttpClient + DeepSeekProvider from the YAML
    config + env (operational, not unit-tested — exercised by an actual run).

Target identity is the URL, not the host: two targets may share a host
(different ports/paths) and must stay distinct end-to-end.
"""

from __future__ import annotations

import pathlib

from agent_alpha.conductor.authorization import AuthorizationStateMachine
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

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"
ENGAGEMENTS_DIR = pathlib.Path(__file__).parent / "fixtures" / "engagements"


class _StubProvider:
    """RULE tier handles Laravel; this only fires for a non-Laravel observation,
    returning a non-Laravel tool -> no false positive."""

    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object):
        return type(
            "R", (), {"text": '{"tool": "generic_http_probe"}',
                      "usage_cost_usd": 0.0, "model": "deepseek-v4-pro"}
        )()


def _orchestrator() -> LLMOrchestrator:
    return LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR), provider=_StubProvider()
    )


def test_load_engagement_config() -> None:
    config = load_engagement_config(ENGAGEMENTS_DIR / "sample.yaml")
    assert config.client_id == "lab_client"
    assert "lab-target.invalid" in config.scope_domains
    assert len(config.targets) == 2
    laravel = next(t for t in config.targets if t.host == "lab-target.invalid")
    assert laravel.ground_truth_vulnerable is True


def test_run_live_fire_produces_clean_scorecard(
    http_client, laravel_target_url, hardened_target_url
) -> None:
    config = EngagementConfig(
        client_id="lab_client",
        scope_ip_ranges=["10.0.0.0/30"],
        scope_domains=["lab-target.invalid", "hardened.invalid"],
        targets=[
            TargetSpec(url=laravel_target_url, host="lab-target.invalid",
                       ground_truth_vulnerable=True),
            TargetSpec(url=hardened_target_url, host="hardened.invalid",
                       ground_truth_vulnerable=False),
        ],
    )

    results = run_live_fire(
        config,
        auth=AuthorizationStateMachine(),
        http_client=http_client,
        orchestrator=_orchestrator(),
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
    )

    # Keyed by URL — the canonical target identity.
    by_url = {r.url: r.predicted_vulnerable for r in results}
    assert by_url[laravel_target_url] is True     # detected -> TP
    assert by_url[hardened_target_url] is False    # not flagged -> TN

    score = score_findings(results, ground_truth_from_config(config))
    assert (score.tp, score.fp, score.fn, score.tn) == (1, 0, 0, 1)
    assert score.fp_rate_of_findings == 0.0
    assert score.passed is True


def test_three_targets_one_host_not_collapsed() -> None:
    """The collision Natanael hit: three targets on the SAME host (127.0.0.1,
    different ports) must each be scored. Ground truth keyed by URL keeps them
    distinct; host-keying would collapse the dict to a single entry."""
    vuln_url = "http://127.0.0.1:8081/trigger-error"
    hardened_url = "http://127.0.0.1:8082/trigger-error"
    static_url = "http://127.0.0.1:8083/"

    http_client = FakeHttpClient({
        vuln_url: FakeHttpResponse(500, LARAVEL_DEBUG_BODY, {"server": "nginx"}, vuln_url),
        hardened_url: FakeHttpResponse(500, HARDENED_BODY, {"server": "nginx"}, hardened_url),
        static_url: FakeHttpResponse(200, "<html>nginx welcome</html>",
                                     {"server": "nginx"}, static_url),
    })

    config = EngagementConfig(
        client_id="internal_lab",
        scope_ip_ranges=["127.0.0.1/32"],
        scope_domains=[],
        targets=[
            TargetSpec(url=vuln_url, host="127.0.0.1", ground_truth_vulnerable=True),
            TargetSpec(url=hardened_url, host="127.0.0.1", ground_truth_vulnerable=False),
            TargetSpec(url=static_url, host="127.0.0.1", ground_truth_vulnerable=False),
        ],
    )

    gt = ground_truth_from_config(config)
    assert len(gt) == 3   # NOT collapsed by the shared host

    results = run_live_fire(
        config,
        auth=AuthorizationStateMachine(),
        http_client=http_client,
        orchestrator=_orchestrator(),
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
    )

    score = score_findings(results, gt)
    assert (score.tp, score.fp, score.fn, score.tn) == (1, 0, 0, 2)
    assert score.passed is True
