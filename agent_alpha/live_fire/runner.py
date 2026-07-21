# agent_alpha/live_fire/runner.py
"""Live-fire runner — ties the whole Phase 2 pipeline together.

Two layers:
  * ``run_live_fire(...)`` — hermetic, injected-dependency (tested with fakes).
  * ``main()`` — builds REAL HttpClient + reasoning provider (via
    ``resolve_reasoning_provider``, ADR §12.15) from config + env
    (operational, not unit-tested).

Reuses canonical types only — never redeclares (anti-Lyndon #6).
"""

from __future__ import annotations

import argparse
import os
import pathlib
from dataclasses import dataclass
from typing import Any

import yaml

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.agents.omega.roaster import Omega
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config.constants import MAX_FP_RATE
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.scoring import TargetResult, score_findings
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.llm.routing import resolve_reasoning_provider
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

# ── Data classes ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class TargetSpec:
    """A single target in an engagement config."""

    url: str
    host: str
    ground_truth_vulnerable: bool


@dataclass(frozen=True)
class EngagementConfig:
    """Parsed engagement config (authorized scope + targets + ground truth)."""

    client_id: str
    scope_ip_ranges: list[str]
    scope_domains: list[str]
    targets: list[TargetSpec]


# ── Config loading ────────────────────────────────────────────────────


def load_engagement_config(path: str | pathlib.Path) -> EngagementConfig:
    """Load and validate an engagement config from a YAML file.

    Raises ``ValueError`` if required keys are missing or malformed.
    """
    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"engagement config must be a YAML mapping, got {type(data).__name__}")

    # Required top-level keys
    for key in ("client_id", "scope", "targets"):
        if key not in data:
            raise ValueError(f"engagement config missing required key: {key!r}")

    scope = data["scope"]
    if not isinstance(scope, dict):
        raise ValueError("engagement config 'scope' must be a mapping")
    for key in ("ip_ranges", "domains"):
        if key not in scope:
            raise ValueError(f"engagement config scope missing required key: {key!r}")

    targets_raw = data["targets"]
    if not isinstance(targets_raw, list):
        raise ValueError("engagement config 'targets' must be a list")

    targets: list[TargetSpec] = []
    for i, t in enumerate(targets_raw):
        if not isinstance(t, dict):
            raise ValueError(f"target #{i} must be a mapping")
        for key in ("url", "host", "ground_truth_vulnerable"):
            if key not in t:
                raise ValueError(f"target #{i} missing required key: {key!r}")
        targets.append(
            TargetSpec(
                url=t["url"],
                host=t["host"],
                ground_truth_vulnerable=bool(t["ground_truth_vulnerable"]),
            )
        )

    return EngagementConfig(
        client_id=data["client_id"],
        scope_ip_ranges=list(scope["ip_ranges"]),
        scope_domains=list(scope["domains"]),
        targets=targets,
    )


def ground_truth_from_config(config: EngagementConfig) -> dict[str, bool]:
    """Extract ground-truth mapping {url: vulnerable?} from config.

    Keyed by URL, not host: two targets may share a host (different
    ports/paths) and must remain distinct (anti-Lyndon #3 collision).
    """
    return {t.url: t.ground_truth_vulnerable for t in config.targets}


# ── Hermetic runner (tested with fakes) ───────────────────────────────


def run_live_fire(
    config: EngagementConfig,
    *,
    auth: Any,
    http_client: Any,
    orchestrator: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any = None,
) -> list[TargetResult]:
    """Run the live-fire pipeline: authorize → recon each target → predict.

    Creates its own engagement and enables RECON_ONLY scope on the
    supplied ``auth`` (the test passes a fresh AuthorizationStateMachine).

    Returns a list of :class:`TargetResult` — one per target in ``config``.
    """
    # ── Authorize engagement ─────────────────────────────────────
    rec = auth.create_engagement(
        client_id=config.client_id,
        target=config.targets[0].host if config.targets else "",
    )
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=config.scope_ip_ranges,
            domains=config.scope_domains,
            exclusions=[],
        ),
    )

    # ── Build Alpha with injected dependencies ───────────────────
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )

    # ── Run recon per target and derive predictions ──────────────
    results: list[TargetResult] = []
    for t in config.targets:
        msg = alpha.run_recon(rec.engagement_id, t.url)
        payload = a2a_pb2.HandoffPayload()
        payload.ParseFromString(msg.payload)
        analyzable = payload.status != a2a_pb2.FAILED
        results.append(
            TargetResult(
                url=t.url,
                predicted_vulnerable=payload.findings_count > 0,
                analyzable=analyzable,
            )
        )

    return results


# ── Operational entry point (not unit-tested) ─────────────────────────


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: read config, run pipeline, print scorecard."""
    parser = argparse.ArgumentParser(description="Agent-Alpha live-fire runner")
    parser.add_argument("config", help="Path to engagement YAML config")
    args = parser.parse_args(argv)

    # ── Load config ──────────────────────────────────────────────
    config = load_engagement_config(args.config)

    # ── Lab-only guard: refuse client/prod domains ─────────────────────────────
    from agent_alpha.live_fire.lab_guard import assert_lab_only_target

    for target in config.targets:
        assert_lab_only_target(target.url)
        assert_lab_only_target(target.host)

    # ── Build real dependencies ──────────────────────────────────
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    http_client = HttpClient(engagement_id=config.client_id)

    api_key = os.environ["DEEPSEEK_API_KEY"]
    # Reasoning role -> provider is config-only (ADR §12.15 / C2).
    provider = resolve_reasoning_provider(api_key=api_key)

    playbook_dir = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"
    playbook_engine = PlaybookEngine.from_directory(playbook_dir)
    orchestrator = LLMOrchestrator(playbook_engine, provider)

    graph_store = NetworkXGraphStore()
    secrets_manager = SecretsManager()

    # ── Run pipeline ─────────────────────────────────────────────
    results = run_live_fire(
        config,
        auth=auth,
        http_client=http_client,
        orchestrator=orchestrator,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
    )

    # ── Score findings ───────────────────────────────────────────
    gt = ground_truth_from_config(config)
    score = score_findings(results, gt)

    # ── Generate report (console-only in Slice A; PDF lives in Slice C) ─────
    report = Omega(graph_store).generate_report("technical")
    report_path = pathlib.Path("./report.pdf")

    # ── Print scorecard ──────────────────────────────────────────
    print("=" * 60)
    print("LIVE-FIRE SCORECARD")
    print("=" * 60)
    print(f"  TP: {score.tp}   FP: {score.fp}   FN: {score.fn}   TN: {score.tn}")
    print(f"  Inconclusive:        {score.inconclusive}")
    print(f"  FP rate of findings: {score.fp_rate_of_findings:.4f}")
    print(f"  MAX_FP_RATE:         {MAX_FP_RATE:.4f}")
    verdict = "PASS" if score.passed else "FAIL"
    print(f"  Verdict:             {verdict}")
    print(f"  Report target (PDF deferred to Slice C): {report_path.resolve()}")
    print("=" * 60)

    return 0 if score.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
