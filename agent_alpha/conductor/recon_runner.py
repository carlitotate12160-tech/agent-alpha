# agent_alpha/conductor/recon_runner.py
"""C6a — the recon run pipeline executed inside the Celery worker (Shape B).

Wires the Phase-2 Alpha→Omega flow into the async run path. Celery args are
json-only (C1.7), so the worker cannot receive live dependencies (HttpClient, LLM
provider, graph store) over `.delay()`; they are built HERE, in-process. The two
seams — `build_recon_pipeline` and `resolve_recon_targets` — are module-level so a
hermetic test monkeypatches them to inject the same fakes the synchronous Phase-2
e2e uses (no live target, no LLM). Per-unit fan-out execution (via FanOutDispatcher)
and the live-fire FP<20% gate are C6b.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass
from typing import Any

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.agents.omega.roaster import Omega, Report
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import EventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.llm.routing import resolve_reasoning_provider
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"


class NoTargetsError(ValueError):
    """The engagement's verified scope yielded no scan targets. An empty recon is
    not a silent success (anti-Lyndon #3) — the worker records a failure instead."""


@dataclass(frozen=True)
class ReconPipeline:
    """The live recon agent plus the graph it populates (one per worker run)."""

    alpha: Any
    graph_store: Any


@dataclass(frozen=True)
class ReconRunResult:
    """Opaque run metadata — never findings/report body (C1.8)."""

    node_count: int
    report: Report
    targets_scanned: int


def build_recon_pipeline(
    engagement_id: str,
    tenant_id: str | None,
    auth: AuthorizationStateMachine,
    store: EventStore,
) -> ReconPipeline:
    """Construct a real recon pipeline (Alpha + its own graph) for one worker run.

    Heavy deps are built in-process because Celery args are json-only (C1.7). This
    is exercised for real under C6b live-fire; hermetic tests monkeypatch this seam.
    """
    http_client = HttpClient(engagement_id=engagement_id)
    provider = resolve_reasoning_provider(api_key=os.environ["DEEPSEEK_API_KEY"])
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider)
    graph_store = NetworkXGraphStore()
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=store,
        orchestrator=orchestrator,
        http_client=http_client,
    )
    return ReconPipeline(alpha=alpha, graph_store=graph_store)


def resolve_recon_targets(record: Any) -> list[str]:
    """Derive concrete scan URLs from an engagement's VERIFIED scope domains.

    Deterministic + order-preserving. The scope (set behind the auth gate) is the
    only source of targets — never free-form caller input. Empty → NoTargetsError
    (no silent no-op).
    """
    scope = getattr(record, "scope", None)
    domains = list(scope.domains) if scope is not None else []
    urls = [f"https://{d.strip()}" for d in domains if d and d.strip()]
    if not urls:
        raise NoTargetsError(
            f"engagement {getattr(record, 'engagement_id', '?')!r} has no in-scope recon targets"
        )
    return urls


def run_recon_for_engagement(
    engagement_id: str,
    tenant_id: str | None,
    auth: AuthorizationStateMachine,
    store: EventStore,
    record: Any,
) -> ReconRunResult:
    """Scan every in-scope target with Alpha, then produce the Omega report.

    Shape B (single-task): one worker scans all of the engagement's targets in
    sequence and aggregates into ONE graph + the one event stream. Returns opaque
    metadata only; the worker keeps findings/report OUT of the Celery result
    backend (C1.8).
    """
    pipeline = build_recon_pipeline(engagement_id, tenant_id, auth, store)
    targets = resolve_recon_targets(record)
    for url in targets:
        pipeline.alpha.run_recon(engagement_id, url)
    report = Omega(pipeline.graph_store).generate_report(style="technical")
    return ReconRunResult(
        node_count=pipeline.graph_store.node_count(),
        report=report,
        targets_scanned=len(targets),
    )
