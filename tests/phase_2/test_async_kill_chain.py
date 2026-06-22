"""C6a contract: async kill chain (Shape B) — the Celery worker runs the REAL
Alpha→Omega recon pipeline and reproduces the synchronous Phase-2 e2e result,
hermetically.

Celery args are json-only (C1.7), so the worker builds its heavy deps in-process
via `recon_runner` seams. Here those seams are monkeypatched to the SAME fakes the
sync e2e uses (FakeHttpClient + a stub provider; the laravel finding comes from the
RULE-tier playbook, no LLM). This proves the async path populates the graph + emits
RUN_COMPLETED + yields a grounded report — with no live target. Per-unit fan-out
execution + live-fire FP<20% are C6b.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_2/test_async_kill_chain.py -v
"""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.omega.roaster import Omega
from agent_alpha.conductor import main as m
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"


class _StubProvider:
    """No-LLM stand-in: the laravel finding is RULE-tier, so complete() is never
    the deciding factor; it returns an empty decision if ever called."""

    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object) -> object:
        return type(
            "R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "deepseek-v4-pro"}
        )()


# ── resolve_recon_targets (real seam, unit) ───────────────────────────


def test_resolve_targets_from_verified_scope_domains() -> None:
    record = type(
        "_R",
        (),
        {"engagement_id": "e", "scope": Scope(ip_ranges=[], domains=["a.invalid", "b.invalid"], exclusions=[])},
    )()
    assert recon_runner.resolve_recon_targets(record) == [
        "https://a.invalid",
        "https://b.invalid",
    ]


def test_resolve_targets_empty_scope_raises() -> None:
    record = type(
        "_R",
        (),
        {"engagement_id": "e", "scope": Scope(ip_ranges=["10.0.0.0/30"], domains=[], exclusions=[])},
    )()
    with pytest.raises(recon_runner.NoTargetsError):
        recon_runner.resolve_recon_targets(record)


# ── async worker runs the real pipeline (integration) ─────────────────


def test_async_worker_runs_real_recon_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    celery_eager_config: None,
    http_client: object,
    laravel_target_url: str,
) -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", "lab-target.invalid", tenant_id="tenant_a")
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=["lab-target.invalid"], exclusions=[]),
    )
    # Route the worker's tenant store to ours (same pattern as existing worker tests).
    m.store_provider._stores["tenant_a"] = store

    graph = NetworkXGraphStore()
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR), provider=_StubProvider()
    )

    def fake_build(
        engagement_id: str, tenant_id: str | None, auth_: object, store_: object
    ) -> recon_runner.ReconPipeline:
        alpha = Alpha(
            authorization=auth_,
            graph_store=graph,
            event_store=store_,
            orchestrator=orchestrator,
            http_client=http_client,
        )
        return recon_runner.ReconPipeline(alpha=alpha, graph_store=graph)

    monkeypatch.setattr(recon_runner, "build_recon_pipeline", fake_build)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [laravel_target_url])

    result = m.run_engagement_task(rec.engagement_id, "tenant_a")

    # The async path completed by running the real scan (not a stub status).
    assert result["status"] == "completed"
    assert graph.node_count() >= 1  # Alpha really populated the graph
    assert laravel_target_url in http_client.calls  # Alpha actually READ the target (#3)

    completed = [
        e
        for e in store.get_events(rec.engagement_id)
        if e.event_type == EventType.ENGAGEMENT_RUN_COMPLETED
    ]
    assert len(completed) == 1
    assert completed[0].payload["node_count"] >= 1

    # Reproduces the sync e2e finding: a grounded report, not a fabrication.
    report = Omega(graph).generate_report(style="technical")
    assert "laravel" in report.narrative.lower()


def test_async_worker_refuses_unauthorized(celery_eager_config: None) -> None:
    """No recon clearance → the gate refuses BEFORE any pipeline runs (no completed)."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", "lab-target.invalid", tenant_id="tenant_b")
    # CREATED state — never enable_recon.
    m.store_provider._stores["tenant_b"] = store

    result = m.run_engagement_task(rec.engagement_id, "tenant_b")

    assert result["status"] == "refused"
    assert auth.can_agent_proceed(a2a_pb2.ALPHA, rec.engagement_id) is False
    assert not [
        e
        for e in store.get_events(rec.engagement_id)
        if e.event_type == EventType.ENGAGEMENT_RUN_COMPLETED
    ]
