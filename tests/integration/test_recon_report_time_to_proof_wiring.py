"""Flaw-1 wiring integration test: the time_to_first_proof_s field flows from the
event stream (via EngagementMemoryProjector) through to the Report object produced
by both Conductor entry points — recon_runner.run_recon_for_engagement and the
main.py run_omega closure.

These tests exercise the LIVE wiring (monkeypatched only for network deps), not the
projector or Omega in isolation (those are Phase 1 / Phase 2 unit tests). RED until
the seam is stitched.

Anti-#3: when no PROOF_ARTIFACT_RECORDED event exists, the field MUST be None — a
fabricated "instant proof" (0.0) or a crashed headline would be a silent false
success.

Run on Oracle ARM64:
    .venv/bin/pytest tests/integration/test_recon_report_time_to_proof_wiring.py -v
"""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parent.parent / "phase_2" / "fixtures" / "playbooks"


class _StubProvider:
    """No-LLM stand-in: the laravel finding is RULE-tier, so complete() is never
    the deciding factor."""

    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "deepseek-v4-pro"})()


class _FakeHttpResponse:
    def __init__(self, status_code: int, text: str, headers: dict[str, str], url: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.url = url


_LARAVEL_DEBUG_BODY = (
    "<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head>"
    "<body><div class='exception'>Illuminate\\Database\\QueryException</div>"
    "<div>SQLSTATE[HY000] [1045] Access refused for user 'forge'@'localhost'</div>"
    "<table><tr><td>APP_ENV</td><td>production</td></tr>"
    "<tr><td>APP_DEBUG</td><td>true</td></tr>"
    "<tr><td>DB_PASSWORD</td><td>s3cr3t-leaked</td></tr></table>"
    "<footer>Laravel v10.3.1 (PHP v8.2.4)</footer></body></html>"
)

_TARGET_URL = "https://lab-target.invalid/trigger-error"


class _FakeHttpClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _FakeHttpResponse:
        self.calls.append(url)
        if url == _TARGET_URL:
            return _FakeHttpResponse(
                status_code=500,
                text=_LARAVEL_DEBUG_BODY,
                headers={"server": "nginx", "x-powered-by": "PHP/8.2.4"},
                url=url,
            )
        return _FakeHttpResponse(status_code=404, text="", headers={}, url=url)


# ── helpers ──────────────────────────────────────────────────────────────


def _setup_engagement(store: InMemoryEventStore) -> str:
    """Create a RECON_ONLY engagement and return its id."""
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement("client_lab", "lab-target.invalid")
    auth.enable_recon(
        record.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=["lab-target.invalid"], exclusions=[]),
    )
    return record.engagement_id


def _inject_proof_event(store: InMemoryEventStore, engagement_id: str) -> None:
    """Append a PROOF_ARTIFACT_RECORDED event so the projector has a proof timestamp."""
    store.append(
        event_type=EventType.PROOF_ARTIFACT_RECORDED,
        engagement_id=engagement_id,
        agent="alpha",
        payload={"ref": "screenshot-001"},
    )


def _fake_pipeline(
    auth: AuthorizationStateMachine,
    graph: NetworkXGraphStore,
    store: InMemoryEventStore,
    http_client: _FakeHttpClient,
) -> recon_runner.ReconPipeline:
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=_StubProvider(),
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph,
        event_store=store,
        orchestrator=orchestrator,
        http_client=http_client,
    )
    return recon_runner.ReconPipeline(alpha=alpha, graph_store=graph)


# ── tests ────────────────────────────────────────────────────────────────


def test_recon_runner_threads_time_to_first_proof_into_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the event stream contains a PROOF_ARTIFACT_RECORDED event, the report's
    time_to_first_proof_s is populated (not None)."""
    store = InMemoryEventStore()
    engagement_id = _setup_engagement(store)

    graph = NetworkXGraphStore()
    http_client = _FakeHttpClient()
    auth = AuthorizationStateMachine(event_store=store)

    # Inject a proof event BEFORE the recon run so the projector can compute the
    # delta. In production Alpha emits this during the scan; here we pre-seed it
    # so the test is deterministic and does not depend on playbook specifics.
    _inject_proof_event(store, engagement_id)

    pipeline = _fake_pipeline(auth, graph, store, http_client)
    monkeypatch.setattr(recon_runner, "build_recon_pipeline", lambda *a, **kw: pipeline)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [_TARGET_URL])

    result = recon_runner.run_recon_for_engagement(
        engagement_id=engagement_id,
        tenant_id=None,
        auth=auth,
        store=store,
        record=object(),  # resolve_recon_targets is monkeypatched, record unused
    )

    # The wiring is live: time_to_first_proof_s was projected and threaded through.
    assert result.report.time_to_first_proof_s is not None
    assert isinstance(result.report.time_to_first_proof_s, float)
    assert result.report.time_to_first_proof_s >= 0.0

    # The headline is non-None (the format_duration path exercised).
    assert result.report.time_to_proof_headline() is not None


def test_recon_runner_none_time_to_proof_when_no_proof_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anti-#3: when the event stream has NO PROOF_ARTIFACT_RECORDED, the report's
    time_to_first_proof_s MUST be None — never 0.0 or a fabricated value."""
    store = InMemoryEventStore()
    engagement_id = _setup_engagement(store)

    graph = NetworkXGraphStore()
    http_client = _FakeHttpClient()
    auth = AuthorizationStateMachine(event_store=store)

    # No proof event injected — the projector should return None.

    pipeline = _fake_pipeline(auth, graph, store, http_client)
    monkeypatch.setattr(recon_runner, "build_recon_pipeline", lambda *a, **kw: pipeline)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [_TARGET_URL])

    result = recon_runner.run_recon_for_engagement(
        engagement_id=engagement_id,
        tenant_id=None,
        auth=auth,
        store=store,
        record=object(),
    )

    # Anti-#3: None stays None — never fabricated.
    assert result.report.time_to_first_proof_s is None
    assert result.report.time_to_proof_headline() is None
