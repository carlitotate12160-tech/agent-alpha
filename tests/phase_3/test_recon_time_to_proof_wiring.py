"""RED gate: the Conductor recon path must thread time_to_first_proof_s into Omega.

Flaw this closes (Lyndon #2 — dead code treated as done, across a seam):
    The producer (`EngagementMemoryProjector` -> EngagementMemoryRecord.
    time_to_first_proof_s) and the consumer (`Omega.generate_report(...,
    time_to_first_proof_s=...)` -> Report.time_to_proof_headline) both exist and
    are each unit-tested. But NOTHING wires them together: every live caller of
    generate_report() passes nothing, so the value is None in every real run.
    In `run_recon_for_engagement` the report is built as
    `Omega(pipeline.graph_store).generate_report(style="technical")` — the
    engagement's own proof timing is dropped on the floor. Green unit tests hid
    it because they inject the value directly and test the producer separately;
    no test crosses the handoff. The "proved in X min" headline — the whole point
    of the metric — is dead in production.

What "done" looks like (the fix this test drives, impl lane):
    `run_recon_for_engagement` already holds `store` and `engagement_id`. After
    the scan it must project the EngagementMemoryRecord from `store` (via the
    EXISTING EngagementMemoryProjector — do NOT add a new projector, Lyndon #6)
    and thread `record.time_to_first_proof_s` into generate_report:
        emr = EngagementMemoryProjector(store, InMemoryEngagementMemoryStore()).project(engagement_id)
        report = Omega(pipeline.graph_store).generate_report(
            style="technical", time_to_first_proof_s=emr.time_to_first_proof_s
        )
    (The SAME wiring is owed at main.py's run_omega and the other live callers;
    this test pins the recon path — the most testable seam — as the regression
    anchor. Extend to the other callers in the same change.)

Scope of this test (honest):
    It isolates the POST-SCAN seam. `build_recon_pipeline` and
    `resolve_recon_targets` are stubbed because target resolution and the Alpha
    scan are orthogonal to the flaw and would drag in network I/O — the untested
    gap is purely "record projection -> report threading". The producer's own
    correctness is pinned by tests/phase_1/test_engagement_time_to_proof.py and
    the consumer's by tests/phase_2/test_omega_time_to_proof.py; keep all three.

Authoritative run: Oracle ARM64 (`.venv/bin/python3 -m pytest`).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest import mock

import pytest

from agent_alpha.agents.omega.roaster import format_duration
from agent_alpha.conductor import recon_runner
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

ENG_ID = "eng-ttp-wiring-001"


class _FakeAlpha:
    """Records scans; performs no network I/O."""

    def __init__(self) -> None:
        self.scanned: list[str] = []

    def run_recon(self, engagement_id: str, url: str) -> None:
        self.scanned.append(url)


def _seed_created_then_proof(store: InMemoryEventStore, *, gap_seconds: int) -> None:
    """ENGAGEMENT_CREATED at T0, PROOF_ARTIFACT_RECORDED at T0+gap -> metric = gap."""
    with mock.patch("agent_alpha.events.store._utcnow") as mock_utcnow:
        mock_utcnow.side_effect = [
            "2024-01-01T00:00:00Z",
            f"2024-01-01T00:{gap_seconds // 60:02d}:{gap_seconds % 60:02d}Z",
        ]
        store.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})
        store.append(
            EventType.PROOF_ARTIFACT_RECORDED, ENG_ID, "alpha", {"artifact_type": "screenshot"}
        )


def _run(store: InMemoryEventStore, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Invoke run_recon_for_engagement with the scan stubbed out."""
    fake_pipeline = SimpleNamespace(alpha=_FakeAlpha(), graph_store=NetworkXGraphStore())
    monkeypatch.setattr(recon_runner, "build_recon_pipeline", lambda *a, **k: fake_pipeline)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: ["https://lab.local"])

    return recon_runner.run_recon_for_engagement(
        engagement_id=ENG_ID,
        tenant_id="tenant-a",
        auth=cast(Any, None),  # unused: build_recon_pipeline is stubbed
        store=store,
        record=cast(Any, SimpleNamespace()),  # unused: resolve_recon_targets is stubbed
        secrets_manager=None,
    )


def test_recon_report_carries_time_to_proof_headline(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED until run_recon_for_engagement threads the projected metric into Omega.

    A proof recorded 90s after creation must surface as a non-None
    time_to_proof_headline on the report the recon path returns.
    """
    store = InMemoryEventStore()
    _seed_created_then_proof(store, gap_seconds=90)

    result = _run(store, monkeypatch)

    assert result.report.time_to_proof_headline() is not None, (
        "run_recon_for_engagement dropped the engagement's proof timing: the "
        "report has no time_to_proof_headline. Project EngagementMemoryRecord "
        "from `store` and pass record.time_to_first_proof_s into generate_report."
    )
    assert result.report.time_to_proof_headline() == format_duration(90.0)


def test_recon_report_headline_none_when_no_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    """No proof event -> metric is None -> headline None (no fake success, anti-#3).

    Guards the fix against over-correcting: threading the metric must not
    fabricate a headline when the engagement has produced no proof.
    """
    store = InMemoryEventStore()
    with mock.patch("agent_alpha.events.store._utcnow") as mock_utcnow:
        mock_utcnow.side_effect = ["2024-01-01T00:00:00Z"]
        store.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})

    result = _run(store, monkeypatch)

    assert result.report.time_to_proof_headline() is None
