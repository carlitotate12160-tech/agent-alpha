"""FROZEN contract (architect-authored — IDE implements to pass; do NOT edit assertions).

Closes two review findings on the Flaw-1 fix (time_to_first_proof_s wiring):

  Nit 1 — main.py run_omega's projection wiring is UNTESTED. `execute_agent` is
          tested with a FAKE agent_factory, so the REAL run_omega closure in
          main.py (which projects + threads the metric) is never exercised —
          coverage shows main.py lines ~374-395 missing. It is wired but no test
          crosses it: the same dead-seam class (#2) reborn one level up, and it
          can silently regress to None.

  Nit 2 — the projection logic is DUPLICATED in production. recon_runner has a
          private `_project_time_to_first_proof`, while main.py run_omega
          re-inlines `EngagementMemoryProjector(...).project(...)`. Same logic,
          two copies (seed of #7), and one is a private reached across modules.

Root cause of both: run_omega is a closure buried inside the Celery task body,
needing the whole task (DEEPSEEK_API_KEY, secrets provider, LLM orchestrator)
just to construct — untestable in isolation (mini-#8). The fix is the same move
the team already made for `execute_agent`: extract the report-building step into
ONE testable seam that BOTH call sites use.

Contract the IDE implements:
    agent_alpha/conductor/reporting.py

    def build_engagement_report(
        graph_store: Any,
        store: EventStore,
        engagement_id: str,
        *,
        style: str = "technical",
    ) -> Report:
        '''Project time_to_first_proof_s from the event stream (via the EXISTING
        EngagementMemoryProjector — do NOT add a new projector, #6) and return the
        Omega report with it threaded in. None stays None (anti-#3).'''

Then BOTH callers delegate to it and stop projecting themselves:
  * recon_runner.run_recon_for_engagement -> report = build_engagement_report(...)
    (drop the private _project_time_to_first_proof helper)
  * main.py run_omega -> report = build_engagement_report(...)
    (drop the inline EngagementMemoryProjector construction)

This makes the metric threading testable in ONE place and removes the duplicate,
so the untested run_omega path can no longer silently drop the headline.

NOTE (separate cleanup, not pinned here): tests/phase_3/test_recon_time_to_proof_wiring.py
and tests/integration/test_recon_report_time_to_proof_wiring.py pin the SAME recon
seam (duplicate, #6-adjacent) — keep one, delete the other.

Authoritative run: Oracle ARM64 (`.venv/bin/python3 -m pytest`).
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest import mock

import agent_alpha.conductor.main as main_mod
import agent_alpha.conductor.recon_runner as recon_mod
from agent_alpha.agents.omega.roaster import format_duration
from agent_alpha.conductor.reporting import build_engagement_report
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore

ENG_ID = "eng-report-builder-001"


def _seed(store: InMemoryEventStore, *, proof_after_s: int | None) -> None:
    """ENGAGEMENT_CREATED at T0, optionally PROOF_ARTIFACT_RECORDED at T0+proof_after_s."""
    stamps = ["2024-01-01T00:00:00Z"]
    if proof_after_s is not None:
        stamps.append(f"2024-01-01T00:{proof_after_s // 60:02d}:{proof_after_s % 60:02d}Z")
    with mock.patch("agent_alpha.events.store._utcnow") as mock_utcnow:
        mock_utcnow.side_effect = stamps
        store.append(EventType.ENGAGEMENT_CREATED, ENG_ID, "system", {})
        if proof_after_s is not None:
            store.append(
                EventType.PROOF_ARTIFACT_RECORDED, ENG_ID, "alpha", {"artifact_type": "screenshot"}
            )


def test_build_engagement_report_threads_time_to_proof() -> None:
    """A proof 90s after creation surfaces as a non-None time_to_proof_headline."""
    store = InMemoryEventStore()
    _seed(store, proof_after_s=90)

    report = build_engagement_report(NetworkXGraphStore(), store, ENG_ID)

    assert report.time_to_first_proof_s == 90.0
    assert report.time_to_proof_headline() == format_duration(90.0)
    assert report.time_to_proof_headline() is not None


def test_build_engagement_report_headline_none_when_no_proof() -> None:
    """No proof event -> metric None -> headline None (anti-#3, no fabricated success)."""
    store = InMemoryEventStore()
    _seed(store, proof_after_s=None)

    report = build_engagement_report(NetworkXGraphStore(), store, ENG_ID)

    assert report.time_to_first_proof_s is None
    assert report.time_to_proof_headline() is None


def test_build_engagement_report_defaults_to_technical_style() -> None:
    """Default style is 'technical' (matches the live callers) and renders."""
    store = InMemoryEventStore()
    _seed(store, proof_after_s=None)

    report = build_engagement_report(NetworkXGraphStore(), store, ENG_ID)

    assert report.narrative  # non-empty narrative rendered, no crash


# ── Dedup + wiring gate: BOTH callers must use the shared seam, neither may ──────
# ── re-project on its own. This is what makes the buried run_omega path safe. ────


def _calls_function(source: str, func_name: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == func_name:
                return True
            if isinstance(f, ast.Attribute) and f.attr == func_name:
                return True
    return False


def _constructs_projector(source: str) -> bool:
    """True if the module still constructs EngagementMemoryProjector(...) itself."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == "EngagementMemoryProjector":
                return True
            if isinstance(f, ast.Attribute) and f.attr == "EngagementMemoryProjector":
                return True
    return False


def test_recon_runner_uses_shared_builder_and_does_not_reproject() -> None:
    src = Path(recon_mod.__file__).read_text(encoding="utf-8")
    assert _calls_function(src, "build_engagement_report"), (
        "recon_runner must delegate report construction to build_engagement_report, "
        "not project time_to_first_proof itself."
    )
    assert not _constructs_projector(src), (
        "recon_runner must not construct EngagementMemoryProjector directly anymore "
        "(the projection now lives once, inside build_engagement_report)."
    )


def test_omega_exec_path_uses_shared_builder_and_does_not_reproject() -> None:
    """Pins the untested main.py run_omega closure to the shared seam (Nit 1)."""
    src = Path(main_mod.__file__).read_text(encoding="utf-8")
    assert _calls_function(src, "build_engagement_report"), (
        "main.py run_omega must call build_engagement_report so its metric threading "
        "is exercised by the shared seam's tests (the closure itself is untestable "
        "in isolation)."
    )
    assert not _constructs_projector(src), (
        "main.py must not inline EngagementMemoryProjector in run_omega anymore — "
        "that duplicate projection is the #7 seed this change removes."
    )
