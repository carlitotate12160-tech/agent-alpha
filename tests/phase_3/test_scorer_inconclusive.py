"""FROZEN contract (architect-authored — IDE implements; do NOT edit assertions).

Anti-Lyndon #3 in the FP-validation scorer, surfaced by the live FP-run:

    [ALPHA/ORIENT] Could not orient on <hardened target>: LLM decision failed; non-analyzable

`run_live_fire` derives `predicted_vulnerable = payload.findings_count > 0` and IGNORES the
handoff status. A non-analyzable run (Alpha status FAILED — LLM/orient failure, unreachable,
empty body) has findings_count == 0, so it is silently scored as "not vulnerable" — identical
to a target that WAS analyzed and found clean. On the FP-run this produced a laravel-hardened
TN that validated nothing (the probe never analyzed the page; the LLM call failed). On a
VULNERABLE target the same path would mask a false negative as "clean" — the exact
false-success pattern the project forbids.

Contract the IDE implements:
  * TargetResult gains `analyzable: bool = True`.
  * run_live_fire sets analyzable=False when the Alpha handoff status is FAILED (non-analyzable),
    and does NOT report such a target as a confident prediction.
  * ScanScore gains `inconclusive: int`. score_findings counts a non-analyzable result as
    INCONCLUSIVE — never as TP/FP/FN/TN.
  * passed requires inconclusive == 0: you cannot claim an FP rate over targets that could not
    be analyzed. (A non-analyzable target is an operator problem to fix, not a silent pass.)

RED today: TargetResult has no `analyzable` field and ScanScore has no `inconclusive` field, so
a FAILED run is counted as a clean TN/FN.

Authoritative run: Oracle ARM64.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.runner import EngagementConfig, TargetSpec, run_live_fire
from agent_alpha.live_fire.scoring import TargetResult, score_findings
from agent_alpha.llm.orchestrator import OrientationError

# ── #b-1: the scorer must not count a non-analyzable target as a clean prediction ──


def test_non_analyzable_target_is_inconclusive_not_a_clean_tn() -> None:
    """A non-analyzable result is INCONCLUSIVE — not a TN — and blocks PASS.

    Without this, an FP-run 'passes' while a control target was never actually analyzed
    (the false-success pattern the live run exposed on laravel-hardened).
    """
    results = [
        TargetResult(url="https://vuln.invalid/", predicted_vulnerable=True, analyzable=True),
        TargetResult(
            url="https://could-not-analyze.invalid/",
            predicted_vulnerable=False,
            analyzable=False,
        ),
    ]
    ground_truth = {
        "https://vuln.invalid/": True,
        "https://could-not-analyze.invalid/": False,
    }

    score = score_findings(results, ground_truth)

    assert score.inconclusive == 1, "a non-analyzable target must be counted inconclusive."
    assert score.tn == 0, (
        "a non-analyzable target must NOT be scored as a clean TN — it was never analyzed."
    )
    assert score.passed is False, (
        "PASS must be blocked while any target is inconclusive: you cannot claim an FP rate "
        "over targets that could not be analyzed."
    )


def test_analyzable_clean_target_still_counts_as_tn() -> None:
    """Guard against over-correction: an ANALYZED clean target is still a real TN."""
    results = [
        TargetResult(url="https://vuln.invalid/", predicted_vulnerable=True, analyzable=True),
        TargetResult(url="https://clean.invalid/", predicted_vulnerable=False, analyzable=True),
    ]
    ground_truth = {"https://vuln.invalid/": True, "https://clean.invalid/": False}

    score = score_findings(results, ground_truth)

    assert score.inconclusive == 0
    assert score.tn == 1
    assert score.passed is True


# ── #b-2: run_live_fire must mark a FAILED (non-analyzable) Alpha run ─────────────


@dataclass
class _Resp:
    status_code: int = 200
    text: str = "<html>some analyzable body</html>"
    headers: dict[str, str] = field(default_factory=dict)


class _FakeHttp:
    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        return _Resp()


class _RaisingOrchestrator:
    """ORIENT always fails (mirrors the live 'LLM decision failed' path)."""

    def decide(self, observation: dict[str, object]) -> Any:
        raise OrientationError("simulated orient failure")


def test_run_live_fire_marks_failed_run_non_analyzable() -> None:
    host = "could-not-analyze.invalid"
    config = EngagementConfig(
        client_id="inconclusive-test",
        scope_ip_ranges=[],
        scope_domains=[host],
        targets=[
            TargetSpec(url=f"https://{host}/", host=host, ground_truth_vulnerable=False),
        ],
    )
    event_store = InMemoryEventStore()

    results = run_live_fire(
        config,
        auth=AuthorizationStateMachine(event_store=event_store),
        http_client=_FakeHttp(),
        orchestrator=_RaisingOrchestrator(),
        graph_store=NetworkXGraphStore(),
        event_store=event_store,
    )

    assert len(results) == 1
    assert results[0].analyzable is False, (
        "a target whose Alpha run was non-analyzable (status FAILED) must be marked "
        "analyzable=False, not reported as a confident not-vulnerable prediction."
    )


def test_sanity_alpha_failed_status_is_the_signal() -> None:
    """Documents the signal run_live_fire keys on: a non-analyzable run -> FAILED handoff."""
    host = "could-not-analyze.invalid"
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    from agent_alpha.conductor.authorization import Scope

    rec = auth.create_engagement(client_id="c", target=host)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=[host], exclusions=[], db_endpoints=[]),
    )
    from agent_alpha.agents.alpha.scout import Alpha

    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=event_store,
        orchestrator=_RaisingOrchestrator(),
        http_client=_FakeHttp(),
    )
    msg = alpha.run_recon(rec.engagement_id, f"https://{host}/")
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    assert payload.status == a2a_pb2.FAILED
