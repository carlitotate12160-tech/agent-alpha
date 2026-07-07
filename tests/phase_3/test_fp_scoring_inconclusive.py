"""Contract: inconclusive scoring for non-analyzable targets.

A FAILED Alpha run (status == FAILED in the HandoffPayload) must NEVER be
bucketed into tp/fp/fn/tn — that silently masks a broken analysis as a
confident "not vulnerable" (the confusion-matrix bug).

Instead, the target is marked ``analyzable=False`` and counted as
``inconclusive`` in the ScanScore.  Any non-zero inconclusive count blocks
a PASS verdict.

Four tests:
  1. A single FAILED target → inconclusive == 1, tp/fp/fn/tn == 0.
  2. Inconclusive + a real TP → still FAIL (inconclusive > 0 blocks).
  3. All-analyzable run unaffected (regression guard).
  4. All targets inconclusive → FAIL, zero confusion-matrix counts.
"""

from __future__ import annotations

from agent_alpha.live_fire.scoring import ScanScore, TargetResult, score_findings


# ── Helpers ────────────────────────────────────────────────────────────


def _gt(*urls_and_vuln: tuple[str, bool]) -> dict[str, bool]:
    """Compact ground-truth builder."""
    return {url: vuln for url, vuln in urls_and_vuln}


# ── Tests ──────────────────────────────────────────────────────────────


def test_single_failed_target_is_inconclusive_not_tn() -> None:
    """A FAILED target must be inconclusive — never a confident TN."""
    results = [
        TargetResult(url="http://t/1", predicted_vulnerable=False, analyzable=False),
    ]
    gt = _gt(("http://t/1", False))

    score = score_findings(results, gt)

    assert score.inconclusive == 1
    assert (score.tp, score.fp, score.fn, score.tn) == (0, 0, 0, 0)
    assert score.passed is False


def test_inconclusive_blocks_pass_even_with_real_tp() -> None:
    """Even a clean TP alongside cannot rescue an inconclusive target."""
    results = [
        TargetResult(url="http://t/vuln", predicted_vulnerable=True, analyzable=True),
        TargetResult(url="http://t/broken", predicted_vulnerable=False, analyzable=False),
    ]
    gt = _gt(("http://t/vuln", True), ("http://t/broken", False))

    score = score_findings(results, gt)

    assert score.tp == 1
    assert score.inconclusive == 1
    # The FP rate is fine, there IS a finding — but inconclusive blocks.
    assert score.fp_rate_of_findings == 0.0
    assert score.passed is False


def test_all_analyzable_run_unaffected() -> None:
    """Regression: when every target is analyzable, semantics are unchanged."""
    results = [
        TargetResult(url="http://t/vuln", predicted_vulnerable=True),   # TP
        TargetResult(url="http://t/clean", predicted_vulnerable=False),  # TN
    ]
    gt = _gt(("http://t/vuln", True), ("http://t/clean", False))

    score = score_findings(results, gt)

    assert score.inconclusive == 0
    assert (score.tp, score.fp, score.fn, score.tn) == (1, 0, 0, 1)
    assert score.passed is True


def test_all_targets_inconclusive_is_fail() -> None:
    """If every target failed analysis, the run is a total wash — FAIL."""
    results = [
        TargetResult(url="http://t/a", predicted_vulnerable=False, analyzable=False),
        TargetResult(url="http://t/b", predicted_vulnerable=True, analyzable=False),
    ]
    gt = _gt(("http://t/a", True), ("http://t/b", False))

    score = score_findings(results, gt)

    assert score.inconclusive == 2
    assert (score.tp, score.fp, score.fn, score.tn) == (0, 0, 0, 0)
    assert score.fp_rate_of_findings == 0.0
    assert score.passed is False
