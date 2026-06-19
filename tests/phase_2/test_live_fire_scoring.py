"""Contract: live-fire scoring.

Two contract changes captured here:

1. Target identity is the URL, NOT the host. Multiple targets can share a host
   (different ports/paths); host-keying silently collapses them (the collision
   Natanael hit running three loopback targets on 127.0.0.1).

2. A PASS requires at least one real finding. A zero-finding run is NOT a pass:
   fp_rate = 0/0 = 0.0 < 0.20 previously reported a false PASS (anti-Lyndon #3,
   empty result dressed as success).

"FP rate in findings" stays FP / (TP + FP). Threshold from constants.
"""

from __future__ import annotations

import pytest

from agent_alpha.config import constants
from agent_alpha.live_fire.scoring import TargetResult, score_findings


def test_mixed_results_compute_correct_confusion_matrix() -> None:
    results = [
        TargetResult(url="https://h/a", predicted_vulnerable=True),   # actual True  -> TP
        TargetResult(url="https://h/b", predicted_vulnerable=False),  # actual False -> TN
        TargetResult(url="https://h/c", predicted_vulnerable=True),   # actual False -> FP
    ]
    ground_truth = {"https://h/a": True, "https://h/b": False, "https://h/c": False}

    score = score_findings(results, ground_truth)

    assert (score.tp, score.fp, score.fn, score.tn) == (1, 1, 0, 1)
    assert score.fp_rate_of_findings == 0.5      # 1 of 2 findings false
    assert score.passed is False                 # 0.5 not < 0.20


def test_clean_run_with_a_real_finding_passes() -> None:
    results = [
        TargetResult(url="http://127.0.0.1:8081/trigger-error", predicted_vulnerable=True),   # TP
        TargetResult(url="http://127.0.0.1:8082/trigger-error", predicted_vulnerable=False),  # TN
        TargetResult(url="http://127.0.0.1:8083/", predicted_vulnerable=False),               # TN
    ]
    ground_truth = {
        "http://127.0.0.1:8081/trigger-error": True,
        "http://127.0.0.1:8082/trigger-error": False,
        "http://127.0.0.1:8083/": False,
    }

    score = score_findings(results, ground_truth)

    assert (score.tp, score.fp, score.fn, score.tn) == (1, 0, 0, 2)
    assert score.fp_rate_of_findings == 0.0
    assert score.passed is True                  # TP>=1 and fp_rate < 0.20


def test_same_host_distinct_urls_are_scored_independently() -> None:
    """The bug Natanael found: three targets on ONE host must each be scored
    when keyed by URL — host-keying would collapse the ground-truth dict."""
    results = [
        TargetResult(url="http://127.0.0.1:8081/trigger-error", predicted_vulnerable=True),
        TargetResult(url="http://127.0.0.1:8082/trigger-error", predicted_vulnerable=False),
        TargetResult(url="http://127.0.0.1:8083/", predicted_vulnerable=False),
    ]
    ground_truth = {
        "http://127.0.0.1:8081/trigger-error": True,
        "http://127.0.0.1:8082/trigger-error": False,
        "http://127.0.0.1:8083/": False,
    }

    score = score_findings(results, ground_truth)

    assert score.tp + score.fp + score.fn + score.tn == 3   # not collapsed to 1
    assert (score.tp, score.tn) == (1, 2)


def test_zero_findings_is_not_a_silent_pass() -> None:
    """No findings at all -> NOT a pass (the false-success bug)."""
    results = [
        TargetResult(url="http://127.0.0.1:8082/trigger-error", predicted_vulnerable=False),
        TargetResult(url="http://127.0.0.1:8083/", predicted_vulnerable=False),
    ]
    ground_truth = {
        "http://127.0.0.1:8082/trigger-error": False,
        "http://127.0.0.1:8083/": False,
    }

    score = score_findings(results, ground_truth)

    assert (score.tp, score.fp) == (0, 0)
    assert score.fp_rate_of_findings == 0.0      # no division error
    assert score.passed is False                 # but nothing was found -> not a pass


def test_no_findings_with_a_miss_is_not_pass() -> None:
    """Predicted-clean but actually vulnerable (FN) -> not a pass."""
    results = [TargetResult(url="https://vuln/x", predicted_vulnerable=False)]
    ground_truth = {"https://vuln/x": True}

    score = score_findings(results, ground_truth)

    assert (score.tp, score.fp, score.fn, score.tn) == (0, 0, 1, 0)
    assert score.passed is False


def test_threshold_comes_from_constants() -> None:
    assert constants.MAX_FP_RATE == 0.20


def test_missing_url_raises_keyerror() -> None:
    """Anti-Lyndon #3: a result URL absent from ground_truth raises KeyError."""
    results = [TargetResult(url="https://a/1", predicted_vulnerable=True)]
    ground_truth = {"https://b/2": True}  # the result URL is missing

    with pytest.raises(KeyError):
        score_findings(results, ground_truth)
