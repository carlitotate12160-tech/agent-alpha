# tests/phase_2/test_live_fire_scoring.py
import pytest

from agent_alpha.config.constants import MAX_FP_RATE
from agent_alpha.live_fire.scoring import ScanScore, TargetResult, score_findings


def test_mixed_tp_tn_fp():
    """Mixed results: TP, TN, FP -> counts (1,1,0,1); fp_rate_of_findings==0.5; passed False."""
    results = [
        TargetResult(host="host1", predicted_vulnerable=True),  # TP
        TargetResult(host="host2", predicted_vulnerable=False),  # TN
        TargetResult(host="host3", predicted_vulnerable=True),  # FP
    ]
    ground_truth = {
        "host1": True,  # actual vulnerable
        "host2": False,  # actual not vulnerable
        "host3": False,  # actual not vulnerable
    }

    score = score_findings(results, ground_truth)

    assert score.tp == 1
    assert score.tn == 1
    assert score.fp == 1
    assert score.fn == 0
    assert score.fp_rate_of_findings == 0.5
    assert score.passed is False


def test_clean_tp_tn_tn():
    """Clean results: TP, TN, TN -> counts (1,0,0,2); fp_rate_of_findings==0.0; passed True."""
    results = [
        TargetResult(host="host1", predicted_vulnerable=True),  # TP
        TargetResult(host="host2", predicted_vulnerable=False),  # TN
        TargetResult(host="host3", predicted_vulnerable=False),  # TN
    ]
    ground_truth = {
        "host1": True,  # actual vulnerable
        "host2": False,  # actual not vulnerable
        "host3": False,  # actual not vulnerable
    }

    score = score_findings(results, ground_truth)

    assert score.tp == 1
    assert score.tn == 2
    assert score.fp == 0
    assert score.fn == 0
    assert score.fp_rate_of_findings == 0.0
    assert score.passed is True


def test_no_findings_but_miss():
    """No findings but a miss (FN): counts (0,0,1,0); fp_rate_of_findings==0.0; passed True."""
    results = [
        TargetResult(host="host1", predicted_vulnerable=False),  # FN
    ]
    ground_truth = {
        "host1": True,  # actual vulnerable
    }

    score = score_findings(results, ground_truth)

    assert score.tp == 0
    assert score.tn == 0
    assert score.fp == 0
    assert score.fn == 1
    assert score.fp_rate_of_findings == 0.0  # No division error when tp+fp==0
    assert score.passed is True


def test_max_fp_rate_constant():
    """Verify constants.MAX_FP_RATE == 0.20."""
    assert MAX_FP_RATE == 0.20


def test_missing_host_raises_keyerror():
    """Anti-Lyndon #3: missing host in ground_truth raises KeyError."""
    results = [
        TargetResult(host="host1", predicted_vulnerable=True),
    ]
    ground_truth = {
        "host2": True,  # host1 is missing
    }

    with pytest.raises(KeyError):
        score_findings(results, ground_truth)
