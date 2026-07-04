# agent_alpha/live_fire/scoring.py
from dataclasses import dataclass

from agent_alpha.config.constants import MAX_FP_RATE


@dataclass(frozen=True)
class TargetResult:
    """Result of a live-fire prediction for a single target.

    Identity is the URL, not the host: targets may share a host
    (different ports/paths) and must be scored independently.
    """

    url: str
    predicted_vulnerable: bool
    analyzable: bool = True


@dataclass(frozen=True)
class ScanScore:
    """Score of a live-fire scan against ground truth."""

    tp: int
    fp: int
    fn: int
    tn: int
    inconclusive: int
    fp_rate_of_findings: float
    passed: bool


def score_findings(
    results: list[TargetResult],
    ground_truth: dict[str, bool],
    fp_threshold: float = MAX_FP_RATE,
) -> ScanScore:
    """
    Score live-fire predictions against ground truth.

    Args:
        results: List of TargetResult with predictions
        ground_truth: Dict mapping target URL -> actual vulnerability status
        fp_threshold: Maximum acceptable FP rate (default: constants.MAX_FP_RATE)

    Returns:
        ScanScore with counts, FP rate of findings, and pass/fail status

    Raises:
        KeyError: If a host in results is missing from ground_truth
    """
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    inconclusive = 0

    for result in results:
        actual = ground_truth[result.url]  # Raises KeyError if missing (anti-Lyndon #3)

        # A non-analyzable result (e.g. FAILED Alpha run) must NEVER be
        # bucketed into tp/fp/fn/tn — it is counted as inconclusive so
        # a broken run cannot silently masquerade as a confident TN.
        if not result.analyzable:
            inconclusive += 1
            continue

        if result.predicted_vulnerable:
            if actual:
                tp += 1
            else:
                fp += 1
        else:
            if actual:
                fn += 1
            else:
                tn += 1

    # FP rate in findings = FP / (TP + FP) — fraction of REPORTED findings that are false
    if tp + fp > 0:
        fp_rate_of_findings = fp / (tp + fp)
    else:
        fp_rate_of_findings = 0.0

    # A PASS requires at least one real finding AND an acceptable FP rate.
    # Zero findings is NOT success (anti-Lyndon #3 — that masked failure as "clean").
    # Any inconclusive result also blocks a PASS — we refuse to certify a run
    # where some targets could not even be analyzed.
    passed = (
        (tp + fp > 0)
        and (fp_rate_of_findings < fp_threshold)
        and (inconclusive == 0)
    )

    return ScanScore(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        inconclusive=inconclusive,
        fp_rate_of_findings=fp_rate_of_findings,
        passed=passed,
    )
