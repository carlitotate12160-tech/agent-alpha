# tests/phase_1/test_intelligence.py
# Two deliberately separated concerns (do not merge them):
#
# 1. Pure scoring logic (_wilson_lower_bound, _compute_tool_score) tested
#    with SYNTHETIC fixtures — proves the K20 formula is correct,
#    independent of whether Phase 1 has any real data to feed it.
#
# 2. RecordBackedIntelligenceBase's actual Phase 1 behavior against
#    REAL EngagementMemoryRecord shapes — proves every public method
#    returns InsufficientData today (not a silently-wrong score), because
#    tool_success_rates is always {} and tech_stack/target_type/industry/
#    region don't exist on the record at all (Lyndon failure #3 guard).
#
# If a future change makes group (2) start returning real scores without
# group (1)'s synthetic tests also changing, that is a signal something
# was wired incorrectly — these two groups should evolve independently.

from __future__ import annotations

from agent_alpha.memory.engagement import EngagementMemoryRecord
from agent_alpha.memory.intelligence import (
    InsufficientData,
    RecordBackedIntelligenceBase,
    ToolReliabilityScore,
    _compute_tool_score,
    _wilson_lower_bound,
)

MIN_SAMPLES = 3  # mirrors a constants.MIN_SAMPLES_BEFORE_SKIP value for tests


def _blank_record(
    engagement_id: str, tool_success_rates: dict[str, float]
) -> EngagementMemoryRecord:
    return EngagementMemoryRecord(
        engagement_id=engagement_id,
        confirmed_exploits=[],
        failed_attempts=[],
        time_to_exploit_per_phase={},
        tool_success_rates=tool_success_rates,
        proof_artifacts=[],
        scratchpad_snapshot={},
        time_to_first_proof_s=None,
        time_to_first_exploit_s=None,
        event_stream_id=engagement_id,
        last_sequence_number=0,
    )


# ── Group 1: pure scoring logic, synthetic data ─────────────────────────


class TestWilsonLowerBound:
    def test_zero_samples_returns_zero(self) -> None:
        assert _wilson_lower_bound(0, 0) == 0.0

    def test_small_n_is_conservative_vs_raw_rate(self) -> None:
        # 2/2 successes "looks" like 100%, but Wilson lower bound must be
        # well below 1.0 — small N is never treated as certain (K20).
        bound = _wilson_lower_bound(2, 2)
        assert 0.0 < bound < 1.0
        assert bound < 0.9

    def test_large_n_converges_toward_raw_rate(self) -> None:
        # 800/1000 successes: large N should push the lower bound much
        # closer to the raw rate (0.8) than the small-N case does.
        bound = _wilson_lower_bound(800, 1000)
        assert 0.75 < bound < 0.8


class TestComputeToolScoreSynthetic:
    def test_below_min_samples_is_insufficient_data(self) -> None:
        result = _compute_tool_score(
            tool="nuclei",
            samples_by_record=[("eng_1", 0.9), ("eng_2", 0.8)],  # only 2
            min_samples=MIN_SAMPLES,
        )
        assert isinstance(result, InsufficientData)
        assert result.samples_found == 2

    def test_at_min_samples_returns_real_score(self) -> None:
        result = _compute_tool_score(
            tool="nuclei",
            samples_by_record=[("eng_1", 0.9), ("eng_2", 0.8), ("eng_3", 0.85)],
            min_samples=MIN_SAMPLES,
        )
        assert isinstance(result, ToolReliabilityScore)
        assert result.tool == "nuclei"
        assert result.samples == 3
        # Wilson lower-bound must never exceed the raw rate.
        assert result.success_rate <= result.raw_success_rate

    def test_never_returns_score_disguised_as_zero(self) -> None:
        # Lyndon #3 guard: an empty/zero-ish input must come back as
        # InsufficientData, never as a ToolReliabilityScore with
        # success_rate=0.0 that looks like a real, computed "always fails".
        result = _compute_tool_score(
            tool="ghost-tool", samples_by_record=[], min_samples=MIN_SAMPLES
        )
        assert isinstance(result, InsufficientData)


# ── Group 2: real Phase 1 behavior against actual record shape ─────────


class TestRecordBackedIntelligenceBasePhase1Reality:
    """Every method here MUST return InsufficientData against records
    shaped like what engagement.py actually produces today. If any of
    these assertions start failing because a method suddenly returns a
    real score, that's a sign tool_success_rates or a fingerprint field
    was populated upstream — update this test deliberately, don't relax
    it to "pass either way"."""

    def test_tool_reliability_insufficient_with_empty_success_rates(self) -> None:
        records = [_blank_record("eng_1", tool_success_rates={})]
        base = RecordBackedIntelligenceBase(records, min_samples_before_skip=MIN_SAMPLES)
        result = base.tool_reliability("nuclei", conditions={})
        assert isinstance(result, InsufficientData)

    def test_tool_reliability_works_once_data_exists(self) -> None:
        # Demonstrates the "zero changes required here" claim in
        # intelligence.py's docstring: if tool_success_rates were
        # populated (Phase 2+), the SAME code path produces a real score.
        records = [
            _blank_record("eng_1", {"nuclei": 0.9}),
            _blank_record("eng_2", {"nuclei": 0.85}),
            _blank_record("eng_3", {"nuclei": 0.95}),
        ]
        base = RecordBackedIntelligenceBase(records, min_samples_before_skip=MIN_SAMPLES)
        result = base.tool_reliability("nuclei", conditions={})
        assert isinstance(result, ToolReliabilityScore)

    def test_false_positive_rate_insufficient_with_empty_success_rates(self) -> None:
        records = [_blank_record("eng_1", tool_success_rates={})]
        base = RecordBackedIntelligenceBase(records, min_samples_before_skip=MIN_SAMPLES)
        result = base.false_positive_rate("nuclei", target_type="webapp")
        assert isinstance(result, InsufficientData)

    def test_what_worked_for_similar_targets_always_insufficient_phase1(self) -> None:
        records = [_blank_record("eng_1", {"nuclei": 0.9})]
        base = RecordBackedIntelligenceBase(records, min_samples_before_skip=MIN_SAMPLES)
        result = base.what_worked_for_similar_targets(
            tech_stack=["laravel", "mysql"], target_type="webapp"
        )
        assert isinstance(result, InsufficientData)

    def test_credential_patterns_always_insufficient_phase1(self) -> None:
        records = [_blank_record("eng_1", {"nuclei": 0.9})]
        base = RecordBackedIntelligenceBase(records, min_samples_before_skip=MIN_SAMPLES)
        result = base.credential_patterns(industry="banking", region="id")
        assert isinstance(result, InsufficientData)

    def test_no_silent_zero_for_unknown_tool(self) -> None:
        records = [_blank_record("eng_1", {"other-tool": 0.9})]
        base = RecordBackedIntelligenceBase(records, min_samples_before_skip=MIN_SAMPLES)
        result = base.tool_reliability("nuclei", conditions={})
        assert isinstance(result, InsufficientData)
