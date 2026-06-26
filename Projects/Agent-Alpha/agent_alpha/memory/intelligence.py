# agent_alpha/memory/intelligence.py
# IntelligenceBase: cross-engagement learning queries (K3, K15-K20).
#
# ADR §12.4/§12.7/§12.8/§12.9 (K15-K20): Phase 1-5 use a structured-dict
# scorer over EngagementMemory records — NOT pgvector/RAG (that is Phase 6
# only, once enough cross-engagement data exists to make embeddings
# meaningful).
#
# CRITICAL PHASE 1 CONSTRAINT (verified against current code, not assumed):
# - EngagementMemoryRecord.tool_success_rates is ALWAYS {} until Phase 2
#   emits OutcomeTag-tagged events (see engagement.py's own TODO comment).
# - EngagementMemoryRecord has NO tech_stack / target_type / industry /
#   region fields at all. Fingerprint-matching arguments are accepted by
#   every public method (K3/K18 contract is locked), but Phase 1
#   implementations cannot yet use them to filter records.
#
# Consequently every public method here has exactly two real outcomes:
#   1. InsufficientData  — the only reachable outcome with current data.
#   2. A real score       — reachable today only via the private scorer's
#                            own unit tests (synthetic fixtures), NOT via
#                            any live Phase 1 code path.
# This file intentionally does NOT silently return 0.0 / {} for "no data"
# (Lyndon failure #3 — false success). Callers must branch on the result
# type, not on truthiness.
#
# Backend: Option A, confirmed with Eko — no new storage. This class is a
# pure query layer over an in-memory list[EngagementMemoryRecord] supplied
# by the caller (Conductor / test harness owns the actual record source).
#
# CLASSIFICATION (Phase 2 seal, 2026-06-19): this module is a Phase-1 FOUNDATION
# with NO live caller yet — nothing in the Phase 0-2 execution path imports it
# (verified by grep/trace, anti-Lyndon #2). Its live consumers (the learning /
# reflection loop) arrive in Phase 6. KEPT — tested, correct, isolated — NOT
# quarantined; but do NOT treat it as "wired/done".

from __future__ import annotations

import dataclasses
import math
import typing

from agent_alpha.memory.engagement import EngagementMemoryRecord

# ── Result types (insufficient-data-safe) ──────────────────────────────


@dataclasses.dataclass(frozen=True)
class InsufficientData:
    """Returned when there is not enough source data to compute a score.

    This is a normal, expected outcome in Phase 1-5 (not an error) — it is
    NOT the same thing as "computed a score of zero". Callers MUST check
    for this type before treating a result as a usable score.
    """

    reason: str
    """Human-readable explanation, e.g. 'no tool_success_rates recorded
    in any supplied EngagementMemoryRecord' or 'target_type filtering not
    yet supported — EngagementMemoryRecord has no target_type field
    (Phase 2+ scope)'."""

    samples_found: int = 0


@dataclasses.dataclass(frozen=True)
class ToolReliabilityScore:
    """A real, computed reliability score for one tool under one set of
    conditions. Only ever constructed when ``samples >= MIN_SAMPLES``
    (see ``config/constants.py``)."""

    tool: str
    success_rate: float
    """Wilson lower-bound of the raw success rate (K20) — conservative by
    construction, never overstates confidence for small samples."""

    raw_success_rate: float
    samples: int


@dataclasses.dataclass(frozen=True)
class FalsePositiveRateResult:
    tool: str
    false_positive_rate: float
    samples: int


@dataclasses.dataclass(frozen=True)
class ScanStrategy:
    """K3 return type for ``what_worked_for_similar_targets``."""

    recommended_tool_order: list[str]
    matched_engagement_ids: list[str]
    fingerprint_similarity: float
    """0.0-1.0 composite similarity score (K18 weighted composite). Phase
    1: always unreachable in practice (no tech_stack field to compare),
    kept here so the Protocol shape doesn't change in Phase 6."""


@dataclasses.dataclass(frozen=True)
class CredentialPattern:
    """K3 return type for ``credential_patterns``."""

    pattern: str
    observed_count: int
    industry: str
    region: str


ScoreOrInsufficient = ToolReliabilityScore | InsufficientData
FpRateOrInsufficient = FalsePositiveRateResult | InsufficientData
StrategyOrInsufficient = ScanStrategy | InsufficientData
PatternsOrInsufficient = list[CredentialPattern] | InsufficientData


# ── Protocol ─────────────────────────────────────────────────────────


@typing.runtime_checkable
class IntelligenceBase(typing.Protocol):
    """Cross-engagement learning query interface (K3).

    Signatures match K3/K18 exactly, including the fingerprint-matching
    arguments (``tech_stack``, ``target_type``, ``industry``, ``region``)
    that ``EngagementMemoryRecord`` cannot yet satisfy in Phase 1. This is
    deliberate: the contract is locked now so Phase 2/6 callers never need
    a breaking signature change — only the implementation behind it gets
    more capable as source data (tech_stack, outcome-tagged events) comes
    online.

    Backend (confirmed, Option A): no dedicated storage. Implementations
    query directly over a supplied ``list[EngagementMemoryRecord]`` —
    EngagementMemory itself remains the only source of truth.
    """

    def what_worked_for_similar_targets(
        self, tech_stack: list[str], target_type: str
    ) -> StrategyOrInsufficient:
        """K3/K18: weighted-fingerprint strategy lookup.

        Phase 1: always returns ``InsufficientData`` — EngagementMemoryRecord
        has no tech_stack/target_type field to match against. Real matching
        arrives once that data is captured (Phase 2+) and embedding-based
        fuzzy matching arrives in Phase 6 (K15).
        """
        ...

    def credential_patterns(self, industry: str, region: str) -> PatternsOrInsufficient:
        """K3/K18: credential pattern lookup by industry/region.

        Phase 1: always returns ``InsufficientData`` — neither industry nor
        region exist anywhere in EngagementMemoryRecord or the event types
        it is built from. This is the least-ready of the four methods.
        """
        ...

    def false_positive_rate(self, tool: str, target_type: str) -> FpRateOrInsufficient:
        """K3/K19: false-positive rate for *tool* against *target_type*.

        Phase 1: ``target_type`` cannot be used to filter (no such field on
        EngagementMemoryRecord) — this method always returns
        ``InsufficientData`` against live records. The underlying scoring
        formula is unit-tested directly with synthetic inputs; see
        ``_compute_tool_score`` and its tests.
        """
        ...

    def tool_reliability(self, tool: str, conditions: dict[str, object]) -> ScoreOrInsufficient:
        """K3/K19: reliability score for *tool* under *conditions*.

        Phase 1: ``EngagementMemoryRecord.tool_success_rates`` is always
        ``{}`` until Phase 2 emits OutcomeTag-tagged events (see
        ``memory/engagement.py``'s own TODO). This method always returns
        ``InsufficientData`` against live records today.
        """
        ...


# ── Private scoring core (single source of truth — anti Lyndon #7) ─────


def _wilson_lower_bound(successes: int, samples: int, z: float = 1.96) -> float:
    """Wilson score interval lower bound (K20 statistical correction).

    Ensures small sample counts are never reported as high-confidence —
    confidence scales with ``samples``, not just the raw success ratio.
    ``z=1.96`` corresponds to a 95% confidence level.
    """
    if samples == 0:
        return 0.0
    p_hat = successes / samples
    denominator = 1 + (z**2) / samples
    centre = p_hat + (z**2) / (2 * samples)
    margin = z * math.sqrt((p_hat * (1 - p_hat) + (z**2) / (4 * samples)) / samples)
    return (centre - margin) / denominator


def _compute_tool_score(
    tool: str,
    samples_by_record: list[tuple[str, float]],
    min_samples: int,
) -> ToolReliabilityScore | InsufficientData:
    """Single private scorer shared by ``tool_reliability`` AND
    ``false_positive_rate`` (they are two views of the same underlying
    per-tool statistics — K19). Never duplicate this formula elsewhere.

    ``samples_by_record``: list of (engagement_id, success_rate) pairs
    already filtered down to the tool in question. This function does not
    know about ``EngagementMemoryRecord`` directly — it is pure and
    synthetic-data-testable on purpose (see tests/phase_1/test_intelligence.py).
    """
    if len(samples_by_record) < min_samples:
        return InsufficientData(
            reason=(
                f"only {len(samples_by_record)} sample(s) for tool={tool!r}, "
                f"need >= {min_samples} (config.MIN_SAMPLES_BEFORE_SKIP)"
            ),
            samples_found=len(samples_by_record),
        )

    rates = [rate for _, rate in samples_by_record]
    raw_rate = sum(rates) / len(rates)
    # Treat each record's rate as a Bernoulli-ish proportion contributing
    # one "trial" for the Wilson bound at the engagement-aggregate level.
    # This is intentionally coarse for Phase 1-5; finer per-attempt Wilson
    # bounds require attempt-level events (Phase 6, once outcome-tagging
    # exists at that granularity).
    successes = sum(1 for rate in rates if rate >= 0.5)
    lower_bound = _wilson_lower_bound(successes, len(rates))

    return ToolReliabilityScore(
        tool=tool,
        success_rate=lower_bound,
        raw_success_rate=raw_rate,
        samples=len(samples_by_record),
    )


# ── Concrete implementation (Option A: no dedicated storage) ───────────


class RecordBackedIntelligenceBase:
    """``IntelligenceBase`` implementation that queries directly over a
    supplied list of ``EngagementMemoryRecord`` — no storage of its own.

    Confirmed with Eko: Option A. The caller (Conductor, or a test
    harness) is responsible for sourcing the records, e.g. by reading
    every known engagement via ``EngagementMemoryStore.get()``. This
    class never persists anything and is always rebuilt fresh from the
    records handed to its constructor — consistent with "EngagementMemory
    is the only source of truth" (§8o-1).
    """

    def __init__(
        self,
        records: list[EngagementMemoryRecord],
        min_samples_before_skip: int,
    ) -> None:
        self._records = records
        self._min_samples = min_samples_before_skip

    def what_worked_for_similar_targets(
        self, tech_stack: list[str], target_type: str
    ) -> StrategyOrInsufficient:
        return InsufficientData(
            reason=(
                "EngagementMemoryRecord has no tech_stack/target_type field "
                "to match against — fingerprint matching (K18) requires "
                "data not yet captured at this layer (Phase 2+ scope)."
            ),
            samples_found=0,
        )

    def credential_patterns(self, industry: str, region: str) -> PatternsOrInsufficient:
        return InsufficientData(
            reason=(
                "Neither industry nor region exist anywhere in "
                "EngagementMemoryRecord or the event types it is built "
                "from — this method has no reachable data path in the "
                "current architecture."
            ),
            samples_found=0,
        )

    def false_positive_rate(self, tool: str, target_type: str) -> FpRateOrInsufficient:
        samples = self._collect_tool_rates(tool)
        scored = _compute_tool_score(tool, samples, self._min_samples)
        if isinstance(scored, InsufficientData):
            return scored
        # fp_rate is framed as (1 - success) for the same underlying
        # per-tool statistic — same private scorer, different lens (K19).
        return FalsePositiveRateResult(
            tool=tool,
            false_positive_rate=1.0 - scored.raw_success_rate,
            samples=scored.samples,
        )

    def tool_reliability(self, tool: str, conditions: dict[str, object]) -> ScoreOrInsufficient:
        samples = self._collect_tool_rates(tool)
        return _compute_tool_score(tool, samples, self._min_samples)

    def _collect_tool_rates(self, tool: str) -> list[tuple[str, float]]:
        """Pulls (engagement_id, rate) pairs for *tool* out of every
        supplied record's ``tool_success_rates``.

        Phase 1 reality check: every record's ``tool_success_rates`` is
        ``{}`` (engagement.py TODO, Phase 2 scope) — so this always
        returns ``[]`` against live data today. Kept as a real,
        non-stubbed loop (not hardcoded to return ``[]``) so that the
        instant Phase 2 starts populating ``tool_success_rates``, this
        method starts working with zero changes required here.
        """
        collected: list[tuple[str, float]] = []
        for record in self._records:
            rate = record.tool_success_rates.get(tool)
            if rate is not None:
                collected.append((record.engagement_id, rate))
        return collected
