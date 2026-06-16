"""Phase 0 — Constants contract tests.

TEST CONTRACT (7 tests):
  1. from agent_alpha.config.constants import * → no error
  2. EMERGENCY_STOP_TIMEOUT_SEC == 5
  3. EVENT_SEQUENCE_GAP_ALLOWED == False
  4. "claude" in LLM_PAYLOAD_NEVER (payload routing guard)
  5. len(LOG_SCRUB_PATTERNS) == 5
  6. len(SCOPE_ALWAYS_EXCLUDED) == 3
  7. MAX_TIME_BUDGET_SECONDS == CELERY_TASK_HARD_LIMIT_SEC
     (intentional: budget = hard limit, must be equal)

Run on Oracle ARM64 only (Rule 10).
"""
from agent_alpha.config.constants import *  # noqa: F401, F403


def test_import_all_constants():
    """All constants import without error (no syntax errors)."""
    # If this test passes, the import succeeded.
    pass


def test_emergency_stop_timeout():
    """EMERGENCY_STOP_TIMEOUT_SEC is exactly 5 seconds."""
    assert EMERGENCY_STOP_TIMEOUT_SEC == 5


def test_event_sequence_gap_allowed():
    """EVENT_SEQUENCE_GAP_ALLOWED is False (strict ordering)."""
    assert EVENT_SEQUENCE_GAP_ALLOWED is False


def test_llm_payload_never_includes_claude():
    """LLM_PAYLOAD_NEVER includes 'claude' (payload routing guard)."""
    assert "claude" in LLM_PAYLOAD_NEVER


def test_log_scrub_patterns_count():
    """LOG_SCRUB_PATTERNS has exactly 5 patterns."""
    assert len(LOG_SCRUB_PATTERNS) == 5


def test_scope_always_excluded_count():
    """SCOPE_ALWAYS_EXCLUDED has exactly 3 CIDR ranges."""
    assert len(SCOPE_ALWAYS_EXCLUDED) == 3


def test_time_budget_equals_hard_limit():
    """MAX_TIME_BUDGET_SECONDS equals CELERY_TASK_HARD_LIMIT_SEC (intentional)."""
    assert MAX_TIME_BUDGET_SECONDS == CELERY_TASK_HARD_LIMIT_SEC
