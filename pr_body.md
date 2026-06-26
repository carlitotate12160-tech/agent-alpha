## Summary

Implements C1.4 (failure handling) and C1.5 (timeout recording) for engagement run management.

## C1.4 - Generic Failure Recording

- run_engagement_task already handles exceptions and emits ENGAGEMENT_RUN_FAILED
- Task returns "failed" status instead of raising out
- Failure is captured and recorded, not lost
- test_task_records_generic_failure: verifies ENGAGEMENT_RUN_FAILED event
- test_failure_visible_via_projection: verifies projection shows "failed"

## C1.5 - Timeout Recording

- SoftTimeLimitExceeded caught and recorded as ENGAGEMENT_RUN_FAILED with "timeout" reason
- test_timeout_records_failure: verifies timeout handling

## C1.4 - Safe-Retry Policy

- autoretry_for is narrow TransientStoreError only (not generic Exception)
- max_retries matches CELERY_TASK_MAX_RETRIES constant
- acks_late is True
- task_reject_on_worker_lost is True
- test_safe_retry_policy_configuration: asserts all retry policies

## C1.3 Interplay - Failed Run Re-runnable

- test_failed_run_is_re_runnable: after status "failed", new POST /run accepted
- Failed is a terminal, non-active status

## Tests

- tests/phase_0/test_run_engagement_task.py: +4 tests (failure, projection, timeout, retry policy)
- tests/phase_0/test_run_dispatch.py: +1 test (failed run re-runnable)
- All 159 phase_0 tests passing
- Ruff check clean
- Mypy check clean
