## Summary

Implements C4: Real emergency revoker (Phase 3 / Orchestrator hardening).

## C4 — Real Emergency Revoker

**Purpose:** Terminates work already in flight by broadcasting a Celery revoke for every task the engagement ever queued.

**Two-arm guarantee:**
1. **Synchronous (authoritative):** `EmergencyStopHandler` flips auth gate to EMERGENCY_STOP → `can_agent_proceed` → False (blocks further actions)
2. **Asynchronous (best-effort):** `CeleryTaskRevoker` broadcasts SIGKILL for all queued tasks (terminates in-flight work)

## Implementation

- `agent_alpha/conductor/revoker.py`:
  - `TaskControl` Protocol — structural type for Celery's `app.control` (testable without live broker)
  - `CeleryTaskRevoker` — revokes ALL task_ids an engagement ever queued
  - Best-effort per task: broker errors logged and skipped (single error must not abort kill switch)
  - Returns count of tasks for which revoke was successfully issued

- `agent_alpha/conductor/run_status.py`:
  - `collect_run_task_ids()` — returns EVERY task_id ever dispatched (deduped, ordered)
  - Unlike `project_run_status` (collapses to latest), this returns ALL for revocation
  - Single source of truth for RUN_QUEUED → task_id mapping (anti-Lyndon #7)

- `agent_alpha/conductor/main.py`:
  - Wire `CeleryTaskRevoker` in `emergency_for(tenant_id)`
  - Revoker reads tenant-scoped store for all queued task_ids
  - Broadcasts Celery revoke for each with terminate=True + SIGKILL

- `tests/phase_0/test_emergency_revoker.py` — 7 contract tests:
  - `test_collect_returns_all_queued_task_ids_in_order` — returns all task_ids in order
  - `test_collect_dedupes_and_ignores_non_queued` — dedupes, ignores non-queued events
  - `test_collect_empty_when_no_queued` — empty when no tasks
  - `test_revoker_revokes_every_task_with_terminate_sigkill` — revokes with terminate=True + SIGKILL
  - `test_revoker_returns_zero_when_nothing_queued` — zero when nothing queued
  - `test_revoker_is_best_effort_on_broker_error` — survives per-task broker errors
  - `test_emergency_stop_revokes_all_and_blocks_within_budget` — integration: revokes all + blocks within 5s

## Honesty about Guarantee (anti-Lyndon #3)

`control.revoke` is fire-and-forget control broadcast to workers; it does NOT block for, or confirm, actual task death. The hard "blocks further actions" guarantee is the auth-state flip (already done by handler before this runs); revocation is best-effort termination of in-flight tasks. The count returned is the number of task_ids we *issued a revoke for*, not a death certificate.

## Tests

- 7/7 tests passing
- All hermetic (fake control stands in for Celery broker — no network, no worker)
- Integration test verifies: revokes all + flips auth to EMERGENCY_STOP + within 5s budget

## Tenant Scope

Revoker is built per-tenant in `main.emergency_for(tenant_id)`, closing over that tenant's EventStore, so it reads task_ids from the correct RLS-scoped store. The `CeleryRevoker` Protocol (emergency.py) stays `revoke_engagement_tasks(engagement_id) -> int` — no signature change (anti-Lyndon #10).
