## Summary

Implements C5: Fan-out interface (Phase 3 / §12.13) — degree-1 seam.

## C5 — Fan-out Interface (§12.13)

**Purpose:** Conductor partitions a phase's work into bounded units and enqueues them; up to a per-role cap run concurrently; every result flows back into the one append-only engagement stream.

**Scope (ADR §12.13 phasing, anti-Lyndon #1):**
- Builds the dispatch INTERFACE fan-out-aware **at degree 1**
- Real multi-worker runtime concurrency is C6 (once the agent run pipeline exists)
- Building a runtime limiter now would be a machine with no driver
- The cap is expressed as a deterministic bounded PLAN (`max_concurrency` / `wave_count`) the C6 executor will honour
- Gate-before-enqueue + single-stream aggregation invariants ARE enforced now

## Implementation

- `agent_alpha/conductor/fanout.py`:
  - `WorkUnit` — one bounded, pre-authorized unit of a phase's work (data-parallel)
  - `DispatchResult` — outcome of fan-out dispatch + bounded plan
  - `partition_targets()` — partition scope into bounded units (one per target)
  - `max_workers_for()` — per-role concurrency cap from single source of truth
  - `FanOutDispatcher` — gate → bounded enqueue → aggregate
  - Enforces §12.13 invariants:
    - #1: gate never dilutes (validate BEFORE any enqueue)
    - #2: bounded plan (max_concurrency / wave_count never exceed cap)
    - #3: deterministic aggregation (ONE monotonic, gapless engagement stream)
    - #4: no agent-to-agent dispatch (only Conductor)

- `agent_alpha/config/constants.py`:
  - `DEFAULT_MAX_WORKERS = 4` — fallback for unknown roles
  - `MAX_WORKERS_PER_ROLE` — per-role concurrency caps:
    - alpha: 10 (SCOUT — recon fans out widest)
    - beta: 4 (STRIKE)
    - gamma: 2 (ANCHOR — exploitation kept tight, blast radius)
    - delta: 4 (HUNTER)
    - epsilon: 4 (SCOUT-HUNTER)
  - Single source of truth (anti-Lyndon #7)

- `agent_alpha/events/event_types.py`:
  - `WORK_UNIT_QUEUED` — one event per bounded work unit the Conductor enqueued
  - Aggregating these into the single append-only stream is the deterministic-aggregation invariant (§12.13 #3)

- `tests/phase_0/test_fanout.py` — 9 contract tests:
  - `test_partition_one_unit_per_target_in_order` — N targets → N units, order-preserved
  - `test_partition_drops_blanks` — blanks dropped
  - `test_partition_empty_scope_refused` — empty scope refused (anti-Lyndon #3)
  - `test_cap_from_single_source_of_truth` — caps from constants (#7)
  - `test_dispatch_denied_enqueues_nothing` — gate never dilutes (#1)
  - `test_dispatch_enqueues_all_and_aggregates_gaplessly` — deterministic aggregation (#3)
  - `test_dispatch_plan_bounded_by_cap` — bounded plan never exceeds cap (#2)
  - `test_dispatch_rejects_bad_cap_and_empty_units` — validation
  - `test_dispatch_result_is_frozen` — immutability

## Hermetic Testing

All tests are hermetic (injected enqueue stands in for the broker — no network, no worker). Asserts the §12.13 invariants the INTERFACE must hold now (runtime multi-worker concurrency is C6).

## Tests

- 9/9 tests passing
- All hermetic (fake enqueue stands in for Celery broker)
- Interface ready for degree-N when C6 implements runtime concurrency

## Anti-Lyndon Compliance

- #1: No feature before foundation — interface only, runtime concurrency deferred to C6
- #2: No dead code — degree-1 still functional, interface ready for C6
- #3: No false success — empty scope refused, gate denial enqueues nothing
- #7: Single source of truth — caps from constants, no scattered literals
- §12.13 invariants enforced: gate-before-enqueue, bounded plan, aggregation, no A2A dispatch
