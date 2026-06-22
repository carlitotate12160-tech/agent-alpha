# C6a: Async Kill Chain (Shape B) - Wire Real Alpha→Omega Recon Pipeline into Celery Worker

## Summary

Implements C6a of Phase 3 Test Contract: the async kill chain (Shape B) where the Celery worker runs the REAL Alpha→Omega recon pipeline and reproduces the synchronous Phase-2 e2e result hermetically.

## Changes

### Added Files

- **agent_alpha/conductor/recon_runner.py**
  - `build_recon_pipeline()`: Constructs real recon pipeline (Alpha + graph) for one worker run
  - `resolve_recon_targets()`: Derives concrete scan URLs from verified scope domains
  - `run_recon_for_engagement()`: Scans all in-scope targets with Alpha, then produces Omega report
  - Heavy deps built in-process (json-only Celery args, C1.7)
  - Seams are module-level for hermetic test monkeypatching

- **tests/phase_2/test_async_kill_chain.py**
  - `test_resolve_targets_from_verified_scope_domains()`: Unit test for target resolution
  - `test_resolve_targets_empty_scope_raises()`: Unit test for empty scope error handling
  - `test_async_worker_runs_real_recon_pipeline()`: Integration test proving async path populates graph + emits RUN_COMPLETED + yields grounded report
  - `test_async_worker_refuses_unauthorized()`: Authorization gate test

### Modified Files

- **agent_alpha/conductor/main.py**
  - Added import for `recon_runner`
  - Wired `recon_runner.run_recon_for_engagement()` into `run_engagement_task()`
  - Removed TODO placeholder comment
  - Added ENGAGEMENT_RUN_COMPLETED event emission with opaque metadata (C1.8)
  - Returns "completed" status instead of "started"

## Design Decisions

### Shape B (Single-Task)
- One worker scans all engagement targets in sequence
- Aggregates into ONE graph + single event stream
- Returns opaque metadata only (C1.8) — never report narrative or Celery result backend

### Seams for Hermetic Testing
- `build_recon_pipeline()` and `resolve_recon_targets()` are module-level
- Hermetic tests monkeypatch these seams to inject same fakes as sync Phase-2 e2e
- No live target, no LLM in hermetic tests (laravel finding comes from RULE-tier playbook)

### C1.8 Compliance
- Only opaque metadata leaves to event store (node_count, targets_scanned, report_generated)
- Report narrative never stored in event store (can carry leaked secrets)
- Celery result backend carries only status (completed/refused/failed)

## Testing

Run on Oracle ARM64:
```bash
.venv/bin/pytest tests/phase_2/test_async_kill_chain.py -v
```

## Next Steps

- C6b: Per-unit fan-out execution + live-fire FP<20% gate
- C7: No regression + CI
- C8: Anti-Lyndon gates

## Checklist

- [x] C6a contract implemented
- [x] Hermetic tests added
- [x] C1.8 compliance (opaque metadata only)
- [x] Shape B (single-task) design
- [x] Seams for hermetic testing
- [ ] Run tests on Oracle
- [ ] Merge PR after tests pass
