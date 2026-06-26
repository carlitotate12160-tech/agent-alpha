# Fix Phase 0 Test Stubs - C6a Compatibility

## Summary

Stub `recon_runner.run_recon_for_engagement` in phase 0 tests to avoid running the real Alpha→Omega pipeline (which requires DEEPSEEK_API_KEY + network). These tests exercise the worker's gate/status/failure mechanics, not the pipeline itself (covered hermetically by `tests/phase_2/test_async_kill_chain.py`).

## Changes

### Modified Files

- **tests/phase_0/test_run_engagement_task.py**
  - Added `_stub_recon_pipeline` fixture (autouse=True) to stub the real pipeline
  - Removed unused imports (`patch`, `SoftTimeLimitExceeded`, `StoreProvider`)
  - Added imports (`SimpleNamespace`, `recon_runner`)
  - All tests now use stubbed pipeline returning `SimpleNamespace(node_count=1, targets_scanned=1)`

- **tests/phase_0/test_auth_tenant_routing.py**
  - Added imports (`SimpleNamespace`, `recon_runner`)
  - Added `monkeypatch` parameter to `test_worker_finds_engagement_created_via_api`
  - Added stub for `run_recon_for_engagement` in the test
  - Changed expected status from "started" to "completed" (C6a: real pipeline runs and completes)

## Rationale

C6a wired the real Alpha→Omega pipeline into the worker's authorized path. The phase 0 tests are designed to test:
- Worker gate enforcement (refusal when not authorized)
- Status mechanics (started/completed/failed)
- Tenant routing
- Failure handling

These tests should NOT test the pipeline itself (that's covered by `test_async_kill_chain.py`). By stubbing the pipeline, we:
- Avoid requiring DEEPSEEK_API_KEY in phase 0 tests
- Avoid network dependencies
- Keep tests fast and hermetic
- Maintain clear separation of concerns

## Testing

Run on Oracle ARM64:
```bash
.venv/bin/pytest tests/phase_0/test_run_engagement_task.py -v
.venv/bin/pytest tests/phase_0/test_auth_tenant_routing.py -v
```

## Checklist

- [x] Stub recon_runner in phase_0 tests
- [x] Change expected status to "completed"
- [x] Remove unused imports
- [x] Tests pass locally
