# Add Laravel Template Wiring Test (RED Contract)

## Summary

Adds end-to-end integration test for Laravel template wiring. This test stays RED until the Laravel template is properly wired into scout.py and Laravel-specific redaction patterns are added.

## Changes

### Added Files

- **tests/phase_2/test_laravel_template_wiring.py**
  - End-to-end test for Laravel template integration
  - Validates one canonical detection path (no duplicate inline code)
  - Validates proof is real captured evidence (not boilerplate)
  - Validates redaction holds for Laravel-specific secrets (APP_KEY)
  - Uses fake HTTP client with planted secrets (DB_PASSWORD, APP_KEY)
  - Stays RED until template is wired into scout.py

## Why This Exists (Anti-Lyndon #2, #3, #6)

PR #44 merged `LaravelFindingTemplate`, but NOTHING in the live path calls it:
- scout.py still detects Laravel inline via `_handle_laravel_debug`
- This is dead + duplicate code (Lyndon #2 + #6)
- The agent owns domain logic the tool layer is supposed to own (#4/#8)
- The template's unit test passed in isolation, which hid all of this

This test drives Alpha END-TO-END and stays RED until:
1. scout delegates Laravel detection to the template (one canonical path)
2. The persisted proof is real captured evidence (not boilerplate)
3. Redaction holds for Laravel-specific secrets (APP_KEY)

## Test Coverage

- `test_exactly_one_laravel_vuln_no_duplicate_path`: Ensures one canonical detection path
- `test_proof_is_retrievable`: Validates proof artifacts have storage_ref and artifact_id
- `test_proof_contains_captured_evidence_from_body`: Validates proof contains real evidence from response
- `test_no_raw_secret_reaches_the_graph`: Validates redaction holds for DB_PASSWORD and APP_KEY

## Next Steps

This test is RED by design. To make it pass:
1. Wire Laravel template into scout.py (remove duplicate inline detection)
2. Add Laravel-specific redaction patterns for APP_KEY to LOG_SCRUB_PATTERNS

## Testing

Run on Oracle ARM64:
```bash
.venv/bin/python3 -m pytest tests/phase_2/test_laravel_template_wiring.py -v
```

Expected: RED (fails until template is wired)

## Checklist

- [x] Laravel template wiring test created
- [x] End-to-end integration test
- [x] Validates one canonical detection path
- [x] Validates proof is real captured evidence
- [x] Validates redaction holds for Laravel-specific secrets
- [x] Test is RED by design
