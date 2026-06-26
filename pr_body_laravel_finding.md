# Implement Laravel Debug Exposure Finding Template (ADR §12.16)

## Summary

Implements the first tool-layer finding template per ADR §12.16. LaravelFindingTemplate detects and PROVES a Laravel APP_DEBUG=true / config exposure using RECON_ONLY read-only probing.

## Changes

### Added Files

- **agent_alpha/tools/templates/cms/laravel_finding.py**
  - LaravelFindingTemplate class conforming to Template protocol
  - build(): GET request to ctx.target only (RECON_ONLY, anti-SSRF)
  - verify(): Proof-based detection using playbook signatures
  - Requires debug signature (Whoops/Illuminate) + optional version corroboration
  - Redacts secrets before findings/proof (anti-Lyndon #7)
  - Confidence 0.85 with version, 0.75 without

- **tests/phase_2/test_laravel_finding.py**
  - RED contract for Laravel finding template
  - Tests protocol conformance, metadata validation
  - Tests build target validation (anti-SSRF)
  - Tests verify exposed response (success with proof)
  - Tests verify hardened response (no false positive)
  - Tests verify empty response (failure not crash)
  - Tests verify success requires proof (anti-Lyndon #3)

- **agent_alpha/tools/templates/cms/deepseek_prompt_laravel_finding.md**
  - Specification documentation for DeepSeek implementation
  - Requirements for build() (§3) and verify() (§4)
  - Constraints and test contract
  - Reference for future template implementations

## Design Decisions

### Proof-Based Detection
- Requires debug signature ("Whoops" or "Illuminate") as proof
- Version string alone is NOT a finding (spec §4.1)
- Version match is corroborating evidence only
- Confidence 0.85 with version, 0.75 without

### Secret Redaction
- Uses agent_alpha.llm.redaction.redact_secrets()
- Secrets redacted before entering findings or proof
- Focused snippet extraction around signature match
- Secrets never appear raw in any output

### RECON_ONLY Scope
- build() uses GET request only (no mutating payload)
- Acts only on ctx.target (never invents host - anti-SSRF)
- Rate limiting handled by caller (HttpClient)
- No exploitation, only detection + proof

### Anti-Lyndon Compliance
- #2: No dead code - NotImplementedError until implementation
- #3: No silent success - success requires findings + proof
- #7: Single source of truth - reuses LogScrubber patterns

## Testing

Run on Oracle ARM64:
```bash
.venv/bin/python3 -m pytest tests/phase_2/test_laravel_finding.py -v
```

Expected: 8 tests pass, 0 fail

Then run full suite:
```bash
make check
.venv/bin/python3 -m pytest tests/ -q
```

Expected: Full suite stays green, no regression

## Checklist

- [x] LaravelFindingTemplate class
- [x] build() implementation (RECON_ONLY)
- [x] verify() implementation (proof-based)
- [x] Secret redaction
- [x] Test contract (RED)
- [x] DeepSeek prompt documentation
- [x] Template protocol conformance
- [x] Anti-Lyndon #2, #3, #7 compliance

## Next Steps

- Test on Oracle ARM64
- Merge if tests pass
- Implement additional finding templates per phase
