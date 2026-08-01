## GAP-015 — username-derived credential candidates (Claude lane)

Alpha→Beta moat: turns Alpha-enumerated USER nodes into a small, context-derived candidate set and proves reuse — what Nuclei cannot assemble.

### What this ships (Claude lane — non-offensive)
- `derive_login_candidates(username, host)` — deterministic, bounded (MAX 4), context-only (`[username, username+"123", domain_stem, domain_stem+"123"]`), deduped, no static password, no wordlist file. Domain stem via Public Suffix List (`publicsuffix2`, offline).
- `UserDerivedCredsTool` — Tool contract + `applies_to` (0.75 when USER nodes exist, below cred_reuse 0.9, above blind default_creds 0.7; 0.1 when credential already harvested; 0.0 without enumerated users). Wired into Beta's registry with shared lockout governor.
- `run()` = NotImplementedError (GLM/DeepSeek lane) — the apply+lockout+attestation loop is the offensive body, authored next. `strike.step` already catches NotImplementedError.

### Files (5)
- `agent_alpha/tools/internal/access/user_derived_creds.py` (new)
- `agent_alpha/config/constants.py` (+USER_DERIVED_MAX_CANDIDATES_PER_USER)
- `agent_alpha/agents/beta/strike.py` (import + registry wiring, governor injected)
- `requirements.txt` (`publicsuffix2==2.20191221`)
- `tests/phase_4/test_user_derived_creds.py` (8 RED-first tests)

### Tests
8/8 pass locally. Lint clean. Seal = Oracle ARM64 + `.venv312` + `make check`.

### Safety
Every submission gated by shared `CredentialLockoutGovernor` (§12.22 D2). `required_auth = ACTIVE_APPROVED`.

### NEXT (do NOT parallelize)
1. Rename oracle → attestor (mechanical, ~8 files)
2. DeepSeek/GLM: author `user_derived_creds.run()` — apply + lockout + attestation loop
3. Route `cred_reuse` + `odoo_access` through same governor (open safety debt from #310)
