# Session Handoff & Deferred Tracking

## Tracking Items

### T4: tls_impersonate PARKED
- **Status**: Parked.
- **Why deferred**: SOW alignment (Zero SOW wins, unverified shell bri 403->200).
- **Risk**: None — keep in codebase but parked.

### O1: RULE-OF-THREE version_disclosure
- **Status**: Deferred.
- **Why deferred**: Avoid inline surgery during feature slice.
- **Risk**: Low — technical debt. Dedicated refactor slice needed.

### O2: list_db JSON-RPC deferred
- **Status**: Deferred.
- **Why deferred**: Feature isolation.
- **Risk**: Low — partial discovery, but avoids conflicts.

### O3: Rename deferred: `odoo_dbmanager_probe.py` → `odoo_recon.py`
- **Status**: Deferred.
- **Why deferred**: Keeps file history intact during current feature slice.
- **Risk**: None — cosmetic.

### C1: CHALLENGE handling parity
- **Status**: Deferred.
- **Context**: CodeRabbit finding #4 requested making `odoo_dbmanager_probe.py` handle 200-challenge pages as WAF_BLOCKED. However, `process_odoo_dbmanager_hit` in the same file does not do this yet.
- **Follow-up**: Make BOTH odoo probes (dbmanager + version) record a 200-challenge as WAF_BLOCKED consistently. This must be done in one slice across both sides for parity.
