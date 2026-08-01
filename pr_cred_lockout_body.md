## CredentialLockoutGovernor — safety primitive for §12.22 D2 / GAP-015

Safety-before-capability: bounds login attempts so Beta never locks out a client's real accounts.

### What it does
`CredentialLockoutGovernor` bounds login submissions by **(host, username)** and by **host aggregate**:
- Per-username: max 3 attempts (below common ~5 provider lockout threshold)
- Per-host aggregate: max 20 total login attempts (IP-ban/WAF-trip safety)

Distinct from `recon.transport_resilience.LockoutGovernor` (reach escalations vs login attempts).

### Files (5)
- `agent_alpha/tools/internal/access/cred_lockout.py` — the governor (new)
- `agent_alpha/config/constants.py` — 2 thresholds + `__all__`
- `agent_alpha/tools/internal/access/default_creds.py` — `lockout` seam; `may_attempt` before wire, `record_attempt` after
- `agent_alpha/agents/beta/strike.py` — Beta creates ONE engagement-scoped governor, injects into DefaultCredsTool
- `tests/phase_4/test_cred_lockout.py` — 5 tests incl. RUNNER-SEAL≠WIRED proof

### Tests
5/5 pass locally. Seal = Oracle ARM64 + `.venv312` + `make check`.

### Wiring-debt (tracked)
Governor wired into `default_creds` only. These MUST also route through the same governor before they submit credentials:
- `cred_reuse.run()` — harvested-secret reuse
- `odoo_access.run()` — its own attempt loop
- **GAP-015 `user_derived_creds`** (next slice) — the whole reason this exists
