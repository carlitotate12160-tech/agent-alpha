# AGENTS.md — Workflow & Environment Notes for Devin

> Project-specific workflow conventions. Canonical doctrine lives in `CLAUDE.md`.
> Status lives in `docs/Session_Handoff.md`. This file holds operational workflow only.

## Anti-Diagnose-Spiral Rule (2026-08-20 — NON-NEGOTIABLE)

**Problem:** 5+ sessions produced 0 sealed slices because each session chased a NEW
"kenapa X tidak bekerja?" diagnosis instead of executing the current slice. This is
Lyndon #5 (scope creep) + #2 (activity mistaken for progress) in real-time.

**Rule:**
1. Before answering ANY "kenapa" / "bagaimana" / "sekarang apa" question, check
   `docs/Session_Handoff.md` for the current "NEXT slice."
2. If the current slice is NOT sealed, and the question is NOT the current slice:
   - Pushback FIRST: "Itu pertanyaan diagnostik baru. Current slice = [X]. Eksekusi
     current slice dulu, atau ganti slice dengan alasan?"
   - Only proceed with the new diagnosis if the user EXPLICITLY confirms a slice change.
3. Do NOT silently follow into another diagnosis spiral.
4. Registering a gap is NOT progress. Sealing a slice is progress.
5. End every session with: "Sealed slices this session: [N]. Current slice status:
   [sealed/blocked/in-progress]." If N=0 and no blocker = the session was Lyndon #5.

**DO:** pushback first ("Current slice = X. Eksekusi dulu, atau ganti slice dengan alasan?").
**DON'T:** silently investigate the new question, register a GAP, call it progress.

## Authorized-File-Scope Rule (2026-08-21 — NON-NEGOTIABLE)

**Problem:** A slice spec lists the authorized files to touch. The IDE agent
silently added 2 lines to `scout.py` (dispatch registry) which was NOT in the
authorized file list, pushing it over the size ratchet ceiling. The agent then
tried to accommodate the ratchet failure instead of reverting the unauthorized
change.

**Rule:**
1. If a slice spec lists authorized files, ONLY touch those files. Any file
   outside the list is OFF-LIMITS unless the user explicitly authorizes it.
2. If a ratchet/wiring-gate fails because of a change to an unauthorized file,
   the DEFAULT action is REVERT that change — do NOT accommodate it by raising
   the ceiling, golfing lines, or extracting modules.
3. Do NOT silently wire a new tool into the autonomous path (dispatch registry,
   handler registration, etc.) unless the file containing that wiring is in the
   authorized file list. If wiring is needed but the file is not authorized,
   flag it as a wiring gap for a separate authorized slice — do not touch the
   file.
4. Revert first, then report the wiring gap. Do not argue for keeping the
   unauthorized change because "it makes the tests pass."

**DO:** revert unauthorized file changes immediately when caught.
**DON'T:** accommodate a ratchet/gate failure caused by an unauthorized file change.

## Precondition-Decoupling Protocol (2026-08-21 — NON-NEGOTIABLE)

**Problem:** A slice hits a FOUNDATIONAL blocker (god-object ceiling, missing spine, required refactor)
and the agent either (a) papers over it by tangling unrelated work into the slice, or (b) accommodates a
failing gate by raising a ratchet ceiling, golfing unrelated code, or reverting necessary wiring. Both
compromise the governance that is supposed to protect the architecture.

**Rule:**
1. When the current slice is blocked by a FOUNDATIONAL issue, **STOP**. Do not tangle the fix into the
   current slice and do not accommodate it (never raise a ratchet ceiling, golf unrelated code, or revert
   NECESSARY wiring just to satisfy a gate).
2. **Decouple the precondition as its OWN slice.** Define its authorized file list, scope, tests, and
   Oracle-exit criteria.
3. **Seal the precondition slice first** (Oracle-green, field/lab-proven if needed).
4. **THEN resume the original slice on top** of the now-merged, sealed precondition.

A precondition surfacing is the governance working, not an error to paper over. Decoupling keeps the
original slice honest, keeps the god object from growing, and keeps ratchet/wiring gates meaningful.

**DO:** pause the original slice, open a new precondition slice, seal it, then resume.
**DON'T:** fold foundational work into an unrelated slice or game a gate to keep going.

## Dev Environment

- **Dev machine:** Windows PC with WSL2 Ubuntu 24.04 installed.
- **Repo:** `D:\Agent-Alpha` (Windows) = `/mnt/d/Agent-Alpha` (WSL).
- **Oracle lab (authoritative test env):** Ubuntu 22.04 ARM64 at `168.110.192.62`.
  - SSH alias `oracle-alpha` configured in WSL `~/.ssh/config` (key + host).
  - Repo path on Oracle: `~/Agent-Alpha`.
  - Python 3.12.3, venvs: `.venv` and `.venv312` (both in repo, shared via mount).

## Shell Workflow Rules

### Rule 1 — Local Devin (on the dev PC) does NOT need SSH for local work

If Devin is running **locally on the dev PC** (not in cloud), it can run shell
commands directly via `exec` — no SSH roundtrip needed for repo operations
(git, pytest, ruff, file edits). SSH is only for Oracle lab operations.

### Rule 2 — Use WSL, not PowerShell, for shell commands

PowerShell mangles bash syntax (`&&`, heredoc, `$(...)`, `$var:`). WSL Ubuntu
handles all of these natively. Pattern for commands that need bash:

```
wsl -e bash -lic "<command>"
```

- `wsl -e bash -lic` = login interactive shell (loads PATH from `.bashrc`).
- Do NOT use `wsl bash -c "..."` — PATH will be empty, `ls`/`grep`/`docker` not found.

### Rule 3 — SSH to Oracle from WSL, not PowerShell

```
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; <cmd>'"
```

- `ssh oracle-alpha` uses the configured alias (no `-i "D:\ssh-key..."` needed).
- ssh non-tty does NOT load `.bashrc`, so always `export PATH=...` at the start
  of the remote command, or `ls`/`docker`/`grep` will be "command not found".

### Rule 4 — Do NOT scp helper scripts to Oracle just to bypass PowerShell

If a command is complex, write it inline in the `ssh oracle-alpha '...'` string
or use a heredoc inside WSL. Creating `.git/check_*.sh` files in the Windows repo
just to scp them to Oracle is dead weight (Lyndon #2-adjacent).

## PostgreSQL Query Procedure (Oracle)

Agent-Alpha uses PostgreSQL 16 with **Row-Level Security (RLS)** enabled with
`FORCE` on all 3 tables (`agent_events`, `engagement_memory`, `vault_secrets`).
Every query MUST set `app.tenant_id` first, or RLS silently filters all rows
and you see 0 results — this is NOT an empty database, it is RLS scoping.

### Quick query (tenant = "default")

```bash
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PGPASSWORD=\$(grep AGENT_ALPHA_PG_DSN ~/Agent-Alpha/.env | sed \"s/.*:\([^@]*\)@.*/\1/\"); psql -h 127.0.0.1 -U agent_alpha_app -d agent_alpha -c \"SET app.tenant_id = \\x27default\\x27; SELECT event_type, COUNT(*) FROM agent_events GROUP BY event_type ORDER BY COUNT(*) DESC;\"'"
```

### Rules

- **ALWAYS** `SET app.tenant_id = 'default';` before any SELECT. Without it,
  RLS returns 0 rows silently.
- **NEVER** print the database password in commands or docs. The password is
  sourced from `.env` via `AGENT_ALPHA_PG_DSN` — extract it with grep/sed,
  do not hardcode it.
- `SET row_security = off` does NOT work — RLS is `FORCE`d, even the table
  owner cannot bypass it. You MUST set `app.tenant_id`.
- `sudo -u postgres psql` does NOT work — PostgreSQL listens on TCP 127.0.0.1,
  not Unix socket. Use `psql -h 127.0.0.1 -U agent_alpha_app`.
- Tables: `agent_events` (event stream), `engagement_memory` (projected
  records), `vault_secrets` (encrypted harvested secrets).

### Useful queries

```sql
-- Event type distribution
SET app.tenant_id = 'default';
SELECT event_type, COUNT(*) FROM agent_events GROUP BY event_type ORDER BY COUNT(*) DESC;

-- Per-engagement event counts
SET app.tenant_id = 'default';
SELECT engagement_id, COUNT(*) FROM agent_events GROUP BY engagement_id ORDER BY COUNT(*) DESC LIMIT 20;

-- Distinct hosts discovered
SET app.tenant_id = 'default';
SELECT DISTINCT payload->'properties'->>'host' FROM agent_events
WHERE event_type = 'NodeDiscovered' AND payload->'properties'->>'host' IS NOT NULL
ORDER BY 1;

-- Check for outcome events (GAP-050)
SET app.tenant_id = 'default';
SELECT event_type, COUNT(*) FROM agent_events
WHERE event_type IN ('ExploitConfirmed', 'ExploitFailed') GROUP BY event_type;
```

## Oracle Lab State (as of 2026-08-09)

- **Kali Docker container: REMOVED.** `kali-agent-alpha` (kalilinux/kali-rolling)
  was stopped + removed + image deleted. It was only used to run Python (pytest,
  live_fire runner) — redundant with host venv. Agent-Alpha does NOT depend on
  Kali tools (verified: 0 subprocess calls to nmap/sqlmap/hydra/etc in code).
- **Recon tools still on host (apt-installed):** nmap, sqlmap, hydra, nuclei,
  nikto, wpscan, ffuf, subfinder, masscan, dirb, impacket-secretsdump.
  These are operator-side manual tooling, NOT Agent-Alpha dependencies.
  Only `nuclei` has a legit role: A1 validation comparator (operator runs scan
  externally, Agent-Alpha parses the JSONL — never shells out to nuclei).
- **7 lab stacks via docker-compose:** odoo_lab, wp_lab, git_lab, backup_lab,
  actuator_lab, recon_lab, infra. These are the live-fire target environments.

## Git Line-Ending Note

WSL git has `core.autocrlf=input` set (commits use LF). Many files show as
"modified" in `git status` due to pre-existing CRLF noise from the Windows side.
Do NOT mass-commit these — they are not real changes. Only stage files you
actually edited.

## Git Branch Policy

**ALWAYS create a new branch + PR for ALL changes.** Never push directly to `main`.

- **All changes** (code AND docs): branch → commit → push → PR → wait CI → merge.
- GitHub branch protection **blocks direct pushes to `main`** — even docs-only
  (verified 2026-08-19). No "docs-only exception." PRs get CodeRabbit review +
  CI; direct pushes skip both and break the audit trail.

## Test Commands (Oracle ARM64 — authoritative)

**ALWAYS run on Oracle, never accept Windows/local results (Lyndon #9).**

### Sync Oracle from GitHub

```bash
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd ~/Agent-Alpha && git pull origin main'"
```

### Full CI-equivalent (what GitHub Actions runs)

```bash
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd ~/Agent-Alpha && source .venv312/bin/activate && make all'"
```

### Quality gate only (ruff + mypy + phase 0-1 tests)

```bash
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd ~/Agent-Alpha && source .venv312/bin/activate && make quality'"
```

### Lint + typecheck only (no tests)

```bash
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd ~/Agent-Alpha && source .venv312/bin/activate && make check'"
```

### Specific test file

```bash
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd ~/Agent-Alpha && source .venv312/bin/activate && python -m pytest tests/phase_2_5/test_origin_aware_client.py -v'"
```

### Specific test phase

```bash
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd ~/Agent-Alpha && source .venv312/bin/activate && make test-phase2'"
```

### Live API tests (need DEEPSEEK_API_KEY)

Live tests hit real DeepSeek API. Set env var before running:

```bash
# WSL local
set -a; source .env; set +a
source .venv312/bin/activate
python -m pytest tests/phase_2/ -v

# Oracle (via SSH)
wsl -e bash -lic "ssh oracle-alpha 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cd ~/Agent-Alpha && set -a; source .env; set +a; source .venv312/bin/activate && python -m pytest tests/phase_2/ -v -m live'"
```

To skip live tests (no API calls):

```bash
python -m pytest tests/phase_2/ -v -m "not live"
```

### Make targets reference

See `Makefile` for the canonical target list (`make all`, `make check`, `make
quality`, `make test-phaseN`, etc.).

### Notes

- **venv:** Always use `.venv312` (Python 3.12.3). Not `.venv` (older, no pytest).
- **PATH export:** Required because ssh non-tty does not load `.bashrc`.
- **Repo path on Oracle:** `~/Agent-Alpha` (capital A).
- **Env vars:** `set -a; source .env; set +a` to load API keys before live tests.

---

## Testing Methodology & Phase Exit Criteria

> Moved to `docs/TESTING_METHODOLOGY.md` (Tier 1/2/3 pyramid, per-phase exit
> criteria checklists, bug taxonomy, slice workflow, field-prove cadence).
>
> Current phase status (which slice is sealed / blocked / in-progress) lives in
> `docs/Session_Handoff.md` — the ONLY status doc. Do not duplicate status here.

