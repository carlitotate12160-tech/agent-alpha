# AGENTS.md — Workflow & Environment Notes for Devin

> Project-specific workflow conventions. Canonical doctrine lives in `CLAUDE.md`.
> Status lives in `docs/Session_Handoff.md`. This file holds operational workflow only.

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

**ALWAYS create a new branch + PR for code changes.** Never push directly to `main`.

- **Code changes** (`.py`, `.ts`, `.go`, config files, Makefile, CI workflows):
  branch → commit → push → PR → wait CI + CodeRabbit → merge.
- **Docs only** (`*.md` files in `docs/`, `AGENTS.md`, `ADR*.md`):
  may push directly to `main` (no PR needed — docs only, no code risk).

Why: pushing code directly to `main` skips CodeRabbit review and CI verification
on a PR. CodeRabbit only reviews PRs, not direct pushes. Direct pushes also
break the audit trail (no PR link in commit history).

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

| Target | What it runs |
|--------|-------------|
| `make all` | check + test (full CI equivalent) |
| `make check` | ruff check + ruff format check + mypy |
| `make lint` | ruff check + ruff format check |
| `make typecheck` | mypy |
| `make quality` | lint + typecheck + phase 0-1 tests |
| `make test` | all tests |
| `make test-phase0` | phase 0 tests |
| `make test-phase1` | phase 1 tests |
| `make test-phase2` | phase 2 tests |
| `make test-phase3` | phase 3 tests |
| `make test-phase4` | phase 4 tests |

### Notes

- **venv:** Always use `.venv312` (Python 3.12.3). Not `.venv` (older, no pytest).
- **PATH export:** Required because ssh non-tty does not load `.bashrc`.
- **Repo path on Oracle:** `~/Agent-Alpha` (capital A).
- **Env vars:** `set -a; source .env; set +a` to load API keys before live tests.
