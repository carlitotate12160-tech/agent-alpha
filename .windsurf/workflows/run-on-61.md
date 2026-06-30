---
description: Apply ADR §12.20/21/22 + post-merge #69 verify + 3d MySql on Oracle #61
---

# Run-on-#61 — Apply ADR §12.20/21/22 + post-merge #69 verify + 3d MySql

**Why this is a playbook, not done-in-session:** the mounted sandbox is at HEAD `b79ec5b`
(PR #42, 2026-06-23) with a dirty working tree — it is **NOT** Oracle #61. `docs/ADR.md`
here ends at **§12.12** (no §12.13–§12.19), so appending §12.20 here would mis-number and
edit a divergent tree = Lyndon **#9 (wrong env)** + **#2 (dead/divergent work)**. Everything
below runs on **#61** and is verified there. Claude owns the test/interface/sweep spec;
the MySql body is GLM/Kimi's.

---

## STEP A — Apply the three ADRs to `docs/ADR.md` (on #61)

1. Confirm the real last section number first (do NOT trust the mount):
   ```bash
   grep -nE "### §?12\.[0-9]+" docs/ADR.md | tail -5
   ```
2. Append the three authored bodies **after the true last §12.x**, renumbering if the
   number is taken (the ADR headers already say "renumber if taken"):
   - `adr_amendment_consensus_deferral.md`  → §12.20 (consensus tier → Phase 4 / Gamma)
   - `adr_external_benchmark_gate.md`        → §12.21 (external benchmark gate, Phase 6)
   - `adr_tool_moat_and_scope_safety.md`     → §12.22 (wrap-vs-build + safety gate + CF)
3. Fix the stale docstring §12.20 calls out:
   ```bash
   grep -rn "CONSENSUS tier (parallel MiMo) is deferred to Phase 3" agent_alpha/llm/orchestrator.py
   # change "Phase 3" -> "Phase 4 (Gamma)"
   ```

## STEP B — §12.20 doc-integrity sweep (consensus is NOT a Phase-3 gate)

Strike "multi-LLM consensus" from EVERY Phase-3 exit-criteria list, then prove it is gone:
```bash
# find every place still listing consensus as a Phase-3 gate:
grep -rniE "consensus" docs/ agent_alpha/ \
  | grep -iE "phase.?3|exit|criteria"
# expected AFTER the sweep: only Phase-4/Gamma references + the §12.20 ADR body remain.
```
Targets to edit (per the ADR T1): `docs/ADR.md` Phase-3 list, the architect skill, any
`PROGRESS_TRACKER`, and `docs/PHASE_3_TEST_CONTRACT.md` (already says "DEFERRED → P3b" —
make it consistent, not contradictory). Replace the struck line with the revised Phase-3
hard-stop from the ADR (ends with: `NO consensus / MiMoProvider on any Phase-3 live path`).

**Anti-dead-code guard (T2):** no live path may import/construct `MiMoProvider` or run a
vote at Phase 3.
```bash
grep -rn "MiMoProvider\|decide_tier\|CONSENSUS_LLM" agent_alpha/ \
  | grep -v "test\|docstring"
# expected: empty (consensus has no code at #61 — verified A5). If non-empty -> dead code.
```

## STEP C — Post-merge #69 verify (the GATE before 3d)

> `chain_runner` slices lie — run the FULL suite. Oracle ARM64 only (#9).

```bash
.venv/bin/python3 -m pytest tests/ -q        # FULL suite, not a slice
make check                                    # ruff + format + mypy
```
Then confirm each "independent fix" actually LANDED **and** is test-covered (don't assume — #2):

| Fix | Confirm command | Pass condition |
|-----|-----------------|----------------|
| #4/#15 emit+advance not swallowed | `pytest tests/phase_3/test_emit_handoff_and_advance.py -q` | handoff persisted BEFORE advance; dispatch failure **raises**, not swallowed |
| #14 Omega arity | `grep -n "Omega(" agent_alpha/ -r` + an Omega run | constructed with 1 arg; run does not crash |
| #5 cred_reuse iterates `BoundApplicator` | `grep -n "select_applicator\|BoundApplicator" agent_alpha/tools/internal/access/cred_reuse.py` | iterates injected `BoundApplicator`; `select_applicator` dropped on injected path; `BoundApplicator` did NOT gain `service`/`required_auth` |
| #1 `session_cookie_name` | `grep -rn "session_cookie_name" agent_alpha/` | canonical name; session-token ref minted on cred-reuse path |
| #17 no dummy key | `grep -rn "DEEPSEEK_API_KEY" agent_alpha/` | no `="dummy"` fallback on live paths (fails loud) |

**Also re-confirm the merge itself** — `pr69_merge_checklist.md` still shows open boxes
(#4/#15, full-suite, `test_advance_wiring` T1–T5). If those did not actually close before
the merge to main on #61, that is a stop-the-line item: the merge happened with open
blockers. Verify, don't assume.

**HARD STOP:** if STEP C is not 100% green, do **not** start 3d. Phase exit criteria are
hard stops (#1/#5).

## STEP D — Safety gate FIRST, before the MySql body goes live (§12.22 Decision 2)

3d makes DIRECT DB access real. Before field-proving it, confirm the scope gate the
factory depends on is live on #61:
```bash
grep -n "is_db_endpoint_in_scope\|db_endpoints" agent_alpha/conductor/authorization.py
pytest tests/ -q -k "db_endpoint or applicator_factory"
```
Invariants that MUST hold (already designed into `applicator_factory.py`):
- DB connect target = **in-scope ASSET host:port** from authorized recon, **never** the
  leaked `DB_HOST` (localhost / out-of-SOW trap — FLAW 2).
- `required_auth="OFFENSIVE_APPROVED"` + DB host:port present in the **signed SOW scope**.
- `cohost_pivot`/`symlink` default-DENY per-target (do this gate before ANY Epsilon work).

## STEP E — 3d: MySqlApplicator body (GLM/Kimi) → then field-prove

1. Drop the RED test on #61: `tests/phase_3/test_mysql_applicator.py` (authored — see the
   companion file). It is RED today (`apply()` raises `NotImplementedError`).
2. Hand the body to GLM/Kimi using the prompt in the next section. Claude does **not**
   write `apply()`.
3. Review the body RAW against the test + invariants, then on #61:
   ```bash
   .venv/bin/python3 -m pytest tests/phase_3/test_mysql_applicator.py -q   # GREEN
   .venv/bin/python3 -m pytest tests/ -q && make check                     # no regression
   ```
4. Field-prove leak→reuse→**DIRECT-DB** on a REAL in-scope self-owned DB (like container
   9201): Alpha leaks `DB_PASSWORD` → vault → factory binds mysql applicator to the
   in-scope `host:3306` → `apply()` proves a schema read → Omega renders a HIGH-severity
   **payable** finding. That is the moat going live: "leaked DB cred → direct DB access =
   payable report a scanner cannot assemble."

---

## GLM/Kimi handoff prompt — `MySqlApplicator.apply` (offensive body)

```
PROJECT: Agent-Alpha   PHASE: 3   STEP: 3d
FILE: agent_alpha/tools/internal/access/mysql_applicator.py
LANE: offensive body (GLM/Kimi). Claude owns the shell/test; you own apply() only.
TASK: implement MySqlApplicator.apply — reuse a harvested credential against MySQL/MariaDB
      directly and PROVE data access.

CONTRACT — drive the DB ONLY through the injected connector (already on self._connector):
  conn = self._connector.connect(host=<from target>, port=<from target>,
                                 username=username, secret=secret, timeout_s=<from budget>)
      # connect() RAISES on closed port / auth reject — do not swallow into a truthy conn.
  conn.databases() -> list[str]        # verification READ; non-empty == proven access.
  conn.has_superuser_grant() -> bool   # True -> access_level "db_root", else "db_user".
  conn.server_version() -> str         # safe proof field.
  conn.close() -> None                 # ALWAYS in finally.
  Split target "host:port" -> host, int(port). Bind the REAL driver lazily INSIDE apply()
  (mirror the repo's lazy `import psycopg`); never import a driver at module load. When
  self._connector is None, lazily construct the real-driver connector.

REQUIRED:
  1. On connect() exception OR empty databases() -> return AuthResult(success=False,
     access_level="", service="mysql", confidence=0.0, proof_request={}, proof_response={},
     error=<short, SCRUBBED>). "Did not raise" is NOT success (anti-Lyndon #3).
  2. On a non-empty databases() read -> AuthResult(success=True, service="mysql",
     access_level "db_root"|"db_user", confidence>=0.8, proof carrying ONLY safe fields
     (server_version, schema count, a BOUNDED list of schema NAMES — never rows/values).
  3. The raw `secret` MUST NOT appear in ANY returned field, including error text — scrub
     driver exceptions before putting them in `error`.

CONSTRAINTS:
  - Do NOT touch the contract shell (service/required_auth/applies_to/__init__ seam),
    AuthResult, applicator_factory, or any test.
  - required_auth stays "OFFENSIVE_APPROVED"; the Conductor scope gate already guarantees
    `target` is an in-scope SOW endpoint — do NOT re-resolve or choose a host yourself.
  - No placeholder/TODO/pass.

TEST CONTRACT (must pass, authored by Claude): tests/phase_3/test_mysql_applicator.py
  RED now (NotImplementedError) -> GREEN after your body. Key guards: empty-read => failure;
  closed-port/auth-reject => failure-not-crash; verified read => db_root/db_user; raw secret
  never in result (success AND failure); connects to the bound host:port; proof safe-only.

VERIFY: .venv/bin/python3 -m pytest tests/ -q && make check, on Oracle ARM64 only.
```

---

## CLAUDE.md status block to paste on #61 (after STEP A–C land)
```
Project Phase  : Phase 3 — Beta/STRIKE + autonomous Celery chain (PR #69 MERGED 2026-06-29)
Last Decision  : ADR §12.20 (consensus->Gamma), §12.21 (benchmark gate), §12.22 (tool moat
                 + scope-safety + CF discriminator) — APPLIED to docs/ADR.md on #61.
Next Action    : 3d MySqlApplicator body (GLM) green on tests/phase_3/test_mysql_applicator.py
                 -> field-prove leak->reuse->DIRECT-DB on real in-scope DB -> tool track
                 (Registry+Composer, audit A4) + cohost_pivot default-DENY safety gate.
```
