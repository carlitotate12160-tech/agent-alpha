# Agent-Alpha — Session Handoff (2026-06-30)

Resume in a new session with: **"lanjut Agent-Alpha — apply ADR §12.20/21/22 + post-merge
#69 verify, lalu 3d MySql body."** Memory (`phase-3-audit`, `service-aware-cred-reuse-plan`,
`arsenal-decision`) carries the full context automatically; this file is the quick index.

---

## What landed this session

**Code (PR #69 — MERGED to main on Oracle #61):** Conductor handoff-consumer
(`conductor/advance.py`) + shared `execute_agent` helper + `emit_handoff_and_advance` +
event types (HANDOFF_READY/AGENT_DISPATCHED/AWAITING_APPROVAL/CHAIN_COMPLETE) + cred_reuse
3c (injected applicators) + `applicator_factory` wiring. Closes audit A1 (chain now
auto-advances Alpha→Beta on the Celery path, not chain_runner). 30 phase_3 tests green +
ruff/format/mypy clean.

**Sealed earlier on #61:** gate slice 3a (`Scope.db_endpoints` + `is_db_endpoint_in_scope`)
+ factory 3b. cred-reuse chain field-proven (container 9201, severity HIGH report).

**ADRs authored — NOT yet applied to `docs/ADR.md` on #61 (renumber if the number is taken):**
- **§12.20** consensus tier deferral Phase 3 → Gamma (`adr_amendment_consensus_deferral.md`).
  Includes a doc-integrity sweep (T1): strike "multi-LLM consensus" from every Phase-3
  exit-criteria list (ADR, skill, PROGRESS_TRACKER, PHASE_3_TEST_CONTRACT).
- **§12.21** external benchmark gate AutoPenBench/CyberGym/Cybench at Phase 6/pre-GA
  (`adr_external_benchmark_gate.md`).
- **§12.22** tool moat + scope-safety + Cloudflare (`adr_tool_moat_and_scope_safety.md`).
  **Status: ADDED to docs/ADR.md (2026-06-30)**

**Reference/spec/prompt artifacts (mount, for the IDE/Oracle loop):**
`autonomy_audit_checklist.md`, `step3_gate_slice_handoff.md`, `conductor_advance_handoff.md`,
`ide_prompt_advance_wiring.md`, `execute_agent_spec.md`, `ide_prompt_pr69_fixes.md`,
`pr69_merge_checklist.md`. Tests authored: `test_conductor_advance.py`,
`test_applicator_factory.py`, `test_execute_agent.py`, `test_emit_handoff_and_advance.py`.

---

## Next steps (priority order)

1. **Apply ADR §12.20/21 to `docs/ADR.md` on #61** + run the §12.20 doc-integrity sweep
   (consensus struck from all Phase-3 exit-criteria lists). Update CLAUDE.md status block
   (text below).
2. **Post-merge verify on #61:** `.venv/bin/python3 -m pytest tests/ -q` FULL suite green
   (not a slice — *slices lie*) + `make check`. Confirm #69's independent fixes (#14 Omega
   arity, #5 cred_reuse BoundApplicator iteration, #1 session_cookie_name, #17 no dummy key)
   each landed + test-covered.
3. **3d — `MySqlApplicator.apply` offensive body (GLM/Kimi, NOT Claude)** → then field-prove
   the leak→reuse→DIRECT-DB chain on a REAL in-scope, self-owned DB (like container 9201).
   This is where the "leaked DB cred → direct DB access = payable report" moat goes live.
4. **Tracked follow-ups:** Alpha (`run_engagement_task`) fully unified onto `execute_agent` 
   (gates must MATCH, no second semantics #6/#7); CHAIN_COMPLETE idempotency on the OMEGA
   terminal.
5. **Tool track (§12.22 build order):** Registry + Composer (closes audit A4, the moat
   enabler) → scope/blast-radius governor → external-tool wrap adapters → CF/WAF
   discriminator → IntelligenceBase (Phase 6).
6. **Safety gate FIRST (§12.22 Decision 2):** `cohost_pivot`/`symlink` default-DENY
   per-target scope check before ANY further Epsilon/offensive work (legal landmine —
   co-host = third-party owner = out-of-SOW).
7. **Strengthen (production-grade):** observability (audit A7 = 0, table stakes for an
   autonomous offensive SaaS) and breadth (moat proven on 1 stack — need 2–3 payable chains).

---

## Revised Phase-3 exit criteria (post §12.20, for CLAUDE.md / PROGRESS_TRACKER)

```
[x] Beta (STRIKE) — default_creds + cred_reuse, verified non-empty findings
[x] Conductor auto-advances Alpha→Beta on the Celery path (no agent-to-agent)  ← #69
[x] Auto-advance PARKS across an ungranted auth tier (gate not softened)        ← #69
[x] execute_agent: graph replay + auth re-check + real-outcome status + idempotent ← #69
[ ] cred-reuse chain runs on the Celery path with the shared vault (verify post-merge)
[ ] chain_runner is harness-only, not a second prod orchestrator (#6)
[ ] Live test: 3 real targets, <20% FP  (after 3d)
[ ] NO consensus / MiMo on any Phase-3 live path (§12.20; verified A5: already absent)
[ ] Full suite green on Oracle ARM64 + make check
```

## CLAUDE.md status block — paste on #61

```
Project Phase  : Phase 3 — Beta/STRIKE + autonomous Celery chain (PR #69 MERGED 2026-06-30)
Code Written   : P0+P1+P2 sealed; P3 = Beta + cred-reuse chain + Conductor auto-advance
                 (execute_agent helper: graph-replay + auth-recheck + real-outcome status
                 + offensive-idempotency) all green on Oracle ARM64.
Last Decision  : ADR §12.20 (consensus→Gamma), §12.21 (benchmark gate), §12.22 (tool moat
                 + scope-safety + CF discriminator) — authored, §12.22 applied to docs/ADR.md.
Next Action    : apply ADR §12.20/21 to docs/ADR.md + post-merge full-suite verify → 3d MySqlApplicator body (GLM)
                 → field-prove chain on real in-scope DB → tool track (Registry+Composer).
```

---

## Durable reminders (don't relearn these)

- Mounted folder can be STALE vs Oracle #61 — verify shapes on #61, never assume (#2).
- Read `proto/a2a.proto` (canonical), never the generated `a2a_pb2.py` (gitignored).
- `.venv/bin/python3 -m pytest tests/` — never bare pytest (system python 3.10 fails StrEnum).
- Slices lie — run the FULL suite before claiming green / merge.
- Offensive bodies (templates/*, MySqlApplicator.apply, evasion payloads) = GLM/DeepSeek
  lane (K21). Claude owns interfaces/tests/gates/narrative — never the payload.
- Retryable tasks running an offensive agent need BODY-idempotency, not just dispatch-idempotency.
