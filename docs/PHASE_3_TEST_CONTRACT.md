# Hardening-P3 — Orchestrator — Exit Criteria & Test Contract

**Gate type:** hard stop. P3 is not "done" until every criterion below passes on
**Oracle ARM64 CI** (anti-Lyndon #9), with branch protection still enforcing.

---

## Entry preconditions (already met)
- P0 / P1 / P2 + front-door 2a SEALED & CI-enforced.
- ADR §12.15 (LLM role→provider routing) LOCKED.
- ADR §12.13 (agent scaling / fan-out model) LOCKED.

## Scope

**IN (core P3):**
1. Celery non-blocking execution (chat-while-running, ADR §8a).
2. LLM orchestrator with role-based routing (§12.15).
3. Tenant propagation through Celery — front-door **2b**.
4. Real emergency revoker (replaces the Phase-0 mock).
5. Fan-out interface (§12.13) — partition → enqueue → aggregate, fan-out-aware even at degree 1.

**DEFERRED (explicit, with trigger — do NOT build now = avoid dead code #2):**
- CONSENSUS_LLM tier + `MiMoProvider` → build when consensus is actually exercised, not before.
- Step-level resume (§12.11 step-level) → P3b.
- Inner-monologue WebSocket/Redis pub-sub **delivery** → P3b (emission core already done in P2; can be pulled into P3 once the async path exists — your call).

---

## Exit Criteria (each must pass; each has a test contract)

**C1 — Non-blocking execution.**
POST to start an engagement returns immediately (queued); a Celery worker runs it
in the background; status is queryable while it runs.
- Test: start → endpoint returns without blocking; `/state` shows progress transitions; event stream grows as the worker runs; a second API call succeeds while the task runs.

**C2 — LLM role routing (§12.15).**
`reason()` → `LLM_REASONING_PROVIDER`; `payload()` → `LLM_PAYLOAD_PROVIDER`.
- Test: changing the provider constant swaps the adapter with NO code change (mock registry); `payload()` NEVER resolves to Claude and NEVER to an aggregator-class transport; redaction runs before every provider call (raw creds/PII never leave); `payload()` refuses unless auth state permits.

**C3 — Tenant propagation through Celery (front-door 2b).**
A task carries `tenant_id`; the worker resolves the correct per-tenant store.
- Test: engagement for tenant A executed async → ALL events land in tenant-A's store, none in default/other; a worker cannot read/write outside its tenant (RLS + routing); cross-tenant async access impossible.

**C4 — Real emergency revoker.**
`CeleryRevoker` wired; emergency stop revokes ALL running tasks for an engagement
within the budget (`EMERGENCY_STOP_TIMEOUT_SEC` = 5s) and blocks further actions.
- Test: start a long-running task → emergency stop → task revoked + auth gate = EMERGENCY_STOP → subsequent `can_agent_proceed` denied; measured elapsed < 5s; stop event lands in the tenant store (per the GAP-B fix).

**C5 — Fan-out interface (§12.13).**
Conductor partitions a phase's work into bounded units, enqueues them, aggregates
results deterministically. Fan-out-aware even if degree = 1.
- Test: partition N units → all enqueued only after the auth gate validates state; concurrency cap honored (≤ K concurrent per engagement); results aggregate into ONE engagement event stream (monotonic, gapless); NO code path lets an agent enqueue work for another agent (only Conductor dispatches).

**C6 — End-to-end non-blocking kill chain (no regression).**
Alpha→Omega runs via Celery against a lab target and produces the SAME finding +
report as the proven synchronous Phase-2 path, while the API stays responsive.
- Test: async e2e on ≥1 lab target, FP < 20%, report generated (MITRE-mapped, PDF); the existing `test_alpha_to_omega_e2e` stays green.

**C7 — No regression + CI.**
Full suite green on Oracle ARM64 incl. all new P3 integration tests; `make check`
clean; branch protection still requires `quality-gate`.

**C8 — Anti-Lyndon gates (apply to every component).**
- Wired, not assumed: grep/trace every new component is on a live path (#2).
- No false success: success requires validated non-empty output (#3).
- Single source of truth for every config value (#7).
- No agent-to-agent direct dispatch — only Conductor (§3, §12.13).
- All results verified on Oracle ARM64, never local/Windows (#9).

---

## Suggested build order (anti-Lyndon: foundation before feature)
1. **Celery real execution skeleton** (C1) — prove non-blocking + status, no agent logic yet.
2. **LLM orchestrator role routing** (C2) — `reason()`/`payload()` + redaction + transport policy.
3. **Tenant propagation** (C3) — thread `tenant_id` through tasks → per-tenant store.
4. **Real emergency revoker** (C4) — wire `CeleryRevoker`, prove 5s revoke.
5. **Fan-out interface** (C5) — partition→enqueue→aggregate at degree 1.
6. **E2E async kill chain** (C6) — wire the proven Alpha→Omega onto the async path.

Each step lands with its own tests green before the next begins. No step N+1 work
before step N's tests pass.

## Quality gate (every step)
Unit + integration 100% on Oracle ARM64 · phase checklist 100% · no regression in
P0/P1/P2/2a · CI enforced.
