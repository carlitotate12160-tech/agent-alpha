# Hardening-P3 — Orchestrator — Exit Criteria & Test Contract

**Gate type:** hard stop. P3 is not "done" until every criterion passes on
**Oracle ARM64 CI** (anti-Lyndon #9), branch protection enforcing.

---

## Entry preconditions (already met)
- P0 / P1 / P2 + front-door 2a SEALED & CI-enforced.
- ADR §12.15 (LLM role→provider routing) LOCKED.
- ADR §12.13 (agent scaling / fan-out model) LOCKED.

## Scope

**IN (core P3):** Celery non-blocking execution; LLM role routing (§12.15);
tenant propagation through Celery (front-door 2b); real emergency revoker;
fan-out interface (§12.13).

**DEFERRED → Phase 4 (Gamma) (§12.20; do NOT build now = avoid dead code #2):** CONSENSUS_LLM tier +
`MiMoProvider`; step-level resume (§12.11); inner-monologue WebSocket/Redis
pub-sub **delivery** (emission core already done in P2).

**Phase-3 hard-stop (§12.20):** NO consensus / MiMoProvider on any Phase-3 live path.

---

## C1 — Non-blocking execution (expanded after scope review)  ✅ DONE (Oracle-green 2026-06-21)

### 🔴 C1.0 — PRECONDITION: event-source the auth/engagement state (do FIRST)
Auth/engagement state is an in-memory dict (`authorization.py:142`), NOT a
projection of the event stream. A Celery worker is a SEPARATE PROCESS with its
own empty state machine → it cannot see engagements created by the API process →
the auth gate (§1) is unenforceable in the async path and tenant is unresolvable.
This also contradicts the event-sourced principle (§0, §8o-1) the AttackGraph
already follows.
- **Required:** the `AuthorizationStateMachine` reconstructs `EngagementRecord` +
  state from the durable event stream (via an injected `EventStore` read-side,
  mirroring the AttackGraph projector). Any in-memory dict is only a
  per-process cache rebuilt from events.
- **Test:** instance A creates/transitions an engagement; a *fresh* instance B
  over the **same** store (simulating another process) returns identical record +
  state, incl. an EMERGENCY_STOP transition. Verified on Oracle.
- *Non-negotiable first — without it, C1 cannot be correct.*

### C1.1 — Non-blocking dispatch
Start returns immediately (queued); a worker runs the engagement in background;
a second API call succeeds while it runs.

### C1.2 — Engagement↔task mapping + execution status
Engagement→task_id(s) mapping **persisted** (durable, cross-process) for status
queries AND for emergency-revoke (C4). Execution status (queued/running/done/
failed) is distinct from authorization state and exposed via the API.

### C1.3 — Idempotent start
Starting an already-running engagement never spawns a second concurrent task.

### C1.4 — Failure recorded, never swallowed (anti-Lyndon #3)
A crashing task records a failure event + sets status=failed (with reason);
`acks_late` + bounded retries; exhausted retries → failed, not lost.

### C1.5 — Bounded execution
`soft_time_limit` / `task_time_limit` set (single-source constant); a hung task
cannot run forever; aligns with BoundedAutonomy + the emergency-stop budget.

### C1.6 — Tenant-aware task signature (design now, enforce in C3)
The task resolves tenant in-worker via the engagement record (possible after
C1.0) and emits to the tenant store. Interface must not need redesign in C3.

### C1.7 — JSON serialization only (security)
Pin `task_serializer="json"`, `accept_content=["json"]`,
`result_serializer="json"`. Never pickle (deserialization RCE if broker compromised).

### C1.8 — Sensitive data NOT in the Celery result backend (security)
Findings/creds/payloads flow to the **tenant-scoped event store (RLS)**, never the
Redis result backend (plaintext, not tenant-isolated). The result backend holds
only opaque status, if anything.

---

## C2 — LLM role routing (§12.15)  ✅ DONE (Oracle-green 2026-06-22) — see scope note
`reason()`→`LLM_REASONING_PROVIDER`; `payload()`→`LLM_PAYLOAD_PROVIDER`.
- Test: provider swap = config-only (mock registry); `payload()` never resolves
  to Claude and never to an aggregator transport; redaction before every call;
  `payload()` refuses unless auth state permits.

> **Scope note (delivered 2026-06-22, ADR §12.15 Option A).** C2 ships the *routing
> chokepoint* only: `resolve_reasoning_provider` (wired live) + `resolve_payload_provider`
> guarded factory enforcing `transport=="direct"` + ALLOWED + NEVER (no aggregator, never
> Claude/GPT) + reasoning redaction. Payload **generation** and its **auth-state gate**
> (`payload()` refuses unless OFFENSIVE_APPROVED + SOW) are DEFERRED to **Phase 4 (Gamma)**:
> there is no runtime payload caller yet, so building/gating generation now would be dead
> code (#2). The auth-gate-on-payload bullet above is therefore a **Phase-4** acceptance
> criterion, not a C2 one. Tracked in [pre-phase-3-plan / p3-audit-gaps].

## C3 — Tenant propagation through Celery (front-door 2b)  ✅ DONE (Oracle-green 2026-06-22)
A task carries `tenant_id`; the worker resolves the correct per-tenant store.
- Test: async engagement for tenant A → ALL events in tenant-A's store, none in
  default/other; cross-tenant async access impossible.

## C4 — Real emergency revoker
`CeleryRevoker` wired; emergency stop revokes ALL running tasks for an engagement
within `EMERGENCY_STOP_TIMEOUT_SEC` (5s) and blocks further actions.
- Test: long task → stop → revoked + auth=EMERGENCY_STOP → `can_agent_proceed`
  denied; elapsed < 5s; stop event in the tenant store (GAP-B fix).

## C5 — Fan-out interface (§12.13)
Conductor partitions a phase's work into bounded units, enqueues, aggregates
deterministically. Fan-out-aware even at degree 1.
- Test: units enqueued only after the gate validates state; concurrency cap ≤ K
  honored; results aggregate into ONE monotonic/gapless engagement stream; no
  agent-to-agent dispatch (only Conductor).

## C6 — End-to-end non-blocking kill chain (no regression)
Alpha→Omega via Celery on a lab target produces the SAME finding + report as the
synchronous Phase-2 path, while the API stays responsive.
- Test: async e2e ≥1 lab target, FP < 20%, report generated; existing
  `test_alpha_to_omega_e2e` stays green.

## C7 — No regression + CI
Full suite green on Oracle ARM64 incl. all new P3 integration tests; `make check`
clean; branch protection still requires `quality-gate`.

## C8 — Anti-Lyndon gates (every component)
Wired not assumed (#2); no false success — validated non-empty (#3); single source
of truth (#7); no agent-to-agent direct dispatch (§3, §12.13); Oracle-only (#9).

---

## Pre-Beta Gate (OUTSIDE C1–C8 — must not be skipped on the way to Beta)

Not orchestrator C-steps, but hard requirements before Beta runs against real targets
(see scale-and-rate-limit). Listed here so closing P3 does not silently skip them:

- **Rate-limit enforcement** — `rate_limit_rps` is declared but NOT enforced today
  (Rules-of-Engagement risk + anti-Lyndon #2: declared-not-wired).
- **Observability / CPU-brake monitoring** — no custom resource governor / real monitoring yet.

---

## Build order (foundation before feature)
1. **C1.0** event-source auth state — prove cross-process rebuild. *(first, non-negotiable)*
2. **C1.1 + C1.7 + C1.8** real dispatch + json-only + result-backend hygiene.
3. **C1.2 + C1.3** status mapping + idempotency.
4. **C1.4 + C1.5** failure recording + time limits.
5. **C2** LLM role routing.
6. **C1.6 + C3** tenant-aware task → tenant propagation.
7. **C4** real emergency revoker.
8. **C5** fan-out interface.
9. **C6** e2e async kill chain.
10. **C7** no-regression: full suite green on Oracle + `make check` clean + branch protection.
11. **C8** anti-Lyndon per-component gates verified (#2 wired, #3 no false success, #7 SoT,
    §3/§12.13 no agent-to-agent dispatch, #9 Oracle-only).

Each step lands with its own tests green before the next. No step N+1 before step N passes.

## Quality gate (every step)
Unit + integration 100% on Oracle ARM64 · phase checklist 100% · no regression in
P0/P1/P2/2a · CI enforced.
