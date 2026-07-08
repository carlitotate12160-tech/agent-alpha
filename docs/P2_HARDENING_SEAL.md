# Pre-Phase-3 Hardening (P2 + Front-Door 2a) — Audit & Seal Report

**Date:** 2026-06-21 (supersedes the 2026-06-20 P2-only draft)
**Auditor:** Claude (senior security architect, peer review)
**Method:** Live trace on a fresh GitHub clone (anti-Lyndon #2 — verify, don't trust docs) + CI result review.
**Authoritative verification environment:** Oracle ARM64 only (anti-Lyndon #9).

> **Naming note.** This covers the **pre-Phase-3 hardening gates** (P0→P3),
> SEPARATE from the project's *functional* Phase 2 kill chain already sealed in
> `docs/PHASE_2_AUDIT.md` (2026-06-19). "P2" here = **durable persistence +
> tenant isolation**; "front-door 2a" = **authenticated tenant binding** at the
> API perimeter.

> **Verdict: hardening-P2 + front-door 2a SEALED & ENFORCED.**
> GitHub Actions on the self-hosted Oracle ARM64 runner: **292 passed, 4 skipped**,
> `make check` clean, integration + RLS + auth executed (not skipped, via
> `AGENT_ALPHA_REQUIRE_DB=1`). **Branch protection on `main` requires the
> `quality-gate` check** → a red CI now *blocks* merge (enforced, not just
> reported). Next gate: **hardening-P3 (orchestrator)**.

---

## A. Hardening Gate Status

| Gate | Scope | Status | Evidence |
|------|-------|--------|----------|
| P0 | 5 architecture decisions ratified | ✅ SEALED | Python-only MVP, Telegram approval, `tenant_id`+RLS, OutcomeTag→P3, VERIFY→P6 (`docs/P0_DECISION_RECORD.md`) |
| P1 | CI on Oracle ARM64 + LLM input redaction | ✅ SEALED | Self-hosted ARM64 runner, red-blocks proven; `llm/redaction.py` (`test_redaction.py` 6 green) |
| **P2** | **Durable persistence + tenant isolation** | ✅ **SEALED & ENFORCED** | Postgres event+engagement, Redis session, RLS enforced & proven, fail-closed guard, CI runs integration for real |
| **2a** | **Authenticated tenant binding (API front door)** | ✅ **SEALED & ENFORCED** | JWT authN, tenant from verified claim only, ownership 404 on all engagement routes, per-tenant store routing |
| P3 | Orchestrator (Celery non-blocking + LLM routing) | ⬜ NEXT | Not started; gated by the open LLM-routing decision |

---

## B. P2 Evidence (durable persistence)

| Capability | Status | Proof |
|------------|--------|-------|
| Postgres event store, append-only at DB layer | ✅ | `test_postgres_event_store.py` (4) — restart→replay **byte-identical** + BEFORE UPDATE/DELETE trigger raises |
| Postgres engagement memory (idempotent upsert projection) | ✅ | `test_postgres_engagement_memory_store.py` (4) |
| Redis session store, durable across restart | ✅ | `test_redis_session_store.py` (7) |
| Restart → replay reconstructs state exactly | ✅ | `test_restart_replay_is_byte_identical` |
| EventStore Protocol conformance (no duplicate canonical type) | ✅ | Protocol-conformance tests on both backends |

---

## C. Tenant Isolation — Vulnerability Found & Fixed (headline)

A textbook Lyndon #3 (false success) the prior "18 green" had masked.

**C-1 — RLS was effectively INERT; the green tests proved the wrong layer.**
Every store query carries an explicit `WHERE tenant_id = %s`, so the first
isolation tests passed **even if RLS were dropped entirely** — they validated
the *application filter*, not RLS, the defence-in-depth backstop.

**C-2 — Root cause: the DSN role was a SUPERUSER** (superusers bypass RLS even
under `FORCE`). A corrected test (raw, tenant-filter-free SQL under an
`app.tenant_id` GUC) proved it on Oracle: tenant B read tenant A's rows and a
forged cross-tenant INSERT was accepted.

**Resolution (all verified):**
1. `infra/create_app_role.sql` — `agent_alpha_app` role, `NOSUPERUSER NOBYPASSRLS`, owns the tables so `FORCE` subjects it.
2. `agent_alpha/storage/rls_guard.py` — `assert_role_cannot_bypass_rls`; app refuses to start (`RlsNotEnforcedError`) under a bypass-capable role. Fail-closed. (`test_rls_guard.py` 5 green.)
3. `tests/integration/test_rls_isolation.py` — true-RLS probes (raw unfiltered cross-tenant read = 0, WITH CHECK blocks forged inserts, role-bypass guard). 5 green.

**C-3 — Append-only test reached the trigger only after RLS scoping.** Once RLS
was active, the immutability test had to scope its raw connection to the owning
tenant (else RLS hid the row, mutation hit 0 rows, trigger never fired). Fixed;
further confirmation RLS is enforcing.

---

## D. Front-Door 2a — Authenticated Tenant Binding

RLS (Section C) is the *backstop*; before this gate the Conductor API had **no
authentication** and `tenant_id` came from a process env var, disconnected from
the (unauthenticated) `client_id` body field. The backstop had no front door.

**Decision:** ADR §12.14 (extends §1) — every engagement endpoint requires a
verified JWT; `tenant_id` comes ONLY from the verified claim; engagement
ownership enforced; per-request per-tenant store routing.

**Implementation (verified in code):**
- `conductor/api_auth.py` — PyJWT, algorithm pinned (`algorithms=[JWT_ALGORITHM]`, no `alg=none`/confusion), `exp` checked, **fail-closed** if the secret is missing or < 32 bytes, `tenant_id`/`sub` claims validated.
- `conductor/main.py` — auth-by-default via `APIRouter(dependencies=[Depends(require_principal)])`; new engagement routes cannot ship unprotected.
- `config/stores.py` — `StoreProvider.for_tenant()` routes each tenant to its own RLS-scoped store (independent in-memory store per tenant when no DSN).
- `authorization.py` — `tenant_id` persisted on `EngagementRecord`; `_emit_event` enriches the payload so auth events route to the correct tenant store.

**Gaps found during review & closed (the audit working as intended):**
- **Unwired auth (Lyndon #2).** `require_principal` existed but was not wired into any route — caught immediately by the test-first 401 contract (CI red). Fixed via router-level dependency.
- **`/sow` + `/stop` lacked the ownership check (cross-tenant authZ hole).** Authenticated but not authorized — any tenant could SOW-escalate or emergency-stop another tenant's engagement. The original test contract under-specified (only `state`/`recon` were covered); tests for `sow`/`stop` were added, then the ownership check was applied to all four routes. (`test_api_auth.py` 11 green.)
- **Emergency-stop events routed to the legacy store (audit-isolation gap).** `EmergencyStopHandler` now resolves the engagement's tenant via `StoreProvider`; stop events land in the tenant's own store. (`test_emergency_tenant_routing.py` 2 green.)
- **Cosmetic (open, non-blocking):** the top-of-file docstring in `config/stores.py` still says "single-tenant operation for now" — contradicts `StoreProvider`; tidy in a follow-up commit.

---

## E. Anti-Lyndon Audit (this hardening work)

| Pattern | Result |
|---------|--------|
| #2 Dead code / unwired | ✅ CAUGHT & FIXED — `require_principal` shipped unwired; test-first 401 contract turned it red until wired |
| #3 False success (empty/skip = success) | ✅ CAUGHT & FIXED — flawed RLS test replaced; `AGENT_ALPHA_REQUIRE_DB=1` (`tests/conftest.py`) makes a skipped integration suite a hard error |
| #6 Duplicate canonical type | ✅ None in code — docs-level divergence RESOLVED 2026-07-08: `ADR_ROADMAP.md` retired → `ADR_HISTORY.md`, `ADR.md` is sole canonical source |
| #7 Single source of truth | ✅ table names + JWT alg/secret env via constants; no literals |
| #9 Non-Oracle results accepted | ✅ ENFORCED — CI runs on self-hosted Oracle ARM64 |

---

## F. CI Enforcement

`.github/workflows/ci.yml` (self-hosted Oracle ARM64):
- Ephemeral Postgres (pgvector pg16) + Redis service containers — hermetic, no shared mutable state.
- Provisions the `NOSUPERUSER NOBYPASSRLS` `agent_alpha_app` role (so RLS tests are meaningful, not bypassed).
- `AGENT_ALPHA_REQUIRE_DB=1` → integration backends mandatory; missing/unreachable = hard fail, never a silent skip.
- `make check` (ruff + format + mypy) then the full suite.
- **Branch protection on `main` requires the `quality-gate` check → red CI blocks merge.**

**Proof:** GitHub Actions, self-hosted runner — **292 passed, 4 skipped**
(4 = 2 DeepSeek live without API key + 2 superuser-only guard constructs).
Integration + RLS + auth + emergency-routing executed, not skipped.

---

## G. Remaining & Next

- ✅ Branch protection enabled — seal is ENFORCED. (Verify "Require status checks
  to pass" is ticked with `quality-gate`, and admins cannot bypass / no direct
  push to `main`.)
- 🧹 Cosmetic: tidy the stale `config/stores.py` module docstring (Section D).
- ✅ Docs hygiene: `ADR.md` vs `ADR_ROADMAP.md` divergence RESOLVED 2026-07-08 — `ADR_ROADMAP.md` retired, `ADR.md` is sole canonical.
- ➡️ **Hardening-P3 — Orchestrator:** Celery non-blocking execution + LLM
  orchestrator routing/consensus. Gated by the open LLM-routing decision
  (resolve before building). Carries **front-door 2b** (propagate `tenant_id`
  through Celery tasks) and unblocks the Phase-2 inner-monologue delivery
  transport deferred in `PHASE_2_AUDIT.md` §E.

*This document is the single source of truth for the pre-Phase-3 hardening gates.*
