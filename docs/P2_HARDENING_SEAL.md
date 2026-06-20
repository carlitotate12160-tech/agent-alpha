# Pre-Phase-3 Hardening — Audit & Seal Report

**Date:** 2026-06-20
**Auditor:** Claude (senior security architect, peer review)
**Method:** Live trace on a fresh GitHub clone (anti-Lyndon #2 — verify, don't trust docs) + CI result review.
**Authoritative verification environment:** Oracle ARM64 only (anti-Lyndon #9).

> **Naming note.** This document covers the **pre-Phase-3 hardening gates**
> (P0→P3), which are SEPARATE from the project's *functional* Phase 2 kill chain
> already sealed in `docs/PHASE_2_AUDIT.md` (2026-06-19). The "P2" here is the
> **durable-persistence + tenant-isolation** gate, not the Alpha→Omega chain.

> **Verdict: hardening-P2 SEALED** on GitHub Actions / Oracle ARM64
> (279 passed, 4 skipped, `make check` clean), **conditional on one UI toggle:**
> branch protection requiring the `quality-gate` check must be enabled on `main`,
> otherwise a red CI reports but does not *block* merge. Enable it to make the
> seal enforceable. Next gate: **hardening-P3 (orchestrator)**.

---

## A. Hardening Gate Status

| Gate | Scope | Status | Evidence |
|------|-------|--------|----------|
| P0 | 5 architecture decisions ratified | ✅ SEALED | Python-only MVP, Telegram approval, `tenant_id`+RLS multi-tenancy, OutcomeTag→Phase 3, VERIFY→Phase 6 (`docs/P0_DECISION_RECORD.md`) |
| P1 | CI on Oracle ARM64 + LLM input redaction | ✅ SEALED | Self-hosted ARM64 runner, red-blocks proven; `llm/redaction.py` closes prompt-injection (`test_redaction.py` 6 green) |
| **P2** | **Durable persistence + tenant isolation** | ✅ **SEALED** (this report) | Postgres event+engagement, Redis session, **RLS enforced & proven**, fail-closed guard, CI runs integration for real |
| P3 | Orchestrator (Celery non-blocking + LLM routing) | ⬜ NEXT | Not started |

---

## B. P2 Evidence (durable persistence)

| Capability | Status | Proof |
|------------|--------|-------|
| Postgres event store, append-only at DB layer | ✅ | `test_postgres_event_store.py` (4) — incl. restart→replay **byte-identical** + BEFORE UPDATE/DELETE trigger raises |
| Postgres engagement memory (idempotent upsert projection) | ✅ | `test_postgres_engagement_memory_store.py` (4) |
| Redis session store, durable across restart | ✅ | `test_redis_session_store.py` (7) |
| Restart → replay reconstructs state exactly | ✅ | `test_restart_replay_is_byte_identical` |
| EventStore Protocol conformance (no duplicate canonical type) | ✅ | Protocol-conformance tests on both backends |

---

## C. Tenant Isolation — Vulnerability Found & Fixed (headline)

This is the substantive P2 finding. It is recorded in full because it is a
textbook Lyndon #3 (false success) that the prior "18 green" had masked.

**C-1 — RLS was effectively INERT; the green tests proved the wrong layer.**
Every store query carries an explicit `WHERE tenant_id = %s` (events/store.py
`get_events`/`count`/`append`; engagement.py `get`). The first isolation tests
only exercised the store API, so they passed **even if Row-Level Security were
dropped entirely** — they validated the *application filter*, not RLS, the
defence-in-depth backstop that matters when a query ever forgets that filter.

**C-2 — Root cause: the DSN role was a SUPERUSER.** The Postgres image makes
`POSTGRES_USER` a superuser, and superusers bypass RLS even under
`FORCE ROW LEVEL SECURITY`. A corrected test (raw, tenant-filter-free SQL under
an `app.tenant_id` GUC) proved it on Oracle: tenant B read tenant A's rows and a
forged cross-tenant INSERT was accepted. **Tenant isolation rested entirely on
every query remembering `WHERE tenant_id` — a single point of failure.**

**Resolution (all verified):**
1. `infra/create_app_role.sql` — dedicated `agent_alpha_app` role,
   `NOSUPERUSER NOBYPASSRLS`, owns the tables so `FORCE` subjects it. DSN
   repointed to it.
2. `agent_alpha/storage/rls_guard.py` — `assert_role_cannot_bypass_rls`, called
   from both Postgres stores' `__init__`: the app **refuses to start**
   (`RlsNotEnforcedError`) under a role that can bypass RLS. Misconfig now fails
   closed instead of leaking tenants silently. (`test_rls_guard.py` 5 green.)
3. `tests/integration/test_rls_isolation.py` — true-RLS probes: raw unfiltered
   cross-tenant read = 0, WITH CHECK blocks forged inserts, guard asserts
   non-bypass. 5 green under the restricted role.

**C-3 — Append-only test reached the trigger only after RLS scoping.** Once RLS
was truly active, `test_append_only_rejected_by_db` used a raw connection with no
`app.tenant_id`, so RLS hid the row → UPDATE/DELETE matched 0 rows → the trigger
never fired. Fixed by scoping the raw connection to the owning tenant (the
meaningful immutability test: as the owning tenant, mutation is rejected by the
trigger). Not a product defect — further confirmation RLS is now enforcing.

---

## D. Anti-Lyndon Audit (this hardening work)

| Pattern | Result |
|---------|--------|
| #3 False success (empty/skip = success) | ✅ CAUGHT & FIXED — flawed RLS test replaced; CI `AGENT_ALPHA_REQUIRE_DB=1` turns a skipped integration suite into a hard error (`tests/conftest.py`) |
| #9 Non-Oracle results accepted | ✅ ENFORCED — CI runs on self-hosted Oracle ARM64; integration executes there, not a look-alike |
| #2 Dead code / unwired | ✅ — integration tests now actually *run* in CI (service containers), not collected-then-skipped |
| #6 Duplicate canonical type | ✅ None — single RLS guard shared by both stores |
| #7 Single source of truth | ✅ — table names via `EVENT_STORE_TABLE`/`ENGAGEMENT_MEMORY_TABLE` constants; no hardcoded literals in tests |

---

## E. CI Enforcement

`.github/workflows/ci.yml` (self-hosted Oracle ARM64):
- Ephemeral Postgres (pgvector pg16) + Redis service containers — hermetic, no shared mutable state.
- Provisions the `NOSUPERUSER NOBYPASSRLS` `agent_alpha_app` role; app connects as it (so RLS tests are meaningful, not bypassed).
- `AGENT_ALPHA_REQUIRE_DB=1` → integration backends mandatory; missing/unreachable = hard fail, never a silent skip.
- Runs `make check` (ruff + format + mypy) then the full suite.

**Proof:** GitHub Actions run on the self-hosted runner —
`279 passed, 4 skipped` (4 = 2 DeepSeek live without API key + 2 superuser-only
guard constructs), integration + RLS executed (not skipped).

---

## F. Remaining & Next

- ⏳ **Enable branch protection** on `main`: Settings → Branches → require status
  check `quality-gate`. Until then the seal is *reported* but not *enforced*.
- ➡️ **Hardening-P3 — Orchestrator:** Celery non-blocking execution path + LLM
  orchestrator routing/consensus. This also unblocks the Phase-2 inner-monologue
  *delivery transport* deferred in `PHASE_2_AUDIT.md` §E.

*Seal is conditional (Section F1). This document is the single source of truth for the pre-Phase-3 hardening gates.*
