# P0 Decision Record — Pre-Phase-3 Hardening

**Date:** 2026-06-20
**Decided by:** Natanael (Eko), facilitated by Claude (architect + peer)
**Status:** CLOSED — these resolve the long-standing "open decisions" and unblock P1.
**Supersedes:** the "Open Decisions" list in the master ADR / project instructions.

---

### D0.1 — Execution runtime: **Python-only (record explicitly), Go deferred**
Stay Python through differentiator validation. Rationale: the current bar is
proving the product thesis (context-aware composition + intelligence = a "brain"
problem), not runtime. Go buys stealth + throughput, which only matter at scale /
evasion — neither is on the critical path yet. Adding Go + gRPC now is premature
complexity (a second language, IPC) before the thesis is proven.
**Trigger to revisit Go:** a concrete stealth/evasion requirement from a real
engagement, or a measured throughput ceiling. When triggered, Go is its own
phase, not a side-patch. `a2a.proto` stays the contract so a future Go agent
slots in cleanly.

### D0.2 — Approval channel: **Telegram first, behind an `ApprovalChannel` interface**
Implement an `ApprovalChannel` abstraction; ship the Telegram implementation
first (fastest human-gate: bot, mobile, solo-operator friendly). The Conductor
orchestrator (P3) depends only on the interface, so a web dashboard can be added
later without touching the authorization gate. Anti-Lyndon: interface + one
implementation, not two half-built ones.

### D0.3 — Multi-tenancy: **`tenant_id` column + Postgres Row-Level Security (RLS)**
Single schema, strong per-tenant isolation enforced by RLS. Rationale: a red-team
product holds client secrets/findings — data isolation is mandatory, but
N-schemas-per-tenant adds heavy migration ops. `tenant_id` + RLS gives strong
isolation with one migration path and clean scaling. Queue-only isolation is
explicitly REJECTED (shared tables = weak isolation, unacceptable for this data).
This decision fixes the Postgres schema shape for P2.

### D0.4 — `OutcomeTag` emission: **emit from Phase 3, consume in Phase 6**
Agents begin emitting `OutcomeTag`-tagged events from Phase 3, on *verified*
outcomes (the cognitive-loop VERIFY step). The EngagementMemory projection then
populates `tool_success_rates` + `time_to_exploit_per_phase` from those events.
`IntelligenceBase` (the consumer / learning loop) stays Phase 6, by which time a
real data substrate exists. The stale `TODO(Phase 2)` at `engagement.py:197` has
been relabeled accordingly (it was mislabeled — Phase 2 never owned it).

### D0.5 — VERIFY / re-test mode: **Phase 6 (confirmed closed)**
The VERIFY *step* of the cognitive loop (OBSERVE→…→VERIFY→PERSIST) already exists
and shipped in Phase 2. A VERIFY/re-test *engagement mode* (re-run an engagement
to confirm a client's remediation) belongs to Phase 6 (continuous engagement).
Confirmed and closed — no Phase-2/3 work owed.

---

**Exit criteria for P0: MET.** All five decisions recorded with rationale; stale
TODO relabeled. P1 (CI + redaction) may now begin.
