# Pre-Phase-3 Hardening — Priority Plan

**Date:** 2026-06-20
**Author:** Claude (architect + peer) with Natanael (Eko)
**Purpose:** Close every gap found in the first-principles review BEFORE any
Phase 3 (offensive) work begins. Sequenced by dependency and leverage, not by
gut. Each tier is a HARD GATE — the next tier may not start until the current
tier's exit criteria pass on Oracle ARM64.

> **Peer duty (standing rule, at Natanael's request):** if any tier's exit
> criteria are not 100% met and someone tries to advance, Claude STOPS and says
> so before continuing. No silent progress. No "fix later." This is the
> anti-Lyndon contract.

> **Scope boundary:** this plan hardens the FOUNDATION. It does NOT build the
> product differentiator (exploit composition, cross-engagement intelligence,
> non-trivial findings) — that is Phase 3+ feature work and is tracked
> separately at the bottom so it is never mistaken for "missing/forgotten".

---

## Ordering principle

```
P0 DECISIONS        → cheapest, unblocks correct building (decide before code)
P1 ENFORCEMENT/SAFE → CI + redaction: protect everything built next, close a LIVE hole
P2 REAL FOUNDATION  → durable persistence: the event-sourced spine must be real
P3 ORCHESTRATION    → Conductor orchestrator + real Celery (depends on P2)
────────────────────  HARD GATE  ────────────────────
PHASE 3             → Beta/STRIKE + differentiator, on real foundations
```

---

## P0 — DECISIONS (no code; do first) · effort: S · ✅ DONE 2026-06-20 (see docs/DECISIONS_P0.md)

**Resolved:** D0.1 Python-only (Go deferred, trigger recorded) · D0.2 Telegram behind `ApprovalChannel` interface · D0.3 `tenant_id` + Postgres RLS (queue-only rejected) · D0.4 emit OutcomeTag from Phase 3 / consume Phase 6 (TODO relabeled) · D0.5 VERIFY re-test = Phase 6 (closed). **P1 may now begin.**


Lyndon #1/#10 came from building before deciding. Close these as a short ADR
addendum (one paragraph each, recorded in docs/). **Stop-gate: no P1+ code until
every row below has a written answer.**

| # | Open decision | Why it must be decided now |
|---|---------------|----------------------------|
| D0.1 | Go execution engine: build now, or stay Python (record explicitly)? | Changes the agent runtime + "stealth" claim. Currently de-facto Python — must be a CONSCIOUS, recorded choice, not an accident. |
| D0.2 | Approval channel: Telegram only vs web dashboard for SOW/approvals | Conductor orchestrator (P3) needs to know where human gates surface. |
| D0.3 | Multi-tenancy depth: queue-only isolation vs separate DB schema | Decides the Postgres schema in P2. Cheap to decide now, expensive to retrofit. |
| D0.4 | `OutcomeTag` / `tool_success_rates`: when do agents start emitting it? | The learning substrate is empty today. Decide: Phase 3 agents emit OutcomeTag on verified outcomes. Relabel the stale `TODO(Phase 2)` in engagement.py:197 to its real phase. |
| D0.5 | VERIFY/re-test mode: Phase 2 (done) vs Phase 6 — confirm closed | Listed open since architecture phase; confirm and close. |

Exit criteria: each decision has a one-paragraph recorded answer in
docs/ADR_ROADMAP.md (or an ADR addendum). Stale `TODO(Phase 2)` relabeled.

---

## P1 — ENFORCEMENT + LIVE SAFETY · effort: S each

### P1.1 — CI on Oracle ARM64 (anti-Lyndon enforcement, automated)
The discipline ("Oracle only, 100% green, make check") is currently MANUAL —
a regression is caught only if someone remembers to run. For a 4×-failed
project, automate the gate.
- Exit: a CI workflow runs `pytest tests/` + `make check` on Oracle ARM64 (or
  an ARM64 runner) on every push; red build blocks merge. One intentional
  failing commit proves the gate actually blocks.

### P1.2 — `llm/redaction.py` — close the LIVE prompt-injection surface
Today the SINGLE_LLM tier feeds raw target `observation` (body + headers) into
DeepSeek with NO redaction. Target-controlled content can carry instructions
(ADR §8l). Playbook-first hides this on the RULE path, but the hole is real the
moment a novel observation escalates.
- Exit (test-first): untrusted target text is sanitized/escaped + secrets
  redacted before it reaches any provider; a test injects a prompt-injection
  string in the body and asserts it is neutralized (treated as data, never
  instruction) and that no secret pattern reaches the provider payload.

**Stop-gate:** P2 does not start until CI is green-and-blocking and redaction is
merged.

---

## P2 — REAL FOUNDATION: durable persistence · effort: M

Every store (EventStore, SessionMemory, EngagementMemory, GraphStore) is
IN-MEMORY today. The platform's legal/audit backbone (event-sourced, immutable,
reproducible) is therefore NOT real — events vanish on restart. This must be
real before any offensive agent runs (its audit trail must survive).

Good news: the stores are already behind Protocols, so this is a BACKEND ADAPTER
swap, not a redesign (anti-Lyndon #10 respected).

- Redis adapter for SessionMemory (live, low-latency).
- PostgreSQL adapter for the append-only EventStore + EngagementMemory
  (schema per the P0.3 multi-tenancy decision).
- Exit criteria (the test that proves durability):
  1. Write N events to the real Postgres event store → restart the process →
     replay → projected AttackGraph + EngagementMemory are BYTE-IDENTICAL.
  2. Append-only enforced at the DB layer (attempt to mutate a past event →
     rejected, mirrors the in-memory immutability test).
  3. Secrets never appear in any persisted row or log (extends existing scrub).
  4. All existing 245 tests still green against the real backends (not just
     in-memory fakes) in at least one integration run on Oracle.

**Stop-gate:** P3 does not start until restart→replay→identical passes on real
Postgres/Redis on Oracle.

---

## P3 — ORCHESTRATION: Conductor orchestrator + real Celery · effort: M

Replace the placeholder Celery task (`run_engagement_task` returns
`{"status": "placeholder"}`) with the real Conductor orchestrator. Build it
single-agent first (Alpha THROUGH the Conductor, retiring the
`live_fire → Alpha.run_recon` bypass as a test-only harness) to prove the real
execution path before any second agent exists.

- Exit criteria:
  1. `run_engagement_task` actually runs Alpha via the Conductor, persists
     events (P2), returns a real status — never a placeholder.
  2. Dispatch decisions go ONLY through the Conductor; trace/grep proves no
     agent invokes another agent directly.
  3. Authorization band transitions remain human-gated (a finding cannot
     escalate the band; verified by test).
  4. Emergency-stop revokes a running Celery task within 5s under a real worker
     (not just the in-memory unit test).

**Stop-gate:** Phase 3 (Beta) does not start until a single agent runs
end-to-end through the real Conductor + real persistence + real Celery, green
on Oracle.

---

## HARD GATE → Phase 3

Only after P0–P3 exit criteria all pass on Oracle ARM64 does Beta/STRIKE work
begin. At that point the foundation (decisions, CI, durable persistence, real
orchestration, injection defense) is real — Beta is built on rock, not mock.

---

## Deferred-by-decision (tracked, NOT forgotten, NOT pre-Phase-3 blockers)

These are consciously parked with a named trigger — recorded so they never
resurface as "surprise missing steps":

- **Secrets → HashiCorp Vault / AWS KMS.** Trigger: before the FIRST real client
  engagement (Fernet-in-memory is acceptable for lab/dev only).
- **Go/gRPC execution engine + stealth.** Trigger: per P0.1 decision; if "yes",
  it is its own phase, not a side-patch.
- **Differentiator (the product thesis).** `tools/composer.py` (context-aware
  exploit composition), wiring `IntelligenceBase` to live data, non-trivial
  findings beyond scanner-grade (success condition: "find what a scanner
  missed"). This is Phase 3+ FEATURE work — the reason the platform exists — and
  is expected to be unbuilt now. Do NOT confuse "foundation hardening" with this.

---

## One-line honest status

Foundation LOGIC is proven (Phase 2 sealed). Foundation INFRASTRUCTURE
(durability, orchestration, injection defense, CI) is still mock/manual and is
what P0–P3 makes real. The differentiator has not started — by design.
