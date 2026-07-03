# Phase 3 — Exit Criteria Checklist

**Phase 3 = STRIKE / Initial Access + non-blocking orchestration + the payable
credential/DB kill-chains.** Agent: **Beta (STRIKE)**. Managed by Conductor.

Authored 2026-07-03 (architect + Natanael). Grounded in evidence on Oracle HEAD
`d1e59d0` — 669 pass / 13 skip, coverage 81.27%, `make check` clean (ruff+format+mypy,
83 files). **Rule: a box is only ✅ if there is a green test / field-prove on Oracle
ARM64 — never a claim (anti-Lyndon #3). Do NOT start Phase 4 (Gamma + ToolComposer)
until every ✅-required box below is ✅.**

Legend: ✅ done (evidence) · ⏳ open (blocks exit) · ⏸️ deferred by ADR (does NOT block).

---

## A. Beta / STRIKE agent — the Phase 3 agent

- [x] ✅ **Beta gate is ACTIVE_APPROVED or higher; blocked at CREATED / RECON_ONLY.**
      Evidence: `tests/phase_3/test_beta_strike.py` (gate + blocked-at-recon/created + out-of-scope).
- [x] ✅ **No false success** — empty/identical access is `failed`, not silent success (#3).
      Evidence: `tests/phase_3/test_beta_anti_theater.py` (identical-response, no-auth-signal, rejected-attempt).
- [x] ✅ **Beta live-fire scores against ground truth, leak-free.**
      Evidence: `tests/phase_3/test_beta_live_fire.py`; field-proven container run (cred-reuse chain).
- [x] ✅ **Handoff addressed to Conductor only** (agents never call agents, #A2A rule).
      Evidence: `test_beta_strike.py::test_handoff_addressed_to_conductor`.

## B. Non-blocking orchestration (chat-while-running)

- [x] ✅ **Celery dispatch returns 202 + task_id; status queryable; idempotent; cross-tenant 404.**
      Evidence: `tests/phase_0/test_run_dispatch.py`, `tests/phase_0/test_run_status.py`.
- [x] ✅ **Conductor auto-advances the kill chain, idempotent under retry, parks across tier.**
      Evidence: `tests/phase_3/test_conductor_advance.py`, `test_advance_wiring.py`, `test_emit_handoff_and_advance.py`.
- [x] ✅ **Emergency stop revokes tasks + halts every agent within budget.**
      Evidence: `tests/phase_0/test_emergency.py`, `test_emergency_revoker.py`.
- [x] ✅ **Offensive agent NOT re-run on Celery retry** (terminal handoff = no re-exec).
      Evidence: `tests/phase_3/test_execute_agent.py::test_does_not_rerun_agent_if_terminal_handoff_already_exists`.

## C. A2A integrity / injection defense

- [x] ✅ **A2A messages are structured protobuf; no per-agent free-form handoff types.**
      Evidence: `tests/PROTECTED/test_proto_contract.py` (frozen).
- [x] ✅ **PII/creds redacted before LLM; secrets never persisted to event store.**
      Evidence: `tests/phase_2/test_redaction.py`, `tests/phase_3/test_session_token_redaction.py`, `agent_alpha/llm/redaction.py` (100%).
- [x] ✅ **Reasoning/payload provider policy enforced (Claude forbidden for payload, etc.).**
      Evidence: `tests/phase_2/test_routing.py`, `tests/phase_0/test_policy_enforcer.py`.

## D. Safety gates (non-bypassable, fail-closed) — earned in Phase 3

- [x] ✅ **Auth-gate fails closed on store-read error; role×state matrix; illegal-order transitions.**
      Evidence: `tests/phase_0/test_authorization_gate_coverage.py` (43 tests), `test_authorization.py`.
- [x] ✅ **Co-host scope gate**: bare-IP + sibling-domain-on-same-IP refused for offensive web.
      Evidence: `tests/phase_3/test_cohost_scope_gate.py`.
- [x] ✅ **DB-endpoint scope**: exact host:port from SOW; out-of-scope DB host refused by factory.
      Evidence: `tests/phase_0/test_db_endpoint_scope.py`, `tests/phase_3/test_applicator_factory.py`.
- [x] ✅ **Lab-only guard covers ALL attacker field-prove harnesses (fail-closed discovery gate).**
      Evidence: `tests/integration/test_lab_guard_coverage.py`, `tests/phase_3/test_lab_guard.py` (9).
- [x] ✅ **Tenant isolation (RLS) enforced; superuser/bypass rejected.**
      Evidence: `tests/integration/test_rls_isolation.py`, `test_rls_guard.py`.

## E. The bar — payable chain (finds what a scanner missed, exploitable, payable report)

- [x] ✅ **Credential-reuse chain**: Alpha leaks secret → vault → Beta reuses → access edge;
      Omega report Severity=HIGH (admin, verified). Field-proven on Oracle (container 9201).
      Evidence: `tests/phase_3/test_cred_reuse_chain.py`, `test_chain_finding_severity.py`, `test_chain_runner.py`.
- [x] ✅ **Direct-DB chain**: leak → reuse → verified DIRECT MySQL (db_root) through the factory,
      in-scope host:port. Field-proven vs real in-scope MySQL.
      Evidence: `tests/phase_3/test_db_chain_field_prove.py`, `test_mysql_applicator.py`, `test_credential_pairing.py`.
- [x] ✅ **JS-secret + WP-config recon vectors** field/unit-proven (WAF-block discriminator, no false-clean).
      Evidence: `tests/phase_3/test_js_secret_probe.py`, `test_wp_config_leak.py`, `test_spa_field_prove_clauses.py`.
- [x] ✅ **time-to-proof headline** ("proved in X min") threaded end-to-end via one tested seam.
      Evidence: `tests/phase_3/test_engagement_report_builder_seam.py`, `agent_alpha/conductor/reporting.py` (100%).
- [ ] ⏳ **Honest caveat (NOT a scope gate, but state it): every payable proof to date is on a
      SELF-OWNED lab or an in-scope host we control — no paying-client engagement has been run
      through the Conductor SOW path yet.** Closing this is a business milestone, not a code gate,
      but it is the true "would a client pay?" test. Track separately.

## F. Quality gate (every phase)

- [x] ✅ Full suite green on **Oracle ARM64** (669 pass / 13 skip), not Windows/local (#9).
- [x] ✅ `make check` clean — ruff + format + mypy (83 files).
- [x] ✅ Coverage ≥ 80% floor (81.27%), honest denominator (generated `*_pb2*` + live-fire `main()` glue excluded by design, not gamed).

## G. Deferred by ADR — does NOT block Phase 3 exit (documented, not dead code)

- [ ] ⏸️ **Multi-LLM consensus tier (MiMo reasoning consensus).** Deferred per ADR §12.23 /
      `adr_amendment_consensus_deferral.md`. Wiring it now = dead code (no consumer). Revisit
      when a critical-decision path needs a tie-break. **Not required for exit.**
- [ ] ⏸️ **`PARTIAL` handoff status, `ToolDecision` rename.** Deferred; documented as not-debt.

## H. OPEN before Phase 3 can be CLOSED (hard gate)

- [ ] ⏳ **A7 — Observability = 0.** No tracing/metrics/structured-log infra exists
      (grep: only the time-to-proof *business* metric, no telemetry). For a SaaS that runs
      autonomous offensive tasks, you cannot operate a real engagement blind. **This is the one
      substantial functional gap left in Phase 3.** Minimum bar to define + build: per-engagement
      run trace (agent → tool → outcome), structured audit-log already exists (reuse), and a
      health/queue-depth signal. Test-first, Oracle-only.
- [ ] ⏳ **cohost_pivot default-DENY** (safety landmine, ADR §12.23). Co-host pivot must be
      default-denied BEFORE Epsilon (Phase 5) exists. Cheap to land now as a fail-closed gate;
      do it before it becomes a Phase-5 scramble. (Prereq item, not core Phase-3, but safety.)

---

## Verdict

Phase 3 **functional kill-chain is essentially met** — Beta, non-blocking orchestration,
injection defense, the safety gates, and multiple **field-proven payable chains** (cred-reuse
HIGH, direct-DB db_root) all have green Oracle evidence. The success-condition bar ("scanner-grade
→ real value, payable report") is demonstrated on controlled targets.

**One hard blocker remains before declaring Phase 3 closed: A7 observability (H).** Plus the
cheap cohost_pivot default-DENY safety gate. Consensus (G) is formally deferred and does NOT block.

**Do NOT open Phase 4 (Gamma + ToolComposer + blast-radius) until H is closed and re-verified on Oracle.**
