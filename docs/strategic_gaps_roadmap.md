> DERIVED / NARRATIVE VIEW from BUGS_AND_GAPS.md (G1–G17 ↔ GAP/Bug ids). Ledger of record = BUGS_AND_GAPS.md.

# Agent-Alpha — Strategic Gaps & Resolution Roadmap
**Durable record (commit to `docs/`). Source: architecture peer-review, 2026-07.**

> **Success condition (the ONLY bar):** Agent-Alpha finds something a conventional
> scanner missed, **proves it's exploitable**, and produces a report a client would pay for.
> Every phase below is ranked by leverage toward THIS bar.

## Central weakness
Ferrari-grade recon + governance; go-kart exploitation. The hard 80% of "red team"
(exploitation, hypothesis-driven chaining, business logic, adversary emulation, cross-
engagement memory) is unbuilt, while the recon/cognition front is over-invested.
**Curator ruling: recon is HARD-STOPPED. No more fingerprint enrichment / WAF backoff /
crawl-depth (= Lyndon #5).**

## Weakness inventory (by layer)
**Architecture / agent design**
- G1. "Brain" is reactive tool-selection; HTN planner deferred → pattern-match-and-probe, not hypothesis-and-exploit.
- G2. Agents are dispatchers over a fixed playbook catalog → cannot find a vuln class it has no playbook for.
- G3. Attack graph is a record, not a reasoning substrate (analytics feed reporting, not decisions — GAP-006).

**Behavior**
- G4. Active-first; passive/OSINT is one crt.sh call (GAP-007).
- G5. No adversary emulation / threat-actor TTP modeling.
- G6. OPSEC static (one speed/fingerprint); no adaptive evasion (§12.33 unbuilt).
- G7. No human-in-the-loop for judgment (business-logic/creative chains — AI misses ~58%).

**Tools**
- G8. Arsenal narrow + commodity (path-probe, header-fp, cred-reuse) — all things Nuclei does.
- G9. Zero exploitation tooling (Gamma): no RCE/webshell/post-exploit → cannot "prove exploitable."
- G10. High-value vuln classes absent: IDOR, business logic, SSRF, injection, auth-flow, API fuzzing.
- G11. DeepSeek payload-gen is a design idea, not a wired generate→test→refine loop.
- G12. No HTTP proxy / traffic manipulation.

**Cross-cutting**
- G13. Cross-engagement memory (the real moat) unbuilt (GAP-003 protocol-only) → no memory edge over a scanner.
- G14. "Payable report" (Omega) unproven client-grade; proof is thin without Gamma.
- G15. Validation self-referential (self-owned labs only) — never vs a real target + Nuclei baseline.
- G16. Go execution engine (throughput/stealth) not built; all Python.
- G17. Discipline's shadow: perfecting easy recon foundations = sophisticated avoidance of hard exploitation work.
- G18. Fan-out interface built but not wired to runtime — multi-target engagements run sequential (Shape B), not parallel (Shape A). ADR §12.13 LOCKED but wiring debt fell through cracks (PROGRESS_TRACKER marked DONE, Session_Handoff doesn't track).

### Cross-reference: G-items → BUGS_AND_GAPS.md ledger ids

| G-item | GAP/Bug id | Status |
|--------|-----------|--------|
| G1 | GAP-004 (§12.29) | LOCKED — D1/D2-a/D2-b/D3/D4/D5 LANDED |
| G2 | GAP-001 | OPEN — playbook coverage rubric §12.26 |
| G3 | GAP-006 (§1/§6) | slice-1 DONE #184; slice-2 OPEN (needs GAP-004) |
| G4 | GAP-007 | OPEN — future phase |
| G5 | — (no GAP id; adversary emulation = Phase E3) | OPEN |
| G6 | GAP-012 (§12.33) | LOCKED — curl_cffi DONE #218+#219; 9c browser_solve PARKED (datacenter IP) |
| G7 | — (no GAP id; human-in-the-loop = future enhancement) | OPEN |
| G8 | GAP-001 | OPEN — same as G2 |
| G9 | — (Gamma = Phase B1/B2) | OPEN — STOP-gated behind ToolComposer |
| G10 | GAP-011 (§12.32) | LOCKED in ADR; implementation needs GAP-004 |
| G11 | — (DeepSeek payload loop = Phase B3) | OPEN |
| G12 | — (HTTP proxy = deferred/market-driven) | OPEN |
| G13 | GAP-003 (§8c/§12.11) | OPEN — needs Bug #7 first |
| G14 | — (Omega report = Phase B-dependent) | OPEN |
| G15 | — (A1 validation = Phase A DONE) | DONE — mechanism proven, REACH blocked |
| G16 | — (Go engine = Phase 7) | DEFERRED |
| G17 | — (meta-pattern, no single GAP) | ONGOING — curator rule enforces |
| G18 | GAP-014 (§12.13) | OPEN — interface built, runtime wiring debt |

## Strengths (keep — do not regress)
Event-sourced + auth-gated + auditable governance (real edge for LEGAL red-team SaaS);
anti-Lyndon discipline (clean, tested, non-dead code); chain-proving (leaked-cred→admin)
already beyond a scanner; data-driven catalogs (learnable seed for the moat); rigorous field-prove/lab method.

## Phased resolution (step-by-step, leverage-ranked)

### Phase A — VALIDATE (cheapest; defines everything) ✅ DONE
- **A1.** Success-condition validation harness: Alpha→Beta full chain **vs Nuclei baseline** on a
  SELF-OWNED vulnerable stack (WP/Odoo, planted leaked-cred→admin chain) behind a **real Cloudflare/WAF**.
  - Done = a report showing what Agent-Alpha proves that Nuclei does NOT (or the precise gap).
  - Outcome drives Phase B/C priority. Closes G15.
  - **RESULT:** Mechanism GENUINE (chain proven via harvested cred, T1078+T1552.001). Real CF WAF
    BLOCKS chain (403/challenge, 0 creds). Success condition NOT proved on real targets —
    mechanism yes, REACH no. Evasion is now GATING blocker. See A1 outcome section below.

### Phase B — EXPLOITATION (the missing "prove exploitable")
- **B1.** ToolComposer + blast-radius gate completion (Gamma prereq; blast-gate slice-1 done #184). Claude lane = gate; DeepSeek lane = destructive bodies.
- **B2.** Gamma/ANCHOR skeleton — first real exploitation primitive (Beta access → proof-of-code-exec on self-owned). Closes G9.
- **B3.** Wire the DeepSeek generate→verify→refine payload loop (bounded, gated). Closes G11.

### Phase C — REASONING (so "scanner-missed" is intentional, not luck)
- **C1.** Graph-driven decisions: critical-paths/blast-radius feed the PLANNER, not just the report (GAP-006 slice-2). Closes G3.
- **C2.** Hypothesis-driven exploration + cross-tool verification (§12.30/§12.31). Closes part of G1/G7.
- **C3.** Broaden vuln classes toward high-value: IDOR/auth-flow first (needs a stateful/browser tool). Closes part of G10/G8.

### Phase D — MOAT (durable differentiation)
- **D1.** Bug#7 EngagementMemory persist → GAP-003 IntelligenceBase (cross-engagement + regional intelligence; weights the path/technique catalog by hit-rate). Closes G13.

### Phase E — BEHAVIOR / OPSEC realism (after core capability)
- **E1.** §12.33 adaptive evasion (bounded, evasion-gated) + GAP-005 slice-2b/2c. Closes G6.
- **E2.** Passive OSINT external (DNS/ASN WAF-hint, Shodan/CT) → TargetProfile enrichment (GAP-007). Closes G4.
- **E3.** Adversary/threat-actor emulation profiles (MITRE actor TTPs). Closes G5.

### Background wiring (low-effort, no prerequisites, do anytime)
- **W1.** GAP-014 fan-out parallel worker wiring — `FanOutDispatcher` interface built + tested but not wired to Celery `.delay()`. Replace sequential `for url in targets:` loop in `recon_runner.py` with `FanOutDispatcher.dispatch()`. Effort: Low (3 files, pattern already proven in `run_engagement_task`). Closes G18.

### Deferred / market-driven
Browser automation tooling (G10/G12), Go execution engine (G16), Omega client-grade report polish (G14) — sequence per Phase-A outcome + first client.

## Standing curator rules
1. Recon depth is closed. Reject new recon as #5.
2. Validate before building (Phase A gates B/C priority).
3. One slice at a time, field-proven, single-source, anti-god-object.
4. Gamma stays STOP-gated behind ToolComposer + blast-radius until B1 done.

---

## A1 VALIDATION OUTCOME + RE-RANK (2026-07, session decisions)
**Decisions:** quantum-laboratories.com = self-owned lab (authorized). GTM = **ENTERPRISE-FIRST**.

**A1 gave two decisive, honest signals:**
- ✓ Mechanism GENUINE: self-owned chain proven via HARVESTED cred (edge_from_harvested_cred=True,
  db_enumerated=True, verified admin; T1078+T1552.001). Concern "default-cred contamination" RESOLVED.
- ✗ REAL Cloudflare WAF BLOCKS the whole chain (root=CHALLENGE, leak paths=403, chain_proven=False,
  0 creds). The trycloudflare tunnel earlier was pass-through (false-negative). Against a real WAF
  zone Agent-Alpha never reaches the leak.

**Consequence (evidence-driven re-rank):** enterprise targets sit behind WAF → **evasion (G6/§12.33)
is now the GATING blocker, UPSTREAM of Gamma** (cannot exploit a target you cannot reach). Success
condition is NOT proved on real targets — mechanism is, reach is not.

**Governance finding:** odoo_chain_runner (and peers) do NOT enforce lab_guard — pointed at an
external domain with no gate. Close FIRST (assert_lab_only_target, fail-closed).
**VERIFIED:** all 13 runners DO enforce assert_lab_only_target. Hole was in allowlist process
(quantum-laboratories.com added on verbal confirmation). Process fix: allowlist changes require
PR review + domain ownership proof.

**Revised near-term order (enterprise-first):**
0. Governance fix: lab_guard on all chain/live-fire runners. ✅ DONE (PR #215 merged, DNS TXT proof enforced)
1. Phase B-evasion: §12.33 BOUNDED curl_cffi TLS/JA3 impersonation, evasion-gated, lockout-bounded
   (table-stakes to REACH WAF'd targets — commodity wrap, NOT the moat, NOT an 11-layer engine).
   ✅ DONE (PR #218 + #219 merged — MitigationClass discriminator + LockoutGovernor + EvasionPlanner)
   Re-run A1 vs the real-CF lab to prove reach.
2. Phase B-Gamma: ToolComposer + blast-gate + ANCHOR (depth: turn "got admin login" into
   proof-of-code-exec / real exploitability).
3. Phase D moat (cross-engagement intelligence) + Phase C reasoning.
Note: current stack IS viable TODAY for the un-WAF'd SME segment — a parallel revenue path if desired.

---

## Moat Depth Roadmap (2026-07-23 update)

> DERIVED leverage-narrative view. Canonical status → Session_Handoff.md.
> Durable verification doctrine → CLAUDE.md + ADR §12.31.

How Agent-Alpha deepens its defensibility — and the order that maximizes leverage for a solo
engineer. This is a menu ordered by leverage, not a checklist to finish in parallel.

### Two axes of "deepen" (do not conflate)

1. **Kill-chain DEPTH** (how FAR): Alpha → Beta → Gamma → Delta → Epsilon. Today only recon +
   initial-access are proven (depth ~2). Going deeper = exploitation → post-ex → lateral. This is
   the DANGEROUS, gated lane (Gamma+).
2. **Moat DEPTH vs competitors** (how uncopyable): verification, cross-engagement learning, tool
   breadth. ORTHOGONAL to kill-chain — it makes what exists smarter / more trusted / broader.

The A1 chain is depth-2 but a COMPLETE proof (leak → login → verified admin). The moat is already
demonstrated; deepening moat makes it durable, deepening kill-chain makes the story go farther.

### The Independent Verification Axiom (durable — the core moat principle)

A verifier is meaningful ONLY if its failure mode DIFFERS from the finder's.
- Re-running the same signal (e.g. a graph-walk over what tools asserted) is NOT verification —
  same failure mode = internal-consistency check = #3 (false success) at the oracle level.
- Genuine confirmation = an INDEPENDENT signal: re-authenticate the credential, re-fetch ground
  truth. Different failure mode = real confirmation.
- verified tri-state: `unverified` (asserted) < `self_verified` (finder re-checked, weak) <
  `cross_verified` (independent oracle confirmed). Only `cross_verified` may back a "proven" claim
  in a payable report.
- **ChainOracle = COMPOSITION of independent per-edge oracles** (chain cross_verified iff every
  edge cross_verified), NEVER a graph traversal.

This is the single most important architectural insight of the moat: proof, not consistency.

### The three moat tracks, ranked by leverage

| Track | What | Leverage | Timing |
|-------|------|----------|--------|
| **2. Oracle / verified tier** | independent per-finding verification; "proven" = cross_verified | HIGHEST — deepest moat, synergistic with Omega | now (partly DONE) |
| **1. Cross-engagement intelligence (GAP-003)** | agent learns across engagements | compounds, but SLOW — needs data volume | foundation now, decision-wiring after volume |
| **3. ToolComposer / wrap commodity** | trufflehog/nuclei as graph-feeding tools | breadth, not moat | continuous background |

Notes:
- Track 1 needs DATA. Building the full IntelligenceBase decision-wiring before real engagements =
  training a learner with ~0 data (feature-before-foundation). Land Bug #7 persist + outcome
  tagging opportunistically; HOLD the decision-wiring until engagement volume exists.
- Track 3's trufflehog live-validation is really a special case of Track 2 (prove-or-kill). Not a
  separate phase.

### Current status (what is already done)

- Omega A/B/C: evidence bundle + attack-flow diagram + client-facing HTML report — DONE.
- Track-2 slice: `AttackNode.verification` tri-state + `CredReuseOracle` with PROOF-BINDING
  (subject_ref == enabling credential, access_level + target match) — DONE, non-island in the A1
  runner, gate-ordered after C7. Report claims "proven" only on `cross_verified`.

### The reality that emerged (autonomous-parity now gates everything)

An island audit found the moat + reach capabilities are proven in the field-prove RUNNERS but NOT
in the AUTONOMOUS path (Conductor → execute_agent → scout) a real engagement uses. Confirmed islands
(0 calls in scout.py / execute_agent.py):
- Reach (classify_mitigation, choose_reach, origin_direct_fetch, OriginDiscovery, browser_solve).
- Oracle verification (run_verification_pass) — only in the A1 runner.
- PolicyEnforcer scope/technique checks; OPSEC profile resolution — not in the agent path.
- seed_frontier_from_passive() — passive discovery found subdomains never enter Alpha's frontier.

DOCTRINE (now in CLAUDE.md + enforced via tests/governance/test_wiring_gate.py): a runner-scoped
seal is an ISLAND until the AUTONOMOUS path calls it. Register each gap as tracked wiring-debt so CI
fails until wired — do not rely on memory or docs.

Consequence for the roadmap: bringing the autonomous path to PARITY with the runners is now the
gate before any paid engagement — and therefore before further moat/kill-chain depth.

### Root-cause collapse (do not whack-a-mole)

The Laravel-not-detected / empty-WorldModel / 40-row block-detection findings collapse to ONE root:
Alpha analyzes the defender's WAF page as if it were target content, with no autonomous reach.
- REACT: reach in the autonomous loop (get real content → real nodes → WorldModel works → Laravel
  detected).
- RECOGNIZE: generalize block detection by STRUCTURAL content-authenticity ("real app vs
  interstitial"), NOT per-vendor string lists (an unwinnable arms race) — plus missing status codes
  (401/406/451/521-525, cf-mitigated) and a few mitigation classes (GEO_BLOCK, CONTENT_NEGOTIATION,
  CONNECTION_FAIL).

### Leverage-ordered sequence (current)

1. **Autonomous-parity (pre-engagement, blocking):**
   a. Reach → Alpha's autonomous loop (fatal — else Alpha stops at the client WAF).
   b. Generalized block recognition (structural, not per-vendor).
   c. run_verification_pass → execute_agent (so cross_verified fires autonomously, not only in the
      runner).
   d. seed_frontier_from_passive() + set objective in the client path.
   e. Register all islands as tracked wiring-debt in test_wiring_gate.py.
2. **§12.36 signed authorization gate** (legal prerequisite for any client + brings scope-check +
   capability-gate + OPSEC into the autonomous path).
3. **Re-prove A1 via the AUTONOMOUS path** (scout.run_recon, NOT the runner) — the real reach seal.
4. **First real authorized engagement** (recon + initial-access + proof) → validate + get paid.
5. **ChainOracle** = composition of independent per-edge oracles (finishes the verification moat).
6. **GAP-011 authenticated re-recon** — deepen the chain (depth 2→3) WITHOUT the destructive lane:
   after Beta gets admin, re-crawl with the active session → IDOR, broken access, hidden admin
   functions. Still recon-tier, not Gamma.
7. **Track-1 (IntelligenceBase)** decision-wiring — once engagement volume exists.
8. **Gamma** (ToolComposer + blast-gate → destructive exploitation) — only after: sellable loop +
   moat + §12.36 auth-gate live + client-pull for deeper exploitation. Never before the auth gate.
9. **ToolComposer / trufflehog** — continuous background.

### Gamma gating (non-negotiable)

Gamma = destructive exploitation. It runs ONLY behind §12.36 OFFENSIVE_APPROVED + blast-radius gate.
Building Gamma before the authorization gate exists = softening the gate on the most dangerous lane.
Client-pull justifies Gamma, not speculative build.

Confidence ~80% on ordering. The one shift vs the original brainstorm: autonomous-parity (item 1)
was invisible until the island audit — it now precedes the moat-deepening, because a moat wired only
into runners does not exist for real engagements.
