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
