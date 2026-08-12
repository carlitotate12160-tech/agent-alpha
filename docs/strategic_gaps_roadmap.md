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
- G18. Fan-out interface built but not wired to runtime — multi-target engagements run sequential (Shape B), not parallel (Shape A). ADR §12.13 LOCKED but wiring debt fell through cracks (PROGRESS_TRACKER marked DONE, docs/Session_Handoff.md doesn't track).
- G19. Passive Supply Chain Attack (Subdomain takeover, poisoned CDNs, dependency hijacking) is deferred. Agent is restricted to direct target vectors.

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
| G19 | — (§12.56 Passive Supply Chain) | DEFERRED to Phase E |

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
- **E4.** Passive Supply Chain Attack (Subdomain takeover, dependency OSINT, poisoned CDN detection). Closes G19.

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

> DERIVED leverage-narrative view. Canonical status → docs/Session_Handoff.md.
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

---

## Alpha Recon Completion + Beta Freeze (2026-08-12 amendment)

> **Trigger:** solusibersama.co.id live run (2026-08-12) — Alpha fetched correct
> responses but discarded critical data. Beta failed not because Beta is weak,
> but because Alpha gave insufficient ammo (0 plugin list, 0 WooCommerce version,
> 0 email, 0 security headers, 0 JS secrets). GAP-052-062 registered.
>
> **Scope: UNIVERSAL, not solusibersama-specific.** These are code-level
> capability gaps in Alpha's handlers, not findings unique to one target.
> Solusibersama is the EVIDENCE that exposed the gaps; the gaps affect EVERY
> engagement. Every WordPress target loses plugin list (GAP-053). Every
> WooCommerce target loses version info (GAP-052). Every WP REST users response
> loses email + roles (GAP-054). Every target loses security headers audit
> (GAP-055), robots.txt (GAP-056), XML-RPC (GAP-057), JS secrets (GAP-058),
> cookie audit (GAP-059), TLS/MX/SPF (GAP-062). Fixing these means completing
> Alpha's recon handlers so EVERY client engagement gets full surface map —
> not hardcoding special cases for one target.

### Curator rule #1 — clarification (not amendment)

Curator rule #1 ("recon depth is closed. Reject new recon as #5.") was created
to stop **perfecting** recon to avoid exploitation work (G17). It does NOT mean
"Alpha may skip basic recon that free scanners have."

**"Perfecting" (rejected, #5):** deeper fingerprinting, more WAF backoff
strategies, more crawl depth, softer soft-404 calibration — making what exists
more sophisticated.

**"Completing" (allowed, not #5):** basic recon capabilities that Alpha should
already have — security headers, robots.txt, XML-RPC check, JS secret
extraction, cookie audit, MX/SPF/DMARC. These are minimum viable recon. A
scanner like Nuclei/nikto/wpscan checks these for free. Alpha NOT checking them
= Alpha worse than a free scanner, which violates the success condition.

**Rule:** GAP-052-059, 062 = completing (allowed). GAP-060, 061 = depth (defer).
Curator rule #1 intent preserved: we are not perfecting recon, we are
completing basic recon that should already exist.

### Beta freeze rule

**Beta's existing logic stays running** — credential attack via leak path is
proven (alpha-ai.web.id: origin-exposure → wp-config.php.bak → DB password →
cred reuse on Odoo → uid=2 admin, SELF_VERIFIED). Do NOT break what works.

**Beta ENHANCEMENTS are FROZEN until Alpha P0 gaps are done:**

| Beta enhancement | Frozen because | Unfreeze when |
|------------------|----------------|---------------|
| Breach OSINT (Dehashed/HIBP) | Needs email from WP REST users — Alpha only extracts slug (GAP-054) | GAP-054 done |
| Plugin auth surface attack | Needs plugin list — Alpha has handler but never fires (GAP-053) | GAP-053 done |
| WooCommerce CSRF → admin creation | Needs WC version — Alpha doesn't fetch system_status (GAP-052) | GAP-052 done |
| JS secret → credential reuse | Needs JS extraction — Alpha doesn't extract (GAP-058) | GAP-058 done (P1, can wait) |

**Gamma stays STOP-gated** (non-negotiable, per existing Gamma gating section).
Gamma needs CVE lookup → CVE lookup needs version info → version info needs
GAP-052 + GAP-053. Gamma is unfrozen only after: Alpha P0 done +
IntelligenceBase CVE lookup wired + §12.36 auth gate live.

### Execution order — step by step (the slice sequence)

> ONE slice at a time. Each slice: branch → commit → PR → CI → CodeRabbit →
> merge → field-prove on Oracle ARM64. No parallel slices.

#### Slice 1 — Bug #34 fix (stop cycling)
- **What:** Remove 3 resets from `run_recon` (`_probed`, `_ran_campaigns`,
  `_try_harder_fired`). Make them cumulative across targets in same engagement.
- **Files:** `agent_alpha/agents/alpha/scout.py:241-250` (remove 3 resets),
  keep `_work_queue`, `_dead_hosts`, `_host_stack`, `_soft404_sig` per-target.
- **Test contract:**
  1. Two `run_recon` calls on same Alpha instance → URL probed in call 1 is
     NOT re-fetched in call 2.
  2. Tool run on URL in call 1 is NOT re-selected in call 2.
  3. `try_harder` fires at most once per engagement, not per target.
  4. Single-target engagements behave identically (no regression).
- **Field-prove:** Re-run solusibersama — expect 0 duplicate tool calls in
  cycle 2 (was 8 duplicates). Expect run time < 200s (was ~280s).
- **Why first:** Cycling wastes HTTP + LLM tokens on identical re-probes. Every
  subsequent slice's field-prove is polluted by cycling if this is not fixed.

#### Slice 2 — GAP-053 fix (WP plugin list extraction)
- **What:** `_handle_wp_plugins` exists but never fires because LLM orient fails
  on wp-admin pages. Move the regex extraction (`/wp-content/plugins/(slug)/...?ver=(version)`)
  into a body post-processing step that runs on EVERY WP-host HTML response,
  not just when `wp_plugins` tool is selected.
- **Files:** `agent_alpha/agents/alpha/scout.py:1844-1896` (move regex to body
  post-processing), `agent_alpha/recon/capability_probe.py` (no change —
  extraction is body-side, no new HTTP).
- **Test contract:**
  1. Homepage HTML with `/wp-content/plugins/contact-form-7/...?ver=5.8` →
     SERVICE node (name="contact-form-7", version="5.8") + CVE lookup fires.
  2. wp-admin page HTML with plugin paths → same extraction.
  3. HTML with no plugin paths → 0 nodes (no false positives).
  4. CVE hit → VULNERABILITY node with cve_id, cvss_score, exploit_available=True.
- **Field-prove:** Re-run solusibersama — expect plugin SERVICE nodes (contact-
  form-7, litespeed-cache, yoast-seo, woocommerce, mailchimp-for-wp) with
  versions. Expect CVE checks to fire per plugin.
- **Cross-ref:** §12.61 — plugin CVE determines flank axis (unauth CVE = skip-
  Beta, auth CVE = axis B5 credential).
- **Why P0:** Plugin CVE is #1 WordPress attack vector. Without plugin list,
  IntelligenceBase cannot check CVEs, Gamma cannot know which exploit to
  compose, Beta cannot know which plugin auth surface to attack.

#### Slice 3 — GAP-052 (WooCommerce system_status)
- **What:** Add `/wp-json/wc/v3/system_status` as a frontier_seed after
  woocommerce detection. Add `_handle_wc_system_status` handler that extracts:
  WooCommerce version, PHP version, MySQL version, plugin list + version,
  theme list + version, server info. Mint SERVICE nodes per component with
  version. Cross-reference each (name, version) against CVE catalogue.
- **Files:** `agent_alpha/recon/capability_probe.py` (add system_status seed to
  woocommerce CapabilitySpec), `agent_alpha/agents/alpha/scout.py` (new
  `_handle_wc_system_status` handler).
- **Test contract:**
  1. WC detected + system_status returns 200 JSON → SERVICE node
     (name="woocommerce", version=X) + SERVICE nodes per plugin/theme.
  2. system_status returns 401/403 → no error, no node (graceful skip).
  3. CVE hit for any extracted (name, version) → VULNERABILITY node.
  4. PHP version from system_status merges into ASSET tech_stack.
- **Field-prove:** Re-run solusibersama — expect WooCommerce version in graph.
  Check CVE-2026-3589 (affects WC 5.4.0-10.5.2) applicability.
- **Cross-ref:** §12.61 — WC version determines whether axis B (credential) or
  direct exploit (unauth CVE) is the right flank.
- **Why P0:** CVE-2026-3589 affects WC 5.4.0-10.5.2 (very wide range). Without
  version, Agent-Alpha cannot determine if target is vulnerable. This is a
  false-negative risk: target may be vulnerable but Agent-Alpha reports "no
  known CVE."

#### Slice 4 — GAP-054 (WP REST user full fields)
- **What:** Extend `UserProperties` with `email`, `roles`, `display_name`,
  `avatar_url`, `profile_url`, `description`. Update `_handle_wp_rest_users` to
  extract all available fields from JSON, not just slug.
- **Files:** `agent_alpha/graph/nodes.py:110-119` (extend UserProperties),
  `agent_alpha/agents/alpha/scout.py:1639-1712` (extract all fields).
- **Test contract:**
  1. WP REST users JSON with `slug`, `roles`, `email` → USER node with all
     fields populated.
  2. JSON without `email` (some WP configs hide it) → USER node with
     email="" (graceful, no error).
  3. `roles` containing "administrator" → USER node with roles=["administrator"]
     (Beta can prioritize admin).
  4. 9 users in JSON → 9 USER nodes with all available fields.
- **Field-prove:** Re-run solusibersama — expect 9 USER nodes with email +
  roles (if exposed by this WP config). Admin account should have
  roles=["administrator"].
- **Cross-ref:** §12.61 axis B5 — email is the prerequisite input for breach
  OSINT (Dehashed/HIBP). Without email, GAP-051 RECON_EXHAUSTED pivot cannot
  fire. Roles let Beta prioritize admin accounts.
- **Why P0:** Email is the bridge between Alpha recon and Beta's breach OSINT
  enhancement. Without email in the graph, the entire §12.61 axis B5 doctrine
  is unexecutable. Roles determine Beta's attack priority.

#### [Beta enhancement unfreeze point]

After Slice 4 (P0 complete), Beta enhancements may be built:
- Breach OSINT (Dehashed/HIBP) — needs email from Slice 4.
- Plugin auth surface attack — needs plugin list from Slice 2.
- WooCommerce CSRF → admin creation — needs WC version from Slice 3.

**Beta enhancement is NOT the next slice after P0.** The next slice after P0
is GAP-051 RECON_EXHAUSTED pivot (which IS the breach OSINT integration — it
is both a try_harder pivot AND a Beta enhancement). This is the natural
junction where Alpha's dead-end pivot feeds Beta's new ammo source.

#### Slice 5 — GAP-051 RECON_EXHAUSTED pivot (breach OSINT)
- **What:** When Alpha classifies a dead-end as RECON_EXHAUSTED (all paths
  probed, all 404/200-no-finding, no WAF), pivot to credential breach OSINT.
  Query Dehashed/HIBP for emails harvested from WP REST users (GAP-054).
  If creds found → hand off to Beta with harvested credentials.
  If no creds → honest "no surface found" handoff to Conductor.
- **Files:** `agent_alpha/agents/planner.py` (dead-end classification),
  `agent_alpha/agents/alpha/scout.py` (`_try_harder_recovery` — add
  RECON_EXHAUSTED branch), new module for breach OSINT integration.
- **Test contract:**
  1. RECON_EXHAUSTED + emails in graph → breach OSINT query fires.
  2. Breach OSINT returns creds → CREDENTIAL nodes minted, Beta handoff.
  3. Breach OSINT returns nothing → honest BLOCKED handoff, no false findings.
  4. WAF_BLOCKED_ALL → does NOT fire breach OSINT (wrong pivot — should fire
     proactive origin discovery instead).
- **Field-prove:** Re-run solusibersama — if emails are in graph, breach OSINT
  fires. Result depends on whether solusibersama domain has breach data.
- **Prerequisite:** Slice 4 (GAP-054) must be done — breach OSINT needs email.
- **Auth gate:** Breach OSINT is passive (query external DB, no target touch).
  No auth tier escalation needed. But using harvested creds on target login
  IS Beta's ACTIVE_APPROVED territory — existing gate applies.

#### Slice 6 — GAP-055 (security headers audit)
- **What:** Parse security headers from homepage response (already fetched).
  Mint VULNERABILITY nodes for missing: HSTS, X-Frame-Options, CSP,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **Files:** `agent_alpha/agents/alpha/scout.py` (new `_audit_security_headers`
  method, runs on every homepage response).
- **Test contract:**
  1. Homepage response with no security headers → 6 VULNERABILITY nodes (low sev).
  2. Homepage response with HSTS + X-Frame-Options → 4 VULNERABILITY nodes
     (only missing ones).
  3. All headers present → 0 VULNERABILITY nodes.
  4. 0 new HTTP requests (parse existing response).
- **Field-prove:** Re-run solusibersama — expect VULNERABILITY nodes for
  missing security headers. Compare with `curl -sI https://solusibersama.co.id/`.
- **Why P1:** Missing security headers = attack surface (clickjacking on login
  form, XSS, MIME sniffing). Free scanners check these. Alpha not checking =
  Alpha worse than free scanner. But this is OMEGA report quality, not Beta
  ammo — hence P1, not P0.

#### Slice 7 — GAP-056 (robots.txt + sitemap.xml)
- **What:** Fetch `/robots.txt` and `/wp-sitemap.xml` after wp_fingerprint.
  Parse robots.txt for Disallow paths (enqueue in-scope). Parse sitemap for
  URLs (enqueue in-scope). 2 HTTP requests total.
- **Files:** `agent_alpha/recon/capability_probe.py` (add robots/sitemap
  seeds to wp_fingerprint), `agent_alpha/agents/alpha/scout.py` (new
  `_handle_robots_txt` + `_handle_sitemap_xml` handlers).
- **Test contract:**
  1. robots.txt with `Disallow: /wp-admin/` → enqueue `/wp-admin/` (in-scope
     guard applies).
  2. robots.txt with `Sitemap: https://x/sitemap.xml` → enqueue sitemap URL.
  3. sitemap.xml with 50 URLs → enqueue all in-scope URLs (cap at N, anti-#3).
  4. 404 on robots.txt → no error, no node (graceful).
- **Field-prove:** Re-run solusibersama — expect robots.txt fetch + URL
  discovery. Compare with `curl https://solusibersama.co.id/robots.txt`.

#### Slice 8 — GAP-057 (XML-RPC check)
- **What:** POST `/xmlrpc.php` with `system.listMethods` after wp_fingerprint.
  If 200 + XML response with methods → SERVICE node (name="xmlrpc",
  version="enabled") + VULNERABILITY node (xmlrpc_enabled, low sev).
- **Files:** `agent_alpha/recon/capability_probe.py` (add xmlrpc seed),
  `agent_alpha/agents/alpha/scout.py` (new `_handle_xmlrpc` handler).
- **Test contract:**
  1. xmlrpc.php returns 200 + XML with `<method>system.listMethods</method>` →
     SERVICE + VULNERABILITY nodes.
  2. xmlrpc.php returns 405 (method not allowed) → no node (disabled).
  3. xmlrpc.php returns 404 → no node (not found).
- **Field-prove:** Re-run solusibersama — check if XML-RPC is enabled.

#### Slice 9 — GAP-058 (JS secret extraction)
- **What:** Extract `<script src="...">` URLs from homepage HTML (no new HTTP
  for extraction). For each JS URL (cap at N, anti-#3): fetch + grep for
  `api_key|secret|token|password|nonce|ajaxurl|rest_url`. Mint DATA nodes for
  extracted secrets. Mint SERVICE nodes for AJAX endpoints.
- **Files:** `agent_alpha/agents/alpha/scout.py` (new `_extract_js_secrets`
  method), `agent_alpha/recon/capability_probe.py` (JS fetch seeds).
- **Test contract:**
  1. Homepage HTML with `<script src="/wp-content/themes/x/main.js?ver=1">` →
     JS URL extracted, JS fetched, secrets grepped.
  2. JS with `var ajaxurl = "/wp-admin/admin-ajax.php"` → SERVICE node for
     AJAX endpoint.
  3. JS with `apiKey: "AIza..."` → DATA node (api_key exposed).
  4. JS with no secrets → 0 nodes (no false positives).
  5. Cap at N JS files per host (anti-#3 over-probe).
- **Field-prove:** Re-run solusibersama — expect JS files extracted + checked.
- **Cross-ref:** §12.61 axis B6 — JS secrets complement external repo OSINT.
  Both produce CREDENTIAL/DATA nodes that Beta uses for cred-stuff.

#### Slice 10 — GAP-059 (cookie audit)
- **What:** Parse `Set-Cookie` headers from homepage response. Mint
  VULNERABILITY nodes for missing: HttpOnly, Secure, SameSite, __Host- prefix.
- **Files:** `agent_alpha/agents/alpha/scout.py` (new `_audit_cookies` method).
- **Test contract:**
  1. Cookie without HttpOnly → VULNERABILITY node (low sev).
  2. Cookie with HttpOnly + Secure + SameSite=Lax → 0 nodes.
  3. 0 new HTTP requests (parse existing response).
- **Field-prove:** Re-run solusibersama — expect cookie audit findings.

#### Slice 11 — GAP-062 (TLS/MX/SPF/DMARC passive recon)
- **What:** Add passive infrastructure recon phase to recon_runner (before
  Alpha runs): DNS lookup (MX, TXT/SPF/DMARC, AAAA, CAA), TLS scan (connect
  443, negotiate, extract cert + cipher info). Mint SERVICE nodes for mail
  servers, ASSET nodes for IPv6, VULNERABILITY nodes for missing SPF/DMARC/
  weak TLS. All passive, zero target touch.
- **Files:** `agent_alpha/conductor/recon_runner.py` (new passive infra recon
  phase), `agent_alpha/agents/alpha/scout.py` (handlers for TLS/MX findings).
- **Test contract:**
  1. Domain with MX record → SERVICE node (mail server).
  2. Domain without SPF → VULNERABILITY node (email spoofing possible).
  3. Domain with AAAA record → ASSET node (IPv6 address).
  4. TLS 1.0 supported → VULNERABILITY node (weak TLS).
  5. All passive DNS — 0 HTTP requests to target.
- **Field-prove:** Re-run solusibersama — expect MX/SPF/DMARC/TLS findings.
- **Cross-ref:** §12.61 axis A2 — MX records → origin netblock discovery.
  This is the prerequisite data source for §12.61 A2.

#### [P2 — defer: GAP-060, GAP-061]

GAP-060 (WooCommerce endpoint enumeration) and GAP-061 (WP REST other
endpoints) are depth, not completing. They can be deferred without making
Alpha "incomplete" — they add data harvest surface but don't block Beta or
Gamma. Build when client-pull justifies data exposure assessment.

#### [Gamma unfreeze point]

Gamma may be built only after:
1. Alpha P0 complete (Slices 2-4) — version info + plugin list + email in graph.
2. IntelligenceBase CVE lookup wired (§12.55) — map (name, version) → NVD.
3. GAP-051 RECON_EXHAUSTED + WAF_BLOCKED_ALL pivots done (Slice 5 + future).
4. §12.36 OFFENSIVE_APPROVED auth gate live (non-negotiable, existing rule).
5. Client-pull justifies destructive exploitation (existing Gamma gating).

### Anti-Lyndon check for this sequence

- **#1 (feature before foundation):** Beta enhancement before Alpha P0 = feature
  before foundation. Freeze Beta enhancement until P0 done. ✓ enforced.
- **#2 (dead code):** GAP-053 handler exists but never fires = dead code. Slice 2
  fixes this. ✓ addressed.
- **#3 (false success):** Alpha "completes" with 27 nodes but missing version,
  plugin list, email = false success. Slices 2-4 fix this. ✓ addressed.
- **#5 (scope creep):** One slice at a time, field-proven. No parallel slices.
  P2 (060, 061) deferred. ✓ enforced.
- **#17 (sophisticated avoidance):** Completing basic recon is not avoiding
  exploitation — it's making exploitation possible (Gamma needs CVE, CVE needs
  version, version needs GAP-052/053). ✓ clarified.

Confidence ~85% on ordering. The shift from the original roadmap: Alpha recon
was assumed "over-invested" (G17), but solusibersama evidence shows Alpha is
INCOMPLETE in basic areas (worse than free scanner). Completing basic recon is
a prerequisite for Beta enhancement and Gamma, not a competitor to them.

---

## 3-Layer Recon Matrix + Beta Failure Root Cause (2026-08-12, quantum-laboratories run)

> **Trigger:** quantum-laboratories.com (Odoo behind Cloudflare) live run
> 2026-08-12. Alpha detected Odoo + version + DB manager + auth surface, but
> Beta FAILED. Question: Odoo version extraction works, so why did Beta fail?
> Answer below + the 3-layer recon matrix that emerged from cross-stack
> evidence (solusibersama WP + quantum Odoo).

### Why Beta failed on quantum (Odoo) — root cause trace

**Alpha DID its job for Odoo** (better than WP in some areas):
- ✅ Odoo fingerprint → `tech_stack=["odoo"]` on ASSET node
- ✅ Odoo version → `verify_odoo_version` POSTs to `/web/webclient/version_info`
- ✅ DB manager exposed → `odoo_dbmanager_exposed` finding
- ✅ Auth surface → `/web/login` detected, `auth_surface_probe` ran
- ✅ Router → `has_web_auth_surface` returns True (odoo in `_AUTH_SURFACE_LABELS`)
- ✅ Beta dispatched → `StrikeCandidateAttempted` on both hosts

**Beta FAILED (status=3) because of 3 compounding gaps:**

#### Gap A — No CREDENTIAL nodes in graph (root cause: no leak paths succeeded)

Beta has TWO credential sources:
1. **Harvested credentials** (from Alpha leak paths: `.env`, `.git/config`,
   `wp-config.php.bak`, backup files) → `cred_reuse` tool
2. **Default credentials** (`admin/admin`, `admin/password`, etc.) →
   `default_creds` tool
3. **Derived credentials** (username + domain stem → `user123`, etc.) →
   `user_derived_creds` tool

On quantum:
- `.env` → 404 (not exposed)
- `.git/config` → 404 (not exposed)
- `wp-config.php.bak` → 403 (CF rule blocked — this is a WP path on an Odoo
  target, cross-stack leak path mismatch)
- `config/database.yml.bak` → 404 (not exposed)
- → **0 CREDENTIAL nodes in graph → `cred_reuse` has nothing to try**

#### Gap B — No USER nodes in graph (root cause: Odoo has no REST user enum)

On solusibersama (WP), Alpha enumerated 9 users via `/wp-json/wp/v2/users`.
On quantum (Odoo), there is NO equivalent REST user enumeration endpoint.

Odoo user enumeration vectors that Alpha does NOT use:
- `/xmlrpc/2/common` → `version()` works, but `list_services()` or
  `authenticate()` is cred-stuff territory (Beta, not Alpha)
- `/web/database/manager` → shows database names (GAP-063), NOT user names
- Odoo has NO public user list endpoint (unlike WP REST)

→ **0 USER nodes in graph → `user_derived_creds` has nothing to derive from**

#### Gap C — Default creds tried but Odoo not in platform dict

`_DEFAULT_CREDENTIALS` dict has: `generic`, `wp`, `tomcat`, `jenkins`,
`phpmyadmin`, `grafana`, `joomla`. **No `odoo` entry.**

`_build_credential_list` selects platform-specific creds by matching
`tech_stack` values. Odoo's tech_stack is `["odoo"]` — no match → only
`generic` creds tried: `admin/admin`, `admin/password`, `admin/admin123`,
`root/root`, `root/toor`, `test/test`, `user/user`, `guest/guest`.

Odoo's default admin is `admin` / `admin` (on a fresh install). BUT:
1. Quantum is NOT a fresh install — it's a production Odoo with a real
   admin password. `admin/admin` fails.
2. Odoo login form POSTs to `/web/session/authenticate` with JSON-RPC
   body, NOT a form POST. `HttpFormApplicator` POSTs form fields
   (`username=X&password=Y`) — Odoo may reject the content-type.
3. `WpLoginApplicator` POSTs to `wp-login.php` — wrong endpoint for Odoo.

→ **Default creds tried with wrong applicator shape → all fail → Beta FAILED**

#### The 3 gaps compound

```
Alpha: 0 CREDENTIAL nodes (no leak paths succeeded)
  + 0 USER nodes (no Odoo user enum)
  + Beta: default_creds tries generic admin/admin with HttpFormApplicator
    (wrong shape for Odoo JSON-RPC login)
  = Beta has NOTHING that can succeed → FAILED → OMEGA (honest report)
```

**This is NOT a Beta bug.** Beta's logic is correct — it tries what it has.
The problem is Alpha gave insufficient ammo AND Beta's applicator roster
doesn't have an Odoo-specific login shape.

### What needs to happen for Beta to succeed on Odoo

| Fix | Layer | Gap | Impact |
|-----|-------|-----|--------|
| Odoo XML-RPC discovery | Alpha recon | GAP-064 | Beta knows XML-RPC is enabled → can route cred-stuff there |
| Odoo DB name extraction | Alpha recon | GAP-063 | Beta knows database name "erp" → pre-fills login form |
| Odoo JSON-RPC applicator | Beta tooling | **GAP baru** | Beta can POST to `/web/session/authenticate` with JSON body |
| Odoo default creds entry | Beta tooling | **GAP baru** | `admin/admin` tried with correct Odoo applicator |
| Breach OSINT for Odoo | Beta enhancement | GAP-051 + GAP-054 | If email harvested, breach DB may have Odoo admin creds |

**Two new Beta gaps emerged from this trace:**

#### GAP-067 — Odoo JSON-RPC applicator missing (Beta can't login to Odoo)

- **What:** `HttpFormApplicator` POSTs form fields. Odoo login is JSON-RPC:
  POST `/web/session/authenticate` with body
  `{"jsonrpc":"2.0","method":"call","params":{"db":"erp","login":"admin","password":"X"}}`.
  `WpLoginApplicator` POSTs to `wp-login.php` — wrong endpoint.
  No applicator in the roster speaks Odoo's auth protocol.
- **Fix:** New `OdooJsonRpcApplicator` — POSTs JSON-RPC to
  `/web/session/authenticate`. Verify: `session_id` cookie set (already in
  `SESSION_COOKIE_NAMES` allowlist).
- **Effort:** Medium. New applicator class + register in `beta_web_applicators`.

#### GAP-068 — Odoo default credentials not in platform dict

- **What:** `_DEFAULT_CREDENTIALS` has no `odoo` entry. Odoo fresh install
  default is `admin` / `admin`. Production installs sometimes keep
  `admin` / `admin` (common misconfiguration).
- **Fix:** Add `"odoo": [("admin", "admin")]` to `_DEFAULT_CREDENTIALS`.
- **Effort:** Trivial. 1 line.

### 3-Layer Recon Matrix (cross-stack, from solusibersama + quantum evidence)

**Layer 1: Universal recon** (fix once, works for all stacks)

| Capability | Gap | WP evidence | Odoo evidence | Fix |
|-----------|-----|-------------|---------------|-----|
| Crawl allowlist | Bug #37 | WP has filter | Odoo crawls 20+ junk pages | Universal security-relevance filter |
| Security headers | GAP-055 | Not audited | Not audited | Parse existing response |
| robots.txt + sitemap | GAP-056 | Not fetched | Not fetched | 2 requests |
| JS secrets | GAP-058 | Not extracted | Not extracted | Extract from homepage HTML |
| Cookie audit | GAP-059 | Not audited | Not audited | Parse existing response |
| TLS/MX/SPF/DMARC | GAP-062 | Not checked | Not checked | Passive DNS |

**Layer 2: Stack-specific recon** (per-stack handlers)

| Capability | WP gap | Odoo gap | Laravel gap | Spring gap |
|-----------|--------|----------|-------------|------------|
| Version extraction | GAP-052 (WC) + GAP-053 (plugin) | ✅ works (version_info POST) | GAP baru (composer/debug) | GAP baru |
| User/email enum | GAP-054 (WP REST) | GAP-064 (XML-RPC) | N/A | N/A |
| DB name/list | N/A | GAP-063 + GAP-066 | N/A | N/A |
| XML-RPC | GAP-057 | GAP-064 | N/A | N/A |
| Info endpoint | GAP-052 (system_status) | GAP-065 (/website/info) | GAP baru (Telescope) | GAP baru (Actuator breadth) |
| API endpoints | GAP-060 + GAP-061 | GAP-065 | GAP baru | GAP baru |
| Auth surface | ✅ (wp-admin) | ✅ (/web/login) | GAP baru (Nova/Filament) | GAP baru |
| Crawl filter | ✅ (WP allowlist) | Bug #37 | Bug #37 | Bug #37 |
| Leak paths | ✅ (wp-config, .env) | ✅ (.env, .git) — but 0 succeeded | ✅ (.env) | ✅ (actuator) |

**Layer 3: Cross-stack CVE lookup** (universal, needs IntelligenceBase)

| Capability | Gap | Status |
|-----------|-----|--------|
| Version → NVD → CVE | GAP-050 (IntelligenceBase wiring) | OPEN |
| 1-Day Weaponizer | §12.55 | ACCEPTED, not built |
| Plugin/module CVE | GAP-053 (WP) + GAP-065 (Odoo) | OPEN |

### Beta freeze — refined (2026-08-12)

**Beta existing logic stays running.** Cred attack via leak path is proven
(alpha-ai.web.id). Default creds + derived creds are correct logic.

**Beta enhancements FROZEN until prerequisites met:**

| Beta enhancement | Frozen because | Prerequisite | New finding |
|------------------|----------------|--------------|-------------|
| Breach OSINT (Dehashed/HIBP) | Needs email | GAP-054 (WP) | Odoo has no email enum — needs GAP-064 (XML-RPC) |
| Plugin auth surface | Needs plugin list | GAP-053 (WP) | Odoo has no plugin list — needs GAP-065 |
| WC CSRF → admin | Needs WC version | GAP-052 (WP) | N/A for Odoo |
| **Odoo JSON-RPC login** | **No Odoo applicator** | **GAP-067** | **NEW — Beta can't login to Odoo at all** |
| **Odoo default creds** | **No Odoo entry in dict** | **GAP-068** | **NEW — trivial 1-line fix** |

**Gamma stays STOP-gated** (non-negotiable).

### Revised execution order (with Odoo gaps + Beta gaps)

```
Slice 1: Bug #34 + Bug #37 fix (stop cycling + stop junk crawl)
  ↓
Slice 2: GAP-053 (WP plugin list — fix dead code)
  ↓
Slice 3: GAP-052 (WooCommerce system_status — version + CVE)
  ↓
Slice 4: GAP-054 (WP REST user email + roles)
  ↓
[Beta enhancement unfreeze — WP axis]
  ↓
Slice 5: GAP-051 RECON_EXHAUSTED pivot (breach OSINT — needs email from Slice 4)
  ↓
Slice 6: GAP-067 + GAP-068 (Odoo JSON-RPC applicator + Odoo default creds)
  ← NEW: unblock Beta for Odoo targets
  ↓
Slice 7: GAP-064 (Odoo XML-RPC discovery — Alpha finds it, Beta uses it)
  ↓
Slice 8: GAP-063 + GAP-066 (Odoo DB name extraction — Beta cred-stuff context)
  ↓
Slice 9: GAP-065 (Odoo /website/info — version + module list + CVE)
  ↓
Slice 10: GAP-055 (security headers — universal)
  ↓
Slice 11: GAP-056 (robots.txt + sitemap — universal)
  ↓
Slice 12: GAP-058 (JS secrets — universal)
  ↓
Slice 13: GAP-059 (cookie audit — universal)
  ↓
Slice 14: GAP-062 (TLS/MX/SPF/DMARC — universal passive)
  ↓
[P2 defer: GAP-060, GAP-061 (WC/WP REST depth)]
[Gamma unfreeze: after P0 + CVE lookup + auth gate + client-pull]
```

**Why Slice 6 (Odoo Beta) is positioned after Slice 5 (WP breach OSINT):**
- Slices 2-5 complete the WP axis (Alpha P0 → Beta enhancement).
- Slice 6 starts the Odoo axis (Beta applicator + default creds).
- Odoo Beta gaps (GAP-067, GAP-068) are independent of WP gaps — they can
  be built in parallel with WP P1 gaps IF a second engineer exists. Solo:
  sequential, WP first (more targets in SEA).

**Why Slice 6 is BEFORE Odoo Alpha gaps (Slices 7-9):**
- GAP-067 + GAP-068 unblock Beta for Odoo — even with Alpha's current
  (incomplete) Odoo recon, Beta can at least try `admin/admin` with the
  correct JSON-RPC shape.
- Slices 7-9 (Odoo Alpha gaps) give Beta MORE ammo (XML-RPC, DB names,
  module list) — but Beta can function without them.
- Priority: make Beta functional for Odoo FIRST, then deepen Alpha's
  Odoo recon.
