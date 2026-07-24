> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-07-22)

Resume with: "lanjut Agent-Alpha — CORRECTION: A1-reach was RUNNER-scoped, NOT wired into Alpha's autonomous loop. Audit revealed systemic runner-vs-autonomous split (reach + oracle + scope + OPSEC + passive-discovery-seed all island in the autonomous path). NEXT = bring the AUTONOMOUS path to runner parity (reach first, fatal), then §12.36 auth-gate, then real engagement (quantum/bernofarm/niagamas), then Gamma. Doctrine RUNNER-SEAL ≠ AUTONOMOUS-WIRED added to CLAUDE.md."

## Current Project Status

```
Project Phase  : A1 mechanism PROVEN via runner. AUTONOMOUS path is UNDER-WIRED — the
                 capabilities that made A1 work in the runner are NOT called from Alpha's
                 cognitive loop / execute_agent. Consequence: Alpha in a real engagement
                 stops at a client WAF with no plan B. Gamma STILL STOP-gated. §12.36 auth-
                 gate still to build (prereq for real-client engagement and Gamma).

Correction     : "A1-REACH SEALED" claim from 2026-07-21 was runner-scoped. Real seal =
                 autonomous scout.run_recon exercising reach, not a1_validation_runner.

Live-path audit (verified by grep on main, 2026-07-22):
  Capability                            In runner  In autonomous path      Impact
  choose_reach / classify_mitigation    yes        NO (0 calls in scout)   FATAL: Alpha stops at WAF
  origin_direct_fetch / OriginDiscovery yes        NO                      FATAL
  browser_solve (9c) transport          yes        NO                      FATAL
  run_verification_pass (oracle)        yes        NO in execute_agent     "proven" never fires
  check_scope / assert_target_in_scope  n/a        NO in agent path        SAFETY: out-of-scope not blocked
  resolve_opsec_profile                 n/a        recon_runner only       stealth/rate not applied
  seed_frontier_from_passive (crt.sh)   n/a        NEVER CALLED            subdomains never enter frontier
  set objective (in client path)        n/a        NEVER SET               pure FIFO, WorldModel inert

Not built (deferred, NOT island): ChainOracle, CredentialPatternMutator, curiosity_score,
  AdaptiveEvasion.

Doctrine added to CLAUDE.md (this arc): "RUNNER-SEAL ≠ AUTONOMOUS-WIRED — before claiming
  anything sealed/wired, grep the AUTONOMOUS path (scout.py, execute_agent.py,
  run_cognitive_loop), NOT the runner. Register every gap as tracked wiring-debt in
  tests/governance/test_wiring_gate.py so CI fails until wired — do not rely on memory or
  docs, enforce it." Patch: outputs/claude-md-runner-seal-doctrine.patch.

Next Action    :
  1. alpha_reach_wiring.md — wire classify_mitigation -> choose_reach -> origin-direct/
     browser_solve into Alpha's autonomous OBSERVE step (capability-gated by the signed
     profile; bounded). KEY TEST: autonomous scout.run_recon reaches origin, NOT a
     runner-scoped test.
  2. block_recognition_generalization (to be written) — stop the vendor arms race.
     Classify STRUCTURAL authenticity (real app vs interstitial: small body + JS reload,
     bot-fingerprint JS, missing app markers, cf-mitigated header). Add missing status
     codes to classify_response (401/406/451/521-525). Extend classify_mitigation with
     GEO_BLOCK (451), CONTENT_NEGOTIATION (406/415 -> fix Accept, NOT evasion),
     CONNECTION_FAIL (521-525 -> origin-direct), and activate defined-but-unreturned
     RULE_DENY. First-principles: recognize structure, not vendor names.
  3. wire_seed_frontier_and_objective (small) — call seed_frontier_from_passive in
     client_runner + recon_runner so crt.sh subdomains enter Alpha's frontier; set
     objective in the client path so scoring/WorldModel activate.
  4. oracle_in_autonomous_path (small) — run_verification_pass at chain completion in
     execute_agent (not only a1_runner). Follow-up already flagged in oracle prompt.
  5. engagement_authorization_gate.md — §12.36 signed EngagementProfile + DNS-TXT
     ownership + capability flags (allow_evasion / stealth / scope_targets) + fail-closed
     guardrail (.gov/.mil/.edu + big-tech blocked over consent). This unlocks paid client
     engagements AND is the hard prereq for Gamma.
  6. Re-prove A1 via the AUTONOMOUS path (scout.run_recon, NOT the runner). THAT is the
     real reach seal. Update Session_Handoff again after that succeeds.
  7. Run one authorized engagement (quantum / bernofarm / niagamas) under §12.36. Deliver
     report -> paid. This is the market validation for whether Gamma is worth building.
  8. Gamma only after (a) authorized engagement delivered and (b) client-pull for
     destructive depth.

Governance     : lab_guard covers self-owned lab. Real-client path requires §12.36 signed
                 profile + DNS-TXT ownership before ANY autonomous run at a client. Do NOT
                 point Agent-Alpha at quantum/bernofarm/niagamas until §12.36 lands.

Test env       : Oracle ARM64, Python 3.12.13, .venv312 — ALWAYS `.venv312/bin/python3 -m
                 pytest` or `make check` (NEVER bare pytest — system python 3.10 fails
                 StrEnum). All prompt "VERIFY" sections have been corrected to .venv312.

Phase status (verified 2026-07-22):
  Phase 0-3 : DONE.
  Phase 4   : breadth CONSOLIDATED. Omega Slice A+B+C SEALED (evidence bundle +
              attack-flow SVG + client-facing HTML report; branded, professional; earlier
              plans DID drift into "narrative-only PDF" and were corrected in the Slice A
              hardening PR).
              Verified nodes:
                verification tri-state (unverified < self_verified < cross_verified) +
                property shim (node.verified == cross_verified). CROSS_VERIFIED reachable
                only through provenance-gated NodeVerified from run_verification_pass —
                oracle-exclusive, event-sourced. CredReuseOracle binds proof to the
                specific credential (subject_ref + access_level + target). C7 gate runs
                BEFORE the verification pass (invalid runs emit NO NodeVerified). NOTE:
                run_verification_pass is called only in a1_validation_runner, not in
                execute_agent — that is the follow-up in item 4 above.
              Reach: PROVEN in a1_validation_runner, NOT in the autonomous loop
                (see audit table). That is item 1 above.
  Cognitive : GAP-002 WIRED. GAP-003 IntelligenceBase OPEN (needs Bug #7). GAP-004
              complete except D2-b/D2-c (deferred; do NOT leave scaffolding — a peer
              already flagged reserved-but-unused params in planner.py). GAP-005 slice-2
              OPEN (agent-path OPSEC / technique / scope check). GAP-006 slice-2 OPEN
              (critical-paths -> planner, needs GAP-004).
  Security  : Trivy .trivyignore + Redis 8 (#234). CodeQL 6 low/medium assessed.

Bug ledger  : FIXED (this + prior arcs): #2/#6/#14 (greedy rules), #10 (415), #11 (crawl),
              #18/#19/#20 (CF challenge/body-content/dedup), #21 (LLM exclude_tools),
              CR CWE-918 (probe SSRF/no-follow), CR CWE-862 (consent tautology ->
              signed --profile + verify()), origin-direct TLS split-brain, CLI dep
              under-wiring, oracle island + verified-tier binding.
              OPEN: #17 (mod_autoindex sort), #19 residual, #7 (EngagementMemory persist —
              GAP-003 prereq; canonical in docs/BUGS_AND_GAPS.md). AUTONOMOUS-PATH
              WIRING GAPS (this arc's finding — track as wiring-debt in
              tests/governance/test_wiring_gate.py):
                W-01 reach not in scout        (FATAL, blocks real engagements)
                W-02 oracle not in execute_agent (moat inert in production chain)
                W-03 check_scope not in agent path (SAFETY)
                W-04 resolve_opsec_profile not in execute_agent (OPSEC not applied)
                W-05 seed_frontier_from_passive never called (subdomains not queued)
                W-06 objective never set in client_runner (pure FIFO, WorldModel inert)
              "CF-pin" is a repro/infra task (Cloudflare dashboard), NOT Bug #7.

META (durable): runner is not the live path for engagements. Green tests + runner seals
              can coexist with an island production loop. Grep the autonomous path
              (scout.py, execute_agent.py) — not the runner — before claiming anything is
              wired. Enforce it via test_wiring_gate.py; do not rely on memory or docs.
```

## Landed this arc (2026-07-21 → 2026-07-22)
- Omega Slice A (evidence bundle + structured critical path + BlastRadius surfaced;
  hardening: dedup, correct technique attribution per node's reaching edge, ranking, removal
  of premature narrative-only PDF export).
- Omega Slice B (static Mermaid attack-flow renderer, driven from the SAME selected
  critical_path — diagram-evidence consistency guaranteed).
- Omega Slice C (self-contained HTML report: numbered sections, restrained palette,
  mono for technical artifacts, static SVG attack-path, monoline apex-A logo, branded
  Agent-Alpha not "A1"; content tests including redaction, provenance, and specific
  severity-table assertion after CodeRabbit tightening).
- Real-report close-out: engagement identity (target, engagement_id, assessed_at) now
  passed into Report from the caller (was fabricated from node ids / cred ids). No-secret
  test now seedable at a rendered field (can-fail guard).
- Verification tri-state + CredReuseOracle (PR #249, then wiring #250, then binding
  hardening on top): CROSS_VERIFIED reachable only through provenance-gated NodeVerified
  from run_verification_pass; oracle CONFIRMED requires proof BOUND to the specific
  enabling credential (subject_ref + access_level + target). Legacy verified=True maps to
  SELF_VERIFIED, never CROSS. C7 gate now precedes the pass (invalid runs emit nothing).
  Reverifier machinery stripped (Phase-6 half-scaffold, credential-keyed lockout deferred).

## Not landed this arc (in outputs/, ready for next session to apply)
- outputs/claude-md-runner-seal-doctrine.patch — CLAUDE.md doctrine "RUNNER-SEAL ≠
  AUTONOMOUS-WIRED".
- outputs/alpha_reach_wiring.md — Alpha autonomous reach wiring (item 1; FATAL/P0).
- outputs/engagement_authorization_gate.md — §12.36 signed profile + DNS-TXT + capability
  flags + guardrail + enforcement (item 5).
- (to be written next session) block_recognition_generalization + small wiring
  prompt for seed_frontier_from_passive + objective + oracle-in-execute_agent.

## Peer notes (do not regress)
- "Green != proven" and "runner-seal != autonomous-wired" are the same failure family
  (Lyndon #2). Both caught this arc; both now enforced via tests/governance.
- Reach is offensive → always capability-gated + assert_origin_authorized fail-closed.
- Block detection: recognize STRUCTURE (real app vs interstitial), NOT vendor names.
  The vendor arms race (Sucuri/Incapsula/Imunify/Wordfence/ModSecurity/AWS-WAF/…) is a
  losing shape; structural authenticity + a few status-code + mitigation classes cover
  the long tail.
- Do NOT point Agent-Alpha at any client target before §12.36 lands. It is a legal line,
  not a nice-to-have.
- Deferred work goes OUT, not half-scaffolded (reserved-but-unused params, "will be
  added HERE" comments = dead weight). Peer flagged planner.py D2-b/D2-c seams already —
  clean those on any planner touch.

## Test env
Oracle ARM64, Python 3.12.13, .venv312. Always `make check` or
`.venv312/bin/python3 -m pytest` (never bare pytest — system python 3.10 fails StrEnum).
