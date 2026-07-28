> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-07-28)

Resume with: "lanjut Agent-Alpha — reach arc (§12.40 + §12.41) SEALED. NEXT = build tls_impersonate
transport (curl_cffi) + wire EvasionPlanner into the FINGERPRINT-class reach ladder. This is the
datacenter-viable, cheap, non-lab-locked CF-403 bypass — the one thing blocking real-client findings.
Do NOT start the conductor refactor. Do NOT chase browser_solve for real clients (lab-locked +
Managed-Challenge-ceilinged)."

## Status

```
Phase 4 (recon + reach). Gamma/Delta/Epsilon = 0% built (not stubbed). browser_solve = lab-only
(assert_lab_only_target) + Managed-Challenge-ceilinged from datacenter. Success bar (finding a
scanner missed + proven exploitable + payable report on a REAL target) = STILL UNMET — that is the
milestone the whole reach arc serves.

MERGED to main this session (verified on main / by tests):
  - #272 STACK_CATALOG.md — fingerprint-keyed recon-depth doctrine (general, never per-client).
  - #274 WP recon battery — 4 fingerprint-keyed playbooks: wp_rest_routes (DETECT), wp_rest_users
    (FINDING), woocommerce, wp_version. Body-signature gated (anti-#3; WP soft-404 = 200 HTML).
  - #275 wp_fingerprint auto-seeds the battery via CapabilitySpec.follow_up_tools (non-island).
  - merge_asset_node (CodeRabbit #274) — anti-clobber: apply_event REPLACES node payload, so 11
    AssetProperties writers were dropping ip/open_ports/rest_routes on re-persist. One canonical
    merge helper; all sites migrated (anti #6/#7).
  - Path-catalog consolidation — WP_CONFIG_BACKUP_PATHS is the single source; BACKUP_FILE_PATHS
    splats it (4 WP-unique paths .swp/.dist/.txt now universally seeded). No probe deleted
    (parse_wp_config is reused by leak_extraction; verify_wp_config_leak used by chain runners).
  - #277 plugin_cve deterministic verifier (ADR §12.40 slice-1) — regex plugin asset paths over
    already-fetched HTML → CVE catalogue SSOT (plugin_cve_catalog.py; wp-file-manager→CVE-2020-25213,
    9.8). SELF_VERIFIED node; version-gate (patched/None → NOT a finding). No LLM (deterministic).
  - #279 §12.41 per-host reach-class — classifier reload-shape DEMOTED to a cheap is_reload_shell
    cost-gate (reverted PR #278's fragile verdict + its 3 CodeRabbit defects). _classify_host_reach
    (entry differential) + per-run reach_class memo.
  - #280 §12.41 hardening — trust challenge_solved ALONE (dropped size-`gained` + stack-specific
    "wp-content"). Challenged host = entry-only (browser body consumed once; subsequent paths skip).
  - #283 §12.41 hard-block memo — httpx 403 (BLOCKED) + browser fail → reach_class "blocked" (memo,
    skip subsequent) instead of "clear" (fixed a per-path browser spray). General (keys on Verdict).
  - slice-2 subdomain wiring — recon_runner was dropping result.in_scope (seed_frontier_from_passive
    never called); fix adds in-scope discovered subdomains to run_recon targets. Cardinal +
    wiring-gate (discovered_in_scope-targets) green. MERGED.

ADRs authored this session (commit to docs/ADR.md):
  - §12.40 Content-Analysis Lane — oracle-gated LLM over ALREADY-fetched bodies; every LLM claim
    passes a deterministic per-class verifier before a node (anti-#3). plugin_cve = slice-1 DONE
    (deterministic limiting case). seo_spam_hidden_link + exposed_nonce classes = DEFERRED.
  - §12.41 Reach-class per host — entry-point differential + tiered transport. Reach out of the
    classifier (root-fix CodeRabbit #278). Cookie/session-replay + wildcard-scope explicitly carved out.

FIELD RESULTS (real-target measurement — the point of this arc):
  - bernofarm.com (REAL client, WP+CF): Strix 7 findings vs Agent-Alpha 0. Root = REACH, not
    vectors. Strix's 7 mostly sit in the homepage HTML both tools fetched; Agent-Alpha (raw httpx
    from datacenter) gets CF-403/soft-200 on everything. Apex block = FINGERPRINT-class (TLS/JA3),
    with Managed-Challenge ("Just a moment") on some paths.
  - quantum-laboratories.com (self-owned Odoo lab): Agent-Alpha 1 (odoo_dbmanager) vs Strix 0.
  - alpha-ai.web.id (self-owned CF-fronted lab): reach machinery FIRED end-to-end (browser_solve
    invoked autonomously — §12.41 wiring PROVEN), BUT Camoufox could not solve CF Managed Challenge
    from the Oracle datacenter IP → confirms the residential/mobile-proxy INFRA ceiling (not code).
  - bernofarm re-run: origin-direct found only a CF EDGE IP (104.20.17.247 — useless, re-hit CF);
    subdomain enum was OFF (allow_subdomain_enum=False) so slice-2 was NOT exercised.
```

## NEXT ACTION (in order — start the new session here)

```
1. MERGE slice-2 (subdomain in_scope → recon targets).  ← DONE (verified on main, test passes)

2. PRIMARY — build tls_impersonate transport + wire EvasionPlanner (the reach unlock):
   - EvasionPlanner EXISTS (recon/transport_resilience.py:196) and classifies 403-without-marker →
     MitigationClass.FINGERPRINT → technique "tls_impersonate" (constants:460). BUT there is NO
     executor: comment says "no transport body here (DeepSeek lane: curl_cffi ...)". It is a PLAN
     with no actor, AND not injected into Alpha. Wiring the planner alone does nothing (Lyndon #2).
   - Build a curl_cffi-based transport that impersonates a real browser TLS/JA3 fingerprint; wire it
     as the FINGERPRINT-class reach strategy in the _attempt_reach ladder + inject EvasionPlanner
     into Alpha on the autonomous path. RED-first; register wiring-debt until run_recon exercises it.
   - WHY: bernofarm's 403 is FINGERPRINT (TLS bot-block). curl_cffi bypass is datacenter-viable,
     cheap (no browser, keeps cost moat), NOT lab-locked (unlike browser_solve). Honest caveat: it
     beats the 403-fingerprint tier, NOT interactive Managed Challenge (that still needs JS/cookie).

3. CHEAP PARALLEL (no code): re-run bernofarm with allow_subdomain_enum=True + SOW scope.domains
   listing the non-CF subdomains (cpanel/portal/bo1-4/recruitment/is/logistik). Tests slice-2 for
   real — the subdomains likely aren't behind CF (direct origin) → httpx reaches → findings.
```

## Unwired audit (WIRING_DEBT ledger) — opinion: mostly correctly DEFERRED

```
tls_impersonate transport   -> BUILD+WIRE NOW (only item blocking real-client reach).
IntelligenceBase (GAP-003)  -> LATER (cross-engagement learning; needs findings flowing first).
find_critical_paths         -> LATER (graph analytics; needs multi-hop chains = Gamma).
check_technique / check_scope / run_verification_pass / SessionStore -> LATER (wire when their
                               active path lands; not blocking findings now).
```

## Open gaps (tracked, non-blocking)

```
- Origin discovery returns CF EDGE IPs (current A-record), not true origins -> origin-direct is
  useless vs CF-fronted apex. Real fix = historical-DNS / subdomain-IP origin discovery (later).
- PassiveDiscovery is crt.sh ONLY (Gemini valid point). Broaden LATER via commodity-wrap
  (subfinder/amass/wayback) that FEEDS the synthesis moat — never as the moat itself (anti Lyndon #6).
- Enumerated (out-of-scope) hosts are captured but DISCARDED as intel. Passive OSINT synthesis
  (mine naming/cert patterns to hypothesize in-scope targets, NEVER probe out-of-scope) = safe,
  moat-aligned, connects to the business-logic / lateral-thinking north-star. LATER.
- Business-logic / "black swan" flaws = the true long-term differentiator (Strix + scanners both
  weak here). Phase 5/6: needs Gamma + an OUTCOME-oracle (the §12.40 gate generalizes: LLM
  hypothesizes a logic exploit + test sequence → agent executes → independent oracle confirms the
  outcome → finding). Do NOT build now — recon isn't proven on a real target yet (feature-before-
  foundation). Design when Gamma is imminent.
```

## Doctrine reminders to carry (do not regress)

```
- Success bar = find what a scanner missed, PROVE exploitable, payable report on a REAL target.
  Still unmet. Measure on real targets; do NOT keep hardening lab vectors (treadmill).
- browser_solve is LAB-ONLY (assert_lab_only_target) + Managed-Challenge-ceilinged from datacenter.
  It is NOT the real-client reach path. Real-client reach = tls_impersonate (fingerprint) +
  origin-direct (needs true origin) + subdomain pivot. Challenge-solve = residential-proxy INFRA.
- Reach is consent-gated (allow_evasion). is_in_scope is EXACT-match (no wildcard — co-host safety);
  wildcard *.domain = a separate auth ADR.
- Every new tool/vector: GENERAL + stack/fingerprint-keyed, NEVER per-client. Body-signature gated
  (status alone is never a finding). RED-first. Wire to run_recon (RUNNER-SEAL ≠ WIRED) + wiring-gate.
- Repo CLAUDE.md status block is STALE (still an older Phase-4 slice) — reconcile it to this handoff.
```

## Real engagements (all SOW; market ask = WAF/CDN evasion)

```
bernofarm.com (WP+CF, REAL client — Strix 7 vs Agent-Alpha 0; root=REACH not vectors)
niagamas.com (WP+WooCommerce, Cloudways no CDN — recon-only DONE, origin-direct tested)
ibudanbalita.com (Laravel+Magento, CloudFront — needs reach+laravel_chain)
cimbniaga.co.id (AEM/Java, Imperva, BANK — LAST; origin-exposure only, NOT challenge-defeat)
kalbe.co.id (DNN/ASP.NET+OpenShift — new stack, DEFER)

Honest boundary: sells ORIGIN-EXPOSURE bypass + TLS-fingerprint evasion, NOT interactive
challenge-defeat (browser_solve parked = datacenter egress; true solve needs residential proxy =
INFRA). Never fake "bypassed" (#3).
```

## Architecture comparison context (Strix vs Agent-Alpha vs CyberStrikeAI)

```
Token efficiency: Agent-Alpha ~2-5 LLM calls/engagement (~2-10K tokens) vs Strix ~50-80 (~100-320K).
Deterministic gate: Agent-Alpha ~90% deterministic (RULE tier, zero LLM) vs Strix ~0%.
Verification tier: Agent-Alpha UNVERIFIED→SELF_VERIFIED→CROSS_VERIFIED vs Strix all-LLM (no oracle).
Auth discipline: Agent-Alpha SOW + scope gate + blast-radius gate vs Strix "don't question auth".
Moat: Agent-Alpha detects → vaults → graphs → chains → proves. Scanners detect only.
Gap to close: tls_impersonate (reach), Gamma (exploit), business-logic oracle (leapfrog differentiator).
```

Test env: Oracle ARM64, Python 3.12.13, .venv312 — `.venv312/bin/python3 -m pytest` / `make check`.
1451 tests collected on Windows (local dev). Durable doctrine: CLAUDE.md + this handoff.
Gap ledger: docs/BUGS_AND_GAPS.md.
