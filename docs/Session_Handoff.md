> CANONICAL SOURCE: current status â€” done/next/phase. THE ONLY status doc.

# Agent-Alpha â€” Session Handoff (2026-08-02)

Resume with: "lanjut Agent-Alpha â€” MILESTONE: Phase 4 Recon & Evasion Overhaul. We have locked the architecture for Passive-First Recon (Â§12.48) and Proactive Evasion (Â§12.49) in ADR.md. NEXT = Execute Implementation Plan Slice 1 to 6 (PassiveIntelMap, crt.sh, Stealth Default, StealthPacer, Deep Evasion, and Deep Recon). Do NOT build Gamma. Execute one slice at a time and verify against WAF."

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar â€” NOW MET on a self-owned real-world target:** find something a scanner missed +
prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass â†’
proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) â€” what Nuclei/
Strix cannot assemble.

---

## SEALED / PROVEN this arc

- **PR #346 stealth-by-default** (merged 2026-08-07): curl_cffi chrome124 as DEFAULT transport from request #1 (not reactive fallback). STEALTH_BROWSER SSOT (UA + sec-ch-ua + impersonate pinned to Chrome 124, anti-#7 drift). DEFAULT_OPSEC_PROFILE: announced→stealth. /authorize forwards allow_origin_discovery + allow_subdomain_enum. Consent gate covers allow_subdomain_enum (CodeRabbit fix). httpx fallback warns STEALTH-DEGRADED. Oracle ARM64 verified: 42 passed, 2 skipped, ruff/mypy clean. bernofarm 25→12 WafBlocked.
- **Reach**: origin-direct (bypass CF edge) sealed + robust â€” RC1/RC2/RC3 fixes (deterministic multi-
  vhost probe, 303 confirms, all-hostnames-per-IP), seed_hosts (in-scope targets as origin
  candidates). tls_impersonate correctly NOT chosen for CHALLENGE-class CF (Â§12.33, IP-reputation).
- **GAP-015** (predictable-cred) built + wired + run() authored. Governed applicator seam (Â§12.22 D2)
  = single lockout governor at the factory.
- **odoo_dbmanager**: ruleâ†”classifier markers aligned (Odoo 17 now detected deterministically, no
  LLM dependency). OdooAccessTool audited = Â§12.43-sound independent oracle (db.list() + uid>0).
- **slice-2 Â§12.40 content-analysis**: `detect_seo_injection` (keyword + STRUCTURAL cloaked-link-farm,
  keyword-independent) wired into scout autonomous path. FIRED on real client solusibersama
  (seo_injection_compromise CVSS 9.1).
- **alpha-ai chain (eng_63ebd8a2)**: asset â†’ wp-config leak â†’ cred â†’ access (admin, uid=2), Omega
  report + proof SHA256. SELF_VERIFIED.

---

## Field results (real-world measurement)

- **alpha-ai.web.id** (self-owned full-CF): PROVEN cred-reuse chain (origin-direct â†’ Odoo uid=2).
- **solusibersama.co.id** (real client, Cloudways): Alpha 4 findings (seo_injection 9.1 + wp user
  disclosure 5.3 + woocommerce 5.3 + wp_version 3.1) + 9 users. Beta = default_creds only (no valid).
  GAP-015 UserDerived didn't fire â†’ root cause = empty roster in the full-chain runner â†’ fixed in
  PR #331 (self-built GOVERNED fallback). Re-run pending.
- **bernofarm.com** (real client, Cloudflare): reach-blocked (CF managed challenge from datacenter =
- **bernofarm.com rematch (2026-08-07, post-PR#346)**: WafBlocked 25->12 (reproducible 3x on Oracle ARM64). Stealth-by-default transport (curl_cffi chrome124) confirmed effective -- 52% block reduction. Residual 12 blocks = IP-reputation + managed-challenge = INFRA/forbidden ceiling (§12.44/§12.33), NOT a code slice. DOCTRINE BANKED: stop beating full-CF apex from datacenter IP. bernofarm success = find a REACHABLE non-CF surface (CT subdomains -> origin candidates), not crack the apex.
  infra ceiling; origin hidden, no CT sibling). Strix's 10 findings = commodity recon, later verified
  FALSE POSITIVE â†’ validates our precision-first stance.

---

## NEXT (foundation, in order — one slice at a time)

1. **§12.48 PassiveIntelMap** — SEPARATE component (anti-#8, starts §12.47 decomposition of scout.py 2085 lines). NOT more methods on scout. Flow: crt.sh/Wayback/VirusTotal/etc zero-touch → surface CT subdomains → resolve → non-CF/grey-cloud + origin candidates → feed verify_origin_binding (slice-1 sealed). Build as `agent_alpha/recon/passive_intel.py` + `agent_alpha/tools/passive_*` per §12.47 ToolRegistry.
2. **Origin-binding slice-3** — wire `resolve_and_bind_origin` into `_attempt_reach` (WIRING_DEBT from slice-1 #337 + slice-2 #338). resolve_and_bind_origin exists, just needs the autonomous reach path to call it.
3. **§12.50 pacing** — StealthPacer (recon-arc DEPTH, after reach proven).

## DOCTRINE BANKED (2026-08-07)

- **Stop beating full-CF apex from datacenter IP.** Residual WafBlocked = IP-reputation + managed-challenge = INFRA/forbidden ceiling (§12.44/§12.33), NOT a code slice. Do NOT chase residential proxy (procurement) or browser_solve (lab-only, MC-ceilinged) for real clients.
- **bernofarm success = find a REACHABLE non-CF surface**, not crack the apex. Passive-first (§12.48) surfaces CT subdomains → origin candidates → reach THOSE.
- **ADR discipline**: §12.48/§12.49 = active foundation. §12.50/12.53/12.54 = recon-arc DEPTH, sequenced AFTER reach proven (not parallel). §12.51 Gamma / §12.55 1-day / §12.56 supply-chain = STOP-gated.
- **TECH-DEBT**: scout.py = 2085 lines (Lyndon #8). Build passive-first as SEPARATE component (starts §12.47 decomposition organically). Full scout decomposition = after reach proven.
- **plugin_cve_catalog** = interim, replace w/ live NVD/ExploitDB feed per §12.55 when Gamma lands.

## SEALED but NOT WIRED (WIRING_DEBT)

- origin-binding slice-1 (#337) + slice-2 (#338): `resolve_and_bind_origin` exists in `agent_alpha/recon/origin_binding.py`, but `_attempt_reach` does NOT call it yet. Slice-3 = wire it.

## PENDING (finish before / early next session)

1. **PR #331** (UserDerivedCredsTool governed fallback) â€” CodeRabbit revisions done (cache governor
   [real safety fix], docstring, helper extract, module imports, tests). Apply + merge.
2. Patches produced this session, seal on Oracle + merge: odoo17-dbmanager-marker-fix, slice-2
   (compromise detector + structural hidden-links).
3. **CROSS_VERIFIED**: wire `run_verification_pass` + `CredReuseAttestor` into the Alphaâ†’Beta chain so
   access goes SELF_VERIFIED â†’ CROSS_VERIFIED (Â§12.43). Attestor exists; just needs the pass invoked.
4. **Dedup** `backup_file_leak` vs `wp_config_leak` (same wp-config.php.bak, double-reported) + Omega
   narrative to prefer the specific wp_config_leak as chain entry.

---

## DOCTRINE authored this session (PROPOSED â€” lock on confirm)

- **Â§12.42** Attacker vantage = EXTERNAL + agentless + exhaustive-surface (+ Attacker Doctrine).
- **Â§12.43** Proof standard: independent oracle + human-legible artifact; screenshot = exhibit not oracle.
- **Â§12.44** Evasion catalog: origin-direct = highest ROI; datacenter-viable vs infra-bound; residential
  IP = infra not code; CAPTCHA solvers FORBIDDEN.
- **Â§12.45** Credential-result semantics: NEVER certify "safe"; negative â‰  clean bill; password recall
  scales via offline hash-crack + credential-stuffing, not online spray; Omega forbidden from "safe".
- Consent-checklist design: `/authorize` IS the checklist endpoint (consent_items + allow_evasion +
  tier + signed_by/at). Missing only `blast_threshold`. Manual SOW upload â†’ replace with signed
  checklist-consent (auto-sign). Invite-only trust model.

---

## AUDIT verdict (do NOT regress)

Gate model is ALREADY front-loaded (Â§0 + Â§12.36): sign ONCE at engagement creation â†’ autonomous.
Only runtime human-gates = OFFENSIVE-tier transition + blast>threshold (both pre-consentable in the
profile). No stray per-action gates. Do NOT remove evasion consent (legal RoE) â€” front-load it.

---

## NEXT strategic (deeper than Strix â€” the moat, NOT more analyzers)

Strix's FP proves breadth = FP factory. Priority: (a) VERIFY findings we have (cross_verified),
(b) reach past CF to test injections CF hid (origin-direct), (c) chain into compromise story,
(d) business-logic. Build an analyzer ONLY if it feeds a verified chain (js_secretâ†’cred-reuse: yes;
standalone directory-listing: no). Do NOT chase recon-parity with scanners.

---

## Non-negotiables (unchanged)

External vantage. Auth gate front-loaded in Conductor. A2A = structured English JSON. Event-sourced.
RUNNER-SEAL â‰  AUTONOMOUS-WIRED (grep the live path). Oracle ARM64 + .venv312 ONLY valid test env.
Gap ledger: docs/BUGS_AND_GAPS.md. No hardcoded credential/password lists.

---

## Deep-moat roadmap â€” "deeper than any scanner" (north-star)

Scanners (Nuclei/Strix) do commodity recon; Strix's bernofarm findings verified as FALSE POSITIVE.
Our differentiation is DEPTH, not breadth. Do NOT chase analyzer parity. Build an analyzer only if
it feeds a VERIFIED CHAIN.

### The 4 depth vectors (what a scanner CANNOT do)

1. **Reach PAST the CF edge to test what CF hid.** Scanners' SQLi/XSS die at the CF edge (403).
   Origin-direct (PROVEN on alpha-ai) bypasses CF â†’ test injections at the origin. Uses capability we
   already have. bernofarm has 94 CT subdomains â€” likely a grey-cloud origin to reach.
2. **PROVE exploitability, not presence.** "High-risk plugin" (guess) â†’ "we got a shell" (proof).
   Version-gated plugin_cve â†’ Gamma exploitation. The moat.
3. **CHAIN into an attack-path + compromise root-cause.** Scanner lists 10 separate items; AttackGraph
   connects them into ONE story: entry (WP File Manager RCE) â†’ foothold (fm_backup) â†’ result (SEO
   injection). "How they got in, what they did." Narrative is the moat.
4. **Business-logic reasoning on exposed handlers.** Not "nonce exposed" but "this AJAX handler
   (submit_keluhan_obat) can be abused for IDOR/injection behind a nonce-gate CF doesn't protect."

### Deep capabilities MISSING from the roadmap (gap analysis vs Natanael's 6 Lyndon frustrations)

- **Cross-engagement memory / IntelligenceBase (Â§8c, GAP-003) â€” Lyndon frustration #3.** The agent
  must LEARN across engagements: recurring password patterns, common stacks, reliable plays; the Nth
  engagement smarter than the 1st. Data/playbook only (never self-modifying code). Deferred; needs
  findings flowing first (now they are). This is a CORE differentiator vs scanners (which never learn).
- **Post-access authenticated re-recon (Â§12.32).** We proved admin on alpha-ai â€” the depth is "now
  that we are IN": diff unauth vs auth surface â†’ IDOR / broken-access-control / priv-esc. Directly
  extends the milestone. DETECT is recon; exploiting is Gamma-gated.
- **Compromise root-cause / attacker-artifact hunt.** Deepen vector 3: beyond "SEO spam present" â†’
  find the webshell / backdoor / persistence and the entry point. Detect an EXISTING compromise AND
  its cause. (Still DETECT + PROVE + REPORT; "wrest control" = IR, out of scope.)
- **Omega report narrative â€” Lyndon frustration #4.** Current report = node dump. A payable report is
  a STORY (internet â†’ crown-jewel, prose, executive + technical + remediation). Report quality is a
  differentiator clients pay for. to_narrative(style) exists but is under-built.
- **Reflection / "Try Harder" loop (Â§8j-2).** Agent reflects on findings + tries alternative
  approaches instead of stopping at the first pass (NodeZero-style persistence).

### Phasing (do NOT parallelize; findings drive order)

- **Now / next:** Execute Phase 4 Recon & Evasion Overhaul (Slices 1 to 6). Build `PassiveIntelMap`, integrate `curl_cffi` as stealth default, implement `StealthPacer`, and integrate Deep Recon (Wayback, Dehashed). This solves Bug #26 (Generic blind probing blocked by WAF).
- **Soon:** IntelligenceBase (frustration #3) once findings accumulate across â‰¥3 engagements; Omega
  narrative (frustration #4) since we now have real chains to narrate.
- **Later (Gamma-gated):** prove-RCE exploitation, business-logic outcome-oracle, ToolComposer +
  blast-radius gate. STOP-gated until Phase 4 (Recon + Reach) is fully stabilized and fielded. (Remember Â§12.55: we are a 1-day weaponizer, not a 0-day hunter).

Litmus for every depth build: does it PROVE / CHAIN / LEARN, or is it another surface detector?
Surface detector â†’ skip (Strix-parity FP). Prove/chain/learn â†’ moat.
