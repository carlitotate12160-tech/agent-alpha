> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-07, cont.)

Resume with: "lanjut Agent-Alpha — PR #346 stealth-by-default MERGED. bernofarm apex WafBlocked 25→12 (reproducible 3x on Oracle ARM64). DOCTRINE BANKED: stop beating full-CF apex from datacenter IP — residual 12 blocks = IP-rep + managed-challenge = INFRA ceiling, NOT code. NEXT = §12.48 PassiveIntelMap as SEPARATE component (anti-#8, starts §12.47 decomposition): crt.sh/Wayback/VirusTotal zero-touch → surface CT subdomains → resolve → non-CF/grey-cloud + origin candidates → verify_origin_binding (slice-1 sealed) → reach THOSE, avoid apex. Then origin-binding slice-3 (wire resolve_and_bind_origin into _attempt_reach). Then §12.50 pacing. Do NOT build Gamma."

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — NOW MET on a self-owned real-world target:** find something a scanner missed +
prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass →
proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) — what Nuclei/
Strix cannot assemble.

---

## SEALED / PROVEN this arc

- **PR #346 stealth-by-default** (merged 2026-08-07): curl_cffi chrome124 as DEFAULT transport from request #1 (not reactive fallback). STEALTH_BROWSER SSOT (UA + sec-ch-ua + impersonate pinned to Chrome 124, anti-#7 drift). DEFAULT_OPSEC_PROFILE: announced→stealth. /authorize forwards allow_origin_discovery + allow_subdomain_enum. Consent gate covers allow_subdomain_enum (CodeRabbit fix). httpx fallback warns STEALTH-DEGRADED. Oracle ARM64 verified: 42 passed, 2 skipped, ruff/mypy clean. bernofarm 25→12 WafBlocked.
- **Reach**: origin-direct (bypass CF edge) sealed + robust — RC1/RC2/RC3 fixes (deterministic multi-
  vhost probe, 303 confirms, all-hostnames-per-IP), seed_hosts (in-scope targets as origin
  candidates). tls_impersonate correctly NOT chosen for CHALLENGE-class CF (§12.33, IP-reputation).
- **GAP-015** (predictable-cred) built + wired + run() authored. Governed applicator seam (§12.22 D2)
  = single lockout governor at the factory.
- **odoo_dbmanager**: rule↔classifier markers aligned (Odoo 17 now detected deterministically, no
  LLM dependency). OdooAccessTool audited = §12.43-sound independent oracle (db.list() + uid>0).
- **slice-2 §12.40 content-analysis**: `detect_seo_injection` (keyword + STRUCTURAL cloaked-link-farm,
  keyword-independent) wired into scout autonomous path. FIRED on real client solusibersama
  (seo_injection_compromise CVSS 9.1).
- **alpha-ai chain (eng_63ebd8a2)**: asset → wp-config leak → cred → access (admin, uid=2), Omega
  report + proof SHA256. SELF_VERIFIED.

---

## Field results (real-world measurement)

- **alpha-ai.web.id** (self-owned full-CF): PROVEN cred-reuse chain (origin-direct → Odoo uid=2).
- **solusibersama.co.id** (real client, Cloudways): Alpha 4 findings (seo_injection 9.1 + wp user
  disclosure 5.3 + woocommerce 5.3 + wp_version 3.1) + 9 users. Beta = default_creds only (no valid).
  GAP-015 UserDerived didn't fire → root cause = empty roster in the full-chain runner → fixed in
  PR #331 (self-built GOVERNED fallback). Re-run pending.
- **bernofarm.com** (real client, Cloudflare): reach-blocked (CF managed challenge from datacenter =
  infra ceiling; origin hidden, no CT sibling). Strix's 10 findings = commodity recon, later verified
  FALSE POSITIVE → validates our precision-first stance.
- **bernofarm.com rematch (2026-08-07, post-PR#346)**: WafBlocked 25→12 (reproducible 3x on Oracle ARM64). Stealth-by-default transport (curl_cffi chrome124) confirmed effective — 52% block reduction. Residual 12 blocks = IP-reputation + managed-challenge = INFRA/forbidden ceiling (§12.44/§12.33), NOT a code slice. DOCTRINE BANKED: stop beating full-CF apex from datacenter IP. bernofarm success = find a REACHABLE non-CF surface (CT subdomains → origin candidates), not crack the apex.

---

## MERGED SINCE (2026-08-07 cont. — recon + reach + pacing arc LANDED)

- **§12.48 PassiveIntelMap** — slice-1 crt.sh (PR #347) + slice-2 keyless HackerTarget fallback (PR #349, incl. CodeRabbit first-line parser fix). SEPARATE component `recon/passive_intel.py` (starts §12.47 decomposition). Fills subdomains/in_scope; VT/DNS slots still empty (→ NEXT #2).
- **§12.46 origin-binding — WIRED end-to-end** — Slice A (PR #351): `_attempt_reach` calls `resolve_and_bind_origin` behind the composed gate `assert_origin_authorized_or_bound` (token-canary P2 + capability + proven-event). Slice B: real `LiveOriginDiscovery` (CT/DNS) injected on the Conductor path. §12.38 quick-win: `/authorize` no longer auto-authorizes discovered origins (collateral hole closed) + crude 6-source main.py island removed (#6/#2/self-ID-UA gone).
- **§12.50 StealthPacer** — slice-1 (PR #353): human burst-and-pause + Gaussian jitter + distraction + 429/503 backoff, injected via signed `opsec_stealth`. slice-2: context-adaptive burst (host-aware — new host = navigation pause, same host = asset burst). §12.50 AMENDED: uniform → Gaussian jitter.
- **CROSS_VERIFIED — DONE** (was mislabelled PENDING; see PENDING #3).

## NEXT (foundation, in order — one slice at a time)

1. **Dedup** `backup_file_leak` vs `wp_config_leak` (double-report on the same wp-config.php.bak) + Omega narrative to prefer `wp_config_leak` as chain entry. Last Phase-4-exit cleanup.
2. **§12.48 slice-3 DNS enrichment** — fill PassiveIntelMap MX/TXT/NS + `protection_detected` (NS→CF). KEYLESS. Double-value: feeds §12.46 origin candidates (MX often reveals origin) AND is the OPEN **Bug #26** fix (protection-detect before blind probe; closes part of GAP-007/GAP-016).
3. **Subdomain takeover** (dangling CNAME → expired service) — highest-value payable finding scanners miss; chains to full subdomain control.
4. **Wayback** (GAP-016, keyless) → **VirusTotal** (key-gated enrichment). AXFR DEMOTED (rare + scanner-covered). robots/sitemap low. Dehashed = paid, feeds Beta.

## DOCTRINE BANKED (2026-08-07)

- **Stop beating full-CF apex from datacenter IP.** Residual WafBlocked = IP-reputation + managed-challenge = INFRA/forbidden ceiling (§12.44/§12.33), NOT a code slice. Do NOT chase residential proxy (procurement) or browser_solve (lab-only, MC-ceilinged) for real clients.
- **bernofarm success = find a REACHABLE non-CF surface**, not crack the apex. Passive-first (§12.48) surfaces CT subdomains → origin candidates → reach THOSE.
- **ADR discipline**: §12.48/§12.49 = active foundation. §12.50/12.53/12.54 = recon-arc DEPTH, sequenced AFTER reach proven (not parallel). §12.51 Gamma / §12.55 1-day / §12.56 supply-chain = STOP-gated.
- **TECH-DEBT**: scout.py = 2085 lines (Lyndon #8). Build passive-first as SEPARATE component (starts §12.47 decomposition organically). Full scout decomposition = after reach proven.
- **plugin_cve_catalog** = interim, replace w/ live NVD/ExploitDB feed per §12.55 when Gamma lands.

## SEALED but NOT WIRED (WIRING_DEBT)

- (none open for origin-binding) — RESOLVED by §12.46 Slice A (PR #351): `_attempt_reach` now calls `resolve_and_bind_origin` (composed gate `assert_origin_authorized_or_bound`), Slice B injects a real `LiveOriginDiscovery`. Both proven by non-island W-tests (test_alpha_autonomous_reach + test_conductor_auth_path); `resolve_and_bind_origin` + `LiveOriginDiscovery` are now WIRED_REQUIRED in the wiring gate.

## PENDING (finish before / early next session)

1. **PR #331** (UserDerivedCredsTool governed fallback) — CodeRabbit revisions done (cache governor
   [real safety fix], docstring, helper extract, module imports, tests). Apply + merge.
2. Patches produced this session, seal on Oracle + merge: odoo17-dbmanager-marker-fix, slice-2
   (compromise detector + structural hidden-links).
3. ~~**CROSS_VERIFIED**~~ — **DONE (verified 2026-08-07 via READ-BEFORE).** `verify_access_nodes` 
   (running `CredReuseAttestor` through `run_verification_pass`) is called on the AUTONOMOUS path in
   `run_agent_task → run_beta()` at Beta COMPLETE (`conductor/main.py`). Proven end-to-end by
   `test_autonomous_wp_chain_e2e::test_autonomous_conductor_chain_produces_cross_verified_wp_finding` 
   (asserts an ACCESS_LEVEL node reaches CROSS_VERIFIED on the live chain) + the unit differential in
   `test_conductor_verification`. NOT a gap — do not rebuild.
4. **Dedup** `backup_file_leak` vs `wp_config_leak` (same wp-config.php.bak, double-reported) + Omega
   narrative to prefer the specific wp_config_leak as chain entry.

---

## DOCTRINE authored this session (PROPOSED — lock on confirm)

- **§12.42** Attacker vantage = EXTERNAL + agentless + exhaustive-surface (+ Attacker Doctrine).
- **§12.43** Proof standard: independent oracle + human-legible artifact; screenshot = exhibit not oracle.
- **§12.44** Evasion catalog: origin-direct = highest ROI; datacenter-viable vs infra-bound; residential
  IP = infra not code; CAPTCHA solvers FORBIDDEN.
- **§12.45** Credential-result semantics: NEVER certify "safe"; negative ≠ clean bill; password recall
  scales via offline hash-crack + credential-stuffing, not online spray; Omega forbidden from "safe".
- Consent-checklist design: `/authorize` IS the checklist endpoint (consent_items + allow_evasion +
  tier + signed_by/at). Missing only `blast_threshold`. Manual SOW upload → replace with signed
  checklist-consent (auto-sign). Invite-only trust model.

---

## AUDIT verdict (do NOT regress)

Gate model is ALREADY front-loaded (§0 + §12.36): sign ONCE at engagement creation → autonomous.
Only runtime human-gates = OFFENSIVE-tier transition + blast>threshold (both pre-consentable in the
profile). No stray per-action gates. Do NOT remove evasion consent (legal RoE) — front-load it.

---

## NEXT strategic (deeper than Strix — the moat, NOT more analyzers)

Strix's FP proves breadth = FP factory. Priority: (a) VERIFY findings we have (cross_verified),
(b) reach past CF to test injections CF hid (origin-direct), (c) chain into compromise story,
(d) business-logic. Build an analyzer ONLY if it feeds a verified chain (js_secret→cred-reuse: yes;
standalone directory-listing: no). Do NOT chase recon-parity with scanners.

---

## Non-negotiables (unchanged)

External vantage. Auth gate front-loaded in Conductor. A2A = structured English JSON. Event-sourced.
RUNNER-SEAL ≠ AUTONOMOUS-WIRED (grep the live path). Oracle ARM64 + .venv312 ONLY valid test env.
Gap ledger: docs/BUGS_AND_GAPS.md. No hardcoded credential/password lists.

---

## Deep-moat roadmap — "deeper than any scanner" (north-star)

Scanners (Nuclei/Strix) do commodity recon; Strix's bernofarm findings verified as FALSE POSITIVE.
Our differentiation is DEPTH, not breadth. Do NOT chase analyzer parity. Build an analyzer only if
it feeds a VERIFIED CHAIN.

### The 4 depth vectors (what a scanner CANNOT do)

1. **Reach PAST the CF edge to test what CF hid.** Scanners' SQLi/XSS die at the CF edge (403).
   Origin-direct (PROVEN on alpha-ai) bypasses CF → test injections at the origin. Uses capability we
   already have. bernofarm has 94 CT subdomains — likely a grey-cloud origin to reach.
2. **PROVE exploitability, not presence.** "High-risk plugin" (guess) → "we got a shell" (proof).
   Version-gated plugin_cve → Gamma exploitation. The moat.
3. **CHAIN into an attack-path + compromise root-cause.** Scanner lists 10 separate items; AttackGraph
   connects them into ONE story: entry (WP File Manager RCE) → foothold (fm_backup) → result (SEO
   injection). "How they got in, what they did." Narrative is the moat.
4. **Business-logic reasoning on exposed handlers.** Not "nonce exposed" but "this AJAX handler
   (submit_keluhan_obat) can be abused for IDOR/injection behind a nonce-gate CF doesn't protect."

### Deep capabilities MISSING from the roadmap (gap analysis vs Natanael's 6 Lyndon frustrations)

- **Cross-engagement memory / IntelligenceBase (§8c, GAP-003) — Lyndon frustration #3.** The agent
  must LEARN across engagements: recurring password patterns, common stacks, reliable plays; the Nth
  engagement smarter than the 1st. Data/playbook only (never self-modifying code). Deferred; needs
  findings flowing first (now they are). This is a CORE differentiator vs scanners (which never learn).
- **Post-access authenticated re-recon (§12.32).** We proved admin on alpha-ai — the depth is "now
  that we are IN": diff unauth vs auth surface → IDOR / broken-access-control / priv-esc. Directly
  extends the milestone. DETECT is recon; exploiting is Gamma-gated.
- **Compromise root-cause / attacker-artifact hunt.** Deepen vector 3: beyond "SEO spam present" →
  find the webshell / backdoor / persistence and the entry point. Detect an EXISTING compromise AND
  its cause. (Still DETECT + PROVE + REPORT; "wrest control" = IR, out of scope.)
- **Omega report narrative — Lyndon frustration #4.** Current report = node dump. A payable report is
  a STORY (internet → crown-jewel, prose, executive + technical + remediation). Report quality is a
  differentiator clients pay for. to_narrative(style) exists but is under-built.
- **Reflection / "Try Harder" loop (§8j-2).** Agent reflects on findings + tries alternative
  approaches instead of stopping at the first pass (NodeZero-style persistence).

### Phasing (do NOT parallelize; findings drive order)

- **Now / next:** Execute Phase 4 Recon & Evasion Overhaul (Slices 1 to 6). Build `PassiveIntelMap`, integrate `curl_cffi` as stealth default, implement `StealthPacer`, and integrate Deep Recon (Wayback, Dehashed). This solves Bug #26 (Generic blind probing blocked by WAF).
- **Soon:** IntelligenceBase (frustration #3) once findings accumulate across ≥3 engagements; Omega
  narrative (frustration #4) since we now have real chains to narrate.
- **Later (Gamma-gated):** prove-RCE exploitation, business-logic outcome-oracle, ToolComposer +
  blast-radius gate. STOP-gated until Phase 4 (Recon + Reach) is fully stabilized and fielded. (Remember §12.55: we are a 1-day weaponizer, not a 0-day hunter).

Litmus for every depth build: does it PROVE / CHAIN / LEARN, or is it another surface detector?
Surface detector → skip (Strix-parity FP). Prove/chain/learn → moat.
