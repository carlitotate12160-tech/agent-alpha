> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-09, entry-selection arc + §12.58/§12.59)

Resume with: "lanjut Agent-Alpha — §12.58/§12.59 operator-cognition arc. Entry-selection slice-1 (SituationAssessor instinct #1) LIVE-SEALED on the AUTONOMOUS path: Beta now strikes the reachable auth-surface (`select_strike_entry`, conductor/router.py) instead of the dead apex. Proof = differential test through `run_agent_task` (run_strike receives the selected host, NOT record.target) + wiring-gate ratchet `select_strike_entry -> conductor/main.py`. Oracle: 37 passed (phase_4/test_entry_selection + governance/test_wiring_gate), make check clean, make quality 373 passed / 4 skipped / 0 failed. §12.59 Hybrid Cognition Roadmap ACCEPTED (deterministic-first Phase 4-5; LLM-in-DECIDE = Phase-6 OPEN). Honest-seal event STRIKE_ENTRY_SELECTED WIRED (event-sourced observability of the DECIDE). PENDING: (1) live niagamas re-run to confirm STRIKE_ENTRY_SELECTED = hub.niagamas.com LITERAL in event store, (2) close niagamas exploit path (cred acquisition + Bug #25). NEXT = GAP-029 dead-host skip = deterministic instinct #2. Do NOT build Gamma."

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — MET on self-owned real-world target; autonomous path now exercises binding for real:** find something a scanner missed + prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass → proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) — what Nuclei/Strix cannot assemble.

---

## SEALED / PROVEN this arc (2026-08-09)

| Work | Seal level | Evidence |
|------|-----------|----------|
| **Entry-selection slice-1 — Beta strikes reachable auth-surface, not dead apex (instinct #1, §12.58/§12.59)** | **LIVE-sealed on AUTONOMOUS path** (contract + differential + ratchet) | Pure `select_strike_entry(graph_store, *, default_target)` (router.py, reuses `_AUTH_SURFACE_LABELS` SSOT — anti #7). ONE `strike_entry` computed once, wired to BOTH `build_applicators_for_engagement(web_target=)` and `beta.run_strike(...)` (fixed the Lyndon #10-adjacent two-seam hardcode to record.target). Differential test via `run_agent_task` proves run_strike gets the selected host. wiring-gate ratchet `select_strike_entry -> conductor/main.py`. Oracle: 37 passed, make check clean, make quality 373 passed. |
| **Honest-seal event STRIKE_ENTRY_SELECTED — observability of the DECIDE** | **LIVE-sealed on AUTONOMOUS path** (event-sourced) | `EventType.STRIKE_ENTRY_SELECTED` emitted BEFORE applicator build / run_strike (main.py). `select_strike_entry` returns `StrikeEntrySelection` dataclass (URL + matched_label + fallback_to_default + candidates_considered). Event payload = `{selected_entry, matched_label, fallback_to_default, candidates_considered}`. wiring-gate ratchet `STRIKE_ENTRY_SELECTED -> conductor/main.py`. Oracle: 6/6 phase_4 tests pass (incl. 2 event-emission tests). Converts inferential proof → LITERAL + audited forever. |
| **Slice 1 — origin-binding on autonomous path** | **LIVE-sealed** | `authorized_origins=frozenset()` forces the binding leg; `ORIGIN_BINDING_PROVEN` x2 (wp + odoo, `well_known_token`) on Oracle live run. Non-negotiable "no hand-fed authorized_origins" now actually exercised. |
| **auth-surface-dispatch — router Fix A + detector Fix B** | **Unit-sealed Oracle (36/36 + ruff/format/mypy)** + partially LIVE-proven | Live niagamas: `hub.niagamas.com` persisted `http_basic_auth` (Fix B fired live); Beta dispatched WITHOUT a credential (Fix A — deadlock broken, applicator_calls=[2]). |
| **OAHC wrapper (v2 fail-close + 6 review holes + CodeRabbit Major)** | **Unit-sealed Oracle (15/15 random-order, ruff/format)** | crash→graceful skip (`OriginUnreachableError(HttpClientError)`), per-host WAF_BLOCKED evidence (no over-refuse), both store reads fail-open symmetric. |

### Earlier sealed (still valid — context for this arc)

- **PR #346 stealth-by-default** (merged 2026-08-07): curl_cffi chrome124 as DEFAULT transport from request #1. STEALTH_BROWSER SSOT. bernofarm 25→12 WafBlocked.
- **Reach**: origin-direct (bypass CF edge) sealed + robust — RC1/RC2/RC3, seed_hosts, tls_impersonate correctly NOT chosen for CHALLENGE-class CF.
- **GAP-015** (predictable-cred) built + wired + run() authored. Governed applicator seam (§12.22 D2).
- **odoo_dbmanager**: rule↔classifier markers aligned (Odoo 17 deterministic). OdooAccessTool audited = §12.43-sound independent oracle.
- **slice-2 §12.40 content-analysis**: `detect_seo_injection` wired into scout autonomous path. FIRED on solusibersama (CVSS 9.1).
- **alpha-ai chain (eng_63ebd8a2)**: asset → wp-config leak → cred → access (admin, uid=2), Omega report + proof SHA256. SELF_VERIFIED.
- **§12.48 PassiveIntelMap** — slice-1 crt.sh (PR #347) + slice-2 HackerTarget fallback (PR #349) + slice-3 DNS enrich (#357) + slice-4 CertSpotter primary (#359) + slice-5 OTX (#360). Separate component `recon/passive_intel.py`.
- **§12.46 origin-binding WIRED** — Slice A (PR #351): `_attempt_reach` calls `resolve_and_bind_origin` behind composed gate. Slice B: real `LiveOriginDiscovery` injected on Conductor path. §12.38 quick-win: `/authorize` no longer auto-authorizes discovered origins.
- **§12.50 StealthPacer** — slice-1 (PR #353): human burst-and-pause + Gaussian jitter + distraction + 429/503 backoff. slice-2: context-adaptive burst (host-aware).
- **GAP-017 CompositeOriginDiscovery consumer** (#361) · **Bug#26 consumer** protection_detected+historical_paths (#363) · **GAP-018 seed_hosts** (#365) · **GAP-019 per-host origin cache** (crt.sh 50→2, run 29→6.5min).
- **CROSS_VERIFIED — DONE**: `verify_access_nodes` runs on AUTONOMOUS path in `run_agent_task → run_beta()` at Beta COMPLETE. Proven by `test_autonomous_wp_chain_e2e`.
- **Dedup backup_file_leak vs wp_config_leak — DONE**: `canonical_leak_vuln_suffix` maps `wp-config.php.bak` → `wp_config_leak` for both probes → single vuln node.

---

## Field results (real-world measurement)

- **alpha-ai.web.id** (self-owned full-CF): PROVEN cred-reuse chain (origin-direct → Odoo uid=2). Binding now LIVE-exercised (not hand-fed).
- **niagamas.com** (real client): auth-surface-dispatch partially LIVE-proven — `hub.niagamas.com` persisted `http_basic_auth` (Fix B fired); Beta dispatched (Fix A, applicator_calls=[2]) but did NOT exploit (entry-selection gap — Beta targets apex not hub).
- **solusibersama.co.id** (real client, Cloudways): Alpha 4 findings (seo_injection 9.1 + wp user disclosure 5.3 + woocommerce 5.3 + wp_version 3.1) + 9 users. Beta = default_creds only.
- **bernofarm.com** (real client, Cloudflare): reach-blocked (CF managed challenge = infra ceiling). Strix's 10 findings verified FALSE POSITIVE. Post-PR#346: WafBlocked 25→12 (52% reduction). Residual = IP-reputation + managed-challenge = INFRA ceiling, NOT a code slice.

---

## PENDING (finish before next slice — IN ORDER)

1. **Live niagamas re-run — confirm STRIKE_ENTRY_SELECTED = hub.niagamas.com LITERAL.** The honest-seal event is wired + unit-sealed, but live proof is still INFERENTIAL (graph has only `hub.niagamas.com` as auth-surface + wiring always routes through `select_strike_entry`). Re-run niagamas and grep the event store for `STRIKE_ENTRY_SELECTED` payload — converts inferential → LITERAL. (Re-run started 2026-08-09, in progress.)
2. **Close the niagamas EXPLOIT path** (separate from targeting): Beta now strikes hub but FAILS honestly (no credential for the 401 basic-auth; CREDENTIAL nodes: 0). Needs cred acquisition + **Bug #25** (UserDerived not consuming usernames — RECURRED on niagamas: usernames found, dropped). Targeting is fixed; exploit is NOT closed — do NOT mark closed.

---

## NEXT (foundation, in order — one slice at a time)

**Re-sequence 2026-08-09 (entry-selection arc):** Entry-selection slice-1 + honest-seal DONE. Next = deterministic instinct #2.

**Recommended next order:**

1. **Live niagamas re-run** — confirm STRIKE_ENTRY_SELECTED = hub.niagamas.com LITERAL in event store. [PENDING #1]
2. **Close niagamas exploit path** — cred acquisition + Bug #25 fix. [PENDING #2]
3. **GAP-029 — dead-host short-circuit = deterministic instinct #2 (§12.58/§12.59 Phase-4).** System-1 immediate reflex (not periodic): when a host root fetch raises HttpClientError, record the host as unreachable and SKIP all remaining queued probes for that host. This is the "dead host → skip" instinct — universal, deterministic, closes the massif probe-waste. (See GAP-029 in the ledger — do NOT open a new gap number; this IS it.) Fix option A (minimal, matches ledger): track `_unreachable_hosts: set[str]` on Alpha, add host on root HttpClientError, skip in `_pop_unprobed`. Option B (deeper): defer seed-path enqueue until homepage fetch succeeds (redesign, >2 files — interface, not patch; anti #10). Recommend A for slice-2, register B as the follow-on.

**After GAP-029 (recon-quality trio still valid, lower priority):**
- GAP-020 — 404 pattern-group exhaustion (deterministic, kills robot-spray).
- GAP-021 — fingerprint-driven path hard-filter.
- GAP-022 — deterministic rule coverage + finding correlation.
- Subdomain takeover (R1) — new payable finding.
- J4 cross-target cred reuse — only meaningful after entry-selection + Beta reach parity.

**Auth-gate boundary (ADR §12.57, non-negotiable):** Alpha NEVER does initial access, even on a jackpot; the recon→access pivot is the GATED Alpha→Beta hand-off. Event-driven parallel pivot = DEFERRED Phase 5+.

---

## MISSED / OWED — doc + ledger updates recommended but NOT yet committed

- **Slice 1:** register §12.46 known-deferral (token identical for both hosts = lab artifact; per-host token uniqueness + cert-SAN already deferred). Add Session_Handoff pointer to the binding-proven milestone.
- **Slice 2:** register in `BUGS_AND_GAPS`: opsec-client construction DUPLICATED recon + Beta (`#6` — unify into one factory). Add `test_wiring_gate` WIRED_REQUIRED: `OriginAwareHttpClient -> conductor/main.py`. Record the two wiring decisions: (a) fail-LOUD on missing/invalid profile for Beta, (b) wrap a stealth client.
- **auth-surface-dispatch:** confirm `test_wiring_gate` entries actually committed: `detect_auth_surface_labels -> agents/alpha/scout.py`, `route_next -> conductor/advance.py`.
- **R1–R3 xref fix:** the offline-crack roadmap entries cite **ADR §12.46 — WRONG** (§12.46 is origin-binding). Correct to the **§12.44–45 cred-recall block** (`ADR_SUMMARY` ~L176-178). If not fixed, R1 gets built against the wrong spec.
- **R3 reprioritization:** ledger rates R3 (OSINT wordlist) "Low/online-bounded" — its OFFLINE value (feeding R1 hashcat, unbounded) is **High**. Reframe: build the wordlist/rules engine as INPUT to R1, not an online-spray extension.

---

## GAPS IDENTIFIED (status change — do NOT duplicate)

- **GAP-029 — LIVE-CONFIRMED AGAIN (2026-08-09 entry-selection re-run).** Root confirmed in code: `scout._step_once` `_finish` (scout.py:385-393) ends ONE cognitive-loop iteration only; `run_cognitive_loop` pops the next URL immediately — no host-level abort. Queue seeded at scout.py:260-269 (leak paths + OTX historical + surface paths) is walked path-by-path even after `https://<host>/` is unreachable. Promote GAP-029 to the NEXT build slice (= instinct #2 above). Fix option A (minimal, matches ledger): track `_unreachable_hosts: set[str]` on Alpha, add host on root HttpClientError, skip in `_pop_unprobed`. Option B (deeper): defer seed-path enqueue until homepage fetch succeeds (redesign, >2 files — interface, not patch; anti #10). Recommend A for slice-2, register B as the follow-on.
- **GAP-034 — DEFERRED (entry-selection slice-1).** Entry-selection has no node-level reachability signal — `select_strike_entry` uses auth-surface label presence as a reachability proxy. Breaks for a host that is WAF-dead but still carries a label. Design-first; promote alongside instinct #2 (cred-reuse) under SituationAssessor. See docs/BUGS_AND_GAPS.md.
- **GAP-035 — DEFERRED (entry-selection slice-2).** Entry-selection strikes ONE candidate; multi-surface not iterated. When a target exposes >1 in-scope auth surface (hub 401 + pos login-form), only the top-ranked one is struck. Slice-2 = dispatch-seam loop + per-candidate ctx/gate. See docs/BUGS_AND_GAPS.md.
- **Bug #25 — RECURRED live on niagamas** (usernames found, dropped). RUNNER-SEAL != AUTONOMOUS-WIRED. Blocks the niagamas exploit close. Verify + wire on the live path.
- **GAP-026 (stealth-by-default) still OPEN.** `opsec_stealth: bool = False` default → CF bot-detection → recon degrades. APT tripped at the door = lost. HIGH. (Beta wiring PENDING #2 is the same thread.)
- **protection_detected is producer-only.** Computed, consumed only to suppress blind probes — NOT to route entry via an unprotected sibling. (OAHC now consumes WAF_BLOCKED for reach; protection_detected consumption for target-selection is still open.)
- **CertSpotter reliability (NOT Google CT).** Google CT logs are append-only, not domain-queryable — NOT a crt.sh replacement. CertSpotter (already primary) carried the run despite crt.sh/OTX timeouts. Fix = set a CertSpotter Bearer API key (raises keyless rate limit) + short fail-open timeouts. Deeper reliability = active DNS-brute (future).

---

## DEFERRED (menu — do NOT build now; one vertical slice at a time)

- R1 offline hash-crack + R2 breach-stuffing + R3 OSINT wordlist — Phase 5/6, Gamma-adjacent, needs a hash-harvest source (current chains leak PLAINTEXT, no crack needed). "Do NOT build Gamma."
- SituationAssessor / strategic control-loop — see ADR seed §12.58 (this handoff's sibling).
- GAP-020/021/022 (recon-quality trio) — valid but lower priority than entry-selection.
- Subdomain takeover (R1) — after recon-quality trio.

---

## DOCTRINE BANKED (2026-08-09, entry-selection arc)

- **ADR §12.59 Hybrid Cognition Roadmap** — deterministic-first. Phase 4 = instincts one at a time, field-proven (entry-selection #1 DONE → GAP-029 dead-host skip #2 → cred-reuse). Phase 5 = promote to `SituationAssessor` (still deterministic, only at 3-5 instincts). Phase 6 = LLM advisor in DECIDE = OPEN QUESTION, empirical trigger, NOT locked. Reaffirms §12.57 (LLM in ORIENT, never DECIDE) for Phase 4-5.
- **Key insight**: robot-feel lives on the CONTROL layer (deterministic-fixable, = §12.58); the more-than-deterministic layer (novel hypothesis) is ORIENT and already LLM-backed. DECIDE is where determinism is the STRENGTH (reproducible / gate-safe / seeded-replay).
- **RUNNER-SEAL != AUTONOMOUS-WIRED** re-affirmed: entry-selection sealed via the `run_agent_task` differential (autonomous path), not a runner island. Honest-seal event STRIKE_ENTRY_SELECTED makes live proof LITERAL (not inferential).
- **Honest-seal discipline**: the DECIDE layer's most important targeting decision (which host Beta strikes) is now event-sourced. Every strike selection is auditable forever. Additive over the sealed contract — never touch selector ranking after seal.

---

## DOCTRINE BANKED (2026-08-07, still valid)

- **Stop beating full-CF apex from datacenter IP.** Residual WafBlocked = IP-reputation + managed-challenge = INFRA/forbidden ceiling (§12.44/§12.33), NOT a code slice. Do NOT chase residential proxy (procurement) or browser_solve (lab-only, MC-ceilinged) for real clients.
- **bernofarm success = find a REACHABLE non-CF surface**, not crack the apex. Passive-first (§12.48) surfaces CT subdomains → origin candidates → reach THOSE.
- **ADR discipline**: §12.48/§12.49 = active foundation. §12.50/12.53/12.54 = recon-arc DEPTH, sequenced AFTER reach proven (not parallel). §12.51 Gamma / §12.55 1-day / §12.56 supply-chain = STOP-gated.
- **TECH-DEBT**: scout.py = 2085 lines (Lyndon #8). Build passive-first as SEPARATE component (starts §12.47 decomposition organically). Full scout decomposition = after reach proven.
- **plugin_cve_catalog** = interim, replace w/ live NVD/ExploitDB feed per §12.55 when Gamma lands.

---

## SEALED but NOT WIRED (WIRING_DEBT)

- **origin-binding** — RESOLVED LIVE (2026-08-09): `authorized_origins=frozenset()` forces binding leg; `ORIGIN_BINDING_PROVEN` x2 on Oracle live run. No longer hand-fed.
- **auth-surface-dispatch** — unit-sealed, partially LIVE-proven. `test_wiring_gate` entries to confirm committed: `detect_auth_surface_labels -> scout.py`, `route_next -> advance.py`.
- **OAHC wrapper** — unit-sealed only. WIRED_REQUIRED entry to add: `OriginAwareHttpClient -> conductor/main.py`. Pending LIVE seal.
- **Beta HttpClient naked** — `main.py:515` builds bare `HttpClient` for Beta (no opsec, no pacer, no reach strategy). GAP-026 applies. Wiring debt.

---

## DOCTRINE authored (PROPOSED — lock on confirm)

- **§12.42** Attacker vantage = EXTERNAL + agentless + exhaustive-surface (+ Attacker Doctrine).
- **§12.43** Proof standard: independent oracle + human-legible artifact; screenshot = exhibit not oracle.
- **§12.44** Evasion catalog: origin-direct = highest ROI; datacenter-viable vs infra-bound; residential IP = infra not code; CAPTCHA solvers FORBIDDEN.
- **§12.45** Credential-result semantics: NEVER certify "safe"; negative ≠ clean bill; password recall scales via offline hash-crack + credential-stuffing, not online spray; Omega forbidden from "safe".
- **§12.57** Alpha = gate-respecting operator, closed feedback loop; event-driven parallel pivot DEFERRED Phase 5+; Alpha-never-access affirmed.
- **§12.58** (PROPOSED/SEED) Strategic situation reasoning / "operator instinct" — deterministic strategic control-loop + heuristic reprioritization of work queue. NOT LLM. First instinct = entry-selection / dead-target pivot. Captured in ADR.md §12.58 + ADR_SUMMARY.md. Seed for dedicated session — do NOT implement until ACCEPTED + first-slice scope agreed.
- Consent-checklist design: `/authorize` IS the checklist endpoint (consent_items + allow_evasion + tier + signed_by/at). Missing only `blast_threshold`. Manual SOW upload → replace with signed checklist-consent (auto-sign). Invite-only trust model.

---

## AUDIT verdict (do NOT regress)

Gate model is ALREADY front-loaded (§0 + §12.36): sign ONCE at engagement creation → autonomous. Only runtime human-gates = OFFENSIVE-tier transition + blast>threshold (both pre-consentable in the profile). No stray per-action gates. Do NOT remove evasion consent (legal RoE) — front-load it.

---

## NEXT strategic (deeper than Strix — the moat, NOT more analyzers)

Strix's FP proves breadth = FP factory. Priority: (a) VERIFY findings we have (cross_verified), (b) reach past CF to test injections CF hid (origin-direct), (c) chain into compromise story, (d) business-logic. Build an analyzer ONLY if it feeds a verified chain (js_secret→cred-reuse: yes; standalone directory-listing: no). Do NOT chase recon-parity with scanners.

---

## Non-negotiables (unchanged)

External vantage. Auth gate front-loaded in Conductor. A2A = structured English JSON. Event-sourced. RUNNER-SEAL ≠ AUTONOMOUS-WIRED (grep the live path). Oracle ARM64 + .venv312 ONLY valid test env. Gap ledger: docs/BUGS_AND_GAPS.md. No hardcoded credential/password lists.

---

## Deep-moat roadmap — "deeper than any scanner" (north-star)

Scanners (Nuclei/Strix) do commodity recon; Strix's bernofarm findings verified as FALSE POSITIVE. Our differentiation is DEPTH, not breadth. Do NOT chase analyzer parity. Build an analyzer only if it feeds a VERIFIED CHAIN.

### The 4 depth vectors (what a scanner CANNOT do)

1. **Reach PAST the CF edge to test what CF hid.** Scanners' SQLi/XSS die at the CF edge (403). Origin-direct (PROVEN on alpha-ai) bypasses CF → test injections at the origin. Uses capability we already have. bernofarm has 94 CT subdomains — likely a grey-cloud origin to reach.
2. **PROVE exploitability, not presence.** "High-risk plugin" (guess) → "we got a shell" (proof). Version-gated plugin_cve → Gamma exploitation. The moat.
3. **CHAIN into an attack-path + compromise root-cause.** Scanner lists 10 separate items; AttackGraph connects them into ONE story: entry (WP File Manager RCE) → foothold (fm_backup) → result (SEO injection). "How they got in, what they did." Narrative is the moat.
4. **Business-logic reasoning on exposed handlers.** Not "nonce exposed" but "this AJAX handler (submit_keluhan_obat) can be abused for IDOR/injection behind a nonce-gate CF doesn't protect."

### Deep capabilities MISSING from the roadmap (gap analysis vs Natanael's 6 Lyndon frustrations)

- **Cross-engagement memory / IntelligenceBase (§8c, GAP-003) — Lyndon frustration #3.** The agent must LEARN across engagements: recurring password patterns, common stacks, reliable plays; the Nth engagement smarter than the 1st. Data/playbook only (never self-modifying code). Deferred; needs findings flowing first (now they are). This is a CORE differentiator vs scanners (which never learn).
- **Post-access authenticated re-recon (§12.32).** We proved admin on alpha-ai — the depth is "now that we are IN": diff unauth vs auth surface → IDOR / broken-access-control / priv-esc. Directly extends the milestone. DETECT is recon; exploiting is Gamma-gated.
- **Compromise root-cause / attacker-artifact hunt.** Deepen vector 3: beyond "SEO spam present" → find the webshell / backdoor / persistence and the entry point. Detect an EXISTING compromise AND its cause. (Still DETECT + PROVE + REPORT; "wrest control" = IR, out of scope.)
- **Omega report narrative — Lyndon frustration #4.** Current report = node dump. A payable report is a STORY (internet → crown-jewel, prose, executive + technical + remediation). Report quality is a differentiator clients pay for. to_narrative(style) exists but is under-built.
- **Reflection / "Try Harder" loop (§8j-2).** Agent reflects on findings + tries alternative approaches instead of stopping at the first pass (NodeZero-style persistence).

### Phasing (do NOT parallelize; findings drive order)

- **Now / next:** Entry-selection slice (Beta strikes reachable auth surface) → SituationAssessor instinct #1. OAHC live-seal + Beta reach parity first.
- **Soon:** IntelligenceBase (frustration #3) once findings accumulate across ≥3 engagements; Omega narrative (frustration #4) since we now have real chains to narrate.
- **Later (Gamma-gated):** prove-RCE exploitation, business-logic outcome-oracle, ToolComposer + blast-radius gate. STOP-gated until Phase 4 (Recon + Reach) is fully stabilized and fielded. (Remember §12.55: we are a 1-day weaponizer, not a 0-day hunter).

Litmus for every depth build: does it PROVE / CHAIN / LEARN, or is it another surface detector? Surface detector → skip (Strix-parity FP). Prove/chain/learn → moat.
