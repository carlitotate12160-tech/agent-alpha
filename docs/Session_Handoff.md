> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-19, GAP-118 attestor-resolve SEALED on PR #454 + STEP-2 field-confirmed wpvuln INCONCLUSIVE)

Resume with: "lanjut Agent-Alpha — §12.43 proof-standard LOCKED + GAP-116-B/C authenticated-crawl + WP multi-cookie session jar MERGED (commit 4150814) + GAP-118 attestor Rule 3 hardening SEALED (PR #454 merged as 6fe008d2, Oracle ARM64 green, 606/606 tests). STEP-2 field-prove CONFIRMED: alpha-ai `wpvuln` access now INCONCLUSIVE (F=False) — its bare-UUID secret_ref does NOT resolve in the vault, exactly the false-provenance GAP-118 closes. NEXT IN ORDER: (1) P1 = the FULL §12.43 independent oracle (auth-vs-unauth diff composing the 116-B crawl) — GAP-118 made provenance HONEST, NOT the oracle; (2) Temuan 2 = Odoo cross-service reuse incomplete (E=False, db_enumerated=False) — diagnose with a log, do NOT guess. Do NOT build Gamma. ALWAYS git pull + re-verify first; Oracle ARM64 = the seal (Lyndon #9)."

---

## ▶ START HERE (new session — do this IN ORDER, do not skip the gate)

1. **`git pull` + confirm HEAD.** Is GAP-118 (PR #454, merged as `6fe008d2`) on main AND green on
   Oracle ARM64? It is — sealed 2026-08-19. STEP-2 field-prove already re-run: `wpvuln` = INCONCLUSIVE
   (F=False), the false-provenance is closed. Do NOT re-run STEP-2 unless something regressed.
2. **If sealed & Oracle-green → THE SLICE IS: P1 (§12.43 independent oracle).** GAP-118 only made
   provenance HONEST (secret_ref must resolve to engagement-owned vaulted material). It did NOT add
   the independent auth-vs-unauth diff oracle §12.43 mandates. P1 composes the 116-B authenticated
   crawl (already merged) into an auth-vs-unauth marker diff — that is the payable floor. This is the
   highest-value item: makes a chain claim *defensible* (an independent signal), not just provenance-checked.
3. **Temuan 2 (separate, diagnose-first):** Odoo cross-service reuse still incomplete — STEP-2 shows
   E=False (ENABLES edge does not source from the vaulted cred) and db_enumerated=False. Diagnose with
   a log, do NOT guess (anti-mis-fix). The `wpvuln` cred's secret_ref is a bare UUID that does NOT
   resolve — that is correct post-GAP-118 behavior, but it means the harvested cred is not being vaulted
   with a `secret_` ref on this path. Inspect the harvest→vault→reuse wiring.

*(Do NOT build Gamma. Oracle = the seal. RUNNER-SEAL ≠ AUTONOMOUS-WIRED — verify the live path, not the runner.)*

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — MET on self-owned real-world target; autonomous path now exercises binding for real:** find something a scanner missed + prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass → proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) — what Nuclei/Strix cannot assemble.

---

## ✅ SEALED — GAP-118 attestor-resolve (PR #454, merged 2026-08-19 as `6fe008d2`)

**GAP-118 — CredReuseAttestor Rule 3 hardening.** Fixes a field-confirmed FALSE-PROVENANCE: on alpha-ai the
access reached via cred `wpvuln` cross-verified even though `wpvuln.secret_ref` was a bare UUID that does NOT
resolve in the vault (NOT harvested material). Rule 3 now requires `secret_ref` to RESOLVE to **non-empty,
engagement-owned** vaulted material — provenance ≠ oracle, but at least provenance is now HONEST.

**Commits (all on main via squash merge `6fe008d2`):**

| Commit | What |
|--------|------|
| `8b184d0` | Rule 3 resolve via `retrieve_for_engagement`; threaded through `verify_access_nodes` + odoo/a1 runners; 6 GAP-118 tests; infra errors propagate (not swallowed). |
| `c422271` | `verify_access_nodes(*, secrets_manager)` now KEYWORD-ONLY REQUIRED (production can't silently fall back to legacy non-empty check — Lyndon #3); DEBUG audit log on non-resolving ref (sanitized, CWE-117). |
| `f0bb236` | Decompose `verify()` — extract `_find_backing_credential` + `_has_bound_auth_proof` as `@staticmethod`, collapse nested ifs. **CC 23 → 7 (radon).** |
| `5d0bd57` | Decompose `run_a1_validation` (a1_validation_runner.py) — extract `_resolve_origin_direct_reach`/`_mint_credentials`/`_beta_login_with_reused_cred`/`_run_attestor_pass`. **CC 34 → 17 (radon).** Fixes DeepSource PY-R1000. |
| `1e83914` | Extract `_score_and_build_result` + fix PYL-W0212 (`_raw_value` via getattr). **CC 17 → 11 (radon).** Clears DeepSource re-check. |

**Oracle ARM64 seal:** `make check` clean (ruff + mypy, 148 files); `make all` 606 passed / 1 skipped / 0 fail
(2 live DeepSeek tests deselected — 401, unrelated). `test_a1_validation` 19/19, `test_attestor + test_wiring_gate` 67/67.
DeepSource PASS, quality-gate PASS, all CI green. PR #454 squash-merged + branch deleted.

**STEP-2 field-prove (2026-08-19, post-merge):** `run_alphaai_chain_step2.py` on Oracle, target
`https://odoo.alpha-ai.web.id/` (domain `alpha-ai.web.id`), NO credential injection. Result:
- A. Odoo fingerprinted: **True** | B. Cred HARVESTED+VAULTED: **True** | C. Beta selected/executed: **True/True**
- D. Access WON: **True** | E. ENABLES edge FROM harvested cred: **False** | F. CROSS_VERIFIED: **False** | G. db_enumerated: **False**
- `wpvuln` cred: `secret_ref='a784c712-5fe9-4153-99ec-41fde54e0d83'` (bare UUID, NOT `secret_`-prefixed, does NOT resolve in vault).
- **F=False where it was wrongly F=True before GAP-118 — the false-provenance is closed.** This is the field-confirmation.

**Still open after seal:** P1 §12.43 independent oracle (auth-vs-unauth diff composing 116-B crawl) → Temuan 2 (Odoo cross-service reuse E=False, db_enumerated=False, diagnose with a log not a guess).

---

## SEALED / PROVEN (recent merged arcs)

| Work | Seal level | Evidence |
|------|-----------|----------|
| **GAP-118: CredReuseAttestor Rule 3 hardening (attestor-resolve)** | **MERGED #454 → 6fe008d2, Tier-1 + Tier-3 PROVEN** | `secret_ref` must RESOLVE to non-empty engagement-owned vaulted material via `retrieve_for_engagement`. `verify_access_nodes(*, secrets_manager)` keyword-only required (Lyndon #3). verify() CC 23→7, run_a1_validation CC 34→11. STEP-2 field-prove: `wpvuln` now INCONCLUSIVE (F=False) — false-provenance closed. 606/606 Oracle, DeepSource + quality-gate PASS. |
| **§12.43 Proof Standard (LOCKED doctrine)** | **BANKED 2026-08-18** | Payable floor = independent oracle (auth-vs-unauth diff §12.32) + human-legible artifact. ChainOracle = min over per-edge oracles. Provenance ≠ oracle. GAP-118 hardens provenance; the oracle itself is P1 (unbuilt). |
| **GAP-116-B/C: Beta authenticated crawl + WP multi-cookie session jar (§12.32)** | **MERGED (commit 4150814)** | Playbook-driven GET-only DETECT, stack-gated exact-match (STACK_WP="wp"), auth-vs-unauth marker diff, depth-1 admin-filtered (refuses `?action=`/admin-ajax/destructive tokens), mints SERVICE node `service:{host}:authsurface:{surface}`. Full WP cookie jar (`HttpResponse.cookies` + `applicator._session_jar`); session cookie VALUES never persisted (names only, repr=False, deep-redact). |
| **GAP-169: Fingerprint-First Recon Reorder (§12.65)** | **MERGED #444, Tier-1 Validated** | Root fetch hoisted to $t=0$, stack labels extracted via `fingerprint_all`, frontier seeded with stack-tailored leak paths (eliminates blind spray), `_prefetched` cache primed to prevent double GET, dead-host pruned fail-safe (D-2). 9/9 unit tests + 45/45 wiring gate passed. |
| **GAP-026: StealthPacer Default ON Across Conductor** | **MERGED #423, Tier-1 Validated** | Pacer default ON across conductor per ADR §12.49 with strict §12.36 consent gate preserved. 100% green CI. |
| **GAP-062: MX/SPF Origin Candidates & GAP-154 Gate-Fix** | **MERGED #421, Tier-1 Validated** | In-domain MX subdomains + SPF pass-ip4 origin candidates. Unconditional enrichment on total CT failure (DNS/OTX/VT/MX-SPF/Wayback always fire; `PASSIVE_INTEL_GATHERED` always emitted; anti-#3). Fan-out cap (8), `net.version!=4` IPv6 drop (interim per GAP-155). 247+ test assertions PASS. |
| **GAP-115: Keyless Wayback CDX Historical Recon (Slice 1)** | **MERGED #420, Tier-1 Validated** | Keyless `WaybackClient` queries `web.archive.org/cdx/search/cdx` API (HTTPS) to extract in-domain historical subdomains (for `CompositeOriginDiscovery` origin resolution) + historical URL paths. Additive `enrich_with_wayback` with per-row parsing error resilience. 52/52 PASS, 100% green CI. |
| **GAP-051: Engagement-Level Wall Verdict (Slice 1)** | **MERGED #419, Tier-1 Validated** | Conductor sweep records `WallVerdict` with `reason: Literal["waf_walled", "clear", "dead"]` scoped to stream head (`run_start_seq`) after target sweep. Emits `ENGAGEMENT_WALLED` audit event when all targets encounter WAF blocks. 10/10 PASS, 100% green CI. |
| **Bug #34: Engagement-Scoped State Reset** | **MERGED #418, Tier-1 Validated** | Fixed deduplication and health state (probed URLs, dead/reachable hosts) to persist across sibling targets within the same engagement while keeping content-keyed and egress state target-scoped. State resets on a new engagement ID. 7/7 PASS. |
| **Bug #35: LLM Orientation Budget & Retry Resilience** | **MERGED #417, Tier-1 Validated** | Right-sized orientation token budget (2048 primary, 4096 retry) for reasoning models (DeepSeek-v4-pro). Added one-shot retry resilience on `CompletionTruncatedError` (including non-empty truncated text) with accurate cost aggregation (`prior_cost`) and double-truncation fallback. 6/6 PASS, 100% green CI. |
| **GAP-074 Odoo JSON-RPC Fallback (Slice 2c)** | **MERGED #416, Tier-1 PROVEN** | OdooAccessTool now implements transport fallback (GAP-067). WAF/CDN blocked XML-RPC endpoints automatically fall back to web JSON-RPC login. Resolves CI, SAST (Aikido/GitGuardian), and formatting issues. 29/29 PASS. |
| **Auth Path Test Environment Isolation** | **MERGED #415, Tier-1 PROVEN** | Isolated `AGENT_ALPHA_SKIP_DOMAIN_VERIFICATION` in `test_conductor_auth_path.py` fixture: prevents `.env` environment variables from leaking into domain verification tests. 10/10 PASS, 100% green CI. |
| **Beta Offensive Profile Fail-Closed** | **MERGED #414, Tier-1 PROVEN** | Enforced ADR §12.36 fail-closed for Beta offensive run in `run_agent_task`: missing/invalid signed profile aborts and records `ENGAGEMENT_RUN_FAILED` (`missing_signed_profile`). Isolated to Beta role. 376/376 PASS. |
| **Beta State-Leak Fix** | **MERGED #413, Tier-1 PROVEN** | Fixed `Beta._strike_attempted` state persistence: resets to `False` on `run_strike()` entry. Reused `Beta` instance across multi-target execution no longer skips subsequent targets. 7/7 PASS. |
| **Signed Profile Fail-Closed** | **MERGED #412, Tier-1 PROVEN** | Enforced ADR §12.36 fail-closed: missing/invalid signed `EngagementProfile` records explicit failure (`missing_signed_profile`/`profile_signature_invalid`) and aborts immediately (never null-and-continue / fail-open). 375/375 PASS. |
| **CI Security & Secret Hardening** | **MERGED #411, Tier-1 PROVEN** | Remediated Aikido SAST / CI findings: pinned `gitleaks-action` to immutable commit SHA `e0c47f4f...` (v3), added `persist-credentials: false` to all `actions/checkout@v4` workflows (CWE-522), removed ad-hoc runner scripts `run_lab*.sh`. 100% CI green, Aikido Deep Review PASS. |
| **Slice X: Default-Cred Single-Source Catalog** | **MERGED #410, Tier-1 PROVEN** | Default-cred #7 divergence ditutup: externalized catalog to `default_credentials.yaml` via `default_credentials.py` loader. `default_creds` and `odoo_access` now single-source from YAML (odoo tak lagi punya daftar sendiri). 4/4 PASS. |
| **GAP-074 Coverage Ledger Mechanism Precision (Slice 2b)** | **MERGED #409, Tier-1 PROVEN** | Denominator precision in `coverage_ledger.py`: maps `mech_*` to bare tokens via `bare_mechanisms()`. Excludes mismatched techniques from applicable denominator (e.g. form-only surface excludes `spa_json_login`). Fail-open when unknown. Known limitations documented in `BUGS_AND_GAPS.md`. 10/10 PASS. |
| **GAP-074 Auth Mechanism Selection (Slice 2a)** | **MERGED #408, Tier-1 PROVEN** | Mechanism-aware applicator selection: reads canonical ASSET `tech_stack` `mech_*` labels. Single-source `MECH_TO_APPLICATOR_SERVICES` in `recon.auth_surface`. `applicator_factory._resolve_in_scope_targets` binds only matching services (e.g. JSON-RPC → SPA only, Form-POST → HTTP only). Fail-open when unclassified, fail-closed for any unmapped/unstrikable `mech_*`. 20/20 PASS. |
| **GAP-074 Auth Mechanism Fingerprinting (Slice 1)** | **MERGED #406, Tier-1 PROVEN** | Universal recon fingerprinting in `scout._detect_auth_surface`: detects `mech_http_basic`, `mech_json_rpc`, `mech_jwt`, `mech_saml`, `mech_oauth`, `mech_form_post` without hardcoded catalogs. Persisted to ASSET `tech_stack`. |
| **ADR §12.62 Coverage-Honesty & Report Section (Slice 2)** | **MERGED #407, Tier-1 PROVEN** | OMEGA client report emits formal Coverage & Methodology section: lists tested, not_run, blocked, and capability_absent techniques + not_assessed engagement targets. Anti-false-assurance (§12.45 / §12.62). |
| **ADR §12.62 Engagement Coverage Ledger (Slice 1)** | **MERGED #404, Tier-1 PROVEN** | `agent_alpha/coverage/coverage_ledger.py` + `techniques.yaml` single-source technique catalog. Runtime ledger tracking execution events and surfaces across the engagement lifecycle. |
| **OMEGA-GOV Catalog Integrity & Exit Criteria** | **MERGED #405, Tier-1 PROVEN** | `test_coverage_catalog_integrity.py` validates techniques.yaml against EventType and gap references. Phase Omega exit criteria banked in `AGENTS.md` (OMEGA-1..5, OMEGA-GOV). |
| **GAP-030 / SpaLoginApplicator & Autonomous Path** | **MERGED #403, Tier-1 PROVEN** | JSON-API login reuse tool (`SpaLoginApplicator`): POSTs JSON credentials, extracts JWT from response, verifies via Bearer replay. Fully wired into `applicator_factory` and Conductor autonomous path (no Lyndon #2). |
| **GAP-044 / GAP-048 soft-404 differential calibration** | **MERGED #388, Tier-1 + Tier-2 PROVEN** | Two-probe DIFFERENTIAL: probe 2 independent random missing paths → diff volatile positions (CSRF/session/timestamp) → format-agnostic signature. 7/7 Tier-1 PASS, 11/11 catchall.lab suppressed (0 false findings). |
| **GAP-034 reachability read-model** | **MERGED #390** | `events/reachability.py::unreachable_hosts(events)` — pure read-model over event store. `HOST_ABANDONED` marks host strike-dead; `WAF_BLOCKED` does NOT (origin-exposure-bypass target). `select_strike_entry` demotes dead hosts below live ones. |
| **GAP-035 multi-candidate entry-selection** | **MERGED #389** | Beta strikes ALL in-scope surfaces (up to MAX_STRIKE_CANDIDATES=3), NOT stop-on-first-COMPLETE. Shared CredentialLockoutGovernor per engagement. STRIKE_CANDIDATE_ATTEMPTED/SKIPPED events wired. |
| **catchall.lab & real-world lab stacks** | **MERGED #387, #401, #400** | catchall.lab on Oracle (:443 returns 200 + 93k body), alpha-ai.web.id real-world lab stacks, and vercel-lab multi-IP origin target. |

### Earlier sealed (still valid — context)

- **PR #346 stealth-by-default** (merged 2026-08-07): curl_cffi chrome124 as DEFAULT transport from request #1.
- **Reach**: origin-direct (bypass CF edge) sealed + robust — RC1/RC2/RC3, seed_hosts, tls_impersonate.
- **GAP-029 dead-host skip** (merged): ibudanbalita 118→7 hosts probed.
- **GAP-037 stop-on-block** (#385 merged): mid-run egress death detection.
- **GAP-038/039/040/041** (merged #381-384): cooperative origin discovery, apex scope, ownership gate, stale candidate guard.

---

## OPEN / NOT DONE (registered, prioritised)

**Highest-value next slice — P1: §12.43 independent oracle:**
- **P1 §12.43 independent auth-vs-unauth oracle** ★ — composes the 116-B authenticated crawl (already merged,
  commit 4150814) into an auth-vs-unauth marker diff. GAP-118 made provenance HONEST (secret must resolve);
  it did NOT add the independent oracle. P1 is what makes a chain claim *defensible* (an independent
  auth-vs-unauth signal), not just provenance-checked. This is the payable floor per §12.43.

**Temuan 2 (separate, diagnose-first — do NOT guess):**
- **Odoo cross-service reuse incomplete** — STEP-2 (2026-08-19) shows E=False (ENABLES edge does not source
  from the vaulted cred) and db_enumerated=False. The `wpvuln` cred's secret_ref is a bare UUID
  (`a784c712-...`) that does NOT resolve — correct post-GAP-118, but it means the harvested cred is not
  being vaulted with a `secret_` ref on this path. Inspect the harvest→vault→reuse wiring with a log.

**High-leverage growth (next real slice after P1 — ONE at a time):**
- **GAP-115 historical-DNS origin discovery** ★ (§12.61 A1 DIRECT) — DIRECT pre-CF A-records (the origin IP a domain pointed to BEFORE going behind CF, often still live/unprotected). This is the ADR's "biggest missing signal": 4 field targets (niagamas/bernofarm/ibudanbalita/busonlineticket) are full-CF where crt.sh/VT/OTX ALL failed. GAP-154 now lets this enrichment run even when crt.sh is down (the exact field case). DESIGN GATE (locked, build in a NEW session): keyless-FIRST source seam (ViewDNS/DNSHistory keyless; SecurityTrails key-gated OPTIONAL like OTX/VT, None=off, keyless-safe) → `enrich_with_historical_dns(intel, source)` additive → emits ip4 `origin_ip_candidates` (DROP ip6 per GAP-155) → composes with §12.46 two-proof binding (historical IP = CANDIDATE, stale IP fails binding = fail-closed, the niagamas lesson). Moat = the COMPOSITION (historical A → proven pre-CF origin), NOT the commodity lookup. **DECISION NEEDED FROM NATANAEL:** source/key policy — keyless-only (ViewDNS, rate-limited, autonomous) vs +SecurityTrails paid key (his to provide for Tier-2 field-prove). Then cert/favicon pivot (GAP-093/086), then axis-B. MENU — one slice.
- **GAP-045 CF-ceiling honest-outcome report** — (LOW effort, HIGH product value, isolated Omega/Conductor — turns "beta_failed" on full-CF into a sellable defensive-validation deliverable integrated with CoverageLedger).

**Deferred GAPs (registered, own verticals — do NOT fold into recon slices):**
- **GAP-155** IPv6 origin candidates can't bind — `origin_direct_fetch` lacks `[...]` URL bracketing; ip6 dropped interim.
- **GAP-156** Candidate public IPs token-probed before `is_in_scope(ip)` when Scope.ip_ranges non-empty — binding-layer, all IP sources; domain SOWs unaffected by design.
- **GAP-157** Autonomous ACCESS_LEVEL missing ENABLES edge to CREDENTIAL node in graph projection (#422).
- **GAP-158** Multi-target credential reuse pivot across sibling stacks (#422).
- **GAP-159** Cloud IAM Privilege Escalation & Policy Trust Graph (AWS/GCP/Azure policy traversal).
- **GAP-043** CDN edge IP filter only covers Cloudflare (Sucuri/Incapsula/Akamai).
- **GAP-042** Origin probe bypasses stealth HttpClient (opsec debt).
- **GAP-046/047** Basic-auth applicator, username-harvest breadth — deferred (cred-acquisition).
- **GAP-036** LLM tool-pick on auth pages — root = DUPLICATE password detection.

**Needs a log to diagnose (do NOT guess — anti-mis-fix):**
- **Spectranet frontier cycling** (Bug #34) — run did not converge, repeated same paths across 3+ cycles.

---

## DOCTRINE BANKED (durable)

- **ADR §12.62 Coverage-Honesty Doctrine** — the client report MUST carry a Coverage & Methodology ledger (tested / not_run / blocked / capability_absent). Negative results carry methodology caveats (what WAS / was NOT tested); NEVER emit an affirmative "fully secure" / "no vulnerabilities" from an absence.
- **ADR §12.60 Two-Tier Proof + Field-Feedback Ratchet** — lab-green ≠ field-ready. Tier-1 lab-seal < Tier-2 field-prove (THE bar). Every field failure → permanent fixture in `test_field_regression`.
- **ADR §12.61 Flank-when-CF-hard** — CF "ceiling" is ONLY bruteing the edge. Operator FLANKS: find origin via side channels (historical DNS ★, mail/MX, cert/favicon pivot, grey-cloud) or skip perimeter (leaked-cred stuffing, exposed secrets, S3, subdomain takeover). Full-CF-no-origin → sellable defensive-validation report.
- **GAP-074 Single-Source Mechanism Resolution** — mechanism-to-applicator mapping is centralized in `recon.auth_surface`. ASSET `tech_stack` is the canonical projection. Unknown/unmapped mechanisms fail-closed.
- **Soft-404: two-probe differential > regex whack-a-mole** — let the target reveal its volatile tokens by diffing two catch-all samples; don't enumerate token formats. Verified empirically + Tier-2 catchall.lab proven.
- **GAP-034: read-model over events, not node-schema mutation** (event-sourced; AttackGraph = projection).
- **GAP-026: stealth is consent-gated (§12.36 enforced)** — TEMPO is operator baseline but stays consent-gated. StealthPacer default ON per ADR §12.49.
- **GAP-031: crash FIXED (graceful decline + Omega); residual = CF ceiling, NOT a code slice.**
- **GAP-118: provenance ≠ oracle** — Rule 3 (secret_ref must RESOLVE to engagement-owned vaulted material) makes provenance HONEST, but the §12.43 payable floor still needs the independent auth-vs-unauth oracle (P1, unbuilt). Field-confirmed 2026-08-19: `wpvuln` bare-UUID ref correctly fails cross-verification.
- **Code quality target**: military-grade engineering (fail-safe, deterministic, audited, no false-success) that ENCODES APT tradecraft.
- **Verify-before-ship, every time**: green ≠ proven; always `git pull` before writing a patch; RUNNER-SEAL ≠ AUTONOMOUS-WIRED; Oracle is the seal.
- **Four-Operator Lineage (durable design lens, banked 2026-08-17 w/ ADR §12.65/GAP-169)** — every agent behavior maps to a real APT tradecraft; the lens is "operator OBSERVES/COMPOSES, scanner sprays". PRINCIPLE table, NOT a task list (tasks live as GAPs — do not duplicate, anti-#7):
  - **APT29 (Cozy Bear) → low-and-slow, anti-detection.** Recon: fingerprint-first, probe only stack-relevant paths, no 404 breadth-anomaly that trips the WAF (GAP-169). Beta: bounded credential mutation under the lockout governor (never spray) + honest MFA/CAPTCHA classification.
  - **Volt Typhoon → living-off-the-land, blend with legitimate traffic.** Recon: requests mimic a real browser exploring what EXISTS (GAP-169). Beta: post-access re-recon reuses the won session, read-only, blends as the logged-in user (§12.32).
  - **APT41 → intelligence-driven, victim-tailored toolset.** Recon: seed from the ACTUAL fingerprinted stack, multi-stack aware (`fingerprint_all`, GAP-169). Beta: polyglot applicators tailored per stack (WP/Odoo/Laravel/Spring…), one stack at a time on real need (§12.47).
  - **Lazarus → EXPLOIT CHAINING (Beta's signature).** Stitch small, individually-harmless leaks into total compromise; the AttackGraph chains leak → reused credential → deeper access. Only `cross_verified` per-edge oracles back a payable chain (§12.31/§12.43 — never graph traversal alone). Field-proven: alpha-ai origin-bypass → `wp-config.php.bak` → DB pass → Odoo XML-RPC → uid=2 admin.
  - **The link:** recon precision (169) surfaces the CLEAN small footholds a scanner buries in 404 noise; the chain oracle (Beta) composes them into proof. Recon precision IN → provable chain OUT.

---

## RESUME LINE (paste into new session)
> lanjut Agent-Alpha — §12.43 proof-standard LOCKED + GAP-116-B/C authenticated-crawl & WP multi-cookie session jar MERGED (commit 4150814) + GAP-118 attestor Rule 3 hardening SEALED (PR #454 → 6fe008d2, Oracle ARM64 green, 606/606 tests, DeepSource + quality-gate PASS). STEP-2 field-prove CONFIRMED: alpha-ai `wpvuln` access now INCONCLUSIVE (F=False) — bare-UUID secret_ref does NOT resolve in vault, false-provenance closed. NEXT IN ORDER: (1) P1 = FULL §12.43 independent oracle (auth-vs-unauth diff composing 116-B crawl) — GAP-118 is provenance-resolve only, NOT the oracle; (2) Temuan 2 = Odoo cross-service reuse incomplete (E=False, db_enumerated=False), diagnose with a log not a guess. Do NOT build Gamma. ALWAYS git pull + re-verify on Oracle first (Lyndon #9); RUNNER-SEAL ≠ AUTONOMOUS-WIRED.
