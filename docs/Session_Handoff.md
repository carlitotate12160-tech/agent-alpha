> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-23, P1 §12.43 per-edge oracle SEALED; CURRENT SLICE = Front-door-timeout origin-binding gate fix — reach-diagnostic COMPLETE)

Resume with: "lanjut Agent-Alpha — **P1 §12.43 PER-EDGE oracle is SEALED** (PR #465, Oracle-green). Temuan 2 = PHANTOM (GAP-118 correct downgrade). CURRENT SLICE = **Bounded reach-diagnostic (Class-C accepted 2026-08-23)**: historical-DNS enrichment (`enrich_with_historical_dns` in `passive_intel.py:517`) is ALREADY wired in `conductor/recon_runner.py:646` via `mnemonic_client` and gated through `verify_origin_binding` (§12.46). ChainOracle = **PARKED** (per-edge oracle sealed, ChainOracle non-binding until field-reach exists). §12.66 PROPOSED, deferred behind reach. Earliest-failed-transition = REACH/BLOCK (E0–E2) on real full-CF targets. NEXT = instrument the wired historical-DNS reach path, run `live_fire/recon_integrated_field_prove.py` vs `niagamas.com` + `bernofarm.com` on Oracle, classify A/B/C, then ONE slice (ViewDNS source [B] OR GAP-045 CF-ceiling honest-outcome [C]). JANGAN rebuild GAP-115, JANGAN build ChainOracle/Gamma. Oracle ARM64 = seal; RUNNER-SEAL ≠ AUTONOMOUS-WIRED."

---

## ▶ START HERE (new session — do this IN ORDER, do not skip the gate)

1. **`git pull` + confirm HEAD.** Are PR #470 / #472 / #475 / #477 / #478 on `main` AND green on
   Oracle ARM64? They are — sealed 2026-08-22 (HEAD `7cf1013`). Do NOT re-run the CodeIgniter live-fire unless something regressed.
   - **PR #477 (ledger cleanup) SEALED:** removed the stale `WIRING_DEBT["codeigniter_config_probe"]` false-green (a proven-wired, catalog-dispatched tool mislabelled as un-wired). Guard is now `test_every_catalog_tool_is_dispatchable` + driver proof.
   - **PR #478 (ingco size-gate) SEALED:** `_is_reload_interstitial` in `recon/response_classifier.py` now mirrors `is_reload_shell`'s `RELOAD_SHELL_MAX_BYTES` size gate (single source, anti-#7). Root cause: verdict-producer had no size guard → a 361 KB catch-all-200 SPA shell false-classified as CHALLENGE. Cardinal RED `test_large_catchall_spa_with_reload_signal_stays_ok` proves the fix; true-positive small-body interstitial stays CHALLENGE. Soft-404 suppression kept AFTER challenge (rejected the reorder = §12.62 coverage-honesty regression).
2. **CodeIgniter Conductor autonomous wiring — SEALED (recon-stage). N/A decision recorded 2026-08-22.**
   PR #475 hermetic Conductor driver tests (`test_conductor_driver_vulnerable` / `test_conductor_driver_hardened`)
   prove the `build_recon_pipeline` → `_sweep_targets` → `run_recon` path autonomously drives
   `recon → fingerprint 'codeigniter' → derive /application/config/database.php → codeigniter_config_probe → vault`.
   **N/A decision:** `codeigniter_config_probe` is a RECON-stage (E1→E3) leak vector; `conductor/execute_agent.py` 
   is the OFFENSIVE (Beta/Gamma/Omega) path — a recon leak probe never belongs there, so there is NO
   execute_agent W-test to wait on. The correct regression guard is `test_every_catalog_tool_is_dispatchable` 
   (catalog tool → `Alpha._dispatch_registry`) + the driver proof — NOT a symbol-in-module gate. The stale
   `WIRING_DEBT["codeigniter_config_probe"]` entry (a permanent false-green that mislabelled a proven-wired,
   catalog-dispatched tool as un-wired) was REMOVED; a comment in `test_wiring_gate.py` records why catalog
   tools are not tracked there. `live_fire/codeigniter_field_prove.py` remains a lab RUNNER-SEAL, not the proof.
3. **P1 §12.43 PER-EDGE oracle = SEALED (do NOT rebuild — that is Lyndon #2).**
   Verified live path (HEAD `8b1f5b1`): `conductor/main.py:805 beta.run_strike()` → `run_cognitive_loop`
   → `step()` → `_post_access_authenticated_crawl` → `run_authenticated_crawl` → `_auth_only_diff`
   (real unauth-vs-auth marker diff, §12.32) → `_mint_surface` (`auth_vs_unauth_diff` ProofArtifact bound
   to cred+access) → `conductor/main.py:810 verify_access_nodes()` → attestor `_has_independent_auth_diff`
   → CROSS_VERIFIED. Seam binding matches end-to-end (`access:{host}` + `level` + `subject_ref=cred_id`).
   Proven end-to-end by **slice-1d `test_wp_cred_reuse_chain_is_cross_verified_autonomously` — PASSED on Oracle**
   (characterize J5 SKIPPED by design: needs PROFILE_SIGNING_KEY + real LLM). Owner GAP-118 — mark the
   oracle portion DONE; only the CHAIN-level composition remains (below).

4. **CURRENT SLICE = Front-door-timeout origin-binding gate fix (reach-diagnostic COMPLETE 2026-08-23).**
   Diagnostic result: NOT B (Mnemonic 5 rec both targets), NOT C (§12.61 CF-ceiling NOT proven —
   niagamas candidate 139.59.255.22 live HTTP 200, binding never attempted).
     bernofarm.com = REACH PROVEN (103.113.118.202 cooperative_soft_binding, 37× OriginDirectAttempt
                     authorized, 404 leak-paths = honest zero-finding). No slice.
     niagamas.com  = CONTROL-FLOW DEFECT: front-door timeout → _dead_hosts pre-empts origin-binding.
                     Violates §12.42 external-first (front-door-down is the PRECONDITION for
                     origin-direct, not an abort). Earliest-failed-transition = E1→E2.
   NEXT = grep-confirm gate in live path (recon_runner.py/_dead_hosts) → minimal redirect: front-door
          block/timeout on fronted host routes to resolve_and_bind_origin (reuse verify_origin_binding
          §12.46, NO 2nd binding path). Cardinal RED = niagamas repro. ≤2 files.
   REJECTED post-diagnostic: ViewDNS (source works), GAP-045 CF-ceiling (candidate live), ChainOracle/Gamma.
   GAP: register ONE — "front-door-timeout aborts before origin-direct binding" (distinct reproducible
        defect; owner = reach/origin_binding path; sealed by Cardinal RED). Do NOT proliferate.
5. **AFTER reach slice: resume ChainOracle MIN-composition OR architect review of ADR §12.66 → ACCEPT decision**, tergantung mana yang unblocks. ChainOracle tetap PARKED sampai ORIGIN_BINDING_PROVEN nyata dari field.

*(Do NOT build Gamma. Oracle = the seal. RUNNER-SEAL ≠ AUTONOMOUS-WIRED — verify the live path, not the runner.)*

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — MECHANISM proven (self-owned); REPRESENTATIVE_FIELD_VERIFIED = NOT MET.** alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass → cred-reuse → Odoo admin uid=2 membuktikan mekanisme chain (leak→vault→reuse→cross_verified). Per §12.60 (lab-green ≠ field-ready) + strategic_gaps A1: pada target nyata full-CF (niagamas/bernofarm/ingco) chain BLOCKED di REACH (E0–E2) — real CF WAF, 0 creds, tak ada CROSS_VERIFIED access. REACH adalah gating blocker. Moat (prove, not detect) terbukti sebagai mekanisme; field-readiness menunggu reach.

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

**Reconciled 2026-08-22:** The "Still open" items below were STALE. P1 §12.43 per-edge oracle was BUILT+WIRED+SEALED via PR #465 (slice-1d Oracle-green). Temuan 2 (E=False/F=False) is this same run's CORRECT GAP-118 downgrade of the non-resolving `wpvuln` bare-UUID cred — a PHANTOM, not a bug. Only ChainOracle MIN-composition remains of §12.43.

---

## ✅ SEALED — PR #470: CodeIgniter config-leak field-prove (merged 2026-08-22 as part of `ce9d0844`)

**What:** End-to-end leak → credential → vault vector for CodeIgniter `application/config/database.php` exposure.

**Commits (all on `main` via merge of PR #470):**

| Commit | What |
|--------|------|
| `c0f109b1` | v1: CodeIgniter probe, playbook, parser, live test (collection-time network). |
| `e908838a` | v2: `_unescape_php_string` full PHP double-quoted escapes; `_strip_php_comments` decomposed to CC 7; real-HTTP field-prove moved from `tests/` to `live_fire/codeigniter_field_prove.py`; lab_guard hosts added; `--no-verify` for self-signed lab cert. |
| `9f6414fe` | Classify `codeigniter_field_prove` as `ATTACKER_HARNESS` in `test_lab_guard_coverage.py`. |

**Oracle ARM64 seal:**
- `make check` clean (ruff + ruff format + mypy).
- `pytest tests/phase_2/test_leak_extraction.py tests/phase_4/test_codeigniter_field_prove.py` — **12 passed**.
- `pytest tests/phase_4/` — **623 passed, 1 skipped**.
- Live-fire run (`agent_alpha/live_fire/codeigniter_field_prove.py` against seeded `codeigniter_lab`):
  - `vuln.codeigniter.lab` — `creds_added: 2`, `credential_vaulted: True`, `leak_detected: True` → **positive proven**.
  - `hardened.codeigniter.lab` — `creds_added: 0`, `credential_vaulted: False`, `leak_detected: False` → **negative proven**.
- DeepSource PASS, quality-gate PASS, all CI green.

**What is NOT claimed sealed:** Conductor-autonomous wiring. The live-fire runner is a RUNNER-SEAL (bypasses Conductor). The Conductor path driving this vector end-to-end is the next slice.

---

## ✅ SEALED — PR #472: ADR §12.66 Slice-1 precondition/effect predicate model (merged 2026-08-22 as `079e4791`)

**What:** Closed `requires`/`produces` predicate vocabulary for techniques in `techniques.yaml`; predicate resolution against an AttackGraph-like interface; governance checks ensuring catalog predicates are registered and that capable node-producing techniques declare effects.

**Oracle ARM64 seal:**
- `make check` clean.
- `pytest tests/governance/test_coverage_catalog_integrity.py tests/phase_4/test_predicates.py` — predicate suite passed.
- `pytest tests/phase_4/` — **623 passed, 1 skipped** on the final run.
- DeepSource PASS, quality-gate PASS, all CI green.

---

## SEALED / PROVEN (recent merged arcs)

| Work | Seal level | Evidence |
|------|-----------|----------|
| **GAP-118: CredReuseAttestor Rule 3 hardening (attestor-resolve)** | **MERGED #454 → 6fe008d2, Tier-1 + Tier-3 PROVEN** | `secret_ref` must RESOLVE to non-empty engagement-owned vaulted material via `retrieve_for_engagement`. `verify_access_nodes(*, secrets_manager)` keyword-only required (Lyndon #3). verify() CC 23→7, run_a1_validation CC 34→11. STEP-2 field-prove: `wpvuln` now INCONCLUSIVE (F=False) — false-provenance closed. 606/606 Oracle, DeepSource + quality-gate PASS. |
|| **CodeIgniter config-leak Conductor wiring** | **SEALED 2026-08-22, recon-stage, N/A** | Hermetic Conductor driver tests `test_conductor_driver_vulnerable` / `test_conductor_driver_hardened` in `tests/phase_4/test_codeigniter_field_prove.py` prove `build_recon_pipeline` → `_sweep_targets` → `run_recon` autonomously drives `fingerprint codeigniter → derive /application/config/database.php → codeigniter_config_probe → vault`. Catalog dispatchability guarded by `test_every_catalog_tool_is_dispatchable` (catalog tool → `Alpha._dispatch_registry`). `WIRING_DEBT["codeigniter_config_probe"]` removed as false-debt; catalog-dispatched recon tools do not belong in the OFFENSIVE `execute_agent` path. Live-fire runner on Oracle ARM64: `vuln` positive, `hardened` negative, credentials vaulted. |
| **§12.43 Proof Standard (LOCKED doctrine)** | **BANKED 2026-08-18** | Payable floor = independent oracle (auth-vs-unauth diff §12.32) + human-legible artifact. ChainOracle = min over per-edge oracles. Provenance ≠ oracle. |
| **P1 §12.43 PER-EDGE independent oracle** | **SEALED — PR #465 (2026-08-21), Oracle-green** | `auth_vs_unauth_diff` BUILT (`_auth_only_diff` real unauth-vs-auth) + AUTONOMOUS-WIRED (`conductor/main.py:805` producer via run_strike→cognitive_loop→step→crawl, `:810` consumer `verify_access_nodes`→attestor `_has_independent_auth_diff`). Seam binding matches end-to-end. Proven by slice-1d `test_wp_cred_reuse_chain_is_cross_verified_autonomously` PASSED on Oracle. Remaining §12.43 piece = CHAIN-level MIN-composition (current slice). |
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

**CodeIgniter Conductor recon wiring — SEALED 2026-08-22 (N/A decision).** Moved to `SEALED / PROVEN` table.

**P1 §12.43 per-edge oracle — SEALED (PR #465, slice-1d Oracle-green).** Moved to `SEALED / PROVEN` table. Do NOT rebuild (Lyndon #2).

**Temuan 2 — CLOSED as PHANTOM (2026-08-22).** STEP-2 (2026-08-19) E=False/F=False on alpha-ai is GAP-118's
CORRECT downgrade of the `wpvuln` bare-UUID cred that does NOT resolve in the vault (sealed commit `62d3657`,
"STEP-2 field-confirmed wpvuln INCONCLUSIVE"). No code fix exists because none is needed. db_enumerated=False
follows (no point enumerating on unproven access) — not a separate defect. The ONLY honest residual is a
FIELD-prove of the oracle on a real target with a RESOLVING cred (slice-1d used a WP fake) — optional field-validation, NOT a build gap.

**CURRENT SLICE — ChainOracle MIN-composition (§12.43 chain payability):**
- See START HERE point 4 for the full design. `chain_tier = MIN(edge_tier)`, payable IFF every hop cross_verified,
  `weakest_hop` names the reason. New `attestation/chain_oracle.py` + `narrative.py::summarize_chain_finding` wire-in + test.
  Aggregates per-edge verdicts only (never re-verifies, anti-#3). Gates the multi-hop cred-reuse moat (WP→Odoo) honestly.

**AFTER ChainOracle — ADR §12.66 ACCEPT-review (PROPOSED → decide):**
- §12.66 goal-backward scoring. Slice-2 (production `Planner.score`) is BLOCKED until §12.66 ACCEPTED (ADR.md line 16).
  Slice-3 chain-seeking CONSUMES the ChainOracle payable verdict → ChainOracle is logically prior (anti-#1). Review §12.66
  for ACCEPT first; do NOT write Slice-2 code on a PROPOSED ADR.

**High-leverage growth (next real slice after P1 — ONE at a time):**
- **GAP-115 historical-DNS origin discovery** ★ (§12.61 A1 DIRECT) — DIRECT pre-CF A-records. **CORRECTED 2026-08-23:** historical-DNS enrich + binding SUDAH WIRED di autonomous path — `enrich_with_historical_dns` (`passive_intel.py:517`) dipanggil `conductor/recon_runner.py:646` via `mnemonic_client`; kandidat digate `verify_origin_binding` (§12.46, fail-closed). BUKAN unbuilt. OPEN = kenapa reach masih gagal di .id full-CF: klasifikasi (A) source error/fail-open, (B) source 0-records (Mnemonic lemah utk .id → tambah ViewDNS), (C) kandidat gagal binding = stale/generic = §12.61 CF ceiling PROVEN → GAP-045. **Diagnose dengan log SEBELUM extend** (anti-#2 rebuild). Keyless-FIRST source seam (ViewDNS/DNSHistory keyless; SecurityTrails key-gated OPTIONAL like OTX/VT, None=off, keyless-safe) tetap DESIGN GATE, tetapi hanya diambil jika log membuktikan B. Then cert/favicon pivot (GAP-093/086), then axis-B. MENU — one slice.
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
- **GAP-118: provenance ≠ oracle** — Rule 3 (secret_ref must RESOLVE to engagement-owned vaulted material) makes provenance HONEST. The §12.43 per-edge auth-vs-unauth oracle is now BUILT+WIRED+SEALED (PR #465, slice-1d Oracle-green) — GAP-118 oracle portion DONE; only chain-level MIN-composition remains. Field-confirmed 2026-08-19: `wpvuln` bare-UUID ref correctly fails cross-verification (this is the "Temuan 2" phantom — correct behavior, not a bug).
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
> lanjut Agent-Alpha — **P1 §12.43 PER-EDGE oracle SEALED** (PR #465, Oracle-green). Temuan 2 = PHANTOM (GAP-118 correct downgrade). CURRENT SLICE = **Bounded reach-diagnostic (Class-C accepted 2026-08-23)**: historical-DNS enrichment (`enrich_with_historical_dns` in `passive_intel.py:517`) is ALREADY wired in `conductor/recon_runner.py:646` via `mnemonic_client` and gated through `verify_origin_binding` (§12.46). ChainOracle = **PARKED**. §12.66 PROPOSED, deferred behind reach. Earliest-failed-transition = REACH/BLOCK (E0–E2) on real full-CF targets. NEXT = instrument the wired historical-DNS reach path, run `live_fire/recon_integrated_field_prove.py` vs `niagamas.com` + `bernofarm.com` on Oracle, classify A/B/C, then ONE slice (ViewDNS source [B] OR GAP-045 CF-ceiling honest-outcome [C]). JANGAN rebuild GAP-115, JANGAN build ChainOracle/Gamma. ALWAYS git pull + re-verify on Oracle first (Lyndon #9); RUNNER-SEAL ≠ AUTONOMOUS-WIRED.

---

## SESSION STATUS (2026-08-23)

- **This session: Class-C accepted reach-diagnostic — 0 seals, evidence + decision.**
  P1 §12.43 per-edge oracle remains SEALED (PR #465). ChainOracle PARKED. §12.66 PROPOSED, deferred.
  Corrected handoff overclaim (Success bar = MECHANISM proven, REPRESENTATIVE_FIELD_VERIFIED NOT MET) and
  GAP-115 framing (historical-DNS already wired; open = why reach still fails on .id full-CF).
  Current slice: **Bounded reach-diagnostic** — instrument wired historical-DNS path, run `recon_integrated_field_prove`
  on Oracle vs `niagamas.com` + `bernofarm.com`, classify A/B/C, then ONE slice (ViewDNS [B] vs GAP-045 [C]).
  JANGAN seal sebelum log Oracle memisahkan A/B/C.
- **Sealed slices this session:** 0.
