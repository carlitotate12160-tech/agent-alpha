> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-15, GAP-051 & GAP-115 Slice 1 Tier-1 Validated)

Resume with: "lanjut Agent-Alpha — GAP-115 Slice 1 (Wayback CDX Historical Recon, #420, Tier-1 Validated) + GAP-051 Slice 1 (Engagement-Level Wall Verdict / #419) + Bug #34 Engagement-Scoped State Reset (Tier-1 Validated) + Bug #35 LLM Orientation Budget & Retry Resilience (#417, Tier-1 Validated) + GAP-074 Slice 2c (Odoo JSON-RPC Fallback / #416) + Auth Path Test Environment Isolation (#415) + Beta Offensive Profile Fail-Closed (#414) + Beta State-Leak Fix (#413) + Signed Profile Fail-Closed (#412) + CI & Secret Hardening (#411) + Coverage-Honesty (§12.62, #404/#407) + GAP-074 Slices 1, 2a, 2b (#406/#408/#409) MERGED & PROVEN. Next slice = §12.61 MX/SPF origin discovery (GAP-062) OR GAP-051 Slice 2 Active Origin Hunt. Do NOT build Gamma."

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — MET on self-owned real-world target; autonomous path now exercises binding for real:** find something a scanner missed + prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass → proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) — what Nuclei/Strix cannot assemble.

---

## SEALED / PROVEN (recent merged arcs)

| Work | Seal level | Evidence |
|------|-----------|----------|
| **GAP-115: Keyless Wayback CDX Historical Recon (Slice 1)** | **PR #420, Tier-1 Validated** | Keyless `WaybackClient` queries `web.archive.org/cdx/search/cdx` API (HTTPS) to extract in-domain historical subdomains (for `CompositeOriginDiscovery` origin resolution) + historical URL paths. Additive `enrich_with_wayback` with per-row parsing error resilience. 52/52 PASS, 100% green CI. |
| **GAP-051: Engagement-Level Wall Verdict (Slice 1)** | **MERGED #419, Tier-1 Validated** | Conductor sweep records `WallVerdict` with `reason: Literal["waf_walled", "clear", "dead"]` scoped to stream head (`run_start_seq`) after target sweep. Emits `ENGAGEMENT_WALLED` audit event when all targets encounter WAF blocks. 10/10 PASS, 100% green CI across all checks. |
| **Bug #34: Engagement-Scoped State Reset** | **Tier-1 Validated** | Fixed deduplication and health state (probed URLs, dead/reachable hosts) to persist across sibling targets within the same engagement while keeping content-keyed and egress state target-scoped. State resets on a new engagement ID. 7/7 PASS. |
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

**High-leverage growth (next real slice — pick one, ONE at a time):**
- **§12.61 historical-DNS origin discovery** ★ — opens full-CF targets (niagamas/bernofarm/ibudanbalita all ceiling only because origin isn't found; crt.sh/VT/OTX failed). Passive, datacenter-friendly, extends the moat. Wayback CDX API = priority candidate (free, no key, operator-autonomous). Then cert/favicon pivot, then leaked-cred stuffing (axis-B). MENU — one slice.
- **GAP-045 CF-ceiling honest-outcome report** — (LOW effort, HIGH product value, isolated Omega/Conductor — turns "beta_failed" on full-CF into a sellable defensive-validation deliverable integrated with CoverageLedger).

**Non-blockers (schedule after):**
- GAP-043 CDN edge IP filter only covers Cloudflare (Sucuri/Incapsula/Akamai).
- GAP-042 origin probe bypasses stealth HttpClient (opsec debt).
- GAP-046 basic-auth applicator, GAP-047 username-harvest breadth — deferred (cred-acquisition).
- GAP-026 stealth-by-default = option A (product/SOP): stealth toggle at engagement creation.
- GAP-036 LLM tool-pick on auth pages — root = DUPLICATE password detection.

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
- **GAP-026: stealth is consent-gated (§12.36 enforced)** — TEMPO is operator baseline but stays consent-gated.
- **GAP-031: crash FIXED (graceful decline + Omega); residual = CF ceiling, NOT a code slice.**
- **Code quality target**: military-grade engineering (fail-safe, deterministic, audited, no false-success) that ENCODES APT tradecraft.
- **Verify-before-ship, every time**: green ≠ proven; always `git pull` before writing a patch; RUNNER-SEAL ≠ AUTONOMOUS-WIRED; Oracle is the seal.

---

## RESUME LINE (paste into new session)
> lanjut Agent-Alpha — GAP-074 Slice 2c (Odoo JSON-RPC Fallback / #416) + Auth Path Test Environment Isolation (#415) + Beta Offensive Profile Fail-Closed (#414) + Beta State-Leak Fix (#413) + Signed Profile Fail-Closed (#412) + CI & Secret Hardening (#411) + Coverage-Honesty (§12.62, #404/#407) + GAP-074 Slices 1, 2a, 2b (#406/#408/#409) MERGED & PROVEN. Next slice = §12.61 historical-DNS origin discovery (Wayback CDX) OR GAP-045 CF-ceiling honest-outcome. Do NOT build Gamma. ALWAYS git pull + re-verify first.
