> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-14, Coverage-Honesty & GAP-074 mechanism-aware auth arc CLOSED)

Resume with: "lanjut Agent-Alpha — Coverage-Honesty (§12.62, #404/#407) + GAP-074 Slice 1 & 2a (#406/#408) + SpaLoginApplicator (#403) MERGED & PROVEN. Next slice = §12.61 historical-DNS origin discovery (Wayback CDX) OR GAP-074 Slice 2b (Odoo JSON-RPC fallback / GAP-067) OR GAP-045 CF-ceiling honest-outcome. Do NOT build Gamma."

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — MET on self-owned real-world target; autonomous path now exercises binding for real:** find something a scanner missed + prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass → proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) — what Nuclei/Strix cannot assemble.

---

## SEALED / PROVEN (recent merged arcs)

| Work | Seal level | Evidence |
|------|-----------|----------|
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
- **GAP-074 Slice 2b / GAP-067 Odoo JSON-RPC fallback** — when XML-RPC is blocked by CF/WAF, fallback to `/web/session/authenticate` JSON-RPC endpoint for Odoo credential reuse.
- **GAP-045 CF-ceiling honest-outcome report** — (LOW effort, HIGH product value, isolated Omega/Conductor — turns "beta_failed" on full-CF into a sellable defensive-validation deliverable integrated with CoverageLedger).

**Non-blockers (schedule after):**
- GAP-043 CDN edge IP filter only covers Cloudflare (Sucuri/Incapsula/Akamai).
- GAP-042 origin probe bypasses stealth HttpClient (opsec debt).
- GAP-046 basic-auth applicator, GAP-047 username-harvest breadth — deferred (cred-acquisition).
- GAP-026 stealth-by-default = option A (product/SOP): stealth toggle at engagement creation.
- GAP-036 LLM tool-pick on auth pages — root = DUPLICATE password detection.

**Needs a log to diagnose (do NOT guess — anti-mis-fix):**
- **Spectranet frontier cycling** (Bug #34) — run did not converge, repeated same paths across 3+ cycles.
- **DeepSeek LLM orientation failures** — 512-token tool-selection budget + reasoning-model token consumption → `finish_reason="length"` before JSON.

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
> lanjut Agent-Alpha — Coverage-Honesty (§12.62, #404/#407) + GAP-074 Slice 1 & 2a (#406/#408) + SpaLoginApplicator (#403) MERGED & PROVEN. Next slice = §12.61 historical-DNS origin discovery (Wayback CDX) OR GAP-074 Slice 2b (Odoo JSON-RPC fallback / GAP-067) OR GAP-045 CF-ceiling honest-outcome. Do NOT build Gamma. ALWAYS git pull + re-verify first.
