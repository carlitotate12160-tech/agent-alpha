> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-13, soft-404 arc CLOSED)

Resume with: "lanjut Agent-Alpha — soft-404 arc CLOSED. GAP-044/048 merged (#388), 7/7 Tier-1 tests + Tier-2 catchall.lab field-proven (11/11 suppressed, 0 false findings). GAP-034 (#390) + GAP-035 (#389) merged. NEXT slice = §12.61 historical-DNS origin discovery (highest leverage, opens full-CF targets) OR GAP-045 CF-ceiling honest-outcome (LOW effort, HIGH product value). Do NOT build Gamma."

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — MET on self-owned real-world target; autonomous path now exercises binding for real:** find something a scanner missed + prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass → proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) — what Nuclei/Strix cannot assemble.

---

## SEALED / PROVEN (soft-404 arc — CLOSED 2026-08-11)

| Work | Seal level | Evidence |
|------|-----------|----------|
| **GAP-044 soft-404 false positives** | **CLOSED via GAP-048 (#388 merged)** | Problem: catch-all host returns 200 for all paths, body varies (reflected path, CSRF token, timestamp) → exact hash dedup miss → false findings (Lyndon #3). GAP-044 #386 (regex normalization) was PARTIAL — whack-a-mole per token format. |
| **GAP-048 two-probe differential calibration** | **MERGED #388, Tier-1 + Tier-2 PROVEN** | Two-probe DIFFERENTIAL: probe 2 independent random missing paths → token positions that DIFFER = volatile tokens (CSRF/session/timestamp) — WHATEVER format (hex/UUID/base64). Mask exactly those → format-agnostic signature. FAIL-SAFE: transport error / proper 404 / unstable token count → NO signature. scout.py `_soft404_tokens`/`_soft404_mask`/`_calibrate_soft404`/`_is_soft404`. |
| **GAP-048 Tier-1 tests** | **7/7 PASS Oracle ARM64** | test_soft404_calibration.py: hex true-positive, UUID true-positive, fail-safe cardinal (proper-404 → no signature), false-negative guard (real page on calibrated host NOT suppressed), same-token-count-different-skeleton (masked-hash collision guard), unstable token count (hex vs UUID → no signature), exactly 2 probes per host. |
| **GAP-048 Tier-2 field proof (catchall.lab)** | **11/11 suppressed, 0 false findings** | catchall.lab (#387 merged): nginx vhost returns 200 + 93894-byte body for ALL paths. Agent-Alpha calibrated, suppressed 11 catch-all paths (.git/config, .env, .env.bak, wp-config.php.bak, config/database.yml.bak, openapi.json, swagger.json, v2/api-docs, api-docs, graphql, graphiql). Real homepage (root /) NOT suppressed (_analyzable_probes=1). |
| **GAP-048 field verification (ingco.co.id bodies)** | **Empirically verified** | Two real ingco catch-all bodies differ only in CSRF token (2 lines: L1453 HTML attr handled by old regex, L1866 JS-object colon-context LEAKED). Old regex: signatures mismatch → false positive. New differential: 2 volatile positions found, signatures match → suppressed. ibudanbalita homepage → structural mismatch → NOT suppressed. |
| **GAP-034 reachability read-model** | **MERGED #390** | `events/reachability.py::unreachable_hosts(events)` — pure read-model over event store. `HOST_ABANDONED` marks host strike-dead; `WAF_BLOCKED` does NOT (origin-exposure-bypass target). `select_strike_entry` demotes dead hosts below live ones. |
| **GAP-035 multi-candidate entry-selection** | **MERGED #389** | Beta strikes ALL in-scope surfaces (up to MAX_STRIKE_CANDIDATES=3), NOT stop-on-first-COMPLETE. Shared CredentialLockoutGovernor per engagement. STRIKE_CANDIDATE_ATTEMPTED/SKIPPED events wired. |
| **catchall.lab lab host** | **MERGED #387** | Lab host for GAP-044/048 field-prove. nginx :443 on Oracle, returns 200 + 93894 bytes for all paths. |

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

**Non-blockers (schedule after):**
- GAP-045 CF-ceiling honest-outcome report (LOW effort, HIGH product value, isolated Omega/Conductor — turns "beta_failed" on full-CF into a sellable defensive-validation deliverable).
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

- **ADR §12.60 Two-Tier Proof + Field-Feedback Ratchet** — lab-green ≠ field-ready. Tier-1 lab-seal < Tier-2 field-prove (THE bar). Every field failure → permanent fixture in `test_field_regression`.
- **ADR §12.61 Flank-when-CF-hard** — CF "ceiling" is ONLY bruteing the edge. Operator FLANKS: find origin via side channels (historical DNS ★, mail/MX, cert/favicon pivot, grey-cloud) or skip perimeter (leaked-cred stuffing, exposed secrets, S3, subdomain takeover). Full-CF-no-origin → sellable defensive-validation report.
- **Soft-404: two-probe differential > regex whack-a-mole** — let the target reveal its volatile tokens by diffing two catch-all samples; don't enumerate token formats. Verified empirically + Tier-2 catchall.lab proven.
- **GAP-034: read-model over events, not node-schema mutation** (event-sourced; AttackGraph = projection).
- **GAP-026: stealth is consent-gated (§12.36 enforced)** — TEMPO is operator baseline but stays consent-gated.
- **GAP-031: crash FIXED (graceful decline + Omega); residual = CF ceiling, NOT a code slice.**
- **Code quality target**: military-grade engineering (fail-safe, deterministic, audited, no false-success) that ENCODES APT tradecraft.
- **Verify-before-ship, every time**: green ≠ proven; always `git pull` before writing a patch; RUNNER-SEAL ≠ AUTONOMOUS-WIRED; Oracle is the seal.
- **Anti-#3 in soft-404**: no finding from status code alone; catch-all suppression must be fail-safe (no signature = nothing suppressed); false-negative guard MUST test on CALIBRATED host.

---

## RESUME LINE (paste into new session)
> lanjut Agent-Alpha — soft-404 arc CLOSED. GAP-044/048 merged (#388), 7/7 Tier-1 + Tier-2 catchall.lab (11/11 suppressed, 0 false). GAP-034 (#390) + GAP-035 (#389) merged. NEXT = §12.61 historical-DNS origin discovery (highest leverage) OR GAP-045 CF-ceiling honest-outcome (LOW effort, HIGH value). Open: Spectranet frontier cycling (Bug #34), DeepSeek 512-token truncation. Do NOT build Gamma. ALWAYS git pull + re-verify first.
