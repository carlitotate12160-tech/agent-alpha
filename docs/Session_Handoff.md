> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-11, soft-404 GAP-048 + GAP-044 status arc)

Resume with: "lanjut Agent-Alpha — soft-404 arc. GAP-048 two-probe differential calibration PR #388 OPEN (5/5 tests pass Oracle ARM64, ruff+mypy clean, 67 related tests no regression). SUPERSEDES GAP-044 regex (#386 merged but INCOMPLETE — CSRF-hex-in-JS-object leaked). GAP-048 docs merged to main (1bfb3ed — GAP-048 registered, GAP-044 status → PARTIAL/superseded). PENDING: (1) merge PR #388 after CI+CodeRabbit, (2) add test ke-6 (same-token-count-different-skeleton false-negative guard — spec says 6 tests, only 5 delivered), (3) Tier-2 field-prove on catchall.lab — 0 false findings closes BLOCKER. NEXT slice = Slice-2 entry-selection GAP-034+035 (patch ready, GAP-034 unit-verified, GAP-035 run_beta dispatch-loop COMPILE-ONLY → needs integration test + Oracle make quality before merge) OR §12.61 historical-DNS origin discovery (highest leverage). Do NOT build Gamma."

---

## Phase

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**Success bar — MET on self-owned real-world target; autonomous path now exercises binding for real:** find something a scanner missed + prove exploitable + payable report. alpha-ai.web.id (full-CF, self-owned): origin-exposure bypass → proven cred-reuse to Odoo admin (uid=2). This is the moat (prove, not just detect) — what Nuclei/Strix cannot assemble.

---

## SEALED / PROVEN this arc (2026-08-11)

| Work | Seal level | Evidence |
|------|-----------|----------|
| **GAP-048 two-probe differential soft-404 calibration (format-agnostic)** | **PR #388 OPEN — unit-sealed Oracle ARM64, NOT YET MERGED** | Replaces GAP-044 per-format regex (whack-a-mole) with two-probe DIFFERENTIAL: probe 2 independent random missing paths → token positions that DIFFER = volatile tokens (CSRF/session/timestamp) — WHATEVER format (hex/UUID/base64). Mask exactly those → format-agnostic signature. FAIL-SAFE: transport error / proper 404 / unstable token count → NO signature. scout.py `_soft404_tokens`/`_soft404_mask`/`_calibrate_soft404`/`_is_soft404` rewritten. Oracle: 5/5 tests pass (test_soft404_calibration.py), ruff+mypy clean, 67 related tests pass (soft404 + wp_recon + entry_selection + wiring_gate). |
| **GAP-048 field verification (ingco.co.id catch-all bodies)** | **Empirically verified — NOT a lab fixture** | Two real ingco catch-all bodies (91775 bytes each, from `__gap044_baseline_test1` + `config/database.yml.bak`) differ only in CSRF token (2 lines: L1453 HTML attr handled by old regex, L1866 JS-object colon-context LEAKED). Old regex: signatures mismatch → false positive. New differential: 2 volatile positions found (pos 10524, 15386 = CSRF tokens), signatures match → suppressed. ibudanbalita homepage (125897 bytes, 31933 tokens vs 17539 catch-all) → structural mismatch → NOT suppressed → no false negative. |
| **GAP-044 status update in BUGS_AND_GAPS.md** | **MERGED to main (1bfb3ed, docs-only)** | GAP-044: OPEN BLOCKER → "PARTIAL FIX MERGED (#386) — INCOMPLETE, SUPERSEDED by GAP-048". GAP-048 registered as BLOCKER. Priority matrix + fix order updated. |

### Test contract (5 tests in PR #388 — spec says 6, one MISSING)

| Test | What it checks | Status |
|------|---------------|--------|
| `test_catch_all_calibrated_and_suppressed_hex` | True-positive: hex CSRF token catch-all IS suppressed | PASS Oracle |
| `test_catch_all_suppressed_uuid_format` | True-positive: UUID token (dashes — regex missed) IS suppressed | PASS Oracle |
| `test_no_catch_all_not_calibrated` | CARDINAL fail-safe: proper-404 host → NO signature | PASS Oracle |
| `test_real_page_not_suppressed_on_catch_all_host` | CARDINAL false-negative: real page on CALIBRATED host NOT suppressed (structural mismatch) | PASS Oracle |
| `test_two_probes_per_host` | Structural: exactly 2 probes issued per host | PASS Oracle |
| **MISSING: same-token-count-different-skeleton** | False-negative: same token count as catch-all but different non-volatile content → masked hash differs → NOT suppressed | **NOT WRITTEN** |

### Earlier sealed (still valid — context for this arc)

- **PR #346 stealth-by-default** (merged 2026-08-07): curl_cffi chrome124 as DEFAULT transport from request #1. STEALTH_BROWSER SSOT. bernofarm 25→12 WafBlocked.
- **Reach**: origin-direct (bypass CF edge) sealed + robust — RC1/RC2/RC3, seed_hosts, tls_impersonate correctly NOT chosen for CHALLENGE-class CF.
- **Entry-selection slice-1** (2026-08-09): Beta strikes reachable auth-surface (`select_strike_entry`, conductor/router.py) instead of dead apex. LIVE-sealed on AUTONOMOUS path. STRIKE_ENTRY_SELECTED event WIRED.
- **GAP-029 dead-host skip** (merged): ibudanbalita 118→7 hosts probed.
- **GAP-037 stop-on-block** (#385 merged): all 4 CodeRabbit fixes audited correct.
- **GAP-044 regex version** (#386 merged — INCOMPLETE): per-format regex normalizer. CSRF-hex-in-JS-object leaked. SUPERSEDED by GAP-048.
- **catchall.lab** (#387 merged): lab host for GAP-044/048 field-prove.

---

## PATCHES READY — seal on Oracle, then merge (IN ORDER)

### 1. GAP-048 — soft-404 two-probe DIFFERENTIAL calibration (PR #388 OPEN)

- **Branch**: `gap-048-two-probe-differential`
- **PR**: https://github.com/carlitotate12160-tech/agent-alpha/pull/388
- **Commits**: `be45d81` (fix + tests), `63233a5` (test fix — segs after run_recon), `e942eb7` (ruff B905), `d868ec6` (ruff format)
- **Files**: `agent_alpha/agents/alpha/scout.py` (helper block rewrite), `tests/phase_4/test_soft404_calibration.py` (5 tests)
- **Oracle status**: 5/5 PASS, ruff check PASS, ruff format PASS, mypy PASS (139 files), 67 related tests PASS
- **Action next session**:
  1. Check CI + CodeRabbit on PR #388
  2. **Add test ke-6** (same-token-count-different-skeleton) — construct body with exact same token count as catch-all but different non-volatile values → assert `_is_soft404` returns False. Without this, masked-hash collision regression goes undetected.
  3. Merge PR #388
  4. **Tier-2 field-prove on `catchall.lab` (#387)**: 0 false findings → closes BLOCKER

### 2. GAP-035 multi-candidate entry-selection — BUILT FRESH 2026-08-11 (own slice)

- **Prior bundled patch (GAP-034+035, `unreachable_hosts`/`strike_targets`) DISCARDED** — bundling
  was the bug source. Rebuilt GAP-035 alone; GAP-034 = separate next slice.
- **Design (as built)**: `router.select_strike_entry` returns `ranked_entries:
  tuple[StrikeCandidate,...]` (FULL ranked, uncapped). Dispatch-seam loop in
  `conductor/main.py run_beta` strikes up to `MAX_STRIKE_CANDIDATES=3` IN-SCOPE candidates
  (Conductor scope gate runs FIRST, then cap — out-of-scope never consumes budget). ONE shared
  `CredentialLockoutGovernor` per engagement (§12.22 D2). Status precedence COMPLETE > BLOCKED >
  FAILED. `strike.py` UNTOUCHED (single-entry contract). New audit events
  STRIKE_CANDIDATE_ATTEMPTED/SKIPPED; all wired in `test_wiring_gate.py`.
- **DECISION LOCKED 2026-08-11 — strike-all**: Beta strikes ALL in-scope surfaces (up to
  MAX_STRIKE_CANDIDATES=3), NOT stop-on-first-COMPLETE. Rationale: each surface = its own
  potential payable finding; stopping early = missed finding (the exact problem GAP-035 fixes).
  Shared lockout budget bounds the OPSEC cost. Supersedes the earlier "stop on first COMPLETE" note.
- **Verified this session (Python 3.12.13 = Oracle parity, NOT the seal)**: 19 entry-selection
  tests; phase_4 + phase_3 + governance green; mypy clean; 0 new ruff errors. RED->GREEN proven
  for the multi-candidate cardinal, first-wins, and BLOCKED precedence branches.
- **CodeRabbit round-3 applied**: (1) shared lockout governor, (2) BLOCKED precedence,
  (3) MAX applied post-scope in Conductor (router uncapped), (4) status moved here + ledger
  trimmed, (5) fake constructors store kwargs.
- **SEAL**: `make check` + `make test-phase4` on Oracle ARM64 from HEAD 7f4daa9a + apply patch.
- **Then Tier-2 niagamas**: confirm Beta strikes hub AND pos, WAF-dead apex never struck.

### 3. GAP-034 reachability read-model — BUILT 2026-08-11 (on top of GAP-035)
- `events/reachability.py::unreachable_hosts(events) -> frozenset[str]` — pure read-model over
  the event store. NOT a field on the sealed `AssetProperties` (anti #6).
- **Product decision (locked)**: ONLY `HOST_ABANDONED` marks a host strike-dead. `WAF_BLOCKED`
  does NOT — it is the origin-exposure-bypass target (the moat); demoting it would sabotage the
  core value. (Corrects an earlier loose note that said WAF_BLOCKED excludes.)
- `select_strike_entry(..., unreachable_hosts=...)` — reachability is the PRIMARY sort key;
  dead hosts DEMOTED (not deleted) below live ones, so the MAX_STRIKE_CANDIDATES budget prefers
  reachable surfaces. Conductor computes the set from `target_store` and passes it (router stays pure).
- Wired in `test_wiring_gate.py` (`unreachable_hosts` -> conductor/main.py). Feeds SituationAssessor §12.58 later.
- **Verified (3.12.13)**: 22 entry-selection tests; RED-proven (dead host consumes a slot without demote).
  SEAL = `make check` + `make test-phase4` on Oracle.

---

## OPEN / NOT DONE (registered, prioritised)

**Blocker-adjacent (correctness):**
- GAP-044/048 soft-404 — PR #388 OPEN, 5/5 tests pass. NEEDS: test ke-6 + Tier-2 field-prove on catchall.lab to close BLOCKER.

**High-leverage growth (next real slice — pick one, ONE at a time):**
- **§12.61 historical-DNS origin discovery** ★ — opens full-CF targets (niagamas/bernofarm/ibudanbalita all ceiling only because origin isn't found; crt.sh/VT/OTX failed). Passive, datacenter-friendly, extends the moat. Then cert/favicon pivot, then leaked-cred stuffing (axis-B). MENU — one slice.

**Non-blockers (schedule after):**
- GAP-045 CF-ceiling honest-outcome report (LOW effort, HIGH product value, isolated Omega/Conductor — turns "beta_failed" on full-CF into a sellable defensive-validation deliverable).
- GAP-036 LLM tool-pick on auth pages — root = DUPLICATE password detection (`tools/playbooks/default_credentials_login.yaml` stale twin of GAP-030's regex). SSOT fix, LOW.
- GAP-046 basic-auth applicator, GAP-047 username-harvest breadth — deferred (cred-acquisition).
- GAP-026 stealth-by-default = **option A (product/SOP)**: a stealth toggle at engagement creation that sets `opsec_stealth=True` + the signed consent_item. NO server code (authorization.py hard-rejects a raw default flip). Product/onboarding decision.

**Needs a log to diagnose (do NOT guess — anti-mis-fix):**
- **Spectranet frontier cycling** (Bug #34) — run did not converge, repeated same paths across 3+ cycles. `_ran_campaigns` prevents duplicate findings but URL fetching still repeated.
- **DeepSeek LLM orientation failures** — 512-token tool-selection budget + reasoning-model token consumption → `finish_reason="length"` before JSON. Models available (`deepseek-v4-flash`, `deepseek-v4-pro`), not a model-name mismatch. WordPress admin/login-gated pages repeatedly reach LLM tier (waste).

---

## DOCTRINE BANKED THIS SESSION (durable)

- **ADR §12.60 Two-Tier Proof + Field-Feedback Ratchet** — lab-green ≠ field-ready. Tier-1 lab-seal (fixture MUST carry field-known adversarial shapes) < Tier-2 field-prove (THE bar). Every field failure → permanent fixture in `test_field_regression`.
- **ADR §12.61 Flank-when-CF-hard** — CF "ceiling" is ONLY bruteing the edge. Operator FLANKS: find origin via side channels (historical DNS ★, mail/MX, cert/favicon pivot, grey-cloud) or skip perimeter (leaked-cred stuffing, exposed secrets, S3, subdomain takeover). Full-CF-no-origin → sellable defensive-validation report.
- **Soft-404: two-probe differential > regex whack-a-mole** — let the target reveal its volatile tokens by diffing two catch-all samples; don't enumerate token formats. Verified empirically: ingco catch-all (2 volatile positions = CSRF hex tokens), ibudanbalita homepage (no false negative).
- **GAP-034: read-model over events, not node-schema mutation** (event-sourced; AttackGraph = projection).
- **GAP-026: stealth is consent-gated (§12.36 enforced)** — TEMPO (StealthPacer human-jitter) is operator baseline but stays consent-gated. Option A = engagement-creation toggle.
- **GAP-031: crash FIXED (graceful decline + Omega); residual = CF ceiling, NOT a code slice.** Do NOT implement ledger's old "fall back to CF DIRECT" (violates banked doctrine).
- **Code quality target**: military-grade engineering (fail-safe, deterministic, audited, no false-success) that ENCODES APT tradecraft, sustained with enterprise discipline.
- **Verify-before-ship, every time**: green ≠ proven (read the merged code); always `git pull` before writing a patch; RUNNER-SEAL ≠ AUTONOMOUS-WIRED; Oracle is the seal.
- **Anti-#3 in soft-404**: no finding from status code alone; catch-all suppression must be fail-safe (no signature = nothing suppressed); false-negative guard MUST test on CALIBRATED host (not just proper-404 host).

---

## RESUME LINE (paste into new session)
> lanjut Agent-Alpha — soft-404 arc. GAP-048 two-probe differential PR #388 OPEN (5/5 Oracle, ruff+mypy clean, 67 related no regression). SUPERSEDES GAP-044 regex (#386 INCOMPLETE). Docs merged (1bfb3ed). PENDING: (1) add test ke-6 (same-token-count-different-skeleton) to PR #388, (2) merge after CI+CodeRabbit, (3) Tier-2 catchall.lab field-prove → closes BLOCKER. NEXT = Slice-2 GAP-034+035 (patch ready, GAP-034 unit-verified, GAP-035 needs integration test + Oracle make quality) OR §12.61 historical-DNS (highest leverage). Open: Spectranet frontier cycling (Bug #34), DeepSeek 512-token truncation. Do NOT build Gamma. ALWAYS git pull + re-verify first.
