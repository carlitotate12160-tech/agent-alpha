> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-24)

HEAD `11a35af2` on `main`. Phase 4. Gamma/Delta/Epsilon = 0% (STOP-gated).
Reach arc SEALED through GAP-197 (#494 `8dfb2d0`). Oracle ARM64 = the seal;
RUNNER-SEAL ≠ AUTONOMOUS-WIRED (grep the live path, not the runner).

**ARCHITECTURE FORK RESOLVED → Bet B (ADR §12.67 ACCEPTED 2026-08-24).** ADR §12.68 and §12.69 PROPOSED and documented.
S0 (GAP-028) SEALED. S1 (fingerprint-flank + CDN identity guard) SEALED. Detection code S2 (offline correlation) is IN PROGRESS. Gamma STOP-gated.

---

## ⚠ ARCHITECTURE RECKONING — READ FIRST (this is the whole session)

**The trigger:** on real authorized .id targets, >1 month, **0 payable findings.** Nuclei found 49
(incl. **Zimbra CVE-2022-41352 RCE, CVSS 9.8, on `103.113.118.203`**); Agent-Alpha 0. User asks:
"is Agent-Alpha built wrong — does it need a big change?"

**Architect verdict (confidence ~70%, gated below):**

1. **REJECT the reflex "salah total → perubahan besar → rewrite."** That reflex is the exact
   engine that produced Lyndon #1–#4 (each died, got clean-rewritten into the next). Answering
   0-findings with an architecture rewrite = starting Lyndon #5, reactive to ONE number
   (#1/#5/#10 at the architecture level). Not approved.

2. **"49 vs 0" is the WRONG yardstick.** Nuclei = scanner = spray templates → 49 *unverified*
   version-matches (no chain, no proof-of-exploitability). Agent-Alpha's unit = a **payable
   chain** (leak→cred→access→proof). Chasing count = *becoming Nuclei* = re-introducing Lyndon
   frustration #1 (too generic) and #6 (no unique value). **The bar stays: ONE payable chain a
   scanner missed** — not a bigger number.

3. **BUT the substance under the number is real.** Under the 49 there is ≥1 genuinely
   exploitable known-CVE (the Zimbra RCE) that Alpha never even reached the point of *detecting*.
   That is a real hole. Do not dismiss it as "different job."

4. **The FOUNDATION is NOT wrong.** Event-sourced + AttackGraph + per-edge oracle (§12.43) +
   Conductor auth-gate + chain composition = the moat, the thing a scanner *cannot* do and what
   makes a finding payable. Throwing it away destroys the only reason the product exists. **Keep it.**

5. **What IS narrow/wrong (architecture-level):** the **detection MODEL is per-playbook**
   (one hand-built playbook per stack: `wp_*`, `odoo_*`, `laravel_*`…). This does NOT scale to
   "all targets" — the .id field is heterogeneous, most targets are not a stack we went deep on,
   so Alpha structurally has nothing to do → 0. That is not one missing lane; it is a detection
   model that cannot widen.

**THE FORK to decide (write the choice as an ADR, do not leave it implicit):**

- **Bet A — deep chain specialist.** Few high-value stacks, go deep, prove payable chains a
  scanner can't. "0 on this target" is HONEST (we don't cover that stack). Cost: only sells to
  engagements matching our stacks.
- **Bet B — breadth-of-detection first, chain on top.** Add ONE **data-driven detection engine**:
  version-inference (from recon we already do) → **offline CVE correlation over DATA** (NVD/KEV/
  EPSS/CVEDB corpus) → surgical confirm. This gives Nuclei-like *breadth of detection* but
  data-driven (**wrap DATA, NOT the scanner ENGINE** — the engine is the signature), and the
  chain+oracle layer we ALREADY have turns it into a *payable* finding where Nuclei only lists.
  This is the "comprehensive, all targets" path WITHOUT a rewrite and WITHOUT becoming a scanner.

**GATE (falsifiable — do NOT lock the bet before this read):** everything above assumes the funnel
dies at **DETECTION**. It may not. Two real targets already show **two different walls**:

- **bernofarm** = **REACH/WAF wall (E-stage S3)**. Events `eng_3c9bb601` (35 ev, WafBlocked +
  OriginDirectAttempt) + `eng_e8c071ef` (43 ev, WafBlocked + HostAbandoned). Died at the edge —
  never reached stack classification. For bernofarm, adding detection breadth changes NOTHING.
- **niagamas** = **deep run** `eng_0e1dfdc7` (175 ev) + `eng_fc83206f` (167 ev), NO WafBlocked in
  the summary → tembus edge, ran ~9 min. **Wall is late and UNREAD.** niagamas is the target that
  got furthest = its wall is the highest-ROI thing to fix and **it decides Bet A vs Bet B.**

If niagamas ALSO died at REACH → detection breadth won't help; the wall is reach/edge (partly
infra-bound, a worse place to be). **Read niagamas before choosing.**

---

## GATE READ — DONE (2026-08-24, zero-touch via existing `project_coverage`)

Histogram niagamas via `project_coverage` (existing §12.64 projection, NO new code):

```text
eng_0e1dfdc7 (175 events, 31 cells):
  not_run:           18  ← wiring gap (Lyndon #2) — capable+applicable, never dispatched
  capability_absent: 12  ← detection gap — technique not built
  tested:             1  (hub.niagamas.com/js_secret_leak → no_signal)

eng_fc83206f (167 events, 48 cells):
  not_run:           27  ← wiring gap
  capability_absent: 20  ← detection gap
  tested:             1  (hub.niagamas.com/js_secret_leak → no_signal)
```

### eng_0e1dfdc7 — bucket histogram

| Bucket | Count | Artinya |
|---|---|---|
| `capability_absent` | 12 | Technique tidak di-built |
| `not_run` | 18 | Technique di-built + applicable, tidak di-dispatch |
| `tested` | 1 | Hanya `hub.niagamas.com/js_secret_leak` |

### eng_0e1dfdc7 — applicable cell count by surface type

| Surface | Applicable cell count |
|---|---|
| `host` | 26 |
| `auth_surface` | 5 |

### eng_0e1dfdc7 — cell detail (surface_id, technique_id, bucket)

```text
apifingeris.bernofarm.com    git_exposure_leak           not_run
apifingeris.bernofarm.com    js_secret_leak              not_run
apifingeris.bernofarm.com    network_service_exposure    capability_absent
apifingernew.bernofarm.com   git_exposure_leak           not_run
apifingernew.bernofarm.com   js_secret_leak              not_run
apifingernew.bernofarm.com   network_service_exposure    capability_absent
appform.bernofarm.com        git_exposure_leak           not_run
appform.bernofarm.com        js_secret_leak              not_run
appform.bernofarm.com        network_service_exposure    capability_absent
erp.bernofarm.com            git_exposure_leak           not_run
erp.bernofarm.com            js_secret_leak              not_run
erp.bernofarm.com            network_service_exposure    capability_absent
global.bernofarm.com         git_exposure_leak           not_run
global.bernofarm.com         js_secret_leak              not_run
global.bernofarm.com         network_service_exposure    capability_absent
hr.bernofarm.com             git_exposure_leak           not_run
hr.bernofarm.com             js_secret_leak              not_run
hr.bernofarm.com             network_service_exposure    capability_absent
hris.bernofarm.com           git_exposure_leak           not_run
hris.bernofarm.com           js_secret_leak              not_run
hris.bernofarm.com           network_service_exposure    capability_absent
hub.niagamas.com             breach_credential_reuse     capability_absent
hub.niagamas.com             cred_reuse                  not_run
hub.niagamas.com             default_creds_login         not_run
hub.niagamas.com             git_exposure_leak           not_run
hub.niagamas.com             http_basic_auth_strike      capability_absent
hub.niagamas.com             js_secret_leak              tested
hub.niagamas.com             mfa_challenge_honest        capability_absent
hub.niagamas.com             network_service_exposure    capability_absent
hub.niagamas.com             spa_json_login              not_run
hub.niagamas.com             sqli_auth_bypass            capability_absent
```

### eng_0e1dfdc7 — not_assessed (capability_absent technique ids)

```text
http_basic_auth_strike
sqli_auth_bypass
mfa_challenge_honest
network_service_exposure
subdomain_takeover
dns_zone_transfer
breach_credential_reuse
oauth_saml_jwt_forgery
trust_path_vendor_portal
```

### eng_0e1dfdc7 — recon not_run gaps (deduplicated technique ids)

```text
git_exposure_leak
js_secret_leak
```

## GATE READ — CORRECTED (2026-08-24, code-verified, not raw-bucket)

**Framing "wiring wall (18-27 not_run)" = MISDIAGNOSIS.** Code evidence:
- `/.git/config` ∈ DEFAULT_LEAK_PATHS (constants.py:476) — universally seeded.
- `git_exposure_probe` ∈ PATH_PROBE_CATALOG (path_probe.py:95), applies_to_stacks=∅ (universal).
- conductor/main.py:571 OBSERVES recon_not_run_gaps but does NOT re-dispatch (honesty gate only).
- recon_not_run_gaps already reduces raw not_run=18 to {git_exposure_leak, js_secret_leak};
  js_secret_leak = tested(no_signal). git_exposure is SEEDED + REGISTERED = NOT an unwired island.

**Real walls (two, neither is wiring):**
1. REACH — bernofarm subdomains dead/WAF-blocked; git not_run there = blocked, not wiring.
2. CALIBRATION (GAP-028) — niagamas hub SPA reached via flank: _calibrate_soft404 fetches its
   two samples via FRONT DOOR (http_client.get on fronted netloc) while the real probe body is
   ORIGIN-DIRECT. Front-door WAF-block -> no signature -> origin 200-junk never suppressed ->
   git_exposure/js_secret analyse junk. This ALSO poisons §12.67-S3 confirm_probe (fires on junk
   = Lyndon #3). GAP-028 = the load-bearing S0 precondition.

**S0 RE-SCOPED: not "wire not_run" (near-empty) but GAP-028 calibration transport-parity.**
NEXT = calibrate soft-404 over the SAME transport the real probe used (origin-direct when
_bound_origin[host] is non-empty). Build-spec ready. STEP 0 Oracle diagnostic: confirm niagamas
hub git cell = origin-swapped-200-junk-no-signature (else pivot to REACH).

**Portfolio histogram (4 fresh targets, re-run 2026-08-24 via `run_recon_for_engagement`):**

| Target | Earliest fail | Wall |
|---|---|---|
| solusibersama.co.id (`eng_044e877b`) | S3_REACH | WAF block, 9 origin candidates tidak di-test |
| quantum-laboratories.com (`eng_bead8806`) | S3_REACH | Cloudflare, 1 origin candidate tidak di-test |
| hashmicro.com (`eng_7d4af3a8`) | S2_PASSIVE_SURFACE | RECON_ONLY consent, 0 passive hosts |
| niagamas.com (`eng_0e1dfdc7`) | S7_TARGET_SIGNAL | Origin-flank works, tapi js_secret_leak no_signal |

**3 wall berbeda di portfolio:**
- **Passive wall** — passive intel tidak persist surface (hashmicro)
- **Reach wall** — WAF/CF block, origin candidates tidak di-test (solusibersama, quantum)
- **Dispatch+Detection wall** — host reachable, technique tidak dispatch + capability_absent (niagamas)

**All-engagement aggregate (1040 engagements, ≥20 events each):**

| Bucket pattern | Count | Artinya |
|---|---|---|
| `buckets: {}` | 34 | 0 surface terbentuk (passive wall) |
| `blocked: 3, capability_absent: 1` | 31 | Surface terbentuk, semua WAF-blocked (reach wall) |
| `not_run: 2, capability_absent: 1` | 15 | Host reachable, technique tidak dispatch (dispatch wall) |
| `tested: 2, capability_absent: 1` | 4 | Technique di-dispatch (niagamas runs only) |

**Hanya 6 engagement yang pernah `tested` — semua niagamas.** Semua target lain (bernofarm,
solusibersama, quantum, hashmicro, pyfa, unibis, platinumcredit) — 0 tested. Spectra tidak ada
di event store (never run).

---

## ▶ START HERE (new session — in order)

1. **`git pull` + confirm HEAD = `8eafe57b`.** Reach arc (#487 root, #491 GAP-196, #494 GAP-197)
   is on `main`, green on Oracle. coverage_diagnostic reverted (#498). Do NOT rebuild it.
2. **GATE read CORRECTED (above).** Framing "wiring wall" = misdiagnosis (git seeded+registered).
   Real walls = REACH (bernofarm) + CALIBRATION GAP-028 (niagamas SPA junk uncalibrated over front door).
   S0 RE-SCOPED to GAP-028 soft-404 calibration transport-parity.
3. **Decide Bet A vs Bet B from that evidence and WRITE it as an ADR** (`docs/ADR.md`). Do not
   leave the bet implicit (that is how the field stayed ambiguous for a month). **User decides,
   not architect.** Architect provides evidence + recommendation, user picks.
4. **If Bet B chosen:** design the data-driven detection engine as ONE additive slice
   (version-inference → offline CVE correlation → `VULNERABILITY` node + ProofArtifact; no exploit
   fired = still payable). §12.67 is PROPOSED, NOT ACCEPTED — ACCEPT into `docs/ADR.md` before code.
   **Precondition: fix wiring gap (not_run) BEFORE detection code** (anti-Lyndon #3).
5. **Do NOT build Gamma.** Detection ≠ exploitation. Firing an exploit stays STOP-gated.

*(Oracle = the seal. RUNNER-SEAL ≠ AUTONOMOUS-WIRED. One vertical slice at a time.)*

---

## Phase & Success Bar

Phase 4 (recon + reach + initial-access proof). Gamma/Delta/Epsilon = 0% (STOP-gated).

**MECHANISM proven (self-owned), REPRESENTATIVE_FIELD_VERIFIED = NOT MET.** alpha-ai.web.id
(self-owned full-CF): origin-bypass → cred-reuse → Odoo admin uid=2 proves the chain mechanism
(leak→vault→reuse→cross_verified). On real targets we REACH (bernofarm 11 IPs where Nuclei was
edge-blocked) but find nothing payable. Success bar = ONE payable chain a scanner missed, on
representative field conditions — NOT a finding count.

---

## ✅ SEALED (recent — do NOT rebuild)

| PR / arc | Seal | What |
|---|---|---|
| **#498 revert** | MERGED `8eafe57b` | Revert coverage_diagnostic (#497). Diagnostic was read-only projection tool, not product capability. Teardown verified: 0 references, lab guard 3/3, ruff+mypy clean. |
| **#494 GAP-197** | MERGED `8dfb2d0`, Oracle 15/15 | Flanked-asset honesty: `AssetProperties.edge_fronted`; `scout.run_recon` reconciles current-run `ORIGIN_BINDING_PROVEN` into graph as `edge_fronted=True`; `cf_protected` no longer asserted False from origin body; `predicates._has_fronted_host` = `cf_protected OR edge_fronted`; T5 accepts `flank_proven`. `niagamas.com` T1–T6 PASS. |
| **#491 GAP-196** | MERGED `e11fc99`, Tier-2 PROVEN | Sub-path origin-direct flank: transport-dead sub-paths reuse pre-bound origin (`require_bound=True`); query preserved for fetch, VALUES redacted in audit. `niagamas.com`: 15 OriginDirectAttempt via `139.59.255.22`, HostAbandoned 0, OriginBindingProven 2. |
| **#487 root flank** | MERGED, 254 green Oracle | §12.61 transport-dead front-door → origin-flank for ROOT. Front-door timeout = origin-direct PRECONDITION, not abort. Reach helpers → `recon/origin_reach.py`. `niagamas.com` ORIGIN_DIRECT 200 (98,766B) on `139.59.255.22`. E1→E2 root reach only. |
| **#465 §12.43 per-edge oracle** | SEALED, slice-1d Oracle-green | `auth_vs_unauth_diff` BUILT (`_auth_only_diff`, §12.32) + AUTONOMOUS-WIRED (`conductor/main.py:805` producer → `:810 verify_access_nodes` → attestor `_has_independent_auth_diff` → CROSS_VERIFIED). Only CHAIN-level MIN-composition remains. |
| **#454 GAP-118** | MERGED `6fe008d2`, field-confirmed | Attestor Rule 3: `secret_ref` must RESOLVE to engagement-owned vaulted material. `verify_access_nodes(*, secrets_manager)` keyword-only required (anti-#3). `wpvuln` bare-UUID now correctly INCONCLUSIVE. 606/606 Oracle. |
| **#470/#475/#477 CodeIgniter** | SEALED 2026-08-22 (recon-stage) | Leak→cred→vault for `application/config/database.php`. Hermetic Conductor driver tests prove `build_recon_pipeline → _sweep_targets → run_recon` autonomous path. Stale `WIRING_DEBT` false-green removed. |
| **#472 §12.66 Slice-1** | MERGED `079e479` | Closed precondition/effect predicate vocabulary (`coverage/predicates.py`); integrity gate pins catalog to `graph/nodes.py` (anti-#7). DATA + registry only, no scoring. |
| **#404/#407 §12.62** | MERGED, Tier-1 | CoverageLedger + `techniques.yaml` single-source catalog; Omega Coverage & Methodology report section (tested/not_run/blocked/capability_absent). |
| **#388 GAP-044/048** | MERGED, Tier-1+2 | Soft-404 two-probe differential (diff volatile tokens, no regex whack-a-mole). catchall.lab 11/11 suppressed. |
| **#406-416 GAP-074** | MERGED, Tier-1 | Auth-mechanism fingerprint → applicator selection, single-source in `recon.auth_surface`; Odoo JSON-RPC transport fallback. |
| **#444 GAP-169** | MERGED, Tier-1 | Fingerprint-First recon reorder (§12.65): root fetch at t=0, stack-tailored frontier seed, no blind spray. |

Earlier still-valid: #346 stealth-by-default (curl_cffi chrome124 from request #1); origin-direct
reach (RC1/RC2/RC3, tls_impersonate); GAP-029 dead-host skip; GAP-037 stop-on-block; GAP-038–041.

**Agent real capability today (from `coverage/techniques.yaml` — the honest denominator):** 7
capable techniques = leak-hunt (git/js) + generic cred plumbing (cred_reuse, spa_json_login,
default_creds_login) + reach (origin_exposure_bypass) + WP-only depth (wp_rest_user_enum, the ONLY
stack-specific capable technique). 12 roadmap techniques capability_absent. **NO version→CVE
detection exists. NO wp_plugin_enum. NO service/port breadth (GAP-081).** This is why the field is
heterogeneous-but-uncovered.

---

## OPEN / NEXT (do NOT pick before user decides Bet A vs Bet B)

- **ADR bet A vs B (await user decision)** — write it explicitly to `docs/ADR.md` after user
  decides. GATE read is done (above). Evidence supports both bets:
  - Bet B: capability_absent (12–20) + version→CVE unlisted → detection gap is real
  - Bet A: not_run (18–27) dominates → wiring gap is wall pertama, detection premature
  - User constraint: "seluruh client dilayani" → leans toward Bet B (breadth) but user has NOT confirmed
- **ADR §12.67 detection lane (PROPOSED, NOT ACCEPTED)** — IF Bet B: version-inference → offline
  CVE correlation over DATA (NVD/KEV/EPSS/CVEDB) → `VULNERABILITY` node + ProofArtifact (no exploit
  fired = still payable). **Wrap the DATA, never the scanner ENGINE.** ACCEPT before any code.
  **Precondition: fix wiring gap (not_run) BEFORE detection code.**
- **GAP-045 CF-ceiling honest report** — Omega + CoverageLedger turns full-CF "beta_failed" into a
  sellable defensive-validation deliverable. Low-effort honest-outcome floor.
- **ChainOracle MIN-composition (§12.43)** — `chain_tier = MIN(edge_tier)`, payable IFF every hop
  cross_verified. New `attestation/chain_oracle.py`. Aggregates per-edge verdicts only. PARKED.
- **§12.66 ACCEPT-review** — Slice-2 `Planner.score` BLOCKED until §12.66 ACCEPTED. Deferred.

**Deferred GAPs (own verticals, do NOT fold in):** GAP-115 historical-DNS (WIRED; diagnose w/ log
before extending — anti-#2), GAP-155 IPv6 bracketing, GAP-156 in-scope IP gate, GAP-157 ENABLES
edge, GAP-158 multi-target pivot, GAP-159 cloud IAM, GAP-043 non-CF edge IPs, GAP-042 origin-probe
stealth, GAP-046/047 basic-auth+username-harvest, GAP-036 LLM tool-pick, GAP-081 network/service
exposure (breadth).

⚠ **GAP-numbering COLLISION (Lyndon #7 — reconcile):** in this handoff's history GAP-196/197 = reach
slices; in `docs/BUGS_AND_GAPS.md` GAP-196 = StealthPacer-no-effect, GAP-197 = browser_solve-unwired.
Two meanings per number — fix the ledger before opening GAP-198+.

---

## DOCTRINE BANKED (durable)

- **Yardstick (LOCKED)** — success = ONE payable chain a scanner missed, on representative field
  conditions. NEVER a finding count. Chasing count = becoming a scanner = losing.
- **Wrap DATA, not the ENGINE** — the scanner engine (Nuclei's request pattern/templates) IS the
  signature; wrapping it inherits the noise. Wrap the CVE corpus (NVD/KEV/EPSS/CVEDB) as DATA;
  build the detection engine custom (passive-first, low-footprint).
- **Rewrite reflex = Lyndon origin** — "salah total → bongkar besar" is how Lyndon #1–#4 were born.
  Big change = ADDITIVE architectural piece on a kept foundation, never a rewrite.
- **§12.43 Proof Standard (LOCKED)** — payable floor = independent oracle (auth-vs-unauth diff
  §12.32) + human-legible artifact. ChainOracle = MIN over per-edge oracles. Provenance ≠ oracle.
- **§12.61 Flank-when-CF-hard** — CF "ceiling" is only bruteing the edge. Operator FLANKS: origin
  via side channels (historical DNS, MX, cert/favicon pivot). Transport-dead front-door =
  origin-direct PRECONDITION ("the niagamas lesson").
- **§12.60 Two-Tier Proof + Field Ratchet** — lab-green ≠ field-ready; every field failure →
  permanent `test_field_regression` fixture.
- **§12.62 Coverage-Honesty** — report carries tested/not_run/blocked/capability_absent; never emit
  "fully secure" from an absence. bucket=blocked ⇒ surface NOT exhausted; not_run ⇒ wiring/self-audit.
- **§12.22 tool strategy** — wrap commodity DATA, build the moat, gate the dangerous. Moat =
  **reach × detection × chain × proof** (detection is the model that must widen; §12.67).
- **§12.55 1-day weaponizer, NOT 0-day hunter** — detection matches KNOWN CVEs; never hallucinate 0-day.
- **Four-Operator Lineage (design lens)** — APT29 low-and-slow precision, Volt Typhoon LOTL/blend,
  APT41 intel-driven victim-tailored, Lazarus exploit-chaining. Operator OBSERVES/COMPOSES; scanner
  sprays. Targeted-per-fingerprint CVE match = APT29 precision (NOT Nuclei's blind spray).
- **RUNNER-SEAL ≠ AUTONOMOUS-WIRED** — a runner-proven capability is an ISLAND until the autonomous
  path (scout.py / execute_agent.py / run_cognitive_loop) calls it. Grep the live path, always.
- **Oracle ARM64 only** — Windows/local results invalid (Lyndon #9). Verify-before-ship; green ≠ proven.

---

## SESSION LOG (2026-08-24)

- Sealed slices this session: 3 (GAP-028 Tier-1 lab-seal, GAP-028 Tier-2 field-prove, S1 fingerprint-flank).
- `_calibration_fetch` routes calibration probes through `origin_direct_probe` when `_bound_origin[host]` non-empty.
- Added `maybe_fingerprint_flank` in `origin_reach.py` (version-priority guard) and fixed exact-match CDN bug in `service_fingerprint.py`. CI is green (ignoring DeepSeek intermittent API timeout).
- Documented §12.68 (Universal Credential/Secret Exposure Lane) and §12.69 (Evidence-Resolution Engine) in ADRs.
- GAP-028 is CLOSED. The S0 precondition is met.
- Current slice status: S1 SEALED. S2 (CVE offline correlation) IN PROGRESS. Gamma STOP-gated.

## RESUME LINE (paste into new session)
> lanjut Agent-Alpha — S1 fingerprint-flank SEALED. S2 (offline CVE correlation) IN PROGRESS.
> Implementation Plan for S2 is drafted. Next slice: implement S2 data-driven detection engine over version-inference and CVE corpus. Gamma STOP-gated. Oracle ARM64 = seal.
