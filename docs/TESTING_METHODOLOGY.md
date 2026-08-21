# Testing Methodology & Phase Exit Criteria

> Extracted from `AGENTS.md` on 2026-08-21 to keep AGENTS.md focused on
> operational workflow only (per its own header: doctrine lives in CLAUDE.md,
> this doc holds the detailed testing doctrine). AGENTS.md now points here.
>
> Status of which phase is sealed lives in `docs/Session_Handoff.md` — this
> doc defines the *criteria*, not the current status.

---

## Phase Exit Criteria & Testing Methodology

> **Lesson learned (2026-08-12):** Phase 2 was "sealed" with "output non-empty,
> FP < 20%" — but Alpha was INCOMPLETE (missing plugin list, WC version, email,
> security headers, JS secrets). Phase 3 was "sealed" with "non-empty findings"
> — but Beta only worked for WP→Odoo cred-reuse, not Odoo direct login. Both
> phases passed exit criteria but had critical gaps. Root cause: exit criteria
> measured "non-empty" not "complete for 2+ stacks." This section fixes that.

### Testing pyramid (3 tiers — every gap fix must pass ALL 3 before sealed)

```
Tier 1 — UNIT (lab, deterministic, fast)
  ↓ pass
Tier 2 — INTEGRATION (lab, live-fire, end-to-end)
  ↓ pass
Tier 3 — FIELD-PROVE (real authorized target, real WAF/CF)
  ↓ pass
SEALED — gap is closed, move to next slice
```

**No gap is "closed" until Tier 3 passes.** Tier 1 + Tier 2 = "lab-sealed" (not
field-proven). Tier 3 = "field-proven" (the only bar that counts, per ADR §12.60).

#### Tier 1 — Unit test (lab, deterministic)

- **What:** Handler/function test with mock inputs. Does the regex extract
  correctly? Does the handler mint the right node? Does the filter reject
  correctly?
- **Where:** `tests/` directory on Oracle ARM64.
- **How:** `python -m pytest tests/phase_X/test_<component>.py -v`
- **Speed:** Seconds. No HTTP, no LLM, no real target.
- **Pass criteria:** All assertions pass. No false positives (empty input →
  0 nodes). No false negatives (known input → expected node).

#### Tier 2 — Integration test (lab, live-fire, end-to-end)

- **What:** Run Alpha/Beta against a LAB stack (docker-compose) with known
  ground truth. Does the handler fire in the autonomous path? Does the tool
  produce the expected finding?
- **Where:** Oracle ARM64, docker-compose lab stacks.
- **Available lab stacks:**

| Lab stack | Docker container | Lab guard host | Stack type |
|-----------|-----------------|----------------|------------|
| WP (vuln) | `wp_lab-wordpress-1` | `vuln.wp.lab` | WordPress |
| WP (hardened) | `wp_lab-wordpress-1` | `hardened.wp.lab` | WordPress |
| WP (WAF) | `wp_lab-wordpress-1` | `waf.wp.lab` | WordPress + WAF |
| Odoo (vuln) | `odoo_lab-odoo-1` | `vuln.odoo.lab` | Odoo |
| Odoo (hardened) | `odoo_hardened_lab-odoo-1` | `hardened.odoo.lab` | Odoo |
| Laravel (vuln) | `laravel-lab-laravel-vuln-1` | `laravel-vuln.lab` | Laravel |
| Laravel (hardened) | `laravel-lab-laravel-hardened-1` | `laravel-hardened.lab` | Laravel |
| Actuator (vuln) | — | `vuln.actuator.lab` | Spring Boot |
| Git (vuln) | — | `vuln.git.lab` | Git exposure |
| Backup (vuln) | — | `vuln.backup.lab` | Backup leak |
| Chain lab | `chain_lab_server` | `chain-lab.lab` | Full chain (WP+Odoo) |

- **How:** Run the Conductor autonomous path (NOT a runner script) against
  the lab host. Runner scripts are ISLAND tests (Lyndon #2) — they don't
  prove the autonomous path works.
  ```bash
  # Example: run Alpha against vuln.wp.lab
  wsl -e bash -lic "ssh oracle-alpha 'export PATH=...; cd ~/Agent-Alpha && \
    source .venv312/bin/activate && set -a; source .env; set +a; \
    python run_engagement_task.py --target https://vuln.wp.lab/ ...'"
  ```
- **Speed:** Minutes. Real HTTP, real LLM (DeepSeek), but local network.
- **Pass criteria:**
  1. Handler fires in autonomous path (not just runner).
  2. Expected node(s) appear in graph (query PostgreSQL).
  3. No regression (prior phase tests still pass).
  4. No cycling (Bug #34 check: 0 duplicate tool calls).
  5. No junk crawl (Bug #37 check: 0 content-page probes).

#### Tier 3 — Field-prove (real authorized target)

- **What:** Run the full Conductor autonomous path against a REAL authorized
  target that is NOT a controlled lab. T3 has three sub-tiers:

  - **T3-real:** real WAF/CF/infrastructure (client-approved or self-owned).
    This is the authoritative field-prove for all WAF/CF and cred-reuse work.
  - **T3-lite:** public internet test platforms with no WAF/CF. Used ONLY for
    GAP-001 new-stack playbook validation (ASP.NET, JSP, SPA, etc.).
  - **T3-origin:** multi-IP lab targets (Vercel edge, direct origin). Used ONLY
    for origin-discovery / multi-IP field-prove (GAP-018, GAP-038, GAP-042).

- **Where:** Authorized targets in `lab_guard.py`:
  `client-approved + DNS-TXT verified` (T3-real),
  `public-test:` platform (T3-lite), or
  `dns-txt lab-proof` self-owned multi-IP (T3-origin).
- **Authorized real targets (as of 2026-08-13):

##### T3-real (real WAF/CF, client-approved or self-owned)

| Target | Stack | Auth | Use for |
|--------|-------|------|---------|
| `solusibersama.co.id` | WP + WooCommerce + LiteSpeed | dns-txt client-approved | WP gaps |
| `quantum-laboratories.com` | Odoo + Cloudflare | dns-txt client-approved | Odoo gaps |
| `bernofarm.com` | WP + WooCommerce | dns-txt client-approved | WP gaps (backup) |
| `niagamas.com` | WP + Cloudflare | dns-txt client-approved | WP gaps (CF variant) |
| `ingco.co.id` | CodeIgniter + PHP 7.4 + Hostinger | dns-txt client-approved | CodeIgniter gaps |
| `wp.alpha-ai.web.id` | WP (self-owned) | dns-txt lab-proof | WP cred-reuse chain |
| `alpha-ai.web.id` | Odoo (self-owned) | dns-txt lab-proof | Odoo cred-reuse chain |
| `spectranet.com.ng` | WP + Apache (Nigeria ISP) | dns-txt client-approved (pending live verification) | WP gaps (Africa variant) |

##### T3-lite (real internet, no WAF/CF) — for new-stack playbook testing

| Target | Stack | Auth | Use for |
|--------|-------|------|---------|
| `demo.testfire.net` | JSP/Tomcat | public-test (IBM Alfresco demo) | GAP-001 JSP playbook |
| `testaspnet.vulnweb.com` | ASP.NET/IIS | public-test (Acunetix) | GAP-001 ASP.NET playbook |
| `testasp.vulnweb.com` | Classic ASP | public-test (Acunetix) | GAP-001 Classic ASP playbook |
| `testphp.vulnweb.com` | PHP | public-test (Acunetix) | GAP-001 PHP playbook |
| `juice-shop.herokuapp.com` | SPA/Angular | public-test (OWASP) | GAP-001 SPA playbook |
| `google-gruyere.appspot.com` | Python/App Engine | public-test (Google) | GAP-001 Python stack |

##### T3-origin (multi-IP / origin discovery lab)

| Target | Stack | Auth | Use for |
|--------|-------|------|---------|
| `direct.alpha-ai.web.id` | direct origin (Oracle) | dns-txt lab-proof | origin-direct reach |
| `vercel-lab.alpha-ai.web.id` | Vercel edge (static) | dns-txt lab-proof | GAP-018/038/042 multi-IP origin discovery |

- **How:**
  - **T3-real:** run the Conductor runner script (e.g. `run_solusibersama_conductor.py`,
    `run_quantum_conductor.py`) on Oracle ARM64.
  - **T3-lite/T3-origin:** run targeted handler probes against the public or
    multi-IP target to validate the specific GAP fix. These are NOT full
    Conductor runs and do NOT prove WAF/CF evasion.
- **Speed:**
  - T3-real: 5-15 minutes. Real HTTP, real LLM, real WAF responses.
  - T3-lite: 1-2 minutes. Real HTTP, no LLM, no WAF.
  - T3-origin: 1-2 minutes. Real DNS + HTTP, no WAF.
- **Pass criteria:**
  1. Fix produces expected finding on real target (not just lab).
  2. No new bugs introduced (check for cycling, junk crawl, false positives).
  3. Run completes without timeout (Bug #34 check).
  4. OMEGA report includes the new finding (end-to-end proof).

### When to use lab vs real target

| Scenario | Use lab | Use real target |
|----------|---------|-----------------|
| Unit test handler logic | ✅ Tier 1 | ❌ |
| Test handler fires in autonomous path | ✅ Tier 2 | ❌ |
| Test handler works with real WAF/CF | ❌ | ✅ Tier 3 |
| Test handler works with real plugin versions | ❌ | ✅ Tier 3 |
| Test for cycling/waste | ✅ Tier 2 (faster) | ✅ Tier 3 (confirm) |
| Test Beta cred-reuse chain | ✅ Tier 2 (chain-lab) | ✅ Tier 3 (alpha-ai) |
| Regression check after fix | ✅ Tier 1+2 | ❌ (too slow) |

**Rule:** Tier 1 + Tier 2 for every fix. Tier 3 for fixes that touch:
- WAF/CF evasion (real WAF behavior differs from lab)
- Version extraction (real plugin versions differ from lab)
- Cred-reuse chain (real credentials differ from lab)
- Any fix that claims "field-proven"

### Phase exit criteria (testable, per-stack, completeness-checked)

#### Phase 2 (Alpha/SCOUT) — exit criteria

A phase is "sealed" only when ALL pass on Oracle ARM64, for 2+ stacks:

```
[ ] ALPHA-1: Alpha detects tech_stack for each target stack
    - WP target → tech_stack includes "wp"
    - Odoo target → tech_stack includes "odoo"
    - Laravel target → tech_stack includes "laravel"
    Test: Tier 2 (vuln.wp.lab + vuln.odoo.lab + laravel-vuln.lab)

[ ] ALPHA-2: Alpha extracts version for detected stack
    - WP → WP version + plugin list + versions (GAP-053)
    - WP + WC → WooCommerce version (GAP-052)
    - Odoo → Odoo version (already works)
    Test: Tier 2 + Tier 3 (solusibersama for WP, quantum for Odoo)

[ ] ALPHA-3: Alpha extracts user/email if stack has user enum endpoint
    - WP → USER nodes with username + email + roles (GAP-054)
    - Odoo → no REST user enum (acknowledged, not a gap)
    Test: Tier 2 (vuln.wp.lab) + Tier 3 (solusibersama)

[ ] ALPHA-4: Alpha fetches universal recon (all stacks)
    - Security headers audited (GAP-055)
    - robots.txt + sitemap fetched (GAP-056)
    - JS secrets extracted (GAP-058)
    - Cookie flags audited (GAP-059)
    - TLS/MX/SPF/DMARC checked (GAP-062)
    Test: Tier 2 + Tier 3 (any target)

[ ] ALPHA-5: Alpha does NOT cycle (Bug #34 fixed)
    - 0 duplicate tool calls across targets in same engagement
    - Run completes without timeout
    Test: Tier 2 (multi-target lab) + Tier 3 (solusibersama/quantum)

[ ] ALPHA-6: Alpha does NOT crawl content pages (Bug #37 fixed)
    - 0 probes on product/blog/category/about/contact pages
    - Only security-relevant paths enqueued for non-WP hosts
    Test: Tier 2 (odoo.lab) + Tier 3 (quantum)

[ ] ALPHA-7: FP < 20% AND FN < 30% (false negative check added)
    - FP: Alpha claims finding that doesn't exist
    - FN: Alpha misses finding that lab ground_truth.yaml says exists
    Test: Tier 2 (lab with ground_truth.yaml)

[ ] ALPHA-8: Field-proven on 2+ real targets with DIFFERENT stacks
    - WP target: solusibersama.co.id OR bernofarm.com
    - Odoo target: quantum-laboratories.com OR alpha-ai.web.id
    Test: Tier 3
```

#### Phase 3 (Beta/STRIKE) — exit criteria

```
[ ] BETA-1: Beta succeeds on WP target with leaked creds
    - cred_reuse chain: leak → DB password → wp-login → admin
    Test: Tier 2 (chain-lab) + Tier 3 (alpha-ai.web.id)

[ ] BETA-2: Beta succeeds on Odoo target with default creds (if fresh install)
    - OdooAccessTool: admin/admin → uid > 0
    Test: Tier 2 (vuln.odoo.lab with fresh install)

[ ] BETA-3: Beta fails gracefully when 0 creds + 0 users
    - Returns FAILED (not crash), OMEGA produces honest report
    Test: Tier 2 (hardened.odoo.lab) + Tier 3 (quantum)

[ ] BETA-4: Beta tries ALL applicable tools (not just first one)
    - ToolRegistry.ranked() returns all tools with applies_to() > 0
    - Each tool is tried until one succeeds or all fail
    Test: Tier 1 (unit test ToolRegistry) + Tier 2

[ ] BETA-5: Lockout governor fires on repeated failures
    - CredentialLockoutGovernor caps attempts per username per host
    Test: Tier 1 (unit test governor) + Tier 2

[ ] BETA-6: OdooAccessTool has JSON-RPC fallback (GAP-067 fixed)
    - XML-RPC blocked → JSON-RPC fallback to /web/session/authenticate
    Test: Tier 2 (waf.odoo.lab if exists) + Tier 3 (quantum behind CF)

[ ] BETA-7: Field-proven on 2+ real targets with DIFFERENT stacks
    - WP: alpha-ai.web.id (cred-reuse chain)
    - Odoo: quantum-laboratories.com (default creds OR cred-reuse)
    Test: Tier 3
```

#### Phase 4 (Gamma/ANCHOR) — exit criteria (NOT STARTED)

```
[ ] GAMMA-1: ToolComposer + blast-radius gate complete
[ ] GAMMA-2: Gamma skeleton — first exploitation primitive
[ ] GAMMA-3: DeepSeek generate→verify→refine payload loop
[ ] GAMMA-4: §12.36 OFFENSIVE_APPROVED auth gate live
[ ] GAMMA-5: Field-proven on self-owned target (alpha-ai.web.id)
```

#### Phase Omega/Report — exit criteria (report-honesty gate)

> The report is where false assurance actually reaches the client. Alpha/Beta
> completeness gates do NOT cover it — this section closes that meta-gap
> (ADR §12.62 Coverage-Honesty Doctrine).

```
[ ] OMEGA-1: report emits a Coverage & Methodology section — tested / not_run /
    blocked / capability_absent + engagement not_assessed list.        (GAP-153)
    Test: Tier 1 (test_omega_coverage) + Tier 2 (report on a lab run)

[ ] OMEGA-2: report NEVER emits an affirmative safety verdict from an absence.
    Forbidden-phrase test: "no vulnerabilities" / "system is safe" / "fully secure"
    / "is not vulnerable" absent.                              (§12.45 / §12.62)
    Test: Tier 1 (grep the rendered report)

[ ] OMEGA-3: every NEGATIVE credential result carries a methodology caveat
    (what WAS / was NOT tested), never a verdict.              (§12.45 / GAP-119)
    Test: Tier 1 + Tier 2

[ ] OMEGA-4: not_run == 0 for capability_present techniques on discovered surfaces
    that SHOULD fire — the coverage ledger as a RUNTIME wiring-gate (catches a
    capable-but-unfired technique = Lyndon #2 at report time).
    Test: Tier 2 (lab run → assert no capable technique left not_run)

[ ] OMEGA-5: every POSITIVE Finding is cross_verified + proof-backed (payability
    binary; anti-#3). A Finding with no proof artifact is never constructed.
    Test: Tier 1 (roaster) + Tier 3 (field-prove)

[ ] OMEGA-GOV: techniques.yaml single-source integrity — every catalog run_event is a
    real EventType; every capability_absent links a gap_ref (anti-#7 drift).
    Test: Tier 1 (test_coverage_catalog_integrity)
```

### Bug categorization (when bugs emerge during testing)

Every bug discovered during testing MUST be registered in `docs/BUGS_AND_GAPS.md`
with one of these categories:

| Category | Code | Description | Example |
|----------|------|-------------|---------|
| **RECON_MISS** | RM | Alpha doesn't capture data that's available in the response | GAP-052 (WC version not extracted) |
| **DEAD_CODE** | DC | Handler exists but never fires in autonomous path | GAP-053 (wp_plugins handler never called) |
| **DATA_DISCARD** | DD | Alpha fetches response but discards available fields | GAP-054 (WP REST user email dropped) |
| **TRANSPORT_MISMATCH** | TM | Tool speaks wrong protocol for target stack | GAP-067 (OdooAccessTool only XML-RPC, no JSON-RPC) |
| **CYCLING_WASTE** | CW | Agent re-probes same URLs or crawls irrelevant pages | Bug #34 (cycling), Bug #37 (junk crawl) |
| **FALSE_SUCCESS** | FS | Agent reports "done" but data is incomplete | Phase 2 "sealed" with missing plugin list |
| **ROUTING_GAP** | RG | Router doesn't dispatch to correct agent or pivot | GAP-051 (RECON_EXHAUSTED pivot not built) |
| **WIRING_ISLAND** | WI | Capability proven in runner but not in autonomous path | Reach capabilities in runner only |
| **EXIT_CRITERIA_WEAK** | EC | Exit criteria too weak to catch the gap | "non-empty" instead of "complete for 2 stacks" |
| **STACK_SPECIFIC** | SS | Gap only affects one stack (WP, Odoo, Laravel, Spring) | GAP-057 (WP XML-RPC), GAP-064 (Odoo XML-RPC) |
| **UNIVERSAL** | UN | Gap affects all stacks | GAP-055 (security headers, all targets) |

### Bug registration template

```markdown
## Bug #NN / GAP-NNN — [title]

- **Status**: OPEN / CLOSED / RETRACTED
- **Priority**: P0 / P1 / P2 / P3
- **Category**: RM / DC / DD / TM / CW / FS / RG / WI / EC / SS / UN
- **Discovered during**: Tier 1 / Tier 2 / Tier 3 / field run / code review
- **Target**: lab host / real target name / N/A
- **What**: [description]
- **Evidence**: [output excerpt or query result]
- **Affected files**: [file:line]
- **Proposed fix**: [description]
- **Test contract**: [Tier 1 + Tier 2 + Tier 3 criteria]
- **Effort**: Low / Medium / High
```

### Slice workflow (how to execute one gap fix end-to-end)

```
1. REGISTER gap in BUGS_AND_GAPS.md (with category + test contract)
2. BRANCH: git checkout -b fix/gap-NNN-description
3. WRITE Tier 1 test (RED — test fails before fix)
4. IMPLEMENT fix (code change)
5. RUN Tier 1: pytest tests/phase_X/test_component.py -v
   → must pass (GREEN)
6. RUN quality gate: make check (ruff + mypy)
   → must pass
7. COMMIT + PUSH + PR
8. WAIT for CI + CodeRabbit review
9. MERGE
10. SYNC Oracle: git pull origin main
11. RUN Tier 2: Conductor autonomous path against lab stack
    → must produce expected finding
    → no regression (make test-phase0 + test-phase1)
    → no cycling, no junk crawl
12. RUN Tier 3: Conductor runner against real authorized target
    → must produce expected finding on real target
    → run completes without timeout
    → OMEGA report includes new finding
13. UPDATE gap status to CLOSED in BUGS_AND_GAPS.md
14. COMMIT docs update
15. NEXT slice
```

**Anti-Lyndon enforcement in this workflow:**
- #2 (dead code): Tier 2 tests autonomous path, not runner. If handler
  doesn't fire in Conductor → test fails → not sealed.
- #3 (false success): Tier 1 tests empty input → 0 nodes (no false positive).
  Tier 2 tests known input → expected node (no false negative).
- #5 (scope creep): One slice at a time. No parallel slices. Next slice
  only after current slice is Tier-3 sealed.
- #9 (Windows tests): All tiers run on Oracle ARM64. Windows results
  are NOT accepted.
- #17 (sophisticated avoidance): Tier 3 field-prove prevents "lab-sealed =
  done" avoidance. Lab-sealed < field-proven.

### Field-prove cadence

- **After every P0 slice:** Tier 3 on real target (must field-prove)
- **After every P1 slice:** Tier 3 on real target (must field-prove)
- **After P2/P3 slices:** Tier 2 sufficient (lab-sealed, field-prove batched)
- **Before phase seal:** ALL slices must be Tier-3 sealed for 2+ stacks
