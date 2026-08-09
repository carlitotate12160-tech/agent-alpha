> CANONICAL SOURCE: bugs + GAPs + build order. strategic_gaps_roadmap.md = leverage-narrative view (derived).

# Bug List & Architectural GAPs — Index

This document is the compact index. Detailed English bug descriptions are in `docs/BUGS.md`; raw engagement logs are in `docs/BUGS_AND_GAPS_APPENDIX.md`.

- **Bug catalogue (English):** `docs/BUGS.md` (local only — contains real target names, not committed)
- **Raw engagement logs:** `docs/BUGS_AND_GAPS_APPENDIX.md` (local only — contains raw engagement output, not committed)
- **Architecture decisions:** `docs/ADR.md` §12.27–§12.34

The priority matrix, recommended fix order, GAP classification, and GAP build order remain below.

## Priority Matrix

| # | Bug | Priority | Effort | Blocks |
|---|-----|----------|--------|--------|
| 1 | CDN crawl loop | DONE | Low | — |
| 10 | HTTP 415 not classified | FIXED | Low | WP recon |
| 11 | Crawl not discriminating | **DONE** (via objective path) | Medium | LLM token waste |
| 14 | default_creds rule greedy (Laravel) | FIXED | Low | DeepSeek analysis |
| 2 | Odoo rule greedy | FIXED | Low | DeepSeek analysis |
| 6 | Idempotency blocks LLM | FIXED | Medium | DeepSeek analysis |
| 13 | WP rule mismatch (Cloudways) | High | Low | WP recon |
| 3 | Report not persisted | High | Medium | Client deliverable |
| 5 | No report endpoint | High | Low | Client deliverable |
| 15 | Trailing slash dedup | Medium | Low | Crawl noise |
| 12 | Same page crawled repeatedly | Medium | Low | Crawl noise |
| 4 | Graph not rebuilt from event store | Medium | Medium | Report re-generation |
| 7 | Engagement memory not persisted | Medium | Medium | Cross-engagement learning |
| 8 | Passive discovery not enqueued | Medium | Low | Subdomain coverage |
| 9 | URL backslash not normalized | Low | Low | Crawl noise |
| 17 | Apache mod_autoindex sort URL explosion | High | Low | Crawl noise + LLM waste |
| 18 | Cloudflare JS challenge (200) not classified | High | Medium | CF-protected target recon | **DONE** (PR #188) |
| 19 | Response classifier status-only, no body-content | Medium | Medium | CDN/WAF challenge detection | **DONE** (PR #188) |
| 20 | Identical body dedup — same CDN page analyzed N times | Medium | Low | LLM token waste | **DONE** (PR #188) |
| 16 | Runner script `Report.chains` AttributeError | Low | Low | Local runner scripts |
| 21 | LLM-tier tool re-selection (exclude_tools not passed to LLM) | High | Medium | LLM token waste, tool starvation |
| 22 | Beta FAILED → chain halts (noop), Omega never dispatched | **RESOLVED** | Low | Report never generated on failed access |
| 23 | Beta next_recommended always GAMMA even on FAILED | **RESOLVED** | Low | Advance logic receives GAMMA but status=FAILED → noop |
| 24 | response_classifier `challenge-platform` false positive on CF-proxied sites | High | Low | All CF-proxied sites misclassified as CHALLENGE | **FIXED** |
| 25 | DefaultCredsTool ignores harvested USER nodes — only tries hardcoded creds | **RESOLVED** | Medium | Beta can't spray discovered usernames |
| 26 | Generic blind probing causes excessive 404s → WAF/CF block | **High** | Medium | Agent blocked before finding anything | **IN PROGRESS (Phase 4 Recon/Evasion Overhaul, Slices 1-6)** |
| 26 | StealthPacer gate inverted (code exists, default OFF) | **High** | Low | CF bot detection → wp-json challenged → 0 users → 0 creds → Beta no dispatch |
| 27 | Sensitive files probed before legitimate endpoints | Medium | Low | CF bot detection from .env probes blocks wp-json access |
| 28 | Origin-direct generic homepage not detected | Medium | Low | Origin returns homepage for all paths → 0 findings from origin-direct |

## Recommended Fix Order

1. Bug #10 (HTTP 415) — DONE (PR #180, commit 56056f9).
2. Bug #18 (CF JS challenge 200) + Bug #19 (body-content classifier) + Bug #20
   (identical body dedup) — stop token burn on CF-protected targets.
   — **DONE**: Bug #18/#19 fixed in PR #188 (`Verdict.CHALLENGE` + body-marker
   detection + optional `headers` param). Bug #20 fixed in PR #188 (SHA-256
   body hash dedup in scout). R2 follow-up: marker tiering (STRONG/WEAK) +
   curated-header dedup key — tests pinned RED in PR #188.
3. Bug #14 (default_creds rule) + Bug #2 (Odoo rule) — same pattern: greedy rules
   with page-wide markers. Fix together: make rules match only on specific forms/URLs.
   — **DONE**: Bug #14 fixed in PR #181 (indicator narrowing). Bug #2 fixed in PR #186
   (two-rule split: coarse `odoo_fingerprint` seeds frontier, narrow `odoo_dbmanager_probe`
   fires only on `master_pwd`/`list_db`). F1 double-recon also eliminated in PR #186
   (`process_odoo_dbmanager_hit` classifies already-fetched body, no HTTP client).
4. Bug #11 (crawl not discriminating) — priority queue + depth limit + path filter.
   — **DONE**: Fixed via objective path scoring in scout agent (deterministic v1).
5. Bug #6 (idempotency) — after #14 and #2 are fixed, idempotency no longer blocks the LLM.
   — **DONE**: Fixed in PR #181 (`decide_excluding` + `_ran_campaigns`) and confirmed
   stable in PR #186 (`odoo_fingerprint` recorded as run-once campaign).
6. Bug #13 (WP rule Cloudways) — partially addressed by Bug #10 fix, and Bug #18
   (CF challenge) is now resolved in PR #188. Bug #13 is fully resolved.
7. Bug #15 (trailing slash) + Bug #12 (fragment dedup) — quick win, URL normalization.
8. Bug #19 (body-content classifier) — generalize Bug #18 for other CDNs (Sucuri,
   Imperva, Akamai). After Bug #18 pattern is proven.
   — **DONE**: Fixed in PR #188 (CHALLENGE_BODY_MARKERS covers Sucuri, Incapsula,
   Imperva, Akamai + CHALLENGE_HEADER_HINTS for corroboration).
9. Bug #5 (report endpoint) — quick win, endpoint only.
10. Bug #3 (report persist) — requires #5 for the endpoint.
11. Bug #8 (passive discovery enqueue) — quick win.
12. Bug #4 (graph rebuild from event store) — medium effort, enables #3 and #7.
13. Bug #7 (engagement memory persist) — requires #4 for graph rebuild.
14. Bug #9 (URL backslash normalization) — cleanup, low effort, low impact.
15. Bug #17 (Apache mod_autoindex sort URL explosion) — filter sort query params in `_extract_hrefs()`, quick win.
16. Bug #16 (runner script `Report.chains`) — fix local runner scripts so they do not crash at the end.
17. ~~Bug #21 (LLM-tier tool re-selection)~~ — **CLOSED #196** (pass `exclude_tools` to LLM tier + post-filter + contract guard).

---

## Bug #21: LLM-tier Tool Re-selection (exclude_tools Not Passed to LLM)

- **Status**: CLOSED #196 (fixed: exclude_tools forwarded to LLM tier with prompt instruction + post-filter + contract guard)
- **Priority**: High
- **Effort**: Medium
- **Blocks**: LLM token waste, tool diversification

### Root Cause

`LLMOrchestrator.decide_excluding()` in `agent_alpha/llm/orchestrator.py` passes `exclude_tools` to the **RULE tier** (`decide_rule_only`) but **NOT** to the **LLM tier** (`_build_tool_select_messages`). When the rule tier is skipped (tool already ran), the LLM tier is invoked without any knowledge of which tools have already been run this engagement. DeepSeek therefore re-selects the same tool on every page that shares a fingerprint (e.g. `odoo_dbmanager_probe` on every Odoo page).

### Evidence

Live-fire test against `quantum-laboratories.com` (Odoo-based pharmaceutical site):

| Page | Tool Selected | Tier |
|------|--------------|------|
| `therapeutic-class-medical-devices` | `odoo_dbmanager_probe` | single_llm |
| `medical-devices` | `odoo_dbmanager_probe` | single_llm |
| `research-and-development` | `generic_http_probe` | single_llm |
| `production` | `generic_http_probe` | single_llm |
| `quality-control` | `odoo_dbmanager_probe` | single_llm |

Before the Bug #2/#6 rule-tier fix: 100% `odoo_dbmanager_probe` on every page (rule-tier starvation, never reached LLM).
After the Bug #2/#6 rule-tier fix: rule tier correctly skips `odoo_dbmanager_probe`, but LLM tier still re-selects it on ~60% of pages because it has no `exclude_tools` context.

### Impact

- **Token waste**: DeepSeek API call per page, selecting a tool that was already run and will produce 0 new graph nodes.
- **Tool starvation**: Other recon tools (`laravel_debug_probe`, `wp_config_probe`, `js_secret_probe`, `git_exposure_probe`, `backup_file_probe`) never get selected by the LLM.
- **Reduced coverage**: Alpha does not diversify tool selection across pages with the same fingerprint.

### Affected Files

- `agent_alpha/llm/orchestrator.py:96-97` — `decide_excluding` calls `_build_tool_select_messages(observation)` without `exclude_tools`
- `agent_alpha/llm/orchestrator.py:116-140` — `_build_tool_select_messages` does not accept `exclude_tools` parameter

### Proposed Fix (not yet implemented)

**Option A (prompt-level)**: Pass `exclude_tools` to `_build_tool_select_messages`, add system prompt instruction: "The following tools have ALREADY been run this engagement and must NOT be selected again: {excluded_str}. Choose a DIFFERENT tool from the catalog."

**Option B (programmatic post-filter)**: After LLM returns a tool decision, check if the selected tool is in `exclude_tools`. If yes, either:
- Re-query the LLM with a stronger instruction, or
- Fallback to `generic_http_probe` (safe default that always produces useful graph data)

**Option C (both)**: Prompt-level instruction (A) + programmatic enforcement (B) as safety net — LLMs are not reliable at following negative constraints.

**Recommended**: Option C — defense in depth. Prompt instruction reduces waste, post-filter guarantees correctness.

### Cross-reference

- Bug #2 (Odoo rule greedy) — same symptom, different tier. Bug #2 fix addressed RULE tier; Bug #21 is the LLM tier variant.
- Bug #6 (Idempotency blocks LLM) — Bug #2/#6 fix unblocked the LLM tier, but the LLM tier itself has no exclusion awareness.

---

## Bug #22: Beta FAILED → Chain Halts, Omega Never Dispatched

- **Status**: RESOLVED
- **Priority**: High
- **Effort**: Low
- **Blocks**: Report never generated when Beta fails to gain access
- **Resolved in**: `agent_alpha/conductor/router.py:132-134` + `agent_alpha/conductor/advance.py:138-141`
- **Verified by**: `tests/phase_4/test_router.py:test_alpha_failed_routes_omega`, `tests/phase_3/test_conductor_advance.py:test_bug22_failed_with_omega_dispatches`, `tests/phase_3/test_conductor_advance.py:test_bug22_blocked_with_omega_dispatches`
- **Field-proven**: Both quantum-laboratories.com and bernofarm.com engagements dispatched OMEGA after Alpha handoff (eng_8906b966 seq=99, eng_7b20a815 seq=113). Reports generated successfully.

### Root Cause

`decide_advance()` in `agent_alpha/conductor/advance.py:132` checks `if status != a2a_pb2.COMPLETE → noop`. When Beta returns `status=FAILED` (no access proven), the chain halts completely — no agent is dispatched, including Omega (the read-only reporter).

Omega is a **read-only reporter** that requires no auth tier and performs no offensive action. There is no reason Omega should not run when an earlier agent fails — Alpha's findings (vuln nodes, asset nodes, graph edges) are already persisted and reportable.

### Evidence

E2E test against `quantum-laboratories.com` (residential IP, Odoo e-commerce):
- Alpha found `odoo_dbmanager_exposed` vulnerability (confidence 0.85) + 110 graph nodes
- Beta attempted `OdooAccessTool` (XML-RPC default creds) + `DefaultCredsTool` → all FAILED (no default creds work)
- Beta returned `status=FAILED, next_recommended=GAMMA`
- `decide_advance`: `status != COMPLETE → noop` → chain stopped
- Omega never dispatched → no report generated via autonomous path

### Impact

- **No report on failed access**: Client receives nothing when Beta can't gain access, even though Alpha found valid vulnerabilities
- **Wasted recon effort**: Alpha's 110 graph nodes + vuln finding never reach the report
- **Silent failure**: Engagement appears to "just stop" with no output

### Affected Files

- `agent_alpha/conductor/advance.py:132` — `decide_advance` returns noop on non-COMPLETE status
- `agent_alpha/agents/beta/strike.py:517` — `_build_handoff_message` always sets `next_recommended=a2a_pb2.GAMMA`

### Proposed Fix

**Option A (advance logic)**: In `decide_advance`, add rule: if `status != COMPLETE` and `next_recommended` is an offensive agent (GAMMA/DELTA/EPSILON), fallback to OMEGA for reporting.

**Option B (Beta handoff)**: In `_build_handoff_message`, set `next_recommended=OMEGA` when `status=FAILED` instead of `GAMMA`.

**Option C (both)**: Option B is more precise (Beta knows it failed, should recommend reporter). Option A is defense-in-depth (advance logic doesn't trust agent's recommendation blindly).

**Recommended**: Option C — Beta sets next=OMEGA on FAILED, advance logic also falls back to OMEGA for any non-COMPLETE status where next_recommended is offensive-tier.

### Cross-reference

- Bug #23 (Beta next_recommended always GAMMA) — related root cause
- ADR §12.20 — advance logic design; does not explicitly address FAILED → Omega path

---

## Bug #23: Beta next_recommended Always GAMMA Regardless of Status

- **Status**: RESOLVED
- **Priority**: Medium
- **Effort**: Low
- **Blocks**: Advance logic receives GAMMA but status=FAILED → noop
- **Resolved in**: `agent_alpha/conductor/router.py:132-134` — `route_next` now returns `a2a_pb2.OMEGA` for `FAILED`/`BLOCKED` statuses regardless of Beta's recommendation
- **Verified by**: `tests/phase_4/test_router.py:test_alpha_failed_routes_omega`

### Root Cause

`Beta._build_handoff_message()` in `agent_alpha/agents/beta/strike.py:517` unconditionally sets `next_recommended=a2a_pb2.GAMMA`. This is correct when Beta succeeds (Gamma exploits the access), but wrong when Beta fails — there is nothing for Gamma to exploit.

When Beta fails, the engagement should still produce a report (Omega) from Alpha's recon findings. Recommending GAMMA on failure causes `decide_advance` to receive a non-COMPLETE status with an offensive-tier next agent → noop (chain halts).

### Evidence

```python
# strike.py:517 — always GAMMA, regardless of status
next_recommended=a2a_pb2.GAMMA,
```

### Impact

- Chain dead-ends on Beta failure (see Bug #22)
- No report generated for engagements where access isn't proven

### Affected Files

- `agent_alpha/agents/beta/strike.py:517` — hardcoded `next_recommended=GAMMA`

### Proposed Fix

```python
# When FAILED, recommend OMEGA (reporter) not GAMMA (exploit)
next_recommended = a2a_pb2.GAMMA if status == a2a_pb2.COMPLETE else a2a_pb2.OMEGA
```

### Cross-reference

- Bug #22 (chain halts on FAILED) — direct consequence of this bug
- ADR §12.20 — advance logic; `_is_forward_transition` allows OMEGA from any agent

---

## Bug #24: response_classifier `challenge-platform` False Positive on CF-Proxied Sites

- **Status**: FIXED
- **Priority**: High
- **Effort**: Low
- **Blocks**: All CF-proxied sites misclassified as CHALLENGE

### Root Cause

`CHALLENGE_STRONG_MARKERS` in `agent_alpha/recon/response_classifier.py` included `"challenge-platform"`. Cloudflare injects this string into **all proxied sites** via its analytics/beacon script (`/cdn-cgi/challenge-platform/scripts/jsd/main.js`), not just challenge/interstitial pages. This caused every CF-proxied site with real content to be misclassified as `Verdict.CHALLENGE`.

### Evidence

E2E test against `quantum-laboratories.com` (residential IP, Odoo e-commerce behind CF):
- Before fix: 21 WAF_BLOCKED events, 0 NodeDiscovered, 0 graph nodes, 14.6s duration — Alpha saw every page as CF challenge
- After fix: 5 WAF_BLOCKED events (real blocks on .bak paths), 110 NodeDiscovered, 2 graph nodes, 224.7s duration — Alpha crawled real content, DeepSeek analyzed pages, persisted graph

Direct verification: `https://quantum-laboratories.com/web/database/manager` returns HTTP 200 with 51KB Odoo DB manager page containing `challenge-platform` in CF analytics script — not a challenge page.

### Impact

- **Complete recon failure on CF-proxied sites**: Every page classified as CHALLENGE → WAF_BLOCKED → no crawling, no LLM analysis, no graph nodes
- **No findings possible**: Alpha never reads page content, never detects Odoo/WP/Laravel fingerprints
- **Affects all CF clients**: Any target behind Cloudflare with default analytics injection

### Fix Applied

Removed `challenge-platform` from `CHALLENGE_STRONG_MARKERS`. Added body-size guard: `challenge-platform` only triggers CHALLENGE when body < 5KB (interstitial page size). Real content pages (> 5KB) with CF analytics script classify as OK.

### Affected Files

- `agent_alpha/recon/response_classifier.py:55-76` — `CHALLENGE_STRONG_MARKERS` + `_CHALLENGE_PLATFORM_MARKER` + `_CHALLENGE_MAX_INTERSTITIAL_BODY`
- `agent_alpha/recon/response_classifier.py:138-156` — `_is_challenge()` with body-size guard

### Tests

27/27 pass (`test_cf_challenge_no_llm.py`, `test_response_classifier.py`, `test_transport_resilience.py`). No regressions.

### Cross-reference

- Bug #18/#19 (CF challenge classification) — same area; this is a follow-up false positive from the original fix
- ADR §12.27 — CHALLENGE verdict and body-marker detection

---

## Bug #25: DefaultCredsTool Ignores Harvested USER Nodes — Only Tries Hardcoded Creds

- **Status**: RESOLVED — Fixed by GAP-015 (`UserDerivedCredsTool`, derive-not-spray)
- **Priority**: Medium (downgraded from High — resolved)
- **Effort**: Medium
- **Blocks**: Beta can't credential-spray discovered usernames from Alpha recon

### Root Cause

`DefaultCredsTool` uses a hardcoded `_DEFAULT_CREDENTIALS` dictionary (`default_creds.py:62-95`) with generic pairs like `admin/admin`, `root/root`. It does **not** read `graph_store` for USER nodes harvested by Alpha (e.g. via `wp_rest_user_disclosure` which found 9 usernames on solusibersama.co.id).

`CredReuseTool` also doesn't help — it requires CREDENTIAL nodes (with `secret_ref` from vault), not USER nodes. USER nodes only carry `username` + `slug`, no password.

The result: Alpha discovers 9 valid WordPress users (`admin`, `ahmadsahbana`, `dani`, `inggit`, `jodhi69`, `kurniawan`, `nanda`, `sam`, `vita`), but Beta only tries `admin/admin` and `admin/password` — 7 usernames are completely ignored.

### Evidence

Re-run engagement `eng_0c3fd380` on solusibersama.co.id (2026-07-30, post-PR #296):

```
[ALPHA] Findings: 3 (3 vuln, 0 cred)
  - vuln:solusibersama.co.id:wp_rest_user_disclosure — 9 users
  - vuln:solusibersama.co.id:wp_version_disclosure — WordPress 6.7.5
  - vuln:solusibersama.co.id:woocommerce_exposed

[BETA] applicators count=4
[BETA]   applicator[0]: target=https://solusibersama.co.id (WpLoginApplicator)
[BETA]   applicator[1]: target=https://solusibersama.co.id/wp-login.php (WpLoginApplicator)
[BETA]   applicator[2]: target=https://solusibersama.co.id (HttpFormApplicator)
[BETA]   applicator[3]: target=https://solusibersama.co.id/wp-login.php (HttpFormApplicator)
[BETA] Done in 15.5s — status: FAILED, proofs: 0
```

Beta tried 10 credential pairs (8 generic + 2 WP-specific, deduplicated) across 4 applicators, but **none used the 8 harvested usernames** (ahmadsahbana, dani, inggit, jodhi69, kurniawan, nanda, sam, vita).

### Impact

- **Missed access**: Target may have weak password on non-admin user (e.g. `dani/dani`, `vita/password`) — Agent-Alpha never tries
- **Wasted recon**: Alpha's `wp_rest_user_disclosure` finding produces 9 USER nodes that Beta never consumes
- **False negative**: Engagement reports "no access" when credential spray on harvested usernames might succeed
- **Competitor gap**: Strix and other tools spray harvested usernames; Agent-Alpha only tries known defaults

### Affected Files

- `agent_alpha/tools/internal/access/default_creds.py:62-95` — `_DEFAULT_CREDENTIALS` hardcoded, `_build_credential_list()` doesn't accept graph_store
- `agent_alpha/tools/internal/access/cred_reuse.py` — requires CREDENTIAL nodes (vault), not USER nodes
- `agent_alpha/agents/beta/strike.py` — no tool bridges USER nodes → credential attempts

### Proposed Fix

See **GAP-015** below for the detailed design (Opsi A: `cred_spray` tool baru).

### Cross-reference

- GAP-015 (cred_spray tool) — the fix for this bug
- GAP-013 (Credential pattern mutation, ADR §12.34) — related: pattern mutation from harvested creds, but requires cred_spray as prerequisite for username harvesting
- Bug #22 (Beta FAILED → chain halts) — Bug #25 is a root cause of Beta FAILED status

---

## Bug #26: Generic Blind Probing Causes Excessive 404s → WAF/CF Block

- **Status**: OPEN
- **Priority**: High
- **Effort**: Medium
- **Blocks**: Agent blocked by WAF/CF before finding anything

### Root Cause

Agent-Alpha's `run_recon` seeds `WELL_KNOWN_LEAK_PATHS` (27+ paths) blindly against every target regardless of tech stack. For a WordPress target behind Cloudflare, this means 27 sequential 404 requests to paths like `/.env`, `/.git/config`, `/composer.json`, `/server-status` — most irrelevant to WP. Cloudflare's rate-based protection triggers after ~10-15 rapid 404s from the same IP, blocking all subsequent requests including the ones that would have succeeded.

### Evidence

Lab test against `wp.alpha-ai.web.id` (WordPress behind Cloudflare):

| Metric | Value |
|--------|-------|
| Total paths probed (generic) | 27 |
| 404 responses | ~22 |
| 403/WAF block after | ~15th request |
| WP-relevant paths in generic list | ~9 (WP_CONFIG_BACKUP_PATHS) |
| Non-WP paths wasted | ~18 |

Tiered backup path test reduced WP backup probes from 9 → 3 (67% reduction), but the remaining 18 non-WP generic paths still generate 404 noise.

### Impact

- **WAF/CF block**: Agent gets blocked before reaching high-value paths
- **Wasted requests**: 18+ irrelevant 404s per target for single-stack sites
- **False negatives**: Paths that would return 200 are never reached because WAF blocks first
- **OPSEC failure**: 27 rapid 404s from datacenter IP = obvious scanner pattern

### Affected Files

- `agent_alpha/agents/alpha/scout.py:224-242` — `run_recon` seeds all `WELL_KNOWN_LEAK_PATHS` generically
- `agent_alpha/config/constants.py:275-304` — `WELL_KNOWN_LEAK_PATHS` is a flat list with no stack filtering
- `agent_alpha/agents/alpha/scout.py:1240-1254` — `_handle_capability_fingerprint` seeds stack-specific paths only AFTER fingerprint (too late — generic paths already seeded)

### Proposed Fix (multi-layer)

**Layer 1 — Pre-intel (0 request to target)**:
- Query Wayback CDX for archived URLs → only probe paths that historically returned 200
- Query crt.sh + HackerTarget for subdomains → expand scope passively
- See GAP-016 (Wayback pre-intel)

**Layer 2 — Soft-404 baseline calibration**:
- Before probing real paths, send 1-2 requests to random non-existent paths (e.g. `/{random_uuid}`)
- Record response: status code, body size, body hash
- Any subsequent response matching this baseline = soft-404, skip (even if status 200)
- References: OpenDoor auto-calibration, Capsaicin smart calibration, fck403 baseline fingerprinting

**Layer 3 — Stack-aware tiered probing**:
- Phase 1: Universal paths only (3-5 paths: `/.env`, `/.git/HEAD`, `/robots.txt`)
- Phase 2: After fingerprint detected → stack-specific TIER1 (3 paths)
- Phase 3: Only if TIER1 all 404 → TIER2 (6 paths)
- Already tested in lab: 67% WP 404 reduction

**Layer 4 — Request pacing (anti-rate-limit)**:
- Interleave probe requests with legitimate requests (homepage, API index, readme)
- Add stochastic jitter (Gaussian distribution, 100-300ms)
- Max 5 requests per burst, 30s pause between bursts
- References: Capsaicin jitter engine, rootea stealth Burp config, APT low-and-slow tradecraft

**Layer 5 — WAF detection + circuit breaker**:
- If 3 consecutive 403s or 429s from same host → pause probing
- Switch to origin-direct (if authorized) or back off
- References: OpenDoor WAF guard stop condition, Capsaicin circuit breaker

### Cross-reference

- GAP-016 (Wayback pre-intel) — Layer 1 fix
- GAP-007 (OSINT / external context) — related passive intel
- GAP-012 (Adaptive evasion) — Layer 4/5 fix
- Bug #18/#24 (CF challenge classification) — WAF detection already improved
- ADR §12.33 (IP reputation doctrine) — datacenter ASN limitations

---

GAP di dokumen ini TIDAK diperlakukan seragam terhadap ADR:

- **Ember A — wiring-backlog (BUKAN entri ADR; ADR sudah menyebut, hanya belum di-wire):** ~~GAP-002 (Scratchpad/SessionStore, §12.11)~~ — **CLOSED #192**, GAP-003 (IntelligenceBase, §8c/§12.11), GAP-005 (PolicyEnforcer, §8o-5/§12.20-22 — **slice-1 DONE #184, slice-2 OPEN**), GAP-006 (Graph analytics→decision, §1/§6 — **slice-1 DONE #184, slice-2 OPEN**). Kerjakan sebagai wiring task; jangan tambah entri ADR (duplikasi).
- **Ember B — entri ADR baru (blueprint memang bolong):** GAP-004+010 → **§12.29**, GAP-008 → **§12.30**, GAP-009 → **§12.31**, GAP-011 → **§12.32**, GAP-012 → **§12.33**, GAP-013 → **§12.34**.
- **Ember C — sudah future-phase (BUKAN GAP baru):** GAP-001 (playbook coverage, tunduk rubric §12.26), GAP-007 (OSINT, dekat §8o-3/§8e).

**Prasyarat keras semua GAP kognitif:** Bug #18/#19/#20 (§12.27 CHALLENGE/dedup) — graph bersih dulu, agar planner & curiosity tak teracuni junk.

---

## GAP-001: Missing Tools & Playbooks for Broader Coverage

- **Status**: OPEN
- **Severity**: Medium — no playbook for ASP.NET/JSP/SPA/Classic ASP; Alpha only effective on Laravel/WP/Odoo

### Context

Testing Alpha → Beta chain terhadap target legal publik (2026-07-14):

| Target | Reachable | Alpha Findings | Root Cause |
|--------|-----------|---------------|------------|
| `demo.testfire.net` (JSP/Altoro) | Yes | 1 asset, 0 creds, 0 vuln | Tidak ada playbook JSP/Tomcat login; login disabled |
| `juice-shop.herokuapp.com` (SPA/Angular) | Yes | 1 asset, 0 creds, 0 vuln | SPA catch-all 200; tidak ada tool SPA/API |
| `testaspnet.vulnweb.com` (ASP.NET/IIS) | Yes | 1 asset, 0 creds, 0 vuln | Tidak ada playbook ASP.NET |
| `testasp.vulnweb.com` (Classic ASP) | Yes | 1 asset, 0 creds, 0 vuln | Tidak ada playbook Classic ASP |
| `testphp.vulnweb.com` (PHP/Acunetix) | No (blocked) | N/A | Connection reset (firewall/ISP) |
| Mock lokal (`chain_lab_app.py`) | Yes | 2 creds, 1 vuln | **CHAIN PROVEN** — match pola Laravel |

Alpha hanya efektif untuk tech stack yang sudah dikenali: Laravel, WordPress, Odoo.
Target dengan tech stack lain (ASP.NET, JSP, SPA, Classic ASP) menghasilkan 0 findings.

### Playbook YAML yang Harus Ditambahkan

| # | Playbook File | Match Indicators | Tool | Priority | Fase |
|---|---------------|-----------------|------|----------|------|
| 1 | `aspnet_viewstate.yaml` | `body_contains: "__VIEWSTATE"`, `header_contains: {name: "X-AspNet-Version", value: ""}`, `header_contains: {name: "X-Powered-By", value: "ASP.NET"}` | `aspnet_viewstate_probe` (baru) | 10 | recon |
| 2 | `jsp_tomcat_login.yaml` | `body_contains: "j_security_check"`, `body_contains: "org.apache.catalina"`, `header_contains: {name: "Server", value: "Apache-Coyote"}` | `generic_http_probe` | 15 | recon |
| 3 | `directory_listing.yaml` | `body_contains: "Index of /"`, `body_regex: '<a href="[^"]*">[^<]*</a>.*\\d{4}-\\d{2}-\\d{2}'` | `directory_listing_probe` (baru) | 12 | recon |
| 4 | `spa_fingerprint.yaml` | `body_regex: '<app-root|<ng-view|<router-outlet|react-root|__NEXT_DATA__'`, `body_contains: "webpack"`, `body_contains: "chunk-"` | `spa_probe` (baru) | 15 | recon |
| 5 | `rest_api_discovery.yaml` | `body_regex: '"/api/|"/rest/'`, `body_contains: "swagger-ui"`, `body_contains: "openapi"` (sudah ada `surface_openapi.yaml` tapi hanya match Swagger JSON, bukan SPA yang reference API) | `api_endpoint_probe` (baru) | 15 | recon |
| 6 | `sql_error_disclosure.yaml` | `body_regex: 'SQL syntax.*mysql|SQLSTATE|ORA-[0-9]|Microsoft SQL Server|PostgreSQL.*ERROR|SQLite3::query'`, `body_contains: "sql syntax error"`, `body_contains: "unclosed quotation mark"` | `sqli_probe` (baru) | 8 | recon |
| 7 | `xss_reflected.yaml` | `body_regex: '(value|echo|print).*\\$_GET|\\$_REQUEST|\\$_POST'`, `body_contains: "alert(1)"` (reflected payload detection) | `xss_probe` (baru) | 8 | recon |
| 8 | `error_stacktrace.yaml` | `body_contains: "Traceback (most recent call last)"`, `body_contains: "at java.lang"`, `body_contains: "NullPointerException"`, `body_contains: "System.NullReferenceException"`, `body_regex: 'PHP (Fatal error|Warning|Notice)'`, `body_contains: "Call to a member function"` | `error_stacktrace_probe` (baru) | 10 | recon |
| 9 | `sensitive_file_exposure.yaml` | `body_contains: "DB_PASSWORD"`, `body_contains: "DB_USERNAME"`, `body_regex: 'password\\s*[:=]\\s*["\'][^"\']+["\']'`, `body_contains: "api_key"`, `body_contains: "AWS_ACCESS_KEY"`, `body_contains: "private_key"` | `secrets_probe` (baru, generalisasi dari `laravel_debug_probe`) | 5 | recon |
| 10 | `http_auth_form_generic.yaml` | `body_contains: 'type="password"'` (sudah ada di `default_credentials_login.yaml`), **TAMBAH**: `body_regex: '<input[^>]*name=["\']?(uid|user|uname|tfUName|username|email|log)["\']?'` | `default_creds` | 10 | access |

### Tool Implementasi yang Harus Ditambahkan

| # | Tool Name | Fase | Deskripsi | File Target |
|---|-----------|------|-----------|-------------|
| 1 | `aspnet_viewstate_probe` | recon | Extract `__VIEWSTATE`, `__EVENTVALIDATION` dari ASP.NET pages. Detect debug mode, viewstate tampering surface, event validation bypass. | `tools/internal/recon/aspnet_viewstate.py` |
| 2 | `directory_listing_probe` | recon | Parse Apache/nginx directory listing (`Index of /`). Extract file links, detect sensitive files (`.bak`, `.sql`, `.zip`, `.env`, config files). Follow subdirectories 1 level deep. | `tools/internal/recon/dir_listing.py` |
| 3 | `spa_probe` | recon | Detect SPA frameworks (Angular, React, Vue, Next.js). Extract API endpoints from JS bundles (`main.js`, `chunk-*.js`). Parse `__NEXT_DATA__`, `window.__INITIAL_STATE__`, Angular router config. | `tools/internal/recon/spa_fingerprint.py` |
| 4 | `api_endpoint_probe` | recon | Discover REST API endpoints from: Swagger/OpenAPI JSON, GraphQL introspection, SPA JS bundle analysis, common API path probing (`/api/`, `/rest/`, `/v1/`, `/v2/`). | `tools/internal/recon/api_discovery.py` |
| 5 | `sqli_probe` | recon | Detect SQL injection indicators: error-based (MySQL, PostgreSQL, Oracle, MSSQL, SQLite error messages), boolean-based (response diff), time-based (delay detection). Input vector: URL params, form fields. | `tools/internal/recon/sqli_detect.py` |
| 6 | `xss_probe` | recon | Detect reflected/stored XSS: input reflection in HTML context, JS context, attribute context. Test with canary payload. Check CSP headers. | `tools/internal/recon/xss_detect.py` |
| 7 | `error_stacktrace_probe` | recon | Detect stack traces and error pages: Java (NullPointerException, ClassNotFoundException), Python (Traceback), PHP (Fatal error, Warning), .NET (NullReferenceException, Yellow Screen of Death), Ruby (NoMethodError). Extract file paths, library versions, internal structure. | `tools/internal/recon/stacktrace.py` |
| 8 | `secrets_probe` | recon | General-purpose secret detection (generalisasi dari `laravel_debug_probe`). Scan HTML/JS/config files for: DB credentials, API keys, AWS keys, private keys, JWT secrets, OAuth tokens. Pattern-based + entropy analysis. | `tools/internal/recon/secrets_scan.py` |
| 9 | `json_api_applicator` | access | CredentialApplicator untuk JSON API auth (paralel dengan `HttpFormApplicator`). POST JSON body `{"email":"...","password":"..."}` atau `{"username":"...","password":"..."}`. Verify via JWT token, session cookie, atau response body. | `tools/internal/access/json_api_applicator.py` |
| 10 | `generic_form_applicator` | access | CredentialApplicator yang auto-detect form field names dari HTML (parse `<input>` tags, identify username/password fields by type attribute, bukan hardcoded `username`/`password`). Support custom field names: `uid`/`passw`, `tfUName`/`tfUPass`, `log`/`pwd`, dll. | `tools/internal/access/generic_form_applicator.py` |

### RECON_TOOL_CATALOG yang Harus Diperluas

`agent_alpha/config/constants.py` — `RECON_TOOL_CATALOG` saat ini (7 tool):
```python
RECON_TOOL_CATALOG: frozenset[str] = frozenset({
    "laravel_debug_probe",
    "wp_config_probe",
    "js_secret_probe",
    "odoo_dbmanager_probe",
    "git_exposure_probe",
    "backup_file_probe",
    "generic_http_probe",
})
```

Harus ditambah menjadi (17 tool):
```python
RECON_TOOL_CATALOG: frozenset[str] = frozenset({
    # existing
    "laravel_debug_probe",
    "wp_config_probe",
    "js_secret_probe",
    "odoo_dbmanager_probe",
    "git_exposure_probe",
    "backup_file_probe",
    "generic_http_probe",
    # new — recon
    "aspnet_viewstate_probe",
    "directory_listing_probe",
    "spa_probe",
    "api_endpoint_probe",
    "sqli_probe",
    "xss_probe",
    "error_stacktrace_probe",
    "secrets_probe",
    # new — access (untuk Beta)
    "json_api_applicator",
    "generic_form_applicator",
})
```

### HttpFormApplicator yang Harus Diperluas

`agent_alpha/tools/internal/access/applicator.py` — `HttpFormApplicator.apply()` saat ini hardcoded:
```python
auth_resp = self._http_client.post(
    target, data={"username": username, "password": secret}
)
```

Target publik yang tested semua punya custom field names:
- `demo.testfire.net`: `uid` / `passw`
- `testaspnet.vulnweb.com`: `tbUsername` / `tbPassword`
- `testasp.vulnweb.com`: `tfUName` / `tfUPass`
- WordPress: `log` / `pwd` (sudah ada `WpLoginApplicator` terpisah)

**Solusi**: `generic_form_applicator` yang parse HTML form, detect field names by `type="text"` + `type="password"`, dan POST dengan field names yang benar.

### Prioritas Implementasi

| Priority | Item | Impact | Effort |
|----------|------|--------|--------|
| **P0** | `generic_form_applicator` | Buka Beta chain untuk semua target dengan form login custom | Medium — parse HTML, detect input fields |
| **P0** | `directory_listing_probe` | Apache/nginx dir listing adalah finding paling umum (dnr.id, Juice Shop `/ftp/`) | Low — parse HTML links |
| **P1** | `secrets_probe` (generalisasi) | Generalisasi dari `laravel_debug_probe` ke tech stack apapun | Medium — pattern matching |
| **P1** | `error_stacktrace_probe` | Stack trace = information disclosure, ada di banyak target | Medium — pattern matching |
| **P1** | `json_api_applicator` | Buka Beta chain untuk SPA/REST API target (Juice Shop) | Medium — JSON POST + JWT verify |
| **P2** | `spa_probe` | SPA detection + API endpoint extraction dari JS bundles | High — JS parsing |
| **P2** | `api_endpoint_probe` | REST API discovery dari Swagger/GraphQL | Medium |
| **P2** | `sqli_probe` | SQL injection detection | High — multi-DB support |
| **P2** | `xss_probe` | XSS detection | High — context-aware |
| **P3** | `aspnet_viewstate_probe` | ASP.NET specific | Medium |
| **P3** | Playbook YAML baru (10 file) | Match logic untuk tool baru | Low — YAML only |

### Testing Validation

Setelah implementasi, re-test terhadap target yang sama:

| Target | Expected After Fix |
|--------|-------------------|
| `demo.testfire.net` | `generic_form_applicator` → Beta login dengan `uid`/`passw` field names |
| `juice-shop.herokuapp.com` | `spa_probe` → detect Angular; `api_endpoint_probe` → find `/rest/user/login`; `json_api_applicator` → Beta login dengan JSON body |
| `testaspnet.vulnweb.com` | `aspnet_viewstate_probe` → detect ASP.NET; `error_stacktrace_probe` → find stack traces; `generic_form_applicator` → Beta login dengan `tbUsername`/`tbPassword` |
| `testasp.vulnweb.com` | `generic_form_applicator` → Beta login dengan `tfUName`/`tfUPass`; `sqli_probe` → detect SQLi di forum parameters |
| Mock lokal | Tetap CHAIN PROVEN (regression check) |

---

## GAP-002: Scratchpad/SessionStore — CLOSED

- **Status**: CLOSED — Wired in PR #192 (2026-07-18)
- **Severity**: High — agent berjalan tanpa working memory (RESOLVED)
- **Files**:
  - `agent_alpha/memory/session.py` — `SessionStore` Protocol, `InMemorySessionStore`, `RedisSessionStore` (239 lines, fully implemented)
  - `agent_alpha/conductor/main.py` — tidak ada instantiation `SessionStore`
  - `agent_alpha/conductor/recon_runner.py` — tidak menerima `SessionStore`
  - `agent_alpha/conductor/execute_agent.py` — tidak menerima `SessionStore`
  - `agent_alpha/agents/base.py:112` — `run_cognitive_loop` memanggil `agent.step({})` dengan context kosong
- **Resolution (PR #192)**: `SessionStore` wired into production path:
  - `main.py`: `_ensure_session()` helper + `session_store_for()` tenant-aware instantiation
  - `run_cognitive_loop`: `session_store` + `event_store` + `engagement_id` params; context carries scratchpad
  - `Alpha.scout`: `session_store` param, `_step_once` reads/writes scratchpad observations
  - `Beta.strike`: `session_store` param
  - `recon_runner`: `session_store` threaded through `build_recon_pipeline`
  - `execute_agent`: `session_store` passed to `agent_factory`
  - Scratchpad snapshot to event store per step (`SCRATCHPAD_SNAPSHOTTED`)
  - Tests: `test_scratchpad_loop_wiring.py` (4 tests: accumulation, snapshot, backward-compat, tenant isolation)
- **Dampak**: Agent berjalan tanpa working memory. Inner monologue tidak di-persist. Resume step-level tidak mungkin. Setiap engagement mulai dari blank state — tidak ada scratchpad yang mengalir antar step.
- **Historical root cause (pre-fix)**: `SessionStore` Protocol + `InMemorySessionStore` + `RedisSessionStore` fully implemented di `memory/session.py` tapi tidak ada instantiation di conductor, recon_runner, execute_agent, atau agent manapun. `run_cognitive_loop` memanggil `agent.step({})` dengan context kosong.
- **Cross-reference**: ADR §12.11 (SessionMemory). Bug #7 (Engagement Memory tidak persist) — terkait tapi berbeda: SessionMemory = volatile scratchpad, EngagementMemory = persistent cross-engagement learning.

---

## GAP-003: IntelligenceBase — Protocol Saja, Semua Method Return InsufficientData

- **Status**: OPEN
- **Severity**: High — agent tidak belajar dari engagement sebelumnya
- **Files**:
  - `agent_alpha/memory/intelligence.py` — `IntelligenceBase` Protocol + `RecordBackedIntelligenceBase` (312 lines)
  - `agent_alpha/memory/engagement.py:187` — `tool_success_rates` selalu `{}` (comment: "Phase 2 scope")
  - `agent_alpha/tools/registry.py:37` — `ToolRegistry.ranked()` pakai static `applies_to(ctx)`, tidak baca IntelligenceBase
- **Root cause**: `IntelligenceBase` Protocol + `RecordBackedIntelligenceBase` ada di `memory/intelligence.py` (312 lines). `tool_success_rates` selalu `{}` — confirmed di `engagement.py:187` dengan comment: "Phase 2 scope". `_collect_tool_rates()` di `intelligence.py:295-311` selalu return `[]` terhadap live records. `ToolRegistry.ranked()` di `registry.py:37` pakai `applies_to(ctx)` — static, tidak baca IntelligenceBase. **Tidak ada caller yang wire IntelligenceBase ke tool selection atau orchestrator.**
- **Dampak**: Agent tidak belajar dari engagement sebelumnya. Tool selection tidak mempertimbangkan historical reliability, false positive rates, atau success rates. Setiap engagement menggunakan ranking tool yang sama regardless of past performance.
- **Proposed fix**:
  1. Implement `PostgresIntelligenceBase` yang query `engagement_memory` table untuk historical tool performance.
  2. Wire IntelligenceBase ke `ToolRegistry.ranked()` — ranking tool harus weighted oleh historical success rate + false positive rate.
  3. Wire IntelligenceBase ke `LLMOrchestrator.decide()` — LLM prompt harus include "tool X has 80% success rate on targets like this" context.
  4. Setelah engagement selesai, write tool outcome stats ke `engagement_memory` table.
- **Cross-reference**: ADR §12.11 (IntelligenceBase). Bug #7 (Engagement Memory tidak persist) — prerequisite: engagement memory harus persist dulu sebelum IntelligenceBase bisa query.

> **Catatan L2 — Confidence Calibration**: `ToolResult.confidence` (0.0-1.0) ada tapi never calibrated vs historical FP rates. Bug #2 (Odoo greedy) terjadi karena rule match = confidence tanpa kalibrasi. Wiring IntelligenceBase (GAP-003 fix) juga menyelesaikan confidence calibration — tool confidence harus weighted oleh historical FP rate dari IntelligenceBase.

---

## GAP-004: Planner/World Model — Moved to ADR §12.29

- **Status**: LOCKED in ADR §12.29 (2026-07-15)
- **Severity**: Critical
- **ADR Reference**: `docs/ADR.md` §12.29 *"Goal-directed cognition: Objective + Planner/World-Model + goal-completion"*
- **Summary**: Replaces the reactive 1-step cognitive loop with `EngagementObjective`, `Planner`/`Executor`, `WorldModel`, and a `GOAL_COMPLETED` stop condition.
- **Prerequisites**: ~~GAP-002 (scratchpad wiring)~~ ✅ CLOSED #192, Bug #18/#19/#20 (graph quality).
- **Note**: Full root-cause, proposed fix, and confidence notes are now in ADR §12.29.

---

## GAP-005: PolicyEnforcer — Partially Wired (slice-1 done, slice-2 OPEN)

- **Status**: PARTIALLY WIRED — slice-1 (blast-radius gate) DONE (#184), slice-2 (agent execution path) OPEN
- **Severity**: High — OPSEC, technique check, scope check masih dead code di production agent path
- **Files**:
  - `agent_alpha/conductor/policy.py` — `PolicyEnforcer` class (152 lines, fully implemented)
  - `agent_alpha/conductor/main.py:62` — `policy = PolicyEnforcer()` instantiated
  - `agent_alpha/conductor/main.py` — `policy` variable tidak pernah direferensikan lagi setelah line 62
  - `agent_alpha/live_fire/wp_chain_runner.py:253` — `PolicyEnforcer` dipakai di live-fire test path (bukan production)
  - `agent_alpha/conductor/authorization.py` — `policy.yaml:7` mengkonfigurasi `blast_radius_gate_before: ["ANCHOR", "HUNTER", "SCOUT_HUNTER"]` — gate tidak di-enforce
- **Slice-1 DONE (PR #184)**: `PolicyEnforcer.gate_before_agents()` + `assess_blast_gate()` wired into `advance_engagement()` via `_assess_blast_gate_for_dispatch()`. Blast-radius gate now parks offensive-tier agents when blast severity ≥ threshold.
- **Slice-2 OPEN (agent execution path)**: `check_technique()`, `check_scope()`, `resolve_opsec_profile()` masih hanya dipanggil di `live_fire/wp_chain_runner.py:253` (test path). `policy = PolicyEnforcer()` di `main.py:63` instantiated tapi TIDAK di-pass ke `execute_agent()` atau `recon_runner`. Agent berjalan tanpa OPSEC/technique/scope guardrails.
- **Dampak**: OPSEC profile (rate limit, user-agent rotation, timing), technique check (blocked techniques), scope check (out-of-scope targets), time-window enforcement, human approval gating, blast-radius gate — semua dead code di production path. Agent berjalan tanpa safety guardrails yang sudah diimplementasi.
- **Proposed fix**:
  1. Pass `PolicyEnforcer` ke `execute_agent()` dan `recon_runner.run_recon_for_engagement()`.
  2. Sebelum setiap tool execution, call `policy.check_technique(mitre_id)` — reject jika violation.
  3. Sebelum setiap tool execution, call `policy.check_scope(target)` — reject jika out-of-scope.
  4. Resolve OPSEC profile via `policy.resolve_opsec_profile()` dan pass ke `HttpClient` — rate limit, user-agent, timing.
  5. Sebelum agent yang memerlukan blast-radius gate (ANCHOR, HUNTER, SCOUT_HUNTER), call `calculate_blast_radius()` — block jika severity > threshold.
  6. Call `policy.requires_human_approval()` untuk gate yang memerlukan approval.
- **Nuance**: Review mengatakan "tidak pernah dipanggil" — lebih tepat: "tidak ter-wire di production conductor/agent path, hanya dipakai di live-fire test runner."
- **Cross-reference**: ADR §12.20/21/22 (Policy-as-Code). GAP-006 (Graph Analytics) — blast-radius gate butuh `calculate_blast_radius()` yang juga tidak ter-wire.

> **Catatan L5 — Adversarial Reasoning (Game-Theoretic)**: OPSEC profile (GAP-005 fix) = static rate limit. Red-team nyata butuh defender response prediction: "jika saya eksploitasi ini, defender akan melihat alert X → patch endpoint Y → saya kehilangan akses Y." Ini bukan hanya OPSEC cost, tapi game-theoretic planning. Future enhancement setelah GAP-005 ter-wire.

> **Catatan L6 — Time-Window Awareness**: Temporal reasoning ("defender shift change jam 5pm", "maintenance window jam 2am") harus masuk ke PLAN, bukan hanya static rate limit. OPSEC profile saat ini = static config. Future enhancement: dynamic time-window awareness di planner (GAP-004) + policy enforcer (GAP-005).

---

## GAP-006: Attack Graph Analytics — Partially Wired (slice-1 done, slice-2 OPEN)

- **Status**: PARTIALLY WIRED — slice-1 (blast-radius → decision) DONE (#184), slice-2 (critical paths → planner) OPEN (needs GAP-004)
- **Severity**: Medium — blast-radius gate sudah aktif; critical paths untuk prioritisasi masih hanya di report
- **Files**:
  - `agent_alpha/graph/narrative.py:44-80` — `find_critical_paths()` (graph path-finding ASSET→DATA/ACCESS_LEVEL)
  - `agent_alpha/graph/narrative.py:83-137` — `calculate_blast_radius()` (BFS reachable nodes + HVT identification)
  - `agent_alpha/agents/omega/roaster.py:136` — `to_narrative()` → `_to_executive_narrative()` → calls `find_critical_paths()` + `calculate_blast_radius()`
  - `agent_alpha/conductor/execute_agent.py` — rebuilds graph from event stream tapi tidak call analytics functions
  - `agent_alpha/conductor/authorization.py` — `policy.yaml:7` configures `blast_radius_gate_before` tapi gate tidak di-enforce
- **Root cause**: `find_critical_paths()` dan `calculate_blast_radius()` fully implemented di `narrative.py`. Grep di seluruh codebase: 5 file match — `narrative.py` (definisi + 2 call di `_to_executive_narrative`), 3 test files. **Call chain production:** `Omega.generate_report()` → `to_narrative()` → `_to_executive_narrative()` → `find_critical_paths()` + `calculate_blast_radius()`. **TIDAK ada call dari conductor, execute_agent, agent step, atau decision-making path manapun.** Blast-radius gate (`policy.yaml:7`) tidak aktif.
- **Dampak**: Graph analytics hanya untuk laporan, bukan untuk mengarahkan agent. Agent tidak tahu critical paths atau blast radius saat membuat decision. Blast-radius gate (ADR §1) tidak aktif — agent bisa execute technique dengan blast radius tinggi tanpa human approval.
- **Proposed fix**:
  1. Call `find_critical_paths()` setelah graph rebuild di `execute_agent()` — pass hasil ke planner/agent sebagai context.
  2. Call `calculate_blast_radius()` sebelum agent yang memerlukan gate (ANCHOR, HUNTER, SCOUT_HUNTER) — block jika severity > threshold.
  3. Wire blast-radius gate ke `PolicyEnforcer.requires_human_approval()` — jika blast radius > threshold, require approval.
  4. Use critical paths untuk prioritisasi target dalam planner (GAP-004 fix) — HVT yang reachable via critical path harus diprioritasi.
- **Nuance**: Review mengatakan "tidak pernah dipanggil di conductor/agent path" — ini BENAR. Tapi perlu ditambahkan: `find_critical_paths` dan `calculate_blast_radius` DIPANGGIL di report generation path (`Omega.generate_report()` → `to_narrative()` → `_to_executive_narrative()`). Jadi mereka bukan dead code — mereka **ter-wire ke report, tidak ter-wire ke decision**.
- **Cross-reference**: ADR §1 (blast-radius gate). GAP-005 (PolicyEnforcer) — blast-radius gate butuh PolicyEnforcer untuk enforce. GAP-004 (Planner) — critical paths harus masuk ke planner untuk prioritisasi.

---

## GAP-007: OSINT / External Context Gathering — Tidak Ada Sama Sekali

- **Status**: OPEN
- **Severity**: Medium — agent langsung HTTP probe target tanpa intelligence gathering
- **Files**:
  - `agent_alpha/conductor/recon_runner.py:218-236` — `build_passive_discovery()` hanya crt.sh CT log lookup
  - `agent_alpha/recon/passive_discovery.py` — `PassiveDiscovery.discover()` hanya query crt.sh untuk subdomain enumeration
  - Tidak ada module untuk pastebin, GitHub secrets, LinkedIn employee info, breach databases, social engineering recon
- **Root cause**: `recon_runner.py` langsung mulai dengan crt.sh subdomain discovery → HTTP probe. Grep `OSINT|open.source.intel|social.engineer|phishing|pastebin|breach|github.*secret` di seluruh `agent_alpha/` = **0 hasil**. ADR §8o-3 (Knowledge Ingestion Pipeline) me-reference CVE feeds, exploit-db, nuclei templates, MITRE ATT&CK updates — itu adalah **threat-intel RAG**, bukan traditional OSINT (pastebin, GitHub secrets, LinkedIn, breach databases). ADR §8e me-reference "Phishing Impact Test" sebagai engagement profile, tapi bukan OSINT gathering phase.
- **Dampak**: Agent tidak melakukan intelligence gathering sebelum technical recon. Tidak mencari leaked credentials di pastebin/GitHub, tidak profiling employee untuk social engineering, tidak checking breach databases. Human red teamer selalu mulai dengan OSINT — agent langsung HTTP probe.
- **Proposed fix**:
  1. Tambah fase OSINT sebelum recon: query public breach databases, GitHub secret scanning, pastebin monitoring.
  2. Feed OSINT findings ke graph sebagai CREDENTIAL atau ASSET nodes (pre-engagement intelligence).
  3. Wire OSINT results ke planner (GAP-004) — "saya sudah tahu credential X dari breach DB, coba credential reuse dulu."
  4. Employee profiling untuk phishing impact test profile (ADR §8e).
- **Cross-reference**: ADR §8o-3 (Knowledge Ingestion — threat-intel RAG, BUKAN OSINT). ADR §8e (Phishing Impact Test profile). GAP-004 (Planner) — OSINT findings harus masuk ke planner untuk prioritisasi.

---

## GAP-008: Curiosity-Driven Exploration — Moved to ADR §12.30

- **Status**: LOCKED in ADR §12.30 (2026-07-15)
- **Severity**: Medium
- **ADR Reference**: `docs/ADR.md` §12.30 *"Bounded curiosity-driven exploration"*
- **Summary**: Adds deterministic `curiosity_score(observation)` in ORIENT, bounded to existing capabilities and scope, feeding the planner/scratchpad.
- **Prerequisites**: GAP-004 (planner), ~~GAP-002 (scratchpad)~~ ✅ CLOSED #192.
- **Note**: Full rationale and envelope rules are now in ADR §12.30.

---

## GAP-009: Cross-Validation Between Tools — Moved to ADR §12.31

- **Status**: LOCKED in ADR §12.31 (2026-07-15)
- **Severity**: Medium
- **ADR Reference**: `docs/ADR.md` §12.31 *"Cross-tool verification tiers"*
- **Summary**: Introduces `self_verified` vs `cross_verified` tiers; high-FP tools require an independent second opinion before a finding is confirmed.
- **Prerequisites**: GAP-003 (IntelligenceBase for FP rates).
- **Note**: Full decision details are now in ADR §12.31.

---

## GAP-010: Goal-Completion Detection — Moved to ADR §12.29

- **Status**: LOCKED in ADR §12.29 (2026-07-15)
- **Severity**: Medium
- **ADR Reference**: `docs/ADR.md` §12.29 *"Goal-directed cognition: Objective + Planner/World-Model + goal-completion"* (Decision 4)
- **Summary**: Adds `GOAL_COMPLETED` to `StopReason`; completion criteria flow from planner-defined objectives.
- **Prerequisites**: GAP-004 (planner/objective definition).
- **Note**: Full rationale and criteria are now in ADR §12.29.

---

## GAP-011: Authenticated Crawl / Post-Access Re-Discovery — Moved to ADR §12.32

- **Status**: LOCKED in ADR §12.32 (2026-07-15)
- **Severity**: Medium
- **ADR Reference**: `docs/ADR.md` §12.32 *"Post-access authenticated re-recon"*
- **Summary**: After Beta obtains `valid_credentials`, re-crawl with an active session; diff unauth vs auth surfaces. Exploitation remains Gamma-gated.
- **Prerequisites**: GAP-004 (planner), GAP-010 (next-objective handling).
- **Note**: Full boundary rules are now in ADR §12.32.

---

## GAP-012: Adaptive Evasion — Moved to ADR §12.33

- **Status**: LOCKED in ADR §12.33 (2026-07-15)
- **Severity**: Medium
- **ADR Reference**: `docs/ADR.md` §12.33 *"Adaptive evasion"*
- **Summary**: On repeated `BLOCKED`, switch rate/UA/TLS-fingerprint techniques; implement `cf_curl_cffi` template; wire through PolicyEnforcer/Planner.
- **Prerequisites**: GAP-005 (PolicyEnforcer wiring), GAP-004 (planner re-plan).
- **Note**: Full technique boundaries are now in ADR §12.33.

---

## GAP-013: Credential Pattern Mutation Within Engagement — Moved to ADR §12.34

- **Status**: LOCKED in ADR §12.34 (2026-07-15)
- **Severity**: Low-Medium
- **ADR Reference**: `docs/ADR.md` §12.34 *"Within-engagement credential mutation"*
- **Summary**: `CredentialPatternMutator` extracts patterns from harvested credentials, generates bounded variants, and tries them only after literal reuse fails and under the lockout governor.
- **Prerequisites**: ~~GAP-002 (scratchpad pattern tracking)~~ ✅ CLOSED #192.
- **Note**: Full mutation and gating rules are now in ADR §12.34.

---

## GAP-014: Fan-Out Parallel Worker Wiring — Shape A Not Wired

- **Status**: OPEN
- **Severity**: Medium — multi-target engagements run sequential, ~Nx latency vs design intent
- **ADR Reference**: `docs/ADR.md` §12.13 *"Agent scaling model — Hybrid orchestrated fan-out"*

### Context

ADR §12.13 LOCKED a hybrid orchestrated fan-out design: Conductor partitions a phase's scope into bounded `WorkUnit`s, enqueues them via Celery, up to `MAX_WORKERS_PER_ROLE` execute in parallel. Per-role caps are defined in `constants.py` (alpha=10, beta=4, gamma=2, delta=4, epsilon=4).

The **interface** was built and tested (C3 — `FanOutDispatcher`, `WorkUnit`, `partition_targets`, `DispatchResult` — Oracle-green). PROGRESS_TRACKER.md marked C6b as DONE. However, PROGRESS_TRACKER.md is **superseded** by docs/Session_Handoff.md, which does not mention fan-out. The **runtime wiring** was never completed.

### Root Cause

`recon_runner.py:286-287` runs a sequential loop inside a single Celery worker:

```python
# Shape B (single-task): one worker scans all targets in sequence
for url in targets:
    pipeline.alpha.run_recon(engagement_id, url)
```

`fanout.py:67` defines `EnqueueFn` as an injected callable, with comment: *"C6 wires `run_engagement_task.delay` here"* — but this wiring was never done. There is no `run_recon_unit_task` Celery task.

### Evidence

- `fanout.py` — `FanOutDispatcher` class exists, `partition_targets()` works, `dispatch()` validates gate + enqueues + emits events. But `EnqueueFn` is never wired to a real Celery `.delay()` call in production code.
- `recon_runner.py:246` — comment: *"Shape B (single-task): one worker scans all targets in sequence"*
- `constants.py:338-345` — caps defined (alpha=10, beta=4, gamma=2) but unused at runtime
- PROGRESS_TRACKER.md:88 — *"C6b — Per-unit fan-out execution + live-fire FP<20% (DONE)"* — but doc is superseded
- docs/Session_Handoff.md — no mention of fan-out or parallel workers

### Impact

- **N-target latency**: engagement with 5 targets takes ~5x longer than necessary (sequential vs parallel)
- **Wasted design**: `FanOutDispatcher`, `WorkUnit`, `DispatchResult`, `partition_targets`, per-role caps — all built and tested, but dead code in production
- **False done-status**: PROGRESS_TRACKER marked C6b DONE, but canonical doc (docs/Session_Handoff.md) doesn't track it, and code is sequential

### Affected Files

- `agent_alpha/conductor/recon_runner.py:286-287` — sequential loop, needs to call `FanOutDispatcher.dispatch()` instead
- `agent_alpha/conductor/fanout.py:67` — `EnqueueFn` needs wiring to `run_recon_unit_task.delay()`
- `agent_alpha/conductor/main.py` — needs new `run_recon_unit_task` Celery task (per-target recon)
- `agent_alpha/config/constants.py:338-345` — caps already defined, will be consumed once wired

### Proposed Fix

1. Add `run_recon_unit_task` Celery task in `main.py` — runs `alpha.run_recon()` for a single target, builds deps in-process (same pattern as `run_engagement_task`)
2. Wire `EnqueueFn` in `recon_runner.py` to `lambda unit: run_recon_unit_task.delay(unit.engagement_id, unit.tenant_id, unit.target)`
3. Replace sequential `for url in targets:` loop with `FanOutDispatcher.dispatch(partition_targets(targets, ...), cap=max_workers_for("alpha"))`
4. Aggregate: results flow back via EventStore (already designed — `WORK_UNIT_QUEUED` events, single-stream aggregation)

### Prerequisites

- None blocking — interface is built, caps are defined, Celery is wired. This is pure wiring debt.

### Cross-reference

- ADR §12.13 — design decision (LOCKED)
- PROGRESS_TRACKER.md C3/C6b — marked DONE (superseded doc)
- `fanout.py` — interface code (built, tested, unused at runtime)

---

## GAP-015: Credential Spray Tool — Harvested Usernames × Common Passwords

- **Status**: CLOSED — Implemented as `UserDerivedCredsTool` (derive-not-spray, not `cred_spray` with static password list)
- **Severity**: High — Beta can't use USER nodes from Alpha recon for credential spray
- **Related Bug**: Bug #25 (DefaultCredsTool ignores harvested USER nodes) — RESOLVED by this GAP
- **MITRE Technique**: T1110.001 (Password Guessing — bounded, derived) — NOT T1110.003 (Spraying)
- **Resolved in**: `agent_alpha/tools/internal/access/user_derived_creds.py` (243 lines)
- **Wired in**: `agent_alpha/agents/beta/strike.py:55,332-335` — imported + instantiated in Beta tool roster
- **Verified by**: `tests/phase_4/test_user_derived_creds.py` (13 tests, all pass), `agent_alpha/live_fire/gap015_field_prove.py` (field-prove runner)
- **Field-proven**: wp.alpha-ai.web.id lab engagement — Alpha enumerated `wpvuln` user, Beta derived candidates, `predictable_credential` vuln node minted

### Implementation (Actual — Derive-Not-Spray, NOT Opsi A)

The implemented approach differs from the original Opsi A proposal. Instead of a `cred_spray` tool with a static password list, the team built `UserDerivedCredsTool` with a **derive-not-spray** design contract:

- **NO static passwords** — candidates derived ONLY from username + registrable domain stem (via Public Suffix List)
- **Bounded** — max `USER_DERIVED_MAX_CANDIDATES_PER_USER` per account (no combinatorial blow-up)
- **Lockout-gated** — every submission passes through `CredentialLockoutGovernor` (§12.22 D2)
- **#6 compliance** — no duplication of `default_creds`' well-known defaults

**Candidate derivation** (`derive_login_candidates`):
```
username → [username, username+"123", domain_stem, domain_stem+"123"]
```
Example: `editor` on `bernofarm.com` → `["editor", "editor123", "bernofarm", "bernofarm123"]`

### Why Derive-Not-Spray (vs Opsi A)

| Criteria | Opsi A (cred_spray) | Actual (user_derived_creds) |
|----------|--------------------|-----------------------------|
| Static passwords | Yes (`admin`, `password`, `admin123`) | **NO** — anti-#3 (hardcoded guess ≠ credible finding) |
| #3 (no false positive) | Risk: static password hit = not a credible finding | ✅ Derived = context-specific, payable |
| #4 (derive-not-spray) | Spray (wordlist) | ✅ Derive (bounded, context-derived) |
| #6 (no duplication) | Overlaps with `default_creds` | ✅ Clean separation |
| MITRE technique | T1110.003 (Spraying) | T1110.001 (Password Guessing — bounded) |
| Lockout safety | Built-in | ✅ Built-in (GovernedApplicator) |
| Budget control | Max 3 pwd/user | ✅ `USER_DERIVED_MAX_CANDIDATES_PER_USER` |

### Files

- `agent_alpha/tools/internal/access/user_derived_creds.py` — tool implementation (243 lines)
- `agent_alpha/agents/beta/strike.py:55,332-335` — wired into Beta tool roster
- `tests/phase_4/test_user_derived_creds.py` — 13 tests (domain stem, derive logic, bounds, no static password, lockout gating, applies_to ranking, fallback roster, budget enforcement)
- `agent_alpha/live_fire/gap015_field_prove.py` — field-prove runner (end-to-end chain)
- `agent_alpha/tools/internal/access/cred_finding_catalog.py` — `CredFindingClass.PREDICTABLE_CREDENTIAL` finding class

### Original Design Proposals (Historical — Superseded by Implementation)

**Konsep**: Tool terpisah, MITRE T1110.003 (Password Spraying) — distinct dari T1078.001 (Default Accounts).

```
Alpha (USER nodes) ──→ cred_spray ──→ applicator roster ──→ wp-login.php
                         │
                         ├─ Baca USER nodes dari graph_store
                         ├─ Spray × common password list
                         ├─ Rate limit (lockout prevention)
                         └─ Return ToolResult (same shape as default_creds)
```

**Password list** (WP-aware):
```python
_SPRAY_PASSWORDS = [
    "admin", "password", "admin123", "wordpress",
    "changeme", "123456", "Password1", "wp-admin",
    # username-as-password (common WP mistake)
    # → dinamis: set(username.lower() for username in harvested)
]
```

**Safety**:
- Max 3 passwords per user (anti-lockout)
- Delay between attempts (configurable, default 2s)
- Stop on first success per user

**Pros**:
- Clean separation #6 — `default_creds` = "known defaults", `cred_spray` = "harvested usernames × common passwords"
- Distinct MITRE technique (T1110.003 vs T1078.001)
- Bisa di-rank terpisah di ToolRegistry (cred_spray > default_creds karena context-aware)
- Safety gate (rate limit) terisolasi di tool ini, tidak bocor ke default_creds

**Cons**:
- File baru + test baru + wiring di `strike.py`
- ~200 LOC implementation + ~150 LOC test

**Files affected**:
- `agent_alpha/tools/internal/access/cred_spray.py` (new)
- `agent_alpha/agents/beta/strike.py` (add to candidates)
- `tests/phase_3/test_cred_spray.py` (new)

### Design: Opsi B (Alternative) — Expand `DefaultCredsTool`

**Konsep**: `DefaultCredsTool` baca USER nodes dari graph, inject ke credential list.

```python
def _build_credential_list(tech_stack, graph_store=None):
    creds = list(_DEFAULT_CREDENTIALS["generic"])
    if graph_store:
        for node in graph_store.nodes_by_type(NodeType.USER):
            username = node.properties.username
            for pwd in _SPRAY_PASSWORDS:
                creds.append((username, pwd))
    return list(dict.fromkeys(creds))
```

**Pros**: Minimal code change (~30 LOC), reuse existing applicator infrastructure
**Cons**: Mix concept (#6 violation), wrong MITRE technique, no rate limit safety, budget explosion (9 users × 8 passwords × 4 applicators = 288 attempts)

### Design: Opsi C (Minimal) — Expand Password List Only

Hanya tambah password list di `_DEFAULT_CREDENTIALS[STACK_WP]`, tetap hanya untuk username `admin`.

**Pros**: ~5 LOC change
**Cons**: Tidak pakai harvested usernames — gap utama tidak tertutup

### Perbandingan

| Kriteria | Opsi A (cred_spray) | Opsi B (expand default_creds) | Opsi C (expand password list) |
|----------|-------------------|------------------------------|------------------------------|
| Pakai harvested usernames | ✅ Semua 9 | ✅ Semua 9 | ❌ Hanya admin |
| #6 (one concept per tool) | ✅ Clean | ❌ Mix | ✅ Tetap |
| MITRE technique correct | ✅ T1110.003 | ❌ T1078.001 untuk semua | ✅ T1078.001 |
| Rate limit / lockout safety | ✅ Built-in | ❌ Tidak ada | ❌ Tidak ada |
| Budget control | ✅ Max 3 pwd/user | ❌ Bisa meledak | ✅ Tetap kecil |
| Effort | ~350 LOC | ~80 LOC | ~5 LOC |
| ToolRegistry ranking | ✅ cred_spray > default_creds | ❌ Same tool | ❌ Same tool |

### Recommendation

**Opsi A** — `cred_spray` tool baru. Alasan:

1. **#6 compliance** — default_creds = "known defaults", cred_spray = "harvested usernames × common passwords". Concept berbeda.
2. **Safety** — password spraying butuh rate limit (lockout prevention). Kalau di-mix ke default_creds, safety gate bocor.
3. **ToolRegistry ranking** — cred_spray harus di-rank **di atas** default_creds (context-aware > blind). Kalau same tool, tidak bisa di-rank terpisah.
4. **Budget** — 9 users × N passwords × 4 applicators bisa meledak. Tool baru bisa punya budget logic sendiri (max 3 pwd/user, delay between attempts).

### Prerequisites

- None blocking — applicator roster already built (merged #296), USER nodes already persisted by `wp_rest_user_disclosure` handler.

### Cross-reference

- Bug #25 (DefaultCredsTool ignores harvested USER nodes) — the bug this GAP fixes
- GAP-013 (Credential pattern mutation, ADR §12.34) — cred_spray is prerequisite for pattern mutation (mutation needs harvested usernames to mutate from)
- ADR §12.34 — within-engagement credential mutation

---

## GAP-016: Wayback Machine Pre-Intel — Archive-Driven Probe Selection

- **Status**: OPEN
- **Severity**: Medium — Agent probes blind paths, causing 404 noise and WAF/CF blocks (Bug #26)
- **Effort**: Low-Medium (single module + CDX API query, no target interaction)

### Context

Agent-Alpha currently seeds `WELL_KNOWN_LEAK_PATHS` (27+ paths) blindly against every target. For single-stack targets (e.g. WordPress), 18+ paths are irrelevant and generate 404 noise that triggers WAF/CF rate-based blocking.

Wayback Machine CDX API provides archived URL history for any domain — **zero requests to target**. By querying the archive first, Agent-Alpha can:
1. Discover paths that historically returned 200 → probe only those
2. Detect plugins/themes from archived `/wp-content/plugins/*` paths → CVE lookup without crawling
3. Skip paths never seen in archive → reduce 404 noise
4. Fingerprint tech stack from archived content (WordPress, Laravel, etc.)

### Lab Evidence

Wayback CDX query for `bernofarm.com` (from Oracle server, 0 requests to target):

| Metric | Value |
|--------|-------|
| Total 200 URLs archived | ~1000+ |
| Plugins detected from archive | 7 (woocommerce, elementor-pro, elementor, forminator, wpforms-lite, akismet, advanced-product-labels-for-woocommerce) |
| Themes detected from archive | 1 (astra) |
| Sensitive paths found | `/wp-admin/admin-ajax.php` |
| `.env` / `.git` / `wp-config` in archive | 0 (skip these probes) |

For `wp.alpha-ai.web.id`: no archive exists (domain too new). Wayback is most effective for established domains.

### Industry Precedent

Wayback/archive recon is **standard tradecraft** in bug bounty and pentest, not APT-only:

| Tool | Wayback Integration | Type |
|------|---------------------|------|
| Burp Suite | `Wayback-Recon` extension | Commercial pentest |
| OWASP ZAP | `deja-vu` extension | Open source pentest |
| gau (GetAllURLs) | Wayback + CommonCrawl + OTX + URLScan | Bug bounty recon |
| waymore | Wayback + CommonCrawl + URLScan + VT + IntelligenceX | Bug bounty recon |
| TheTimeMachine | Wayback + backup detection + attack patterns | Bug bounty recon |
| chronos | Wayback OSINT framework (regex, jsluice, HTML, XML) | OSINT framework |
| Nuclei | ❌ No built-in (uses gau as input) | Scanner |
| Strix | ❌ None | AI pentest agent |
| CyberStrikeAI | ❌ None | AI pentest agent |
| Agent-Alpha | ❌ **Not yet** | AI pentest agent |

Agent-Alpha is behind Burp Suite and ZAP here. But with graph store + CVE catalog integration, it can go beyond: archive path → plugin detection → CVE lookup → graph node → Beta cred-reuse chain.

### Proposed Implementation

```python
# recon/wayback_discovery.py (proposed)

class WaybackDiscovery:
    """Query Wayback CDX API for archived URLs. Zero requests to target."""
    
    def query(self, domain: str) -> WaybackResult:
        """Query CDX API for domain, return archived paths + plugins + themes."""
        # GET https://web.archive.org/cdx/search/cdx?url={domain}&output=json
        #   &limit=2000&fl=original,statuscode&collapse=urlkey
        #   &matchType=domain&filter=statuscode:200
        # Parse → extract unique paths, detect plugins/themes from /wp-content/
        
    def priority_paths(self, domain: str) -> list[str]:
        """Return paths that historically returned 200 — probe only these."""
        
    def detected_plugins(self, domain: str) -> set[str]:
        """Return plugin slugs from archived /wp-content/plugins/ paths."""
```

Integration point: `scout.run_recon()` calls `WaybackDiscovery.query()` before seeding `WELL_KNOWN_LEAK_PATHS`. If archive returns paths, use those instead of generic list. If archive is empty (new domain), fall back to tiered probing.

### Limitations

- New domains have no archive (e.g. `wp.alpha-ai.web.id`)
- CDX API can be slow (10-60s for large domains)
- Archive may not include sensitive paths that were briefly exposed
- Some sites block Wayback crawler (no archive at all)
- Does not replace active probing — only informs which paths to probe

### Prerequisites

- None blocking — standalone module, no dependency on other GAPs
- Complements Bug #26 Layer 1 fix and GAP-007 (OSINT)

### Cross-reference

- Bug #26 (Generic blind probing → WAF/CF block) — Layer 1 fix
- GAP-007 (OSINT / external context) — Wayback is one OSINT source within this GAP
- Existing: `passive_discovery.py` (crt.sh), `origin_discovery.py`, `_discover_subdomains` (HackerTarget, OTX, VirusTotal) — Wayback extends this passive intel layer

---

## GAP-018: LiveOriginDiscovery Does Not Seed With In-Scope Siblings — Origin Discovery Fails When crt.sh Is Down

- **Status**: OPEN — wiring-debt registered in `tests/governance/test_wiring_gate.py` (ratchet: test fails when `seed_hosts` appears in `conductor/main.py`, forcing move to WIRED_REQUIRED)
- **Severity**: High — T4 origin-binding MOAT (CF-bypass proof) fails whenever crt.sh is down (flaky/often down)
- **Effort**: Low (2-file additive wiring: `origin_resolver.py` + `conductor/main.py`)

### Context (field-prove 2026-08-08, Oracle ARM64)

The integrated recon field-prove (`recon_integrated_field_prove.py`) drove `run_recon_for_engagement` with production wiring on self-owned alpha-ai.web.id. T1/T2/T5/T6 PASS; T4 (ORIGIN_BINDING_PROVEN) FAIL. Root cause from INFO log:

```
origin_resolver: crt.sh fetch failed for alpha-ai.web.id (seed_hosts may still yield)
origin_resolver: 0 CT subdomain(s) + 0 seed → 0 candidate host(s) for alpha-ai.web.id
```

`discover_origin_ips` has a `seed_hosts` parameter (in-scope authorized hostnames used as origin-candidate sources when crt.sh yields nothing — "a grey-cloud subdomain CT never logged is the #1 real origin leak" per its docstring). The gap015 runner proved the technique by calling `discover_origin_ips(..., seed_hosts=config.scope_domains)`. But the **production** wiring (`conductor/main.py` → `LiveOriginDiscovery(engagement_id, worker_auth)`) does NOT pass `seed_hosts` — so when crt.sh is down, origin discovery returns 0 candidates → no binding → T4 fails.

This is RUNNER-SEAL != AUTONOMOUS-WIRED for the seed_hosts technique (Lyndon #2-adjacent).

### Proposed Fix — two options (A is a subset of C; not exclusive)

**Current state of `discover_origin_ips`** (verified line 108-130): candidate hosts come
from ONLY two sources — (1) crt.sh subdomains (best-effort, fails when crt.sh down), and
(2) `seed_hosts` (in-scope authorized hostnames). The COMPOSED production path
(`CompositeOriginDiscovery` wrapping `LiveOriginDiscovery`) adds a third source: OTX
`origin_ip_candidates` unioned from `PASSIVE_INTEL_GATHERED` events. But `seed_hosts` is
the one NOT wired in production — `LiveOriginDiscovery(engagement_id, auth)` passes none.

**Opsi A — seed_hosts = scope.domains (low effort, proven, closes T4)**

1. `recon/origin_resolver.py`: `LiveOriginDiscovery.__init__` accepts `seed_hosts: Sequence[str] = ()`; `candidates()` passes it to `discover_origin_ips`.
2. `conductor/main.py`: pass `record.scope.domains` as `seed_hosts`.

`seed_hosts` comes from the engagement's VERIFIED scope — `record.scope.domains`, set by
`enable_recon(Scope(...))` and persisted in the `STATE_TRANSITIONED` event. In the lab
case: `[alpha-ai.web.id, wp.alpha-ai.web.id, laravel.alpha-ai.web.id, odoo.alpha-ai.web.id,
direct.alpha-ai.web.id]`. DNS-resolving wp/laravel yields 168.110.192.62 (non-CF origin) —
no crt.sh needed. Proven by gap015 runner (CHAIN PROVEN with crt.sh down).

Limitation: only covers domains explicitly in `scope.domains`. A CT-discovered subdomain
that is `is_in_scope` (wildcard match) but NOT in `scope.domains` is missed.

**Opsi C — reuse passive-stage subdomains from event stream (architecturally cleaner)**

Instead of `discover_origin_ips` fetching crt.sh AGAIN (duplicate of the passive stage's
CertSpotter→crt.sh→HackerTarget chain), read `in_scope_subdomains` from the
`PASSIVE_INTEL_GATHERED` events already written by the passive stage and use them as
candidate hosts. `LiveOriginDiscovery` reads events for the fronted_host's domain, extracts
`in_scope_subdomains`, and passes them as `seed_hosts` (alongside `scope.domains`).

1. `recon/origin_resolver.py`: `LiveOriginDiscovery.__init__` accepts `event_store` + `seed_hosts`; `candidates()` reads `PASSIVE_INTEL_GATHERED` for the domain, unions `in_scope_subdomains` into `seed_hosts`, passes all to `discover_origin_ips`.
2. `conductor/main.py`: pass `target_store` + `record.scope.domains` when constructing `LiveOriginDiscovery`.

Pros over A: (a) reuses the ROBUST 3-source chain (CertSpotter→crt.sh→HackerTarget) instead
of crt.sh-alone — crt.sh down is already handled gracefully in the passive stage; (b) no
duplicate crt.sh fetch (anti-waste, anti-#6 duplication); (c) broader candidate set — all
`in_scope` subdomains from passive, not just `scope.domains`.

Cons: more invasive (event_store into LiveOriginDiscovery, 2-3 files). Requires passive
stage to have run first (ordering OK — recon_runner runs passive before active).

**A vs C verdict**: A is the right IMMEDIATE fix (proven, low risk, closes T4 on the lab).
C is the right LONG-TERM fix (architecturally cleaner, no duplicate fetch, broader
coverage). They are NOT exclusive — C is a superset of A (`seed_hosts = scope.domains ∪
passive subdomains`). Recommended: A now (closes T4), C as a follow-up slice. When either
is wired, the wiring-debt test trips → move `seed_hosts` to WIRED_REQUIRED.

### Cross-reference

- §12.46 (Origin binding) — `seed_hosts` feeds `discover_origin_ips` candidate list
- GAP-015 — the runner that proved seed_hosts works (but production path doesn't use it)
- `recon_integrated_field_prove.py` — the field-prove that surfaced this gap (T4 FAIL)

---

## GAP-017: PassiveIntelMap Enrichment Dead-End — Consumer Not Wired

- **Status**: PARTIALLY — origin_ip_candidates consumer wired; protection_detected consumer (Slice A/B/C) still OPEN
- **Severity**: Medium — enrichment data written to event store but read by nobody
- **Effort**: Medium (3-slice fix: World Model ingestion, planner scoring, reach pivot)

### Context

§12.48 slice-3 fills `protection_detected`, `mx_records`, `nameservers` in `PassiveIntelMap`. Slice-4 adds CertSpotter subdomains. Slice-5 adds OTX origin-IP candidates + historical paths. But NO consumer reads these fields:

1. **World Model** does not ingest `PassiveIntelMap` — no protection awareness
2. **Planner** does not use `protection_detected` for scoring — Bug #26 stays OPEN
3. **`choose_reach()`** cannot pre-emptive pivot from passive intel — reactive only

### Proposed Fix (3 slices)

- **Slice A — World Model ingestion**: `passive_intel_map` → `world_model.py` (protection awareness)
- **Slice B — Planner scoring**: `protection_detected` → `planner.py` (adjust probe budget for CF-protected targets)
- **Slice C — Reach strategy pivot**: `origin_ip_candidates` → `reach_strategy.py` (pre-emptive origin-direct pivot)

### Prerequisites

- §12.48 slice-3/4/5 producer wired — DONE
- Consumer wiring = this GAP

### Cross-reference

- Bug #26 (Generic blind probing → WAF/CF block) — Layer 1/5 fix needs planner awareness
- GAP-007 (OSINT / external context) — passive intel is the OSINT layer
- §12.46 (Origin binding) — `origin_ip_candidates` feeds origin discovery
- §12.48 slice-3 — producer wired, consumer = this GAP

---

## GAP Priority & Build Order

Urutan fix GAP (terpisah dari Bug Priority Matrix dan Recommended Fix Order):

| # | GAP | Effort | Prerequisite | Dampak |
|---|-----|--------|-------------|--------|
| 1 | ~~GAP-002 (Scratchpad wiring)~~ | Low | — | **CLOSED #192** — Working memory untuk agent, prerequisite untuk GAP-004 ✅ |
| 2 | GAP-003 (IntelligenceBase wiring) | Low | Bug #7 (Engagement Memory persist) | Agent belajar dari engagement sebelumnya, fix confidence calibration |
| 3 | GAP-005 (PolicyEnforcer wiring) | Medium | — | **slice-1 DONE #184** (blast gate). slice-2 OPEN: OPSEC, technique check, scope check ke agent path |
| 4 | GAP-006 (Graph Analytics wiring) | Medium | GAP-005 (untuk blast-radius gate enforcement) | **slice-1 DONE #184** (blast radius → decision). slice-2 OPEN: critical paths → planner (needs GAP-004) |
| 5 | GAP-004 (Planner/World Model) | High | ~~GAP-002~~ ✅ (scratchpad), Bug #18/#19/#20 (graph quality) | Core agentic gap: reactive loop → planning agent |
| 6 | GAP-010 (Goal-completion detection) | Low | GAP-004 (objective definition) | Agent berhenti saat objective tercapai, bukan hanya saat budget habis |
| 7 | GAP-009 (Cross-validation between tools) | Medium | GAP-003 (IntelligenceBase untuk FP rate) | Findings di-cross-validate sebelum confirmed, reduce false positives |
| 8 | GAP-008 (Curiosity-driven exploration) | Medium | GAP-004 (planner), ~~GAP-002~~ ✅ (scratchpad) | Agent mengejar anomali, bukan hanya tool-ranked path |
| 9 | GAP-007 (OSINT / external context) | High | — | Intelligence gathering sebelum technical recon |
| 10 | GAP-013 (Credential pattern mutation) | Low | ~~GAP-002~~ ✅ (scratchpad untuk pattern tracking) | Credential reuse tidak hanya literal, tapi generate varian dari pola |
| 11 | GAP-012 (Adaptive evasion) | Medium | GAP-005 (PolicyEnforcer untuk dynamic OPSEC) | Agent mengubah teknik saat terdeteksi, bukan catat dan lanjut |
| 12 | GAP-011 (Authenticated crawl) | High | GAP-004 (planner untuk post-access objective), GAP-010 (goal-completion untuk next objective) | Re-discovery dengan sesi aktif: IDOR, broken access control, priv esc |
| 13 | GAP-014 (Fan-out parallel worker wiring) | Low | — | N-target engagement latency: sequential → parallel (alpha=10, beta=4, gamma=2). Interface built, pure wiring debt |
| 14 | ~~GAP-015 (Credential spray tool)~~ | Medium | None blocking — applicator roster built (merged 296), USER nodes persisted by wp_rest_user_disclosure | **CLOSED** — Implemented as `UserDerivedCredsTool` (derive-not-spray). Fixes Bug #25. Prerequisite for GAP-013 (pattern mutation) |
| 15 | GAP-016 (Wayback pre-intel) | Low-Medium | None blocking — standalone module | Archive-driven probe selection, reduce 404 noise (Bug #26 Layer 1), plugin detection without crawling |
| 16 | GAP-017 (PassiveIntelMap → World Model/Planner) | Medium | §12.48 slice-3 ✅ producer wired | Enrichment signal consumed for pre-emptive pivot + Bug #26 Layer 1/5 fix + MX→origin (§12.46) |

> ToolComposer (review GAP 8) sengaja tidak dimasukkan — akan di-build nantinya sebagai bagian dari Gamma phase.
> GAP 7 (4 agents missing: Gamma/Delta/Epsilon) sengaja tidak dimasukkan — sedang dalam proses.
> Item berikut sudah di ADR sebagai future phase, BUKAN GAP (belum dibangun, bukan kelewat dibangun):
> - Structured decision explanation (ADR §8j-2, Phase 2) — monologue sudah ada, structured reasoning trace = future enhancement
> - Team coordination / blackboard (ADR §8o-5, Phase 5) — parallel agent coordination, scheduled for Delta/Epsilon phase
> - HVT / objective-based engagement (ADR §8i, Phase 6) — crown-jewel targeting, belum dibangun
> - SPA / Camoufox rendering (ADR §12.16.1) — shared capability untuk Alpha+Beta, belum dibangun
> - Hypothesis→verify loop (ADR §8j-2 + §12.16.3) — prerequisite untuk external RAG, belum dibangun
> - Engagement teardown/restore (ADR §12.22 Decision 3) — cleanup tool, build setelah IntelligenceBase

---

## Conductor refactor (pre-Gamma trigger)

Deferred debts tracked here — enforce via review, don't rely on memory. The trigger is
Gamma (3rd agent build) or when main.py next needs surgery. slice-1d is the safety net
that makes the refactor safe.

| id | Debt | Why it's deferred | TRIGGER |
|----|------|-------------------|---------|
| D1 | `main.py` = 724 LOC mixing 4 concerns (FastAPI API + 3 Celery tasks + agent construction + dep wiring). Split into `api.py` / `tasks.py` / agent-build. | Works, green; refactoring it pre-emptively = churn on the highest-stakes module. | Before Gamma (next agent), or when main.py next needs surgery. |
| D2 | Agent construction is an inline closure (`agent_factory` in `run_agent_task`). Bloats per-agent. Extract to a role-keyed `AgentBuilder`/registry (anti-#8). | Only bloats at the 3rd agent build (Gamma). Extracting now = speculative (YAGNI). | Gamma (3rd agent). |
| D3 | Alpha bypasses `execute_agent` (own `run_engagement_task` path) → duplicated setup (store/auth/secrets/session/http/orchestrator built twice) + the false "all agents" docstring (D3-a fixes the doc now). Give Beta a `build_strike_*` seam mirroring `build_recon_pipeline`, route Alpha through execute_agent. | Reconciling the two paths is a real change; not needed for slice-1d (module-symbol patch suffices). | Pre-Gamma refactor (with slice-1d as the safety net). |

---

## TLS-Impersonate Transport — Refinements

| id | Item |
|----|------|
| T1 | **Ordering gap**: if `browser_solve` IS injected and the browser is also blocked, `_apply_host_reach_class` marks the host "blocked" and short-circuits BEFORE `_attempt_reach`, so `TLS_IMPERSONATE` never runs. |
| T2 | **OriginDirectResult misnomer**: once reused by `tls_impersonate_fetch`, the name is misleading. Neutral rename to `ReachTransportResult`. |
| T3 | **Per-host TLS-impersonate failure not cached**: a host that stays blocked after impersonation is re-attempted once per URL (bounded by `_reach_attempted` per-URL set, not infinite). |
| T4 | **tls_impersonate**: Zero SOW wins, unverified shell (bri 403->200) |

---

## Odoo Recon — Refinements

| id | Item |
|----|------|
| O1 | **RULE-OF-THREE version_disclosure**: version-disclosure now has wp_version, db_service server_version, and odoo. Extract a shared `version_disclosure` helper for ONE finding contract. |
| O2 | **list_db JSON-RPC**: Reconcile with `odoo_access.py` XML-RPC `_discover_databases` (Bug #6). |
| O3 | **Rename**: `odoo_dbmanager_probe.py` → `odoo_recon.py`. |

---

## Password Recall Ladder — Roadmap Vectors (ADR §12.45)

| id | Vector | Description | Dependency | Priority |
|----|--------|-------------|------------|----------|
| R1 | **Offline hash crack** | When Alpha harvests password hashes (DB dump / backup / wp-config→DB access), crack OFFLINE with hashcat + rockyou + rules (billions of guesses, NO lockout, safe). High-recall. | Gamma-adjacent (hash-harvest chain) | High — THE strong recall vector |
| R2 | **Credential stuffing** | Check enumerated identities against known breach corpuses (reuse across services). Needs ethical/legal breach-data source (paid). | External data source | Medium — needs legal review |
| R3 | **OSINT-targeted wordlist** | Company/year/season/local terms → hashcat rules. Broader than 4 derived candidates but still online-lockout-bounded. | None (extends UserDerivedCredsTool) | Low — marginal recall gain online |

---

## Wiring ledger — audited 2026-08-08 (post slice-4/5/6)

Verified by grep on the live path (RUNNER-SEAL != AUTONOMOUS-WIRED), not by doc trust.

- **CLOSED**: `origin_ip_candidates` dead-end — consumed by `CompositeOriginDiscovery` 
  (`origin_discovery.py` + `main.py`, PR #361). OTX origin IPs now reach
  `verify_origin_binding` (candidate proven, not hand-fed).
- **WIRING_DEBT registered (gate-enforced)**: `protection_detected` + `historical_paths` 
  are produced (slice-3 / slice-5 OTX) but have NO consumer → registered against
  `agents/alpha/scout.py` so CI fails when the Bug #26 consumer wires them. Closing
  Bug #26 (probe selection) graduates BOTH.
- **Producer-only, no committed consumer yet** (acceptable per GAP-017, revisit):
  `mx_records`, `nameservers` (internal input to `protection_detected`), `txt_records`.
- **OdooAccessTool — WIRING now gate-protected** (WIRED_REQUIRED → `agents/beta/strike.py`),
  AUTONOMOUS-WIN PROOF test RUN on Oracle ARM64 (2026-08-08):
  `tests/phase_4/test_conductor_chain_characterize.py` drives the alpha-ai Odoo chain
  through the REAL Conductor Celery path (`run_engagement_task` eager) instead of the
  `odoo_chain_runner` ISLAND. Oracle result (live network + real DeepSeek LLM):
  - **J1b GREEN**: Alpha autonomously selected `backup_file_probe` (NOT `wp_config_probe`
    hand-fed by runner) on `wp-config.php.bak`, vaulted 2 CREDENTIAL nodes with
    `secret_ref` prefixes. The autonomous loop DOES find the chain entry without
    `verify_wp_config_leak`.
  - **J2 GREEN**: `advance_engagement` dispatched BETA (route_next returned BETA,
    auth tier ACTIVE_APPROVED, decide_advance=dispatch).
  - **J4 CARDINAL RED**: `OdooAccessTool` did NOT win `ToolRegistry.ranked()` —
    `access_level=''` (no ACCESS_LEVEL node created), `odoo_access_proof_seen=False`.
    Beta ran with applicators bound but no tool achieved access on the autonomous path.
  - **J1a WIRING GAP**: no ACCESS_LEVEL ENABLES-edge traced back to a vaulted CREDENTIAL
    (consequence of J4 — no access = no edge).
  - **J5 GUARD FAILED**: ACCESS_LEVEL node never reached CROSS_VERIFIED
    (`verify_access_nodes` had nothing to promote).
  Root cause hypothesis: Beta's cred_reuse/default_creds applicators target the WP
  login form (wp.alpha-ai.web.id) but the harvested DB credentials need to be tried
  against Odoo XML-RPC (odoo.alpha-ai.web.id) — the runner hand-routes this via
  `verify_wp_config_leak` → `OdooAccessTool`; the autonomous path relies on
  `ToolRegistry.ranked()` picking OdooAccessTool from the candidate set, which it
  did NOT. Do not mark this debt closed until J4 is GREEN on Oracle.
  **J4 fix slice (mandatory, not optional):** (1) fix `_project_target_context`
  (strike.py:88-93) so cross-target ASSET tech_stack enters ctx (the Odoo ASSET
  `tech_stack=['odoo']` is filtered out because host != target `wp.alpha-ai.web.id`);
  (2) emit a non-mutating `TOOL_SELECTED` event from `ToolRegistry.ranked()` (or
  `Beta.step`) so the J4 assert reads ranking evidence directly instead of inferring
  from proof-artifact `method == "authenticate"` — the current inference is sound for
  RED (absence of odoo proof = odoo did not win) but insufficient for GREEN (need to
  prove OdooAccessTool was SELECTED, not just that some odoo proof exists). Both
  must land in the same slice.
- **GAP-014 (fan-out)**: confirmed accurate — `conductor/fanout.py` interface EXISTS, Shape A
  not wired (pure wiring debt, not stale).
- **SessionStore (GAP-002)**: scratchpad mechanism lives in `agents/base.py` (#192), but the
  `SessionStore` CLASS is not referenced in `recon_runner.py`/`execute_agent.py` (only the
  lowercase `session_store` param) — gate still tracks it as debt. Doc "CLOSED" = mechanism
  built; live-path class wiring incomplete. Reconcile when the pre-Gamma Conductor refactor lands.
- **GAP-023 (routing): `route_next` blocks Beta when only USER nodes exist (no CREDENTIAL)**
  — `router.py:137` requires `has_harvested_credential(graph_store)` (CREDENTIAL node with
  `secret_ref` prefix) AND `has_web_auth_surface` to dispatch BETA. GAP-015 CLOSED built
  `UserDerivedCredsTool` (reads USER nodes, derives candidates) and wired it in `strike.py`,
  but the ROUTING GATE still blocks Beta from ever running when Alpha finds USER nodes
  without a leaked credential. Confirmed on niagamas.com (Oracle, 2026-08-08): Alpha found
  4 USER nodes (amdhartono, bahrul, elvin, yudha) via `wp_rest_user_disclosure` + WooCommerce
  exposed (auth surface), but `route_next` returned OMEGA (recon-only report) because
  `has_harvested_credential` = False. `UserDerivedCredsTool` exists and is wired but never
  reached. Fix: extend `route_next` ALPHA→BETA predicate to include `has_user_disclosure`
  (USER nodes + auth surface) as an alternative trigger to `has_harvested_credential`.
  This is Beta breadth B1 from Session_Handoff NEXT #5.

---

## GAP-018 — RESOLVED 2026-08-08 (field-prove caught it, unit tests missed it)

- **Status**: FIXED (self-contained, `recon/origin_resolver.py`).
- **Caught by**: integrated recon field-prove on alpha-ai (T4 origin-binding MOAT = bound=[]).
  RUNNER-SEAL != AUTONOMOUS-WIRED made concrete: the gap015 ISLAND passed seed_hosts and
  discovered 168.110.192.62; the AUTONOMOUS `LiveOriginDiscovery.candidates()` did NOT pass
  seed_hosts → when crt.sh was down, 0 candidates → no binding.
- **Root cause**: `candidates()` called `discover_origin_ips(...)` WITHOUT `seed_hosts`; the
  in-scope authorized domains (an origin-candidate source independent of crt.sh, §12.44) were
  never seeded.
- **Fix (deviates from the registered Option A on purpose)**: NOT main.py-passes-seed_hosts.
  `LiveOriginDiscovery` already holds `auth`+`engagement_id`, so it derives its own seeds via
  `_scope_seed_hosts()` (reads `auth.get_record(eid).scope.domains`, fail-open to ()). 1 file,
  better encapsulation, fix lives with the bug. `discover_origin_ips` still re-filters each seed
  through `is_in_scope` (defense-in-depth, never a scope bypass).
- **Guarded by**: `test_origin_resolver::test_live_origin_discovery_seeds_scope_domains`
  (RED before / GREEN after) + wiring gate `_scope_seed_hosts` WIRED_REQUIRED in origin_resolver.


---

## GAP-019 — Per-host origin-resolution cache (RESOLVED 2026-08-08)

- **Status**: FIXED (`agents/alpha/scout.py`, `_bound_origin` per-host cache).
- **Symptom**: field-prove timed out (~29 min, 10-min kill). Root cause: `_reach_attempted` is
  keyed per-URL but origin discovery + binding (crt.sh 30 s when down) re-ran for EVERY blocked
  path on the SAME host → ~15×/host (~50 crt.sh fetches). Also an opsec fingerprint (50× same
  endpoint). Fix: resolve origin ONCE per host (incl. the empty negative case), reuse for all
  paths — mirrors the `_reach_class` per-host cache. Result: crt.sh 50×→2×, run 29→~6.5 min.
- **Guard**: `test_alpha_autonomous_reach::test_origin_resolution_cached_once_per_host`.

## GAP-020 — Mid-engagement pattern-group exhaustion (OPEN, next slice)

- **Status**: OPEN. ADR §12.57 point 2.
- **What**: N consecutive 404 on a path pattern-group (`.env*`, `wp-config.php.*`) → emit
  `PATTERN_GROUP_EXHAUSTED` → skip the remaining variants (this host; other hosts when stack
  differs). Deterministic counter, extends `EvasionPlanner` (anti-#6). NOT LLM, NOT
  cross-engagement (IntelligenceBase stays deferred).
- **Why**: field log — 7× `.env*` 404 re-probed on every host = pure waste + WAF-noise (Bug #26
  family). Highest-leverage gate-safe recon-precision fix.

## GAP-021 — Fingerprint-driven path hard-filter (OPEN)

- **Status**: OPEN. ADR §12.57 point 3.
- **What**: a confirmed stack REMOVES irrelevant generic paths, not only adds stack-specific ones.
  Currently `_handle_capability_fingerprint` ADDS `frontier_seeds`; the initial generic seed still
  fires. Fingerprint (e.g. WP, Odoo) → filter out API/other-stack paths before probing. Static
  filter, deterministic (no dynamic path generation).
- **Why**: field log — API paths (`openapi.json`, `graphql`) sprayed at WP/Odoo hosts.

## GAP-022 — Deterministic rule coverage + finding correlation (OPEN)

- **Status**: OPEN. ADR §12.57 points 1 & 4 (recon-side).
- **What**: (a) extend the deterministic rule-tier catalog so known exposures fire WITHOUT the LLM
  (`install.php`/`upgrade.php` 200 = WP-setup-exposed) — the rule-tier exists, its catalog is thin;
  (b) finding correlation — combine `wp-config.php.bak` DB creds + enumerated WP users into a
  single prioritised CREDENTIAL/USER hand-off for Beta (findings currently persist independently).

## GAP-026 — StealthPacer gate inverted: code exists, default OFF (violates §12.49)

- **Status**: OPEN. Doctrine §12.49: "Stealth by default from the 1st request (curl_cffi, Header
  ordering, Pacing)."
- **What**: `StealthPacer` (§12.50) is fully implemented — multi-modal burst-and-pause, Gaussian
  jitter, adaptive backoff on 429/503. BUT the gate in `recon_runner.py:156` requires
  `engagement_profile.opsec_stealth=True` to activate it. The API default in `main.py:152` is
  `opsec_stealth: bool = False`. All 3 runner scripts (`run_niagamas_conductor.py`,
  `run_quantum_conductor.py`, `run_full_chain.py`) do NOT set `opsec_stealth=True`. Result:
  pacer never activates → agent fetches 40+ URLs with zero delay → CF bot detection triggers
  → challenges all subsequent requests including legitimate endpoints (wp-json).
- **Classification**: NOT "code missing" — code EXISTS, gate is INVERTED. Doctrine says
  "stealth by default" but code defaults to OFF. This is Lyndon #2 (dead code treated as done)
  — StealthPacer has unit tests that pass, but it is never active in field.
- **Evidence**: niagamas.com field-prove — Run 1 (83 events, natural pacing from crt.sh 30s
  timeouts) → wp-json/wp/v2/users accessible via CF DIRECT → 4 users + 2 vulns. Run 2 (247
  events, zero pacing) → CF challenge on wp-json → origin-direct fallback → origin returns
  homepage (~98KB) → 0 users, 0 vulns.
- **Impact**: Cascade — no pacing → CF bot detection → wp-json challenged → origin-direct →
  homepage → 0 users → 0 credentials → Beta never dispatches. Root cause of "0 findings" on
  aggressive runs.
- **Fix direction**: Flip the default. Either (a) `opsec_stealth: bool = True` in `main.py:152`
  so the API defaults to stealth-on, OR (b) remove the gate entirely in `recon_runner.py:156`
  so `StealthPacer` is always used (pacing is basic operational hygiene, not an elevated
  capability). Option (b) is cleaner — `opsec_stealth` consent item should gate EVASION
  techniques (browser solve, TLS impersonate), not pacing. Runner scripts do NOT need changes
  if the default is flipped.

## GAP-027 — Probing order: sensitive files before legitimate endpoints

- **Status**: OPEN.
- **What**: Agent probes sensitive files (`.env`, `.git/config`, `wp-config.php.bak`) BEFORE
  legitimate endpoints (`wp-json`, `wp-admin`). Sensitive file probes trigger CF bot detection,
  which then blocks legitimate endpoints that were previously accessible.
- **Evidence**: niagamas.com — `.env` and `.git/config` probed early → CF switches to challenge
  mode → wp-json/wp/v2/users (probed later) gets challenged → origin-direct fallback → homepage.
- **Impact**: Legitimate endpoint data (wp-json users, woocommerce API) lost because CF already
  in bot-detection mode from sensitive file probes.
- **Fix direction**: Two-phase probing — Phase 1: legitimate endpoints (wp-json, robots.txt,
  sitemap, homepage) via CF DIRECT. Phase 2: sensitive files (`.env`, `.git`, backup files) via
  origin-direct (after binding proven). APT nyata tidak ketok `.env` di detik pertama.

## GAP-028 — Origin-direct response validation (generic homepage detection)

- **Status**: OPEN.
- **What**: Origin server `139.59.255.22` returns WordPress homepage (~98KB) for ALL paths
  including `.env`, `.git/config`, `wp-json/wp/v2/users`. Agent treats this as real content,
  runs probes against homepage body → 0 findings. No baseline comparison to detect that
  origin-direct returns generic homepage instead of path-specific content.
- **Evidence**: niagamas.com field-prove — ALL origin-direct fetches return ~98KB body
  (98766-98789 bytes, ±23 bytes variance). wp-json/wp/v2/users via CF = 5,903 bytes (real JSON),
  via origin-direct = 98,785 bytes (homepage). Agent does not detect this.
- **Impact**: Origin-direct probes waste LLM tokens analyzing homepage body. False "HTTP 200"
  on sensitive files that don't exist (origin returns homepage, not 404).
- **Fix direction**: After origin-direct fetch, compare body hash to homepage baseline (fetched
  once per host at start). If identical → flag as "origin returns generic homepage" → skip probe,
  try CF DIRECT instead (if not challenged), or mark as non-analyzable.
- **Why**: field log — `install.php` 200 skipped as "non-analyzable" when the LLM declined;
  creds + users found but never combined.
