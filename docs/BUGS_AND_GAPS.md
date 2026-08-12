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
| 29 | Unreachable subdomain still probed for all 12 paths | **High** | Low | APT operator skips dead hosts; agent wastes ~15min probing 12 URLs × 4 unreachable subdomains |
| 30 | auth_surface regex misses Vue.js `:type` password bindings | **High** | Low | pos.niagamas.com/admin/login not detected as auth surface |
| 31 | Beta crashes on OriginUnreachableError when no origin binding | **High** | Medium | Beta dispatched (GAP-023 fix) but crashes on entry — can't strike |
| 32 | OTX timeout 30s blocks sequential OSINT chain | Low | Medium | 30s wasted per engagement before VT runs |
| 33 | Subdomain pivot path not designed (architectural gap) | Medium | High | Subdomain access not used as stepping stone to main domain |
| 34 | Frontier queue re-enqueues already-probed URLs → infinite cycle | **High** | Medium | Run never converges; burns HTTP + LLM tokens re-probing identical URLs (spectranet: 3 full cycles in 5+ min, 0 new findings after cycle 1) |
| 35 | `LLM_TOOL_SELECT_MAX_TOKENS=512` too small for reasoning model | **High** | Low | `deepseek-v4-flash` reasoning_content consumes token budget → intermittent `CompletionTruncatedError` → `OrientationError` on wp-admin pages (2/5 calls fail with 7KB body). Model is correct/available; token budget is the root cause |
| 36 | `/wp-admin/*` login-gated pages enter frontier without rule match | Medium | Low | `update-core.php`, `upgrade.php`, `import.php` (login-gated WP admin pages) escalate to LLM tier → token burn for predictable non-findings. Add playbook rule for wp-admin login redirect body signature |

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
18. **Bug #35** (LLM token budget too small) — one-line constant fix, stops intermittent `OrientationError` on wp-admin pages. **Do this FIRST** — it's the lowest effort + highest impact.
19. **Bug #34** (frontier cycling) — add `seen_urls` dedup to `enqueue_discovered_url`. Without this, no run ever converges.
20. **Bug #36** (wp-admin login-gated playbook) — add one playbook YAML. Quick win after #35 is fixed (reduces LLM calls that would otherwise truncate).

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
- **Fix direction**: Option A — stealth toggle at engagement creation (consent_items +
  signed_by[login] + signed_at[timestamp]). Do NOT flip the server default
  (`authorization.py:583-591` hard-raises `ConsentRequiredError`). No server code change —
  the operator sets `opsec_stealth=True` at engagement creation with signed consent.
  Runner scripts should be updated to set `opsec_stealth=True` for field engagements.

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

## GAP-029 — Unreachable subdomain still probed for all 12 paths

- **Status**: OPEN.
- **What**: `run_recon` seeds probe paths (leak paths + surface discovery paths) for EVERY
  target before the homepage is fetched. If a subdomain is unreachable (DNS fail, connection
  timeout, host down), the agent still probes 12+ paths against it — each timing out at 15-30s.
  4 unreachable subdomains × 12 paths × 15s timeout = ~12 minutes wasted.
- **Evidence**: bernofarm.com field-prove (2026-08-09) — `apifinger.bernofarm.com`,
  `apifingeris2.bernofarm.com`, `apifingernew2.bernofarm.com`, `att3a2.bernofarm.com` all
  unreachable, each probed for 12 paths. Total run time ~16 minutes for recon alone.
  niagamas.com same pattern: `ainotulensi.niagamas.com`, `notulensi.niagamas.com`,
  `scraping.niagamas.com`, `www.niagamas.com` all unreachable, each probed 12 paths.
- **Impact**: Massif time waste. APT operator skips dead hosts immediately. Agent does not.
- **Fix direction**: Track `_unreachable_hosts: set[str]`. When homepage fetch fails
  (`HttpClientError`), add host to `_unreachable_hosts`. In `_pop_unprobed` or
  `enqueue_discovered_url`, skip URLs whose host is in `_unreachable_hosts` UNLESS the URL
  is the homepage (already probed). Alternatively: defer seed paths until after homepage
  fetch succeeds (redesign, >2 files).
- **Effort**: Low (1 file, scout.py — track + skip predicate).

## GAP-030 — auth_surface regex misses Vue.js / framework-bound password inputs

- **Status**: DONE (PR #391 Slice 1a merged `2b85fed` + PR #392 Slice 1b merged `5554e8d`).
- **What**: `detect_auth_surface_labels` regex `<input[^>]*type\s*=\s*['\"]?password\b['\"]?>`
  matches only static `type="password"`. Modern frameworks (Vue, React, Alpine) use dynamic
  bindings: `:type="showPassword ? 'text' : 'password'"` or `:type="password"`. These do NOT
  match the regex, so login forms with framework-bound password inputs are not detected.
  Additionally, the pre-fix classifier unconditionally labeled ANY `401` as `http_basic_auth`
  regardless of whether `WWW-Authenticate: Basic` was present.
- **Evidence**: niagamas.com field-prove — `pos.niagamas.com/admin/login` has
  `<input :type="showPassword ? 'text' : 'password'" name="password">`. Regex does not match.
  `pos.niagamas.com` never persisted as ASSET with `login-form` label. Router never saw it.
- **Root cause of stale `http_basic_auth` on hub.niagamas.com** (investigated 2026-08-12):
  The pre-#391 `detect_auth_surface_labels` had `if status_code == 401 or has_www_auth:
  labels.append("http_basic_auth")` — ANY 401 was mislabeled `http_basic_auth`. The hub API
  (`https://hub.niagamas.com/api/`) returns `401` JSON `{"message":"Unauthorized","statusCode":401}`
  with NO `WWW-Authenticate` header, so the old code misclassified it as `http_basic_auth`.
  The capability fingerprint path (`http_basic_auth_fingerprint`) was NOT the source: its
  playbook (`http_basic_auth.yaml`) requires `WWW-Authenticate: Basic` regex match, which the
  hub API does not send, so that rule never fired. Provenance = stale pre-#391 classifier only.
  Current `main` (`5554e8d`) correctly produces `api_auth` for the hub API (401 JSON, no
  challenge) and `login-form` for pos.niagamas.com. No code defect remains; no regression test
  needed because the fix is already in place and covered by `tests/phase_4/test_auth_surface.py`.
- **Impact**: Login forms using Vue/React/Alpine bindings are invisible to the agent.
  Beta never dispatches for these targets. Missed attack surface. (Pre-fix: bare 401 also
  routed a basic-auth strike at a non-basic surface — false positive routing, NOT a false
  positive vulnerability finding; no credential/access/proof was minted in the prior run.)
- **Fix direction**: DONE. Slice 1a (PR #391): header-aware 401 classification (Basic/Digest/
  Bearer/api_auth/unknown_auth) + dynamic password-input detection + strikable split. Slice 1b
  (PR #392): SPA login-from-JS detection via `scan_js_for_login_surface` (classify-only
  `spa-login-form`, reuses existing JS fetch, no second network round-trip). Slice 1b backtick
  fix (PR #393): Vite/esbuild minified bundles use backtick template-literal quotes
  (`type:`password``) instead of `['"]`; the regex character class was extended to `['"\`]` so
  SPA login forms in Vite-minified bundles (e.g. hub.niagamas.com) are now detected.
- **Effort**: DONE. Slice 1a = `auth_surface.py` + tests. Slice 1b = `auth_surface.py` +
  `js_secret_probe.py` + tests. Slice 1b backtick fix = `auth_surface.py` + tests (1 regex
  character class change + 3 regression tests).

## GAP-031 — Beta crashes on OriginUnreachableError when no origin binding exists

- **Status**: PARTIALLY FIXED 2026-08-09 (crash FIXED — graceful decline + Omega handoff,
  verified ibudanbalita). Residual = CF ceiling (no origin → no strike surface), NOT a code
  slice — see §12.61 Flank-when-CF-hard for the strategic answer.
- **What**: Beta uses `OriginAwareHttpClient` which is fail-closed: if no proven/authorized
  origin exists for a host, it raises `OriginUnreachableError` instead of falling back to
  CF DIRECT. This crashes Beta's `step()` at `self.http_client.get(self._entry_point)`.
- **Evidence**: niagamas.com field-prove (2026-08-09) — Beta dispatched (GAP-023 fix works),
  but crashed immediately:
  ```
  OriginUnreachableError: no proven/authorized origin for 'niagamas.com'
  - refusing naked reach (fail-closed; would hit the CDN edge and burn the technique)
  ```
  Beta never tried CF DIRECT as fallback. Applicator calls = [2] but both failed before
  reaching the target.
- **Impact**: Beta dispatch (GAP-023 fix) is wasted if Beta crashes on entry. The deadlock
  is broken but Beta can't act.
- **Fix direction**: ~~Beta should fall back to CF DIRECT when no origin is bound~~
  REJECTED — violates banked doctrine ("stop beating full-CF apex from datacenter IP").
  Crash is FIXED (graceful decline + Omega honest report). Residual = CF ceiling = §12.61
  flank doctrine (find origin via side channels, not brute the edge).
- **Effort**: Crash fix = DONE. Residual = doctrine (§12.61), not a code slice.

## GAP-032 — OTX timeout 30s blocks sequential OSINT chain

- **Status**: OPEN.
- **What**: OSINT sources run sequentially: CertSpotter → crt.sh → HackerTarget → DNS →
  OTX → VT. OTX has 30s timeout. If OTX is down (frequently from Oracle), 30s wasted before
  VT runs. No parallel execution.
- **Evidence**: bernofarm.com + niagamas.com field-prove — OTX timeout 30s every run.
  VT runs after OTX timeout, adding 30s to every engagement.
- **Impact**: 30s wasted per engagement. Not critical, but unnecessary.
- **Fix direction**: Run OSINT sources in parallel (ThreadPoolExecutor), merge results.
  Or reduce OTX timeout to 10s. Or skip OTX if VT key is set (VT is more reliable).
- **Effort**: Medium (recon_runner.py — parallel execution or timeout reduction).

## GAP-033 — Subdomain pivot path not designed (subdomain as entry to main domain)

- **Status**: OPEN (design gap, not yet implemented).
- **What**: Agent discovers subdomains and probes them independently, but never uses
  accessible subdomains as pivot points to the main domain. APT operator: if main domain
  is CF-protected but `pos.niagamas.com/admin/login` is accessible, attack via subdomain
  → pivot to main domain via shared infrastructure (session, cookie, API, DB).
- **Evidence**: niagamas.com field-prove — `pos.niagamas.com/admin/login` accessible (Laravel),
  `niagamas.com` CF-protected. Agent probes both independently, never connects them.
  No concept of "subdomain access → main domain pivot" in the architecture.
- **Impact**: Missed attack paths. Subdomain access is treated as end goal, not as
  stepping stone to main domain.
- **Fix direction**: Design phase needed. Not a wiring fix — this is an architectural
  gap. Requires: (1) cross-host access tracking in graph, (2) Beta/Gamma awareness of
  subdomain-to-main pivot opportunities, (3) credential/session reuse across hosts.
- **Effort**: High (architectural — multiple files, design first).

## GAP-034 — Entry-selection has no node-level reachability signal

- **Status**: BUILT 2026-08-11 (HOST_ABANDONED-only demote read-model; WAF_BLOCKED NOT excluded). Detail → docs/Session_Handoff.md.
- **What**: `select_strike_entry` (conductor/router.py) picks Beta's entry_point by
  auth-surface-label presence on ASSET nodes (reuses `_AUTH_SURFACE_LABELS`). Label
  presence is used as a *reachability proxy* — you cannot fingerprint `http_basic_auth` /
  `login-form` on a host Alpha never reached. This proxy holds for the niagamas/bernofarm
  topology (dead apex has no label; reachable subdomain has one) but BREAKS for a host that
  is WAF-dead yet still carries an auth-surface label (e.g. an apex that returned a login
  once, then went WAF_BLOCKED). There is no `reachable`/`waf_confirmed_unreachable` property
  on the ASSET node, and `protection_detected` is producer-only (computed, not consumed for
  target-selection — see Session_Handoff GAPS).
- **Evidence**: `agent_alpha/graph/nodes.py` `AssetProps` = `host`, `tech_stack` only (no
  reachability field). `WAF_BLOCKED` is an event, not projected onto the node. Verified
  HEAD 3c3127e.
- **Impact**: Entry-selection cannot deterministically DEMOTE a dead-but-labelled host below
  a live one. Slice-1 is correct for the field topology but not fully general.
- **Fix direction**: Project a per-host reachability verdict from `WAF_BLOCKED` /
  transport-fail events onto a node property (or a small read-model over the event store),
  then have `select_strike_entry` rank live > dead. This is the deterministic reachability
  signal the SituationAssessor (ADR §12.58) will also consume. Design-first: touches recon
  persist + nodes schema + selector (>2 files → interface, not a patch — anti #10).
- **Effort**: Medium (design first; multi-file). Promote alongside instinct #2 (cred-reuse)
  under the SituationAssessor container, not before.

## GAP-035 — Entry-selection strikes ONE candidate; multi-surface not iterated

- **Status**: BUILT FRESH 2026-08-11 (own slice; multi-candidate dispatch loop). Build/status/seal detail → docs/Session_Handoff.md.
- **What**: `select_strike_entry` returns a SINGLE best entry_point, and Beta's `run_strike`
  contract is single-entry_point. When a target exposes MORE than one in-scope auth surface
  (e.g. `hub` 401 basic-auth AND `pos` login-form), only the top-ranked one is struck; the
  rest are never attacked. Session_Handoff defines the full instinct as "Beta enumerates
  in-scope auth-surface ASSETs as strike candidates, per-host ctx + per-host gate" — that is
  the multi-candidate form, deliberately out of slice-1 scope.
- **Evidence**: `conductor/main.py` run_beta dispatches one `run_strike(engagement_id,
  strike_entry)`; `agents/beta/strike.py` builds ctx for a single `self._entry_point`.
  Verified HEAD 3c3127e.
- **Impact**: Second/third reachable login surface on the same engagement goes unstruck =
  missed payable finding.
- **Fix direction**: Iterate ranked candidates from `select_strike_entry` (return a list),
  each with its OWN per-host ctx (`_project_target_context`) and its OWN per-host
  `authorization.is_in_scope` gate (the authoritative gate stays in Beta/Conductor). Bounded
  (≤N) to avoid queue sprawl. Keep Beta's single-entry_point contract intact — the loop lives
  at the dispatch seam, not inside strike.py (anti #8/#10).
- **Effort**: Medium (dispatch-seam loop + per-candidate ctx/gate; no strike.py rewrite).

## GAP-036 — LLM tool-pick fires on auth-surface pages (no deterministic RULE)

- **Status**: OPEN, LOW priority (efficiency/OPSEC noise, NOT correctness).
- **What**: LLMOrchestrator = RULE→SINGLE_LLM. No playbook RULE matches a login/auth-surface
  page, so DECIDE falls to the LLM tier, which picks the nearest framework-vuln tool
  (laravel_debug_probe) → success=False → 0 nodes + a wasted probe. Violates §12.57 (DECIDE
  must be deterministic; LLM stays in ORIENT). Distinct from GAP-030 (that = detection regex).
- **Evidence**: niagamas — `[ALPHA/ORIENT] Selected tool 'laravel_debug_probe' via the
  single_llm tier` on pos.niagamas.com/admin/login, /signup, /forget-password. Verified in
  code: no login-form RULE exists; _detect_auth_surface records the label anyway (scout.py:559).
- **Impact**: 1 wasted probe per auth URL + misleading logs + minor OPSEC noise. Correctness
  unaffected once GAP-030 lands (label persists regardless of tool).
- **Fix direction**: Add a deterministic RULE-tier rule for auth surfaces (password input / 401 /
  known login route on a clean 200) → route to a lightweight generic/auth-surface handler; do
  NOT build a login-form_fingerprint tool (duplicates _detect_auth_surface — anti #6). Guard:
  rule applies to clean 200 auth pages only; debug/Ignition (500/error) probing stays intact.
- **Effort**: Low (1 playbook rule + test). Do AFTER GAP-030 + entry-selection close.

## GAP-037 — Mid-run host death not detected (consecutive-failure threshold)

- **Status**: FIXED 2026-08-11 (merged PR #385). Stop-on-block egress death detection.
- **What**: GAP-029 fix only marks a host dead on ROOT transport failure (path `/` or `""`).
  If the root succeeded early but the host goes unreachable MID-RUN (WAF rate-limit block,
  IP ban, transient network failure), non-root path failures emit "unreachable" but do NOT
  trigger dead-host abandonment. The agent continues probing every remaining queued path
  for that host — each timing out at 30s — wasting minutes and generating OPSEC noise.
- **Evidence**: busonlineticket.co.th — root fetched 200 (line 48), 37 requests succeeded,
  then Sucuri WAF triggered IP rate-limit block. From line 133 onward, 30+ requests all
  timed out (30s each = 15+ min waste). GAP-029 did NOT fire because root already succeeded.
  `apps.busonlineticket.co.th` (root unreachable from start) → correctly abandoned (GAP-029
  fired). Host utama (`busonlineticket.co.th`) → NOT abandoned because root was 200 earlier.
- **Impact**: 15+ minutes wasted probing a blocked host. Each timeout = 30s. OPSEC noise
  from repeated failed connection attempts to a WAF that already blocked the source IP.
- **Root cause chain**: GAP-026 (StealthPacer OFF) → 37 requests burst → Sucuri rate-limit
  trigger → IP blocked → mid-run death. GAP-026 is the ROOT cause; GAP-037 is the mitigation
  for when block occurs despite pacing (aggressive WAF, shared IP, etc.).
- **Fix direction**: Track consecutive transport failures per host (`_host_fail_count:
  dict[str, int]`). Increment on HttpClientError, reset to 0 on any successful response.
  When count ≥ threshold (3-5), mark host dead + prune queue (same mechanism as GAP-029).
  Threshold tunable via constants. This is defense-in-depth on top of GAP-026 (pacer ON).
- **Effort**: Low (counter dict + threshold check in except block, ~15 lines + test).

## GAP-038 — Cooperative mode short-circuits origin discovery (no binding proof)

- **Status**: FIXED 2026-08-09 (merged PR #381).
- **What**: `resolve_and_bind_origin` (origin_binding.py L90-92) requires `token_for(profile, host)`
  to return a non-None ownership token before invoking `discovery.candidates()`. Cooperative mode
  sets `ownership_tokens={}` (no DNS-TXT, operator-approved SOW) → `token_for` returns None →
  `resolve_and_bind_origin` exits at L92 → `candidates()` NEVER called → 0 ORIGIN_DIRECT_ATTEMPT
  → Beta has no origin IP → applicator fail → `beta_failed`.
- **Evidence**: ibudanbalita — `ORIGIN_DIRECT_ATTEMPT events: 0`, `Applicator calls: [2]` (both
  failed), `ENGAGEMENT_RUN_FAILED reason='beta_failed'`. Trace: token_for returns None karena
  ownership_tokens=frozenset() di cooperative profile.
- **Root cause**: Token canary adalah satu-satunya binding proof. Cert-SAN corroboration
  di-desain (origin_binding.py L9 comment) tapi deferred. Cooperative mode tidak punya
  binding proof alternative.
- **Fix direction (Option A — loose, fast-to-market)**: Skip binding proof when
  `verification_mode="cooperative"` AND token is None. `discover_origin_ips` already does
  soft binding via `_probe_as_origin` (Host header + non-CF filter + confirming status).
  Trust anchor = operator-approved SOW (cooperative mode), bukan cryptographic token.
  Fail-closed tetap jalan: discover_origin_ips return [] → None → no reach.
  Future upgrade: cert-SAN corroboration (Option B) untuk cryptographic proof tanpa token.
- **Effort**: Low (~10 lines di resolve_and_bind_origin + test).

## GAP-039 — CompositeOriginDiscovery exact-host filter drops apex intel for subdomain binding

- **Status**: FIXED 2026-08-10 (fix branch fix/gap-039-composite-apex-scope).
- **What**: `CompositeOriginDiscovery.candidates()` (origin_discovery.py) scoped
  event-sourced OTX/VT `origin_ip_candidates` with an EXACT host match
  (`payload.domain == fronted_host`). Passive intel is gathered per APEX domain
  (one `PASSIVE_INTEL_GATHERED` per engagement target), but origin binding is
  requested per blocked HOST — usually a subdomain (`pos.ex.com` WAF-blocked).
  Exact match → apex event never matches subdomain host → OTX/VT historical-DNS
  IPs never reach `resolve_and_bind_origin` → `ORIGIN_DIRECT_ATTEMPT=0` even with
  OTX/VT keys active and historical IPs present.
- **Evidence**: niagamas re-run 2026-08-10 with `.env.runtime` keys loaded
  (VT/OTX/CERTSPOTTER all SET): direct API query proves OTX+VT hold origin
  candidates (`206.189.93.100` for niagamas, `216.106.184.20` for bernofarm),
  yet `ORIGIN_DIRECT_ATTEMPT events: 0`, `beta_failed`. WAF_BLOCKED on
  `pos.niagamas.com` paths triggered binding for host `pos.niagamas.com` while
  the only PASSIVE_INTEL_GATHERED event carried `domain=niagamas.com`.
- **Root cause**: Filter written for the CodeRabbit cross-domain-leak guard used
  exact match, conflating "same registrable domain family" (apex ↔ its
  subdomains, same token scope) with "cross-domain" (must reject).
- **Fix**: Dot-boundary suffix match: accept when `host == domain` OR
  `host.endswith("." + domain)`. Cross-domain and false-suffix (`notex.com` vs
  `ex.com`) still rejected. Adversarial fixtures added per §12.60 ratchet:
  `test_composite_subdomain_inherits_apex_candidates`,
  `test_composite_dot_boundary_no_false_suffix` (test_origin_binding.py).
- **Effort**: Low (filter change + 2 tests).

## GAP-040 — Ownership gate rejects consented subdomains (origin-direct crash)

- **Status**: FIXED 2026-08-10 (fix branch fix/gap-040-subdomain-ownership-gate).
- **What**: TWO defects on the origin-direct path for subdomains:
  1. `_assert_fronted_host_owned` (engagement_profile.py) demanded an EXACT
     `scope_targets` hit (apex only). Subdomains discovered via VT/crt.sh pass
     Gate 1 (`is_in_scope`, `allow_subdomains` suffix match) and get probed, but
     on WAF block → binding proven → composed gate raised
     `OriginNotAuthorizedError: fronted host 'pos.niagamas.com' not a
     proven-owned target`. Gate 2 was STRICTER than Gate 1 — inconsistent.
  2. `scout._attempt_reach` let that raise propagate, crashing the whole
     engagement (`ENGAGEMENT_RUN_FAILED`), violating its own contract
     ("Returns None if reach is not authorized — honest block, anti-#3").
- **Evidence**: niagamas re-run 2026-08-10 post-GAP-039 — `ORIGIN_BINDING_PROVEN`
  emitted for the first time, then immediate `OriginNotAuthorizedError` traceback;
  `status: failed`, `AGENT_DISPATCHED=0`, engagement aborted mid-recon.
- **Fix**: (1) Gate 2 mirrors Gate 1: subdomain of a signed scope_target is owned
  when `allow_subdomain_enum` is consented (dot-boundary suffix, lookalikes
  rejected). (2) `_attempt_reach` catches `OriginNotAuthorizedError` → honest
  block (return None). Lab allowlist stays exact-match (harness strictness by
  design).
- **Tests**: `test_subdomain_of_owned_apex_passes_ownership_gate`,
  `test_subdomain_rejected_without_subdomain_consent`,
  `test_lookalike_domain_never_inherits_ownership` (§12.60 ratchet fixtures).
- **Effort**: Low (gate + crash guard + 3 tests).

## GAP-041 — Cooperative soft-binding emits PROVEN for unprobed (stale) candidates

- **Status**: FIXED 2026-08-10 (fix branch fix/gap-041-false-soft-binding).
- **What**: The cooperative soft-binding branch (GAP-038 Option A) assumed
  `discover_origin_ips` already confirmed every candidate via `_probe_as_origin`.
  That holds for `LiveOriginDiscovery` (base candidates are pre-probed). But
  `CompositeOriginDiscovery` unions event-sourced OTX/VT historical IPs that
  were NEVER probed — the cooperative branch emitted `ORIGIN_BINDING_PROVEN`
  for the first non-CF, non-internal candidate without any liveness check.
- **Evidence**: niagamas re-run 2026-08-10 (post-GAP-039+040) —
  `ORIGIN_BINDING_PROVEN` for `206.189.93.100` (VT historical, 2025), then
  all 3 `ORIGIN_DIRECT_ATTEMPT` fetches failed with
  `origin_direct_fetch failed` (connection refused — server moved). False
  proof: PROVEN event with zero confirming traffic.
- **Fix**: Cooperative branch now calls `probe_as_origin(ip, fronted_host)`
  before emitting PROVEN. Dead/stale candidate → skip, try next. All dead →
  return None (fail-closed, no false proof). Also renamed `_probe_as_origin`
  → public `probe_as_origin` (was only used internally; now called from
  `origin_binding.py` cooperative path).
- **Tests**: `test_cooperative_dead_candidate_skipped_live_candidate_bound`,
  `test_cooperative_all_candidates_dead_returns_none` (§12.60 ratchet).
  Existing GAP-038 tests updated to mock `probe_as_origin`.
- **Effort**: Low (probe call + rename + 2 new tests + 2 updated tests).

## GAP-042 — Origin probe bypasses stealth HttpClient (opsec debt)

- **Status**: OPEN 2026-08-10 (identified by CodeRabbit review on PR #384).
- **What**: `probe_as_origin` → `origin_direct_fetch` builds its own
  `httpx.Client` with only `{"Host": host}`, without `curl_cffi` TLS
  impersonation, header ordering, or `acquire()`/`sleep()` pacing controls.
  The live Alpha path uses `HttpClient` for all other recon traffic (§12.49
  proactive evasion), but the origin-probe path (both `LiveOriginDiscovery`
  base candidates AND GAP-041 cooperative candidates) bypasses the configured
  opsec transport.
- **Evidence**: CodeRabbit inline review on `agent_alpha/recon/origin_binding.py:131`
  (PR #384, 2026-08-10). Pre-existing — not introduced by GAP-041; GAP-041
  extended the call surface from base discovery only to also cooperative path.
- **Impact**: Origin-direct probes to client infrastructure are fingerprintable
  by WAF/IDS (vanilla httpx TLS signature, no pacing). For engagements with
  `opsec_stealth=True` this violates §12.49 (stealth by default from 1st request).
- **Fix scope**: Route `probe_as_origin` through `HttpClient` (or inject a
  stealth-aware fetcher). Touches `origin_resolver.py` + `origin_binding.py` +
  `reach_transport.py`. NOT a single-file change — needs interface design.
- **Effort**: Medium (cross-module transport refactor + stealth test fixtures).
- **Note**: Not blocking PR #384 — GAP-041 fix is correct independent of this
  opsec debt. GAP-041 prevents false proofs; GAP-042 prevents fingerprinting.

## GAP-043 — CDN edge IP filter only covers Cloudflare (Sucuri/Incapsula/Akamai false proof)

- **Status**: OPEN 2026-08-10 (identified during busonlineticket.co.th re-run).
- **What**: `is_cloudflare_ip()` (reach_strategy.py) is the ONLY CDN edge IP
  filter in the origin-discovery pipeline. It checks 14 Cloudflare CIDR ranges
  (`CF_IP_RANGES` in constants.py). Origin candidates from VT/OTX that resolve
  to Sucuri/Incapsula/Akamai/Fastly edge IPs pass the filter (not CF range) →
  treated as "origin" → `probe_as_origin` may return 200 (edge responds 200 for
  homepage) → `ORIGIN_BINDING_PROVEN` for a CDN edge IP → `ORIGIN_DIRECT` hits
  the same WAF, not the origin. False proof: "origin bound" but still behind WAF.
- **Evidence**: busonlineticket.co.th re-run 2026-08-10 —
  `CompositeOriginDiscovery.candidates()` returned [] (crt.sh down + VT/OTX
  empty for .co.th), so the bug did NOT fire (no IP reached the filter). But
  if VT/OTX had returned a Sucuri edge IP, it would have passed
  `is_cloudflare_ip` (not CF range) → false proof. Bug #19 (DONE PR #188) only
  covers response classification (detect Sucuri 403/challenge), NOT edge IP
  filtering (detect Sucuri IP as non-origin). Two different layers.
- **Impact**: Any non-CF CDN/WAF target with VT/OTX historical IPs → potential
  false `ORIGIN_BINDING_PROVEN` → wasted `ORIGIN_DIRECT_ATTEMPT` to edge IP →
  no actual bypass. Audit trail polluted with false proof events.
- **Fix scope (2 layer — NOT enumerate all vendors upfront)**:
  - **Layer 1 (filter time — IP range registry)**: generalize
    `is_cloudflare_ip` → `is_cdn_edge_ip` backed by `CDN_EDGE_RANGES` dict
    (`{"cloudflare": (...), "sucuri": (...), "incapsula": (...)}`). Vendor
    baru = 1 dict entry, bukan fungsi baru (anti-#6). CF + Sucuri sekarang
    (field-prove encountered), vendor lain additive.
  - **Layer 2 (probe time — response marker detection)**: `probe_as_origin`
    checks response headers for CDN edge markers (`cf-ray`, `x-sucuri-id`,
    `x-iinfo`) → if edge response, return False (false proof guard). Catches
    edge IPs not in Layer 1 registry (vendor baru, range berubah).
- **Effort**: Medium (3-4 files: `constants.py`, `reach_strategy.py`,
  `origin_resolver.py`, `origin_binding.py` + test fixtures).
- **Priority**: After GAP-037 (host death detection). Not a blocker for
  busonlineticket now (no IP candidates = bug doesn't fire). Latent risk for
  any non-CF CDN target with VT/OTX coverage.
- **Anti-pattern guard**: do NOT create `is_sucuri_ip()`, `is_incapsula_ip()`
  as parallel functions (Lyndon #6 — duplicate canonical types). Do NOT
  hardcode all 20+ CDN vendors upfront (Lyndon #5 — scope creep). Generalize
  interface, add vendors incrementally as field-prove encounters them.

## GAP-044 — Soft-404 false positives: exact-hash dedup misses reflected/varying error pages

- **Status**: FIXED via GAP-048 (#388, two-probe differential — format-agnostic).
  GAP-044 #386 (regex normalization) was PARTIAL — whack-a-mole per token format.
  GAP-048 SUPERSEDES the GAP-044 regex normalizer. Keep GAP-044 as the problem
  statement; GAP-048 carries the final fix. Tier-1 (7 tests) + Tier-2
  (catchall.lab field proof: 11/11 suppressed, 0 false findings) — DONE.
- **What**: The identical-body dedup (`test_identical_body_dedup.py`) uses exact body
  hash to suppress repeated catch-all responses. But many targets serve VARYING error
  pages — reflected path in body, dynamic timestamp, session token, CSRF nonce — so the
  hash differs per request even though the page is a soft-404 catch-all. Result: every
  non-existent path appears to be a "unique" response → analyzed as a real finding →
  false positive. The agent cannot distinguish "200 with reflected path" from "200 with
  real content."
- **Evidence**: ingco.co.id + ibudanbalita — 93858-byte catch-all SPA shell served 200
  for every path. Body varies slightly (reflected path in meta tag) → hash differs →
  dedup does not fire → 10+ "findings" on non-existent paths. seven-retail.com
  datalab.seven-retail.com — Vite React SPA, 1016-byte index.html for all paths (stable
  hash → dedup DID fire → correct). The bug fires on DYNAMIC error pages, not static.
- **Impact**: False positives in report (Lyndon #3). Wasted LLM tokens analyzing
  catch-all bodies. OPSEC noise from probing "unique" paths that are all the same page.
- **Fix (GAP-048, MERGED #388)**: Two-probe DIFFERENTIAL calibration — probe TWO
  independent random missing paths; both 200 with equal token count → catch-all. Token
  positions that DIFFER between samples = volatile tokens (CSRF/session/timestamp —
  WHATEVER format). Mask exactly those → format-agnostic signature. Fail-safe: any
  transport error, proper 404, or unstable token count → no signature stored → real
  content never suppressed. Single source (anti-#7); drops the three GAP-044 regexes.
- **Effort**: Medium (1 file: scout.py — replaces the GAP-044 helper block).
- **Priority**: BLOCKER — false positives violate Lyndon #3. **DONE** (GAP-048 #388).

## GAP-045 — CF-ceiling honest-outcome classification (Omega/Conductor)

- **Status**: OPEN 2026-08-11. LOW effort, HIGH product value.
- **What**: When a full-CF target yields NO exposed origin (crt.sh fails, VT/OTX empty,
  no historical DNS), the engagement ends with `beta_failed` or `alpha_complete` —
  neither communicates "CF ceiling reached, defensive-validation deliverable." Omega
  has no classification for "edge held N techniques from datacenter-IP attacker." The
  honest outcome (§12.61 product framing) is NOT wired into the report pipeline.
- **Evidence**: ibudanbalita — Beta correctly declined (fail-closed), but the outcome
  was logged as `beta_failed`, not `cf_ceiling_defensive_validation`. Client sees
  "failed" instead of "your edge held."
- **Impact**: SEA market product value lost. Client pays for "seberapa kuat proteksi
  kami" but gets "failed" instead of a defensive-validation report.
- **Fix direction**: Add `CF_CEILING` outcome classification in Conductor router
  (BLOCKED + no origin binding → CF_CEILING, not generic BLOCKED). Omega report template
  includes defensive-validation section when CF_CEILING. No auth gate change.
- **Effort**: Low (1-2 files: router.py + omega template).
- **Priority**: LOW effort, HIGH product value. After GAP-044.

## GAP-046 — HTTP Basic Auth applicator absent (cred-acquisition breadth)

- **Status**: OPEN 2026-08-11. Deferred (after §12.61 slices).
- **What**: Beta's credential applicator handles form-login (POST username/password)
  and session-cookie auth, but NOT HTTP Basic Auth (401 + WWW-Authenticate: Basic).
  When Alpha discovers a basic-auth surface (e.g. `hub.niagamas.com` returns 401
  Basic), Beta cannot apply harvested/default credentials to it — the auth surface
  is detected but unattackable.
- **Evidence**: niagamas.com field-prove — `hub.niagamas.com` returns 401 with
  `WWW-Authenticate: Basic realm="Restricted"`. Alpha correctly detected auth_surface
  (http_basic_auth). Beta dispatched but could not attempt credentials — no basic-auth
  applicator in the cred application pipeline.
- **Impact**: Basic-auth-protected surfaces are detected but never attacked. Cred-reuse
  chain broken at the applicator step for basic-auth targets.
- **Fix direction**: Add `BasicAuthApplicator` to Beta's cred application pipeline.
  Constructs `Authorization: Basic <base64(user:pass)>` header. Governed by the
  existing lockout-governor (per-host attempt cap). Distinct `Tool` implementation
  (anti-#6, ToolRegistry §12.47).
- **Effort**: Medium (1 new tool + test fixtures).
- **Priority**: Deferred — after §12.61 historical DNS slice (origin discovery opens
  more targets than basic-auth applicator).

## GAP-047 — Username harvest WP-REST-only (producer breadth, non-WP surfaces)

- **Status**: OPEN 2026-08-11. Deferred (relates to GAP-015).
- **What**: Username harvesting (`user_derived_creds.py`) only enumerates users via
  WP-REST API (`/wp-json/wp/v2/users`). Non-WP surfaces (Odoo, custom login forms,
  email patterns from OSINT, breach data) are not harvested. Cred-reuse chain is
  limited to WP-derived usernames.
- **Evidence**: niagamas.com — `pos.niagamas.com` is a Vue.js login form (not WP).
  Username harvest returned 0 users (WP-REST only). No cred-reuse possible without
  usernames to pair with harvested/default passwords.
- **Impact**: Cred-reuse chain broken at the username-producer step for non-WP targets.
- **Fix direction**: Extend username harvesting beyond WP-REST: (1) Odoo user
  enumeration via XML-RPC, (2) email-pattern derivation from OSINT (Hunter.io,
  breach data), (3) form-field username extraction from login pages. Distinct
  `Tool` implementations (anti-#6). Relates to GAP-015 (credential pattern mutation).
- **Effort**: High (multiple producers + test fixtures).
- **Priority**: Deferred — after GAP-046 (basic-auth applicator) and §12.61 slices.

## Summary: All open GAPs from field-prove (niagamas + bernofarm + ingco + bot)

| GAP | Title | Severity | Effort | Field-prove source |
|-----|-------|----------|--------|-------------------|
| 023 | route_next blocks Beta when only USER nodes exist | **FIXED** | Low | niagamas (merged 60d0071) |
| 026 | StealthPacer gate inverted (default OFF) | High | Low | niagamas |
| 027 | Sensitive files probed before legitimate endpoints | Medium | Low | niagamas |
| 028 | Origin-direct generic homepage not detected | Medium | Low | niagamas |
| 029 | Unreachable subdomain probed for all 12 paths | High | Low | bernofarm + niagamas |
| 030 | auth_surface regex misses Vue.js password inputs | High | Low | niagamas (pos.niagamas.com) |
| 031 | Beta crashes on OriginUnreachableError | High | Medium | niagamas |
| 032 | OTX timeout 30s blocks sequential OSINT | Low | Medium | bernofarm + niagamas |
| 033 | Subdomain pivot path not designed | Medium | High | niagamas (design gap) |
| 034 | Entry-selection has no node-level reachability signal | Medium | Medium | niagamas/bernofarm (entry-selection slice-1) |
| 035 | Entry-selection strikes ONE candidate; multi-surface not iterated | Medium | Medium | niagamas (hub + pos both reachable) |
| 036 | LLM tool-pick fires on auth-surface pages (no deterministic RULE) | Low | Low | niagamas (pos.niagamas.com) |
| 037 | Mid-run host death not detected (consecutive-failure threshold) | **FIXED** | Low | busonlineticket.co.th (Sucuri WAF) |
| 038 | Cooperative mode short-circuits origin discovery (no binding proof) | High | Low | ibudanbalita (cooperative, 0 origin attempts) |
| 039 | CompositeOriginDiscovery exact-host filter drops apex intel | **FIXED** | Low | niagamas (merged PR #382) |
| 040 | Ownership gate rejects consented subdomains (origin-direct crash) | **FIXED** | Low | niagamas (merged PR #383) |
| 041 | Cooperative soft-binding emits PROVEN for unprobed (stale) candidates | **FIXED** | Low | niagamas (merged PR #384) |
| 042 | Origin probe bypasses stealth HttpClient (opsec debt) | Low | Low | registered (opsec debt) |
| 043 | CDN edge IP filter only covers Cloudflare | Medium | Medium | busonlineticket (latent) |
| 044 | Soft-404 false positives (exact-hash dedup misses varying error pages) | **FIXED** (GAP-048) | Medium | ingco/ibudanbalita (Lyndon #3) |
| 045 | CF-ceiling honest-outcome classification (Omega/Conductor) | Low | Low | ibudanbalita (product value) |
| 046 | HTTP Basic Auth applicator absent | Medium | Medium | niagamas hub 401 |
| 047 | Username harvest WP-REST-only (non-WP surfaces) | Medium | High | niagamas pos Vue login |
| 048 | Soft-404 signature format-fragile (regex whack-a-mole) | **FIXED** (#388) | Medium | ingco (CSRF-hex-in-JS-object leaked by GAP-044 regexes) — SUPERSEDES GAP-044 fix |
| 049 | STEALTH_BROWSER header contradiction (UA=Windows, sec-ch-ua-platform=macOS) | **FIXED** (#396) | Small | tls.peet.ws verification — partial header override created fingerprint contradiction (§12.49 implementation gap) |

## Recommended fix order (one slice at a time)

1. **GAP-029** (unreachable skip) — **DONE** (merged)
2. **GAP-030** (auth_surface regex) — **DONE** (merged)
3. **GAP-026** (pacer default) — Option A: stealth toggle at engagement creation
4. **GAP-031** (Beta crash) — **DONE** (graceful decline + Omega). Residual = §12.61
5. **GAP-027** (probing order) — legitimate endpoints first
6. **GAP-028** (origin homepage detection) — baseline comparison (relates to GAP-044)
7. **GAP-032** (OTX parallel/timeout) — performance, bukan correctness
8. **GAP-033** (subdomain pivot) — design phase, bukan sekarang
9. **GAP-037** (mid-run host death) — **DONE** (merged PR #385)
10. **GAP-043** (CDN edge IP filter) — after GAP-037
11. **GAP-044/048** (soft-404 catch-all calibration) — **DONE** (GAP-044 #386 partial →
    GAP-048 #388 two-probe differential, format-agnostic). Tier-1 + Tier-2 proven.
12. **GAP-045** (CF-ceiling honest outcome) — LOW effort, HIGH product value
13. **§12.61 slice 1** (historical DNS origin discovery) — biggest missing passive signal
14. **GAP-046** (basic-auth applicator) — after §12.61 slices
15. **GAP-047** (username harvest non-WP) — after GAP-046

---

## Bug #34: Frontier Queue Re-enqueues Already-Probed URLs → Infinite Cycle

- **Status**: OPEN
- **Priority**: High
- **Effort**: Medium
- **Blocks**: Run never converges; burns HTTP + LLM tokens re-probing identical URLs
- **Observed**: spectranet.com.ng live-fire run (2026-08-11) — 3 full cycles in 5+ min, 0 new findings after cycle 1

### Root Cause

The scout's frontier queue re-enqueues URLs that have already been fetched and
analyzed. `_ran_campaigns` correctly prevents tool handlers from re-running
(handler returns 0 on repeat), but the URL is still **fetched** (HTTP request)
and **sent to the LLM** (token burn) before the handler no-ops. The frontier
has no `seen_urls` dedup at the enqueue boundary.

### Evidence (spectranet.com.ng, 2026-08-11)

Cycle 1: homepage → leak paths → wp-json → readme → wc/v3 → users → wp-admin pages
Cycle 2: `.git/config` → leak paths → wp-json → readme → wc/v3 → users → wp-admin pages
Cycle 3: `.git/config` → leak paths → wp-json → ... (identical, killed after 5+ min)

Each cycle: ~15 HTTP requests + ~4 LLM calls = 0 new findings after cycle 1.

### Affected Files

- `agent_alpha/agents/alpha/scout.py` — `enqueue_discovered_url` (no seen-set check)
- `agent_alpha/agents/alpha/scout.py:636-641` — frontier expansion loop re-enqueues hrefs from re-fetched pages

### Proposed Fix

Add a `_seen_urls: set[str]` to the scout. `enqueue_discovered_url` checks
`url in self._seen_urls` before adding to the queue. Deterministic catalog
seeds (`WELL_KNOWN_LEAK_PATHS`, `wp_fingerprint.frontier_seeds`) also go through
this check — they are first-time only. Test contract: a re-enqueued URL is a
no-op (returns False), and the scout's `_step_once` never fetches a URL twice.

---

## Bug #35: `LLM_TOOL_SELECT_MAX_TOKENS=512` Too Small for Reasoning Model

- **Status**: OPEN
- **Priority**: High
- **Effort**: Low (one-line constant change + test)
- **Blocks**: Intermittent `OrientationError` on wp-admin pages; ~40% LLM call failure rate on 7KB+ bodies
- **Observed**: spectranet.com.ng live-fire run (2026-08-11) — `upgrade.php`, `import.php`, `update-core.php` (cycle 2) all failed with "LLM decision failed; non-analyzable"

### Root Cause

`LLM_TOOL_SELECT_MAX_TOKENS = 512` in `agent_alpha/config/constants.py:149`.
The reasoning provider `deepseek-v4-flash` is a reasoning model: it spends
completion tokens on `reasoning_content` **before** emitting the final
`content` (the JSON tool decision). `reasoning_content` IS counted against
the `max_tokens` budget by the DeepSeek API.

When reasoning is long (~500+ tokens), the 512-token budget is exhausted by
reasoning alone → `finish_reason="length"` → `CompletionTruncatedError`
(subclass of `RuntimeError`) → `OrientationError` in the orchestrator.

### Evidence (reproduced 2026-08-11)

Direct LLM call with 7201-byte wp-admin body, `max_tokens=512`, 5 consecutive calls:

| Call | Result | reasoning_content length |
|------|--------|--------------------------|
| 1 | **FAIL** (CompletionTruncatedError) | >512 tokens |
| 2 | OK (`{"tool": "wp_version"}`) | 2240 chars (~498 tokens) |
| 3 | OK | 2164 chars |
| 4 | OK | 1287 chars |
| 5 | **FAIL** (CompletionTruncatedError) | >512 tokens |

2/5 calls fail (40%). The failure is **intermittent** because reasoning length
varies per call — sometimes ~498 tokens (just under 512), sometimes >512.

### Model verification

`deepseek-v4-flash` IS available on api.deepseek.com (confirmed via
`provider.list_models()`). The model is correct — the token budget is the
root cause, not a model mismatch.

### Affected Files

- `agent_alpha/config/constants.py:149` — `LLM_TOOL_SELECT_MAX_TOKENS = 512`
- `agent_alpha/llm/providers/deepseek.py:94-97` — `CompletionTruncatedError` raised when `finish_reason == "length"` and `content` is empty
- `agent_alpha/llm/orchestrator.py:111-115` — `OrientationError` wraps the truncation

### Proposed Fix

Raise `LLM_TOOL_SELECT_MAX_TOKENS` from 512 to **2048**. This gives headroom
for reasoning (~500-600 tokens) + content (~50 tokens) with safety margin.
Cost impact: `deepseek-v4-flash` output pricing is $0.0002/1K tokens →
+1536 tokens = +$0.0003 per LLM call. Negligible.

Test contract: 5 consecutive LLM calls with a 7KB wp-admin body at
`max_tokens=2048` must produce 0 `CompletionTruncatedError` exceptions.

---

## Bug #36: `/wp-admin/*` Login-Gated Pages Enter Frontier Without Rule Match

- **Status**: OPEN
- **Priority**: Medium
- **Effort**: Low (one playbook YAML file)
- **Blocks**: LLM token burn for predictable non-findings on login-gated WP admin pages
- **Observed**: spectranet.com.ng live-fire run (2026-08-11) — `update-core.php`, `upgrade.php`, `import.php` all escalated to LLM tier (no rule match) → token burn + Bug #35 truncation

### Root Cause

`WP_CRAWL_ALLOW_PATH_PREFIXES` includes `/wp-admin/` (correctly — some wp-admin
pages have real surface value). But login-gated pages (`update-core.php`,
`upgrade.php`, `import.php`, `plugins.php`, etc.) return HTTP 200 with a login
form or maintenance page body that matches NO playbook rule → escalates to
SINGLE_LLM tier → token burn for a page that has zero unauthenticated recon
value.

### Evidence

| Page | HTTP | Body | Rule match? | LLM called? | Finding? |
|------|------|------|-------------|-------------|----------|
| `update-core.php` | 200 | 8511 B (login redirect) | No | Yes (cycle 1: OK, cycle 2: FAIL) | 0 |
| `upgrade.php` | 200 | 1357 B (maintenance) | No | Yes (FAIL) | 0 |
| `import.php` | 200 | 8506 B (login form) | No | Yes (FAIL) | 0 |

### Affected Files

- `agent_alpha/config/constants.py:380-386` — `WP_CRAWL_ALLOW_PATH_PREFIXES` includes `/wp-admin/`
- `agent_alpha/tools/playbooks/` — no playbook for wp-admin login-gated body signature

### Proposed Fix

Add `wp_admin_login_gated.yaml` playbook that matches on WP login form body
signature (`<form name="loginform"`, `wp-login.php`, "You must log in",
"Database Update Required") → tool `generic_http_probe` with rationale
"wp-admin login-gated page; no unauthenticated recon surface". This prevents
LLM escalation for predictable login-gated pages while keeping `/wp-admin/`
in the crawl allowlist (for genuine surface like `install.php` info disclosure).

Test contract: a wp-admin page with login form body matches the new rule
(RULE tier, not LLM tier) and produces 0 findings.

---

## GAP-048 — Soft-404 signature is format-fragile: regex normalization is whack-a-mole

- **Status**: MERGED (#388). SUPERSEDES the GAP-044 regex normalizer. Tier-1 (7 tests
  pass on Oracle) + Tier-2 (catchall.lab field proof: 11/11 suppressed, 0 false
  findings). DONE.
- **What**: GAP-044 (#386) normalized the catch-all body with per-format REGEXES — reflected
  path, then HTML attribute values, then digit runs. Each only covers ONE token shape. Field
  showed the pattern is whack-a-mole: a CSRF **hex** token inside a JS object
  (`'csrf_token_name': '<32hex>'`, colon-delimited) is neither an HTML attribute (needs `=`)
  nor digit-only (`\d{6,}` misses hex) → survives normalization → signature differs per
  request → catch-all NOT suppressed → false-positive finding returns. Adding a hex regex
  closes hex; the NEXT target's token (base64 session, UUID, JWT) breaks it again. Enumerating
  token formats never terminates.
- **Evidence**: ingco.co.id catch-all — diff between the baseline probe and
  `/config/database.yml.bak` was exactly 2 lines, both the per-request CSRF token
  (`value="0a12ffca…"` at L1453 handled by the attr regex; `'csrf_token_name': '0a12ffca…'`
  at L1866 NOT handled — colon context). 32-char hex changes per request → hash differs →
  `_is_soft404` False → 93858-byte catch-all analysed as a real finding.
- **Impact**: BLOCKER re-opened — false positives persist (Lyndon #3) on any target whose
  catch-all carries a per-request token the current regexes miss. Blocks the GAP-044
  field-prove (`catchall.lab`, #387).
- **Fix (MERGED #388 — two-probe DIFFERENTIAL calibration, format-agnostic)**: probe TWO
  independent random missing paths; both 200 with equal token count → catch-all. The token
  POSITIONS that DIFFER between the two samples ARE the per-request volatile tokens (CSRF,
  session, timestamp) — WHATEVER their format. Mask exactly those positions → the signature is
  driven by *what the target actually varies*, not by an enumerated regex list. Reflected path
  is neutralised first (path→constant) so paths of any complexity keep a stable token count
  (alignment). Ends the whack-a-mole. FAIL-SAFE: any transport error, a proper 404/redirect,
  or an unstable token count (e.g. variable-length JWT) stores NO signature → real content is
  never suppressed. Single source (anti-#7); drops the three GAP-044 regexes.
- **Tests (§12.60, ALL PASS)**: true-positive (hex + **UUID** — the format the regex missed);
  fail-safe cardinal (proper-404 host → no signature); TWO false-negative guards on a
  CALIBRATED host — structural mismatch AND same-token-count-different-skeleton (masked-hash
  collision); unstable token count (hex vs UUID → no signature); exactly 2 probes per host.
  Field regression: `catchall.lab` Tier-2 = 11/11 suppressed, 0 false findings.
- **Cost/known-limit**: +1 calibration GET per reachable host (2 probes total). Variable-length
  tokens (JWT payloads) → unstable token count → fail-safe skip (no false positive), register
  as a follow-on only if seen. Deterministic (seeded probe paths) → seeded-replay stable.
- **Effort**: Medium (1 file: scout.py — replaces the GAP-044 helper block). DONE.

## GAP-049 — STEALTH_BROWSER header contradiction (UA=Windows, sec-ch-ua-platform=macOS)

- **Status**: DONE (PR #396, merged `96f716d`).
- **What**: `constants.STEALTH_BROWSER` set a Windows `User-Agent` but omitted
  `sec-ch-ua-platform`. curl_cffi's `chrome124` impersonate preset sends
  `sec-ch-ua-platform: "macOS"` by default. The result: every request carried
  `User-Agent: ...Windows NT 10.0...` alongside `sec-ch-ua-platform: "macOS"` —
  a fingerprint contradiction that WAF/CDN bot detection (Cloudflare, Akamai)
  can flag as non-browser. Additionally, the custom `Accept` header was
  stripped (missing `image/apng` and `application/signed-exchange;v=b3;q=0.7`
  that real Chrome 124 sends), and `Accept-Encoding`, `upgrade-insecure-requests`,
  and `sec-ch-ua-mobile` were not explicitly set — leaving curl_cffi defaults
  that may diverge from the overridden UA.
- **Root cause**: Partial header override. §12.49 mandates "realistic browser
  headers as DEFAULT", but the implementation overrode SOME headers (UA, Accept,
  sec-ch-ua) while leaving others (sec-ch-ua-platform, Accept-Encoding) at
  curl_cffi preset defaults. A partial override is worse than no override — it
  creates contradictions between overridden and non-overridden headers.
- **Evidence**: Verified via `https://tls.peet.ws/api/all` (canonical TLS
  fingerprint check). Before fix: `UA=Windows`, `sec-ch-ua-platform="macOS"`,
  `Accept` stripped. After fix: `UA=Windows`, `sec-ch-ua-platform="Windows"`,
  `Accept` complete. JA4 and Akamai HTTP/2 fingerprints matched Chrome 124 in
  both cases (TLS layer was never the issue — header content was).
- **Impact**: STEALTH-DEGRADED — any WAF that cross-checks `sec-ch-ua-platform`
  against `User-Agent` OS (Cloudflare bot management, Akamai BMP) could flag
  Agent-Alpha traffic as bot despite correct JA4/Akamai TLS fingerprints.
  Not a false-positive/blocker like GAP-044/048, but a stealth erosion that
  undermines §12.49's core promise (evasion-by-default from first request).
- **Fix (MERGED #396 — hybrid header consistency)**:
  1. `STEALTH_BROWSER` completed with all Chrome 124 Windows headers:
     `sec_ch_ua_platform`, `sec_ch_ua_mobile`, `accept_encoding`,
     `upgrade_insecure_requests`, and full `accept` matching real Chrome 124.
  2. `_derive_platform_from_ua()` — auto-derives `sec-ch-ua-platform` from the
     UA string when opsec overrides UA. Recognizes Windows, macOS, Linux,
     Chrome OS, Android, iOS; returns `"Unknown"` with log warning for
     unrecognized UAs (anti-silent-fallback).
  3. `_validate_header_consistency()` — runs in `_request()` on the FINAL
     merged headers (after per-call overrides), logging warnings on any
     UA/platform mismatch. Catches contradictions introduced at construction
     time AND per-request.
  4. Explicit opsec `headers` dict still wins over auto-derivation — operator
     takes responsibility for the override.
- **Tests (ALL PASS on Oracle ARM64)**: 28 in `test_http_client.py` (15 new:
  default platform match, derive Windows/macOS/Linux/CrOS/iOS/Android/Unknown,
  consistency validation no-mismatch/mismatch, opsec UA auto-derive Windows/mac,
  opsec explicit platform not clobbered, inconsistent warning logged, per-request
  override validates consistency). Phase 2: 265 passed, 2 deselected. Phase 4:
  489 passed, 1 skipped. `make check` clean.
- **Anti-Lyndon**: #7 (single source — `STEALTH_BROWSER` is the canonical header
  set, curl_cffi preset is the canonical TLS/H2 fingerprint, no duplication).
  #3 (honest outcome — header contradiction is a real stealth bug, not cosmetic).
  #6 (no duplicate canonical type — `_derive_platform_from_ua` is the single
  platform derivation function, `_validate_header_consistency` is the single
  validation function).
- **Effort**: Small (3 files: constants.py, http_client.py, test_http_client.py).
  DONE.

