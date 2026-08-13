> CANONICAL SOURCE: bugs + GAPs ledger. Compact format — AI-readable, no prose.
> Strategic narrative: docs/strategic_gaps_roadmap.md (derived). ADR: docs/ADR.md.

# Bug & Gap Ledger

## Summary Table — Bugs

| # | Title | Status | Pri | Cat | Effort | Blocks |
|---|-------|--------|-----|-----|--------|--------|
| 1 | CDN crawl loop | DONE | — | CW | Low | — |
| 2 | Odoo rule greedy | FIXED | — | FS | Low | DeepSeek analysis |
| 3 | Report not persisted | OPEN | High | RG | Med | Client deliverable |
| 4 | Graph not rebuilt from event store | OPEN | Med | RG | Med | Report re-gen |
| 5 | No report endpoint | OPEN | High | RG | Low | Client deliverable |
| 6 | Idempotency blocks LLM | FIXED | — | FS | Med | DeepSeek analysis |
| 7 | Engagement memory not persisted | OPEN | Med | RG | Med | Cross-engagement learning |
| 8 | Passive discovery not enqueued | OPEN | Med | RG | Low | Subdomain coverage |
| 9 | URL backslash not normalized | OPEN | Low | CW | Low | Crawl noise |
| 10 | HTTP 415 not classified | FIXED | — | RM | Low | WP recon |
| 11 | Crawl not discriminating | DONE | — | CW | Med | LLM token waste |
| 12 | Same page crawled repeatedly | OPEN | Med | CW | Low | Crawl noise |
| 13 | WP rule mismatch (Cloudways) | OPEN | High | FS | Low | WP recon |
| 14 | default_creds rule greedy (Laravel) | FIXED | — | FS | Low | DeepSeek analysis |
| 15 | Trailing slash dedup | OPEN | Med | CW | Low | Crawl noise |
| 16 | Runner `Report.chains` AttributeError | OPEN | Low | RG | Low | Local runner scripts |
| 17 | Apache mod_autoindex sort URL explosion | OPEN | High | CW | Low | Crawl noise + LLM waste |
| 18 | CF JS challenge (200) not classified | DONE | — | RM | Med | CF-protected target recon |
| 19 | Response classifier status-only | DONE | — | RM | Med | CDN/WAF challenge detection |
| 20 | Identical body dedup | DONE | — | CW | Low | LLM token waste |
| 21 | LLM-tier tool re-selection (exclude_tools) | CLOSED #196 | — | RG | Med | LLM token waste, tool starvation |
| 22 | Beta FAILED → chain halts (Omega not dispatched) | RESOLVED | — | RG | Low | Report never generated on failed access |
| 23 | Beta next_recommended always GAMMA | RESOLVED | — | RG | Low | Advance logic receives GAMMA but status=FAILED |
| 24 | response_classifier `challenge-platform` FP on CF | FIXED | — | FS | Low | All CF-proxied sites misclassified |
| 25 | DefaultCredsTool ignores harvested USER nodes | RESOLVED | — | RG | Med | Beta can't spray discovered usernames |
| 26 | Generic blind probing → excessive 404s → WAF/CF block | OPEN | High | CW | Med | Agent blocked before finding anything |
| 34 | `run_recon` resets `_probed` across targets → cycling | OPEN | High | CW | Low | Run never converges; burns HTTP + LLM tokens |
| 35 | `LLM_TOOL_SELECT_MAX_TOKENS=512` too small | OPEN | High | RM | Low | Reasoning model truncates → OrientationError |
| 36 | `/wp-admin/*` login-gated pages enter frontier | OPEN | Med | CW | Low | Token burn for predictable non-findings |
| 37 | Non-WP hosts have no crawl allowlist | OPEN | High | CW | Low | Alpha crawls 20+ content pages, 0 findings |

## Summary Table — Gaps

| # | Title | Status | Pri | Cat | Effort | Blocks |
|---|-------|--------|-----|-----|--------|--------|
| 001 | Missing tools & playbooks (ASP.NET/JSP/SPA) | OPEN | Med | SS | High | Alpha only effective on Laravel/WP/Odoo |
| 002 | Scratchpad/SessionStore not wired | CLOSED #192 | — | WI | Med | Agent runs without working memory |
| 003 | IntelligenceBase — protocol only, all methods return InsufficientData | OPEN | High | WI | Med | Agent doesn't learn from past engagements |
| 004 | Planner/World Model | LOCKED → ADR §12.29 | — | RG | High | Reactive 1-step loop, no goal-directed cognition |
| 005 | PolicyEnforcer partially wired (slice-1 done, slice-2 OPEN) | PARTIAL | High | WI | Med | OPSEC/scope/technique checks dead in production |
| 006 | Attack graph analytics partially wired (report only, not decision) | PARTIAL | Med | WI | Med | Blast-radius gate not active in decision path |
| 007 | OSINT / external context gathering — none | OPEN | Med | RG | High | Agent probes target without intelligence |
| 008 | Curiosity-driven exploration | MOVED → §12.30 | — | — | — | — |
| 009 | Cross-validation between tools | MOVED → §12.31 | — | — | — | — |
| 010 | Goal-completion detection | MOVED → §12.29 | — | — | — | — |
| 011 | Authenticated crawl / post-access re-discovery | MOVED → §12.32 | — | — | — | — |
| 012 | Adaptive evasion | MOVED → §12.33 | — | — | — | — |
| 013 | Credential pattern mutation | MOVED → §12.34 | — | — | — | — |
| 014 | Fan-out parallel worker wiring (Shape A not wired) | OPEN | Med | WI | Med | Parallel target scanning not available |
| 015 | Credential spray tool (harvested usernames × passwords) | DONE | — | RG | Med | Beta can't spray discovered usernames |
| 016 | Wayback Machine pre-intel | OPEN | Low | RG | Med | No archive-driven probe selection |
| 017 | PassiveIntelMap enrichment dead-end (consumer not wired) | OPEN | Med | WI | Med | OSINT data collected but not consumed |
| 018 | LiveOriginDiscovery doesn't seed in-scope siblings | RESOLVED | — | RG | Med | Origin discovery fails when crt.sh down |
| 019 | Per-host origin-resolution cache | RESOLVED | — | CW | Low | Redundant DNS lookups |
| 020 | Mid-engagement pattern-group exhaustion | OPEN | Med | CW | Med | Agent re-tries exhausted patterns |
| 021 | Fingerprint-driven path hard-filter | OPEN | Med | CW | Low | Irrelevant paths probed for known stack |
| 022 | Deterministic rule coverage + finding correlation | OPEN | Med | RM | Med | Rules miss known patterns |
| 026 | StealthPacer gate inverted (default OFF) | OPEN | High | WI | Low | §12.49 violation — stealth not default |
| 027 | Probing order: sensitive files before legitimate | OPEN | Med | CW | Low | .env probes trigger CF before wp-json |
| 028 | Origin-direct generic homepage detection | OPEN | Med | RM | Low | Origin returns homepage for all paths → 0 findings |
| 029 | Unreachable subdomain still probed for all 12 paths | DONE | — | CW | Low | Wastes ~15min on dead hosts |
| 030 | auth_surface regex misses Vue.js `:type` password | DONE | — | RM | Low | Vue login forms not detected |
| 031 | Beta crashes on OriginUnreachableError | DONE | — | RG | Med | Beta can't strike when no origin binding |
| 032 | OTX timeout 30s blocks sequential OSINT | OPEN | Low | CW | Med | 30s wasted per engagement |
| 033 | Subdomain pivot path not designed | OPEN | Med | RG | High | Subdomain access not used as stepping stone |
| 034 | Entry-selection has no node-level reachability signal | DONE | — | RG | Med | Dead hosts selected as strike candidates |
| 035 | Entry-selection strikes ONE candidate | DONE | — | RG | Med | Multi-surface not iterated |
| 036 | LLM tool-pick fires on auth-surface pages | OPEN | Med | RM | Low | No deterministic RULE for auth pages |
| 037 | Mid-run host death not detected | DONE #385 | — | CW | Low | Agent probes dead host indefinitely |
| 038 | Cooperative mode short-circuits origin discovery | OPEN | Med | RG | Med | No binding proof when cooperative |
| 039 | CompositeOriginDiscovery exact-host filter drops apex | OPEN | Med | RM | Med | Apex intel lost for subdomain binding |
| 040 | Ownership gate rejects consented subdomains | OPEN | Med | RG | Med | Origin-direct crash on consented subdomain |
| 041 | Cooperative soft-binding emits PROVEN for unprobed | OPEN | Med | FS | Med | Stale candidates marked proven |
| 042 | Origin probe bypasses stealth HttpClient | OPEN | Med | WI | Low | OPSEC debt — origin probe not stealthy |
| 043 | CDN edge IP filter only covers Cloudflare | OPEN | Med | RM | Med | Sucuri/Incapsula/Akamai false proof |
| 044 | Soft-404 false positives (exact-hash dedup) | FIXED #386 | — | FS | Med | Reflected error pages not deduped |
| 045 | CF-ceiling honest-outcome classification | OPEN | Low | RG | Low | Omega/Conductor honest report on CF-blocked |
| 046 | HTTP Basic Auth applicator absent | OPEN | Med | SS | Med | 401-protected surfaces not attacked |
| 047 | Username harvest WP-REST-only | OPEN | Med | SS | High | Non-WP surfaces (Vue login) not harvested |
| 048 | Soft-404 signature format-fragile | FIXED #388 | — | RM | Med | Regex normalization whack-a-mole |
| 049 | STEALTH_BROWSER header contradiction | FIXED #396 | — | RM | Low | UA=Windows, sec-ch-ua-platform=macOS |
| 050 | IntelligenceBase wiring: data exists, never reaches memory | OPEN | High | WI | Med | 3 wiring gaps (tech_stack, metadata, outcomes) |
| 051 | `try_harder` is path-recovery only, not strategic pivot | OPEN | Med | RG | Med | Only 2 pivots needed: WAF_BLOCKED_ALL→origin, RECON_EXHAUSTED→cred OSINT |
| 052 | WooCommerce version not extracted (system_status not fetched) | OPEN | P0 | RM | Low-Med | CVE-2026-3589 affects WC 5.4-10.5; no version = no CVE check |
| 053 | WP plugin handler exists but never fires | OPEN | P0 | DC | Low | Handler correct but LLM orient fails on wp-admin → dead code |
| 054 | WP REST user fields truncated (slug only) | OPEN | P0 | DD | Low | Email/roles dropped — needed for breach OSINT + admin targeting |
| 055 | Security headers not audited | OPEN | P1 | UN | Low | HSTS/X-Frame/CSP missing = attack surface. 0 new requests |
| 056 | robots.txt + sitemap.xml not fetched | OPEN | P1 | UN | Low | 2 requests, high discovery value |
| 057 | XML-RPC not checked | OPEN | P1 | SS | Low | `/xmlrpc.php` = brute force multiplier. 1 request |
| 058 | JS secret extraction missing | OPEN | P1 | UN | Low-Med | ADR charter says Alpha delivers js_secrets — not done |
| 059 | Cookie audit missing (HttpOnly/Secure/SameSite) | OPEN | P2 | UN | Low | Parse from existing response, 0 new requests |
| 060 | WooCommerce endpoint enumeration missing | OPEN | P2 | SS | Med | orders/customers/products not probed → PII exposure missed |
| 061 | WP REST other endpoints not probed | OPEN | P2 | SS | Med | posts/pages/comments/media not probed |
| 062 | TLS/MX/SPF/DMARC infrastructure recon missing | OPEN | P3 | UN | Med | Passive DNS, 0 target touch, §12.48 |
| 063 | Odoo database list not extracted from DB manager | OPEN | P1 | DD | Low | `/web/database/manager` 51KB fetched, DB names discarded |
| 064 | Odoo XML-RPC not checked | OPEN | P1 | SS | Low | `/xmlrpc/2/common`, `/xmlrpc/2/db` not probed |
| 065 | Odoo /website/info not fetched | OPEN | P2 | SS | Low | Version + module list endpoint not checked |
| 066 | Odoo database name from URL not captured | OPEN | P2 | DD | Low | `/web?db=erp` fetched, "erp" not in graph |
| 067 | OdooAccessTool only XML-RPC, no JSON-RPC fallback | OPEN | P1 | TM | Med | CF blocks XML-RPC → no fallback → Beta fails |
| 068 | ~~Odoo default creds not in dict~~ | RETRACTED | — | — | — | OdooAccessTool has own candidates. No fix needed |

## Category Legend

| Code | Category | Meaning |
|------|----------|---------|
| RM | RECON_MISS | Alpha doesn't capture data available in response |
| DC | DEAD_CODE | Handler exists but never fires in autonomous path |
| DD | DATA_DISCARD | Alpha fetches response but discards available fields |
| TM | TRANSPORT_MISMATCH | Tool speaks wrong protocol for target stack |
| CW | CYCLING_WASTE | Re-probes same URLs or crawls irrelevant pages |
| FS | FALSE_SUCCESS | Reports "done" but data is incomplete |
| RG | ROUTING_GAP | Router doesn't dispatch to correct agent or pivot |
| WI | WIRING_ISLAND | Proven in runner, not in autonomous Conductor path |
| EC | EXIT_CRITERIA_WEAK | Exit criteria too weak to catch the gap |
| SS | STACK_SPECIFIC | Gap only affects one stack (WP/Odoo/Laravel/Spring) |
| UN | UNIVERSAL | Gap affects all stacks |

## Recommended Fix Order (one slice at a time)

1. **Bug #35** — LLM token budget (1-line constant fix, stops OrientationError)
2. **Bug #34** — frontier cycling (seen_urls dedup, stops re-probing)
3. **Bug #37** — non-WP crawl allowlist (universal security-relevance filter)
4. **Bug #36** — wp-admin login-gated playbook (1 YAML, stops token burn)
5. **GAP-053** — WP plugin handler wiring (P0, dead code fix)
6. **GAP-052** — WC system_status version extraction (P0, CVE prerequisite)
7. **GAP-054** — WP REST user email/roles (P0, breach OSINT prerequisite)
8. **GAP-051** — try_harder strategic pivot (WAF_BLOCKED_ALL→origin, RECON_EXHAUSTED→cred OSINT)
9. **GAP-067** — OdooAccessTool JSON-RPC fallback (CF-blocked Odoo targets)
10. **GAP-064** — Odoo XML-RPC discovery (Alpha finds it, Beta uses it)
11. **GAP-063** — Odoo DB list extraction (DB names = Beta cred-stuff context)
12. **GAP-066** — Odoo DB name from URL (URL parse, 0 new requests)
13. **GAP-065** — Odoo /website/info (version + module list + CVE)
14. **GAP-055** — Security headers (universal, 0 new requests)
15. **GAP-056** — robots.txt + sitemap (universal, 2 requests)
16. **GAP-058** — JS secret extraction (universal, ADR charter requirement)
17. **GAP-059** — Cookie audit (universal, 0 new requests)
18. **GAP-062** — TLS/MX/SPF/DMARC (universal passive, 0 target touch)
19. **GAP-057** — WP XML-RPC (stack-specific, 1 request)
20. **GAP-060** — WC endpoint enumeration (P2, data harvest surface)
21. **GAP-061** — WP REST other endpoints (P2, data harvest surface)

**Deferred:** GAP-001 (new stack playbooks), GAP-003 (IntelligenceBase), GAP-007 (OSINT), GAP-014 (fan-out), GAP-016 (Wayback), GAP-017 (PassiveIntelMap consumer), GAP-020-022, GAP-026-028, GAP-032-033, GAP-036, GAP-038-043, GAP-045-047, GAP-050.

**STOP-gated (Gamma):** GAP-004 (Planner), GAP-005 slice-2 (PolicyEnforcer agent path), GAP-006 slice-2 (graph analytics → decision). These require Phase 4 (Gamma) authorization gate + ToolComposer.

---

## Bug Details (compact)

### Bug #21 — LLM-tier tool re-selection
- **Status:** CLOSED #196
- **Root cause:** `LLMOrchestrator.decide_excluding()` passes `exclude_tools` to RULE tier but NOT to LLM tier. DeepSeek re-selects same tool on every page with same fingerprint.
- **Fix:** `exclude_tools` forwarded to LLM tier + prompt instruction + post-filter + contract guard.
- **Files:** `agent_alpha/llm/orchestrator.py:96-140`

### Bug #22 — Beta FAILED → chain halts
- **Status:** RESOLVED
- **Root cause:** `decide_advance()` returns noop on non-COMPLETE status. Omega never dispatched when Beta fails.
- **Fix:** `route_next` returns OMEGA for FAILED/BLOCKED status (router.py:132-134).
- **Tests:** `test_router.py:test_alpha_failed_routes_omega`
- **Field-proven:** quantum-laboratories.com, bernofarm.com — OMEGA dispatched after Beta FAILED.

### Bug #23 — Beta next_recommended always GAMMA
- **Status:** RESOLVED
- **Root cause:** `strike.py:517` hardcoded `next_recommended=GAMMA` regardless of status.
- **Fix:** `route_next` ignores Beta's recommendation — returns OMEGA for FAILED/BLOCKED.

### Bug #24 — response_classifier `challenge-platform` FP
- **Status:** FIXED
- **Root cause:** `CHALLENGE_STRONG_MARKERS` included `"challenge-platform"` — CF injects this into ALL proxied sites via analytics script, not just challenge pages.
- **Fix:** Removed from strong markers. Added body-size guard: only triggers CHALLENGE when body < 5KB (interstitial size).
- **Files:** `agent_alpha/recon/response_classifier.py:55-156`
- **Evidence:** quantum-laboratories.com — before: 21 WAF_BLOCKED, 0 nodes. after: 5 WAF_BLOCKED (real), 110 nodes.

### Bug #25 — DefaultCredsTool ignores USER nodes
- **Status:** RESOLVED (via GAP-015 UserDerivedCredsTool)
- **Root cause:** DefaultCredsTool uses hardcoded dict only. CredReuseTool requires CREDENTIAL nodes (vault), not USER nodes. Alpha's 9 harvested usernames ignored by Beta.
- **Fix:** UserDerivedCredsTool derives candidates from username + domain stem.

### Bug #26 — Generic blind probing → WAF/CF block
- **Status:** OPEN
- **Root cause:** `run_recon` seeds 27+ `WELL_KNOWN_LEAK_PATHS` blindly against every target. CF rate-based protection triggers after ~10-15 rapid 404s.
- **Proposed fix:** Stack-aware tiered probing (universal 3-5 → stack-specific TIER1 3 → TIER2 6) + soft-404 baseline calibration + request pacing.
- **Files:** `scout.py:224-242`, `constants.py:275-304`

### Bug #34 — `run_recon` resets `_probed` across targets
- **Status:** OPEN
- **Root cause:** `run_recon` resets `_probed`/`_work_queue`/`_frontier` at start of each target. `try_harder` re-probes all previous URLs when cycling to next target.
- **Evidence:** spectranet 3 cycles timeout 600s. solusibersama 2 cycles, 8 duplicate tool calls, 0 new findings in cycle 2.
- **Fix:** Preserve per-engagement cumulative probe state. Add `seen_urls` dedup.
- **Files:** `scout.py:241-260`

### Bug #35 — `LLM_TOOL_SELECT_MAX_TOKENS=512` too small
- **Status:** OPEN
- **Root cause:** `deepseek-v4-flash` reasoning_content consumes token budget → intermittent `CompletionTruncatedError` → `OrientationError` on wp-admin pages (2/5 calls fail with 7KB body).
- **Fix:** Increase to 2048 or 4096. 1-line constant fix.

### Bug #36 — `/wp-admin/*` login-gated pages enter frontier
- **Status:** OPEN
- **Root cause:** `update-core.php`, `upgrade.php`, `import.php` (login-gated WP admin pages) escalate to LLM tier → token burn for predictable non-findings.
- **Fix:** Add playbook YAML for wp-admin login redirect body signature.

### Bug #37 — Non-WP hosts have no crawl allowlist
- **Status:** OPEN
- **Root cause:** `_frontier_expansion_allowed` (scout.py:2045-2075) returns True for ALL non-WP hrefs. WP has `WP_CRAWL_ALLOW_PATH_PREFIXES` filter. Odoo/Laravel/Spring/unknown crawl every content page.
- **Evidence:** quantum-laboratories.com — 20+ content pages crawled (`/visi-misi`, `/total-quality`, `/ethicals`, `/generic`, `/otc`, etc.), 0 findings. Security-relevant paths (`/xmlrpc/2/common`, `/website/info`) NOT crawled.
- **Fix:** Universal security-relevance filter for non-WP hosts. Allow: `/admin`, `/login`, `/auth`, `/api`, `/config`, `/env`, `/debug`, `/xmlrpc`, `/jsonrpc`, `/graphql`, `/actuator`, `/manager`, `/web/login`, `/web/database`, `/web/webclient`, `/website/info`, `/.env`, `/.git`. Reject content pages.
- **Files:** `scout.py:2045-2075`, `constants.py:386-392,630`

---

## Gap Details (compact)

### GAP-001 — Missing tools & playbooks (ASP.NET/JSP/SPA)
- **Status:** OPEN
- **What:** Alpha only effective on Laravel/WP/Odoo. ASP.NET, JSP, SPA, Classic ASP = 0 findings.
- **Needed:** 10 playbook YAML + 10 tools (aspnet_viewstate, dir_listing, spa_probe, api_endpoint, sqli, xss, stacktrace, secrets, json_api_applicator, generic_form_applicator).
- **Priority:** P0 = generic_form_applicator + directory_listing_probe. P1 = secrets + stacktrace + json_api. P2 = spa + api + sqli + xss. P3 = aspnet + playbooks.

### GAP-002 — Scratchpad/SessionStore
- **Status:** CLOSED #192
- **What:** SessionStore Protocol + implementations existed but never instantiated in conductor/agent path. Agent ran without working memory.
- **Fix:** Wired into main.py, recon_runner, execute_agent, Alpha, Beta. Scratchpad snapshot per step.

### GAP-003 — IntelligenceBase
- **Status:** OPEN
- **What:** `IntelligenceBase` Protocol + `RecordBackedIntelligenceBase` (312 lines) exist. `tool_success_rates` always `{}`. No caller wires IntelligenceBase to tool selection or orchestrator.
- **Fix:** Implement `PostgresIntelligenceBase`. Wire to `ToolRegistry.ranked()` + `LLMOrchestrator.decide()`. Write tool outcome stats after engagement.
- **Files:** `agent_alpha/memory/intelligence.py` (Protocol + stub), `agent_alpha/memory/engagement.py:187` (`tool_success_rates={}`), `agent_alpha/tools/registry.py:37` (static ranking)

### GAP-004 — Planner/World Model
- **Status:** LOCKED → ADR §12.29
- **What:** Reactive 1-step cognitive loop. No goal-directed cognition, no Planner/Executor, no WorldModel, no GOAL_COMPLETED stop condition.

### GAP-005 — PolicyEnforcer partially wired
- **Status:** PARTIAL (slice-1 DONE #184, slice-2 OPEN)
- **What:** `PolicyEnforcer` (152 lines) instantiated in main.py:62 but never passed to execute_agent or recon_runner. `check_technique`, `check_scope`, `resolve_opsec_profile` only called in live_fire runner (test path, not production).
- **Slice-1 DONE:** Blast-radius gate wired into `advance_engagement()`.
- **Slice-2 OPEN:** OPSEC/scope/technique checks still dead in production agent path.
- **Fix:** Pass `PolicyEnforcer` to `execute_agent()` + `recon_runner`. Call `check_technique` + `check_scope` before tool execution. Resolve OPSEC profile → pass to HttpClient.
- **Files:** `agent_alpha/conductor/policy.py` (152 lines, implemented), `agent_alpha/conductor/main.py:62` (instantiated, not passed), `agent_alpha/conductor/execute_agent.py`, `agent_alpha/conductor/recon_runner.py`

### GAP-006 — Attack graph analytics partially wired
- **Status:** PARTIAL (slice-1 DONE #184, slice-2 OPEN)
- **What:** `find_critical_paths()` + `calculate_blast_radius()` implemented in narrative.py. Called by Omega report generation. NOT called by conductor, execute_agent, or any decision-making path.
- **Fix:** Call after graph rebuild in execute_agent. Wire blast-radius gate to PolicyEnforcer. Use critical paths for target prioritization in planner.
- **Files:** `agent_alpha/graph/narrative.py:44-137` (implemented), `agent_alpha/agents/omega/roaster.py:136` (called in report only), `agent_alpha/conductor/execute_agent.py` (not called)

### GAP-007 — OSINT / external context gathering
- **Status:** OPEN
- **What:** Agent directly HTTP probes target without intelligence gathering. No crt.sh, VirusTotal, Wayback, Dehashed integration in autonomous path.
- **Fix:** Wire passive intel (crt.sh subdomains, VT reputation, Wayback URLs, Dehashed breach) into recon_runner before active probing. Feed results to frontier + tool selection.
- **Files:** `agent_alpha/recon/passive_intel.py` (exists, consumer not wired), `agent_alpha/conductor/recon_runner.py`

### GAP-014 — Fan-out parallel worker (Shape A not wired)
- **Status:** OPEN
- **What:** Celery fan-out for parallel target scanning designed but Shape A (one worker per target) not wired. Shape B (single worker, sequential) works.
- **Fix:** Wire Shape A — one Celery worker per target, results merged via event store.
- **Files:** `agent_alpha/conductor/main.py` (Celery dispatch), `agent_alpha/conductor/recon_runner.py`

### GAP-015 — Credential spray tool
- **Status:** DONE
- **What:** `UserDerivedCredsTool` — derives login candidates from Alpha-enumerated usernames + domain stem. Bounded by `USER_DERIVED_MAX_CANDIDATES_PER_USER`. Lockout-gated.

### GAP-016 — Wayback Machine pre-intel
- **Status:** OPEN
- **What:** No archive-driven probe selection. Wayback CDX API not queried.
- **Fix:** Query Wayback CDX API for archived URLs of target domain. Filter to URLs that returned 200 historically. Feed to frontier before active probing.
- **Files:** `agent_alpha/recon/passive_intel.py` (add Wayback CDX provider)

### GAP-017 — PassiveIntelMap enrichment dead-end
- **Status:** OPEN
- **What:** OSINT data collected (crt.sh, OTX, VT) but consumer not wired. Data exists in graph but never influences tool selection or probe paths.
- **Fix:** Wire PassiveIntelMap results to frontier seeding + tool selection. Subdomains from crt.sh → frontier. VT reputation → evasion tier. OTX pulses → probe paths.
- **Files:** `agent_alpha/recon/passive_intel.py` (producer), `agent_alpha/agents/alpha/scout.py` (consumer not wired)

### GAP-018 — LiveOriginDiscovery sibling seeding
- **Status:** RESOLVED 2026-08-08
- **What:** Origin discovery failed when crt.sh down because no sibling seeding. Fixed.

### GAP-019 — Per-host origin-resolution cache
- **Status:** RESOLVED 2026-08-08
- **What:** Redundant DNS lookups per host. Cache added.

### GAP-020 — Mid-engagement pattern-group exhaustion
- **Status:** OPEN
- **What:** Agent re-tries exhausted pattern groups mid-engagement. No tracking of which patterns have been tried and failed.
- **Fix:** Track pattern-group attempts per engagement. Skip exhausted groups in subsequent cycles.
- **Files:** `agent_alpha/agents/alpha/scout.py` (pattern tracking)

### GAP-021 — Fingerprint-driven path hard-filter
- **Status:** OPEN
- **What:** Irrelevant paths probed for known stack. E.g. `.env` probed on WP target (Laravel path). Stack fingerprint should filter leak paths.
- **Fix:** After fingerprint detected, filter `WELL_KNOWN_LEAK_PATHS` by stack relevance. WP → wp-config paths only. Laravel → .env/composer paths only.
- **Files:** `agent_alpha/agents/alpha/scout.py:224-242` (seeds all paths), `agent_alpha/config/constants.py:275-304` (flat list, no stack filter)

### GAP-022 — Deterministic rule coverage + finding correlation
- **Status:** OPEN
- **What:** Rules miss known patterns. No correlation between related findings (e.g. wp-config leak + DB password → cred_reuse should auto-trigger).
- **Fix:** Add missing rules. Add finding correlation layer that links related findings into chains.
- **Files:** `agent_alpha/llm/playbooks/` (rule YAMLs), `agent_alpha/agents/alpha/scout.py` (finding correlation)

### GAP-026 — StealthPacer gate inverted
- **Status:** OPEN
- **What:** StealthPacer code exists but default OFF. §12.49 violation — stealth should be default. Agent runs without pacing → CF bot detection triggers.
- **Fix:** Toggle stealth at engagement creation. Default ON. `opsec_stealth=True` in engagement profile.
- **Files:** `agent_alpha/agents/stealth_pacer.py` (implemented), `agent_alpha/conductor/recon_runner.py:156-160` (conditional, default OFF)

### GAP-027 — Probing order: sensitive before legitimate
- **Status:** OPEN
- **What:** `.env` probes trigger CF bot detection before `wp-json` access. Legitimate endpoints should be probed first to establish "normal visitor" pattern.
- **Fix:** Reorder: homepage → API index → robots.txt → then leak paths. Interleave legitimate + sensitive.
- **Files:** `agent_alpha/agents/alpha/scout.py:224-242` (seeds leak paths first), `agent_alpha/config/constants.py` (path order)

### GAP-028 — Origin-direct generic homepage detection
- **Status:** OPEN
- **What:** Origin returns homepage (200) for all paths → 0 findings from origin-direct. No baseline comparison to detect catch-all 200.
- **Fix:** Send 2 random non-existent paths to origin. If both return same body hash as homepage → catch-all 200 detected. Skip origin-direct.
- **Files:** `agent_alpha/recon/origin_binding.py` (origin probe), `agent_alpha/recon/response_classifier.py` (catch-all detection)

### GAP-029 — Unreachable subdomain probing
- **Status:** DONE
- **What:** Dead hosts probed for all 12 paths. Fixed — reachability check before probing.

### GAP-030 — auth_surface regex misses Vue.js
- **Status:** DONE
- **What:** `:type="password"` (Vue.js binding) not detected by auth_surface regex. Fixed.

### GAP-031 — Beta crashes on OriginUnreachableError
- **Status:** DONE
- **What:** Beta dispatched but crashes when no origin binding. Fixed — graceful decline + Omega.

### GAP-032 — OTX timeout 30s
- **Status:** OPEN
- **What:** OTX API timeout 30s blocks sequential OSINT chain. If OTX is slow, VT never runs. Performance issue, not correctness.
- **Fix:** Reduce OTX timeout to 10s. Run OTX + VT in parallel (asyncio.gather). If OTX times out, continue with VT only.
- **Files:** `agent_alpha/recon/passive_intel.py` (OTX provider, timeout config)

### GAP-033 — Subdomain pivot path not designed
- **Status:** OPEN
- **What:** Subdomain access not used as stepping stone to main domain. If subdomain `dev.example.com` is compromised, no path to pivot to `example.com`. Architectural gap.
- **Fix:** Design subdomain→apex pivot path. If subdomain has cred reuse → try same creds on apex. If subdomain shares DB → pivot via DB access.
- **Files:** `agent_alpha/conductor/router.py` (no subdomain→apex routing), `agent_alpha/agents/beta/strike.py` (no pivot logic)

### GAP-034 — Entry-selection reachability signal
- **Status:** DONE
- **What:** Dead hosts selected as strike candidates. Fixed — node-level reachability signal.

### GAP-035 — Entry-selection multi-candidate
- **Status:** DONE
- **What:** Only ONE candidate struck. Fixed — multi-surface iteration.

### GAP-036 — LLM tool-pick on auth-surface pages
- **Status:** OPEN
- **What:** No deterministic RULE for auth pages. LLM tier fires on every auth surface page, burning tokens for predictable `auth_surface_probe` selection.
- **Fix:** Add RULE-tier match for auth surface body signature (`type="password"` in body → `auth_surface_probe` deterministically).
- **Files:** `agent_alpha/llm/playbooks/` (add auth_surface rule YAML), `agent_alpha/llm/orchestrator.py` (rule tier)

### GAP-037 — Mid-run host death
- **Status:** DONE #385
- **What:** Agent probes dead host indefinitely. Fixed — consecutive-failure threshold.

### GAP-038 — Cooperative mode short-circuits origin
- **Status:** OPEN
- **What:** Cooperative mode (operator-approved SOW) skips binding proof entirely. Trust anchor = signed SOW, not cryptographic token. No origin verification → false origin assumption.
- **Fix:** Cooperative mode should still probe origin candidates but accept SOW as trust anchor instead of token canary. Probe but don't require canary match.
- **Files:** `agent_alpha/recon/origin_binding.py:93-126` (cooperative branch)

### GAP-039 — CompositeOriginDiscovery apex filter
- **Status:** OPEN
- **What:** Passive intel gathered per APEX domain but origin binding requested per blocked HOST (often subdomain). Exact-host filter drops apex OTX/VT candidates when subdomain needs them.
- **Fix:** Match apex domain OR dot-boundary subdomain (same registrable domain). Cross-domain still rejected.
- **Files:** `agent_alpha/recon/origin_discovery.py:84-90` (comment acknowledges gap, fix started)

### GAP-040 — Ownership gate rejects consented subdomains
- **Status:** OPEN
- **What:** Origin-direct gate stricter than recon gate. Recon allows subdomain probing (`allow_subdomain_enum`) but origin-direct gate rejects same subdomain → crash.
- **Fix:** Align origin-direct gate with recon gate's subdomain rule. Subdomain of scope domain = in scope.
- **Files:** `agent_alpha/conductor/engagement_profile.py:377` (comment acknowledges), `agent_alpha/agents/alpha/scout.py:945`

### GAP-041 — Cooperative soft-binding PROVEN for unprobed
- **Status:** OPEN
- **What:** Cooperative mode (operator-approved SOW) skips binding proof. CompositeOriginDiscovery unions event-sourced OTX/VT IPs that were NEVER probed. Emitting PROVEN for unprobed candidate = false proof.
- **Fix:** Probe EVERY candidate with `probe_as_origin` before emitting PROVEN. Fail-closed: all probes fail → None.
- **Files:** `agent_alpha/recon/origin_binding.py:95-126` (comment acknowledges, partial fix started)

### GAP-042 — Origin probe bypasses stealth HttpClient
- **Status:** OPEN
- **What:** Origin probe uses raw `requests`/`httpx` calls, not the stealth `HttpClient` that has curl_cffi impersonation, header ordering, pacing. OPSEC debt — origin probe fingerprint differs from recon probe.
- **Fix:** Replace raw origin probe calls with `HttpClient` instance. Same stealth profile as recon.
- **Files:** `agent_alpha/recon/origin_binding.py` (probe_as_origin function), `agent_alpha/agents/http_client.py`

### GAP-043 — CDN edge IP filter only Cloudflare
- **Status:** OPEN
- **What:** CDN edge IP filter only covers Cloudflare ASN. Sucuri/Incapsula/Akamai edge IPs not filtered → false origin proof (edge IP mistaken for real origin).
- **Fix:** Add Sucuri (AS55286), Incapsula (AS19551), Akamai (AS20940, AS16625) ASN ranges to edge IP filter.
- **Files:** `agent_alpha/recon/origin_discovery.py` (CDN edge IP filter), `agent_alpha/config/constants.py` (ASN list)

### GAP-044 — Soft-404 false positives
- **Status:** FIXED #386
- **What:** Exact-hash dedup misses reflected/varying error pages. Partial fix.

### GAP-045 — CF-ceiling honest outcome
- **Status:** OPEN
- **What:** When CF blocks everything (all WAF_BLOCKED, 0 findings), Omega/Conductor needs honest classification: "CF-blocked, recon incomplete, recommend authorized origin access" — not "0 vulnerabilities found" (false negative).
- **Fix:** Add CF-ceiling outcome classification to router/advance. Omega report includes "recon blocked by WAF/CF" section with recommendation.
- **Files:** `agent_alpha/conductor/router.py`, `agent_alpha/agents/omega/roaster.py`

### GAP-046 — HTTP Basic Auth applicator
- **Status:** OPEN
- **What:** 401-protected surfaces (Apache `.htpasswd`, nginx `auth_basic`, Tomcat manager) not attacked. No Basic Auth applicator in Beta's roster — only WpLogin + HttpForm + OdooXmlRpc.
- **Fix:** New `BasicAuthApplicator` — sends `Authorization: Basic base64(user:pass)` header. Verify: 200 response (not 401). Register in `beta_web_applicators`.
- **Files:** `agent_alpha/tools/internal/access/applicator.py` (new class), `agent_alpha/conductor/applicator_factory.py:57-69` (register)

### GAP-047 — Username harvest WP-REST-only
- **Status:** OPEN
- **What:** Alpha harvests usernames only from WP REST (`/wp-json/wp/v2/users`). Non-WP surfaces (Vue.js login forms, custom login pages, Laravel Nova/Filament, Odoo) not harvested. Beta's `UserDerivedCredsTool` has 0 USER nodes on non-WP targets.
- **Fix:** Add username harvest for: (1) HTML login forms with visible usernames, (2) Laravel Nova/Filament user lists, (3) Odoo user enum via XML-RPC `list_services` (if enabled), (4) JS bundle analysis for SPA user references.
- **Files:** `agent_alpha/recon/auth_surface.py` (auth surface probe), `agent_alpha/agents/alpha/scout.py` (harvest handler)

### GAP-048 — Soft-404 signature format-fragile
- **Status:** FIXED #388
- **What:** Regex normalization whack-a-mole. Supersedes GAP-044 fix. Two-probe differential, format-agnostic.

### GAP-049 — STEALTH_BROWSER header contradiction
- **Status:** FIXED #396
- **What:** UA=Windows but sec-ch-ua-platform=macOS. Fingerprint contradiction. Fixed.

### GAP-050 — IntelligenceBase wiring
- **Status:** OPEN
- **What:** 3 wiring gaps: (1) tech_stack in graph not bridged to events, (2) target metadata not captured, (3) outcome events (ExploitConfirmed/ExploitFailed) defined but never emitted.
- **Fix:** Bridge graph → events, capture metadata, emit outcome events.

### GAP-051 — try_harder strategic pivot
- **Status:** OPEN
- **What:** `try_harder` is path-recovery only (re-probes same paths). Not strategic pivot. Only 2 genuine pivots needed: WAF_BLOCKED_ALL→proactive origin discovery (§12.33 reactive only), RECON_EXHAUSTED→credential OSINT (§12.54 not built). Subdomain enum + login routing already exist.
- **Cross-ref:** §12.61 (Flank-when-CF-hard). GAP-054 (email for breach OSINT). GAP-062 (MX/SPF for origin discovery).

### GAP-052 — WooCommerce version not extracted
- **Status:** OPEN (P0)
- **What:** Alpha detects WooCommerce (`woocommerce_exposed` finding) but does NOT extract version. `/wp-json/wc/v3/system_status` returns PHP/MySQL/WP/plugin/theme versions in 1 request. Not fetched.
- **Evidence:** solusibersama.co.id — WC API fetched (200, 178KB), version NOT in graph.
- **Fix:** Add `/wp-json/wc/v3/system_status` as frontier_seed. Add `_handle_wc_system_status` handler → SERVICE nodes with version.
- **Files:** `scout.py:1714-1768`, `capability_probe.py:104-107`
- **Cross-ref:** §12.61 — WC version determines axis B (credential) vs axis A (origin). CVE-2026-3589 affects WC 5.4-10.5.

### GAP-053 — WP plugin handler never fires
- **Status:** OPEN (P0)
- **What:** `_handle_wp_plugins` (scout.py:1844) extracts plugin slug + version from HTML via regex + checks CVE. Handler is CORRECT but NEVER FIRES because: (1) `wp_plugins` tool never selected by orient tier, (2) wp-admin pages fetched but LLM decision fails, (3) `auth_surface_probe` selected instead, (4) homepage body also contains plugin paths but `wp_fingerprint` doesn't extract them.
- **Evidence:** solusibersama.co.id — plugin paths in homepage HTML, 0 plugin nodes in graph.
- **Fix:** Wire `wp_plugins` handler to fire on homepage body (not just wp-admin pages). Or extract plugin paths in `wp_fingerprint` handler.
- **Category:** DC (dead code — Lyndon #2)
- **Cross-ref:** §12.61 — plugin info supports credential/authenticated paths.

### GAP-054 — WP REST user fields truncated
- **Status:** OPEN (P0)
- **What:** `/wp-json/wp/v2/users` response has id/name/email/roles/avatar/url/description. Alpha extracts slug only. Email needed for breach OSINT (GAP-051). Roles needed for admin targeting.
- **Evidence:** solusibersama.co.id — 9 users found, 0 emails, 0 roles in graph.
- **Fix:** Extract email + roles from WP REST users response. Add to USER node properties.
- **Files:** `scout.py` — WP REST user handler
- **Cross-ref:** §12.61 axis B5 (leaked-credential OSINT). GAP-051 (breach OSINT pivot).

### GAP-055 — Security headers not audited
- **Status:** OPEN (P1, universal)
- **What:** HSTS/X-Frame-Options/CSP/X-Content-Type-Options missing = attack surface. Detectable from existing homepage response, 0 new requests.
- **Fix:** Parse security headers from existing response. Mint finding per missing header.

### GAP-056 — robots.txt + sitemap.xml not fetched
- **Status:** OPEN (P1, universal)
- **What:** robots.txt = admin's hidden path map. sitemap.xml = full URL list. 2 requests, high discovery value.
- **Fix:** Fetch `/robots.txt` + `/sitemap.xml`. Parse disallow paths + sitemap URLs. Add to frontier.

### GAP-057 — XML-RPC not checked
- **Status:** OPEN (P1, WP-specific)
- **What:** `/xmlrpc.php` enabled = brute force multiplier (system.multicall = 1000 attempts/request). 1 request to check.
- **Fix:** Fetch `/xmlrpc.php`. Check if `system.multicall` available. Mint finding if enabled.

### GAP-058 — JS secret extraction missing
- **Status:** OPEN (P1, universal)
- **What:** ADR §5 charter says Alpha delivers `js_secrets` to Beta. Homepage HTML has `<script src>` + `wp_localize_script` data. 0 extraction.
- **Fix:** Extract from homepage HTML: `wp_localize_script` data, inline JS variables, `<script src>` URLs. Parse for api_key, nonce, ajaxurl, AJAX endpoints.

### GAP-059 — Cookie audit missing
- **Status:** OPEN (P2, universal)
- **What:** Cookie flags (HttpOnly, Secure, SameSite) affect session theft/CSRF assessment. Parse from existing response, 0 new requests.
- **Fix:** Parse Set-Cookie headers. Audit flags per cookie. Mint finding for missing flags.

### GAP-060 — WooCommerce endpoint enumeration
- **Status:** OPEN (P2, WP-specific)
- **What:** `/wp-json/wc/v3` lists orders/customers/products endpoints. Not probed → cannot assess PII data exposure.

### GAP-061 — WP REST other endpoints
- **Status:** OPEN (P2, WP-specific)
- **What:** Route index lists posts/pages/comments/media. Only users probed. Data harvest surface missed.

### GAP-062 — TLS/MX/SPF/DMARC infrastructure recon
- **Status:** OPEN (P3, universal)
- **What:** Passive DNS: MX/SPF/DMARC (phishing surface), AAAA (IPv6 bypass), TLS (downgrade). Zero target touch, §12.48 passive-first.
- **Cross-ref:** §12.61 axis A2 (origin discovery — MX/SPF is prerequisite).

### GAP-063 — Odoo database list not extracted
- **Status:** OPEN (P1, Odoo-specific)
- **What:** `/web/database/manager` fetched (51KB) but DB names not parsed. DB names = Beta cred-stuff target selection.
- **Evidence:** quantum-laboratories.com — DB manager page fetched, 0 DB names in graph.
- **Fix:** Parse DB names from DB manager HTML. Mint DATA nodes per DB name.
- **Category:** DD (data discard — same pattern as GAP-054)

### GAP-064 — Odoo XML-RPC not checked
- **Status:** OPEN (P1, Odoo-specific)
- **What:** `/xmlrpc/2/common`, `/xmlrpc/2/db` not probed. Odoo XML-RPC = parallel attack surface (like WP XML-RPC GAP-057). Beta uses it for cred reuse but Alpha doesn't discover it.
- **Fix:** Probe `/xmlrpc/2/common` (version) + `/xmlrpc/2/db` (db.list). Mint finding if reachable.

### GAP-065 — Odoo /website/info not fetched
- **Status:** OPEN (P2, Odoo-specific)
- **What:** Odoo's equivalent of WC system_status (GAP-052). 1 endpoint gives version + modules + server info. Not fetched.
- **Fix:** Fetch `/website/info`. Parse version + module list. Mint SERVICE nodes.

### GAP-066 — Odoo database name from URL not captured
- **Status:** OPEN (P2, Odoo-specific)
- **What:** `/web?db=erp` fetched but `db=erp` param not captured as DATA node. DB name = Beta context. URL parse, 0 new requests.
- **Fix:** Parse `db` query param from URL. Mint DATA node.

### GAP-067 — OdooAccessTool only XML-RPC, no JSON-RPC fallback
- **Status:** OPEN (P1)
- **What:** `OdooAccessTool` (odoo_access.py, 480 lines) IS wired in Beta. Speaks XML-RPC only. If CF blocks XML-RPC (text/xml content-type), no fallback to JSON-RPC (`/web/session/authenticate`). Odoo web login uses JSON-RPC — that endpoint reachable through CF.
- **Evidence:** quantum-laboratories.com — Beta FAILED. OdooAccessTool ran (0.85 rank) but XML-RPC likely CF-blocked. DefaultCredsTool (0.7) tried form POST → Odoo expects JSON-RPC → failed.
- **Fix:** Add JSON-RPC fallback transport to OdooAccessTool. Try XML-RPC first, fall back to JSON-RPC POST `/web/session/authenticate` with `{"jsonrpc":"2.0","method":"call","params":{"db":db,"login":user,"password":pwd}}`. Verify: `session_id` cookie (already in SESSION_COOKIE_NAMES allowlist).
- **Files:** `odoo_access.py:120-211`
- **Category:** TM (transport mismatch)

### GAP-068 — ~~Odoo default creds not in dict~~
- **Status:** RETRACTED
- **What:** Original entry claimed Odoo default creds missing from `_DEFAULT_CREDENTIALS`. But `OdooAccessTool` has own hardcoded candidates (`admin/admin`, `admin/password` at odoo_access.py:254-257). Does NOT use `_DEFAULT_CREDENTIALS` dict. No fix needed.
