> CANONICAL SOURCE: bugs + GAPs ledger. Bugs = compact format. GAPs = full narrative.
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

## GAP Index by Group

### WP Recon

- GAP-052 — WooCommerce version not extracted (system_status endpoint not fetched) (OPEN.)
- GAP-053 — WP plugin handler exists but never fires (LLM orient fails on wp-admin pages) (OPEN.)
- GAP-054 — WP REST user fields truncated (slug only, drops email/roles) (OPEN.)
- GAP-057 — XML-RPC not checked (OPEN.)
- GAP-060 — WooCommerce endpoint enumeration missing (orders, customers, products) (OPEN.)
- GAP-061 — WP REST other endpoints not probed (posts, pages, comments, media) (OPEN.)

### Odoo Recon

- GAP-063 — Odoo database list not extracted from DB manager page (OPEN.)
- GAP-064 — Odoo XML-RPC not checked (/xmlrpc/2/common, /xmlrpc/2/db) (OPEN.)
- GAP-065 — Odoo /website/info not fetched (version + module list) (OPEN.)
- GAP-066 — Odoo database name from URL not captured (/web?db=erp) (OPEN.)

### Universal Recon

- GAP-055 — Security headers not audited (OPEN.)
- GAP-056 — robots.txt + sitemap.xml not fetched (OPEN.)
- GAP-058 — JS secret extraction missing (api_key, nonce, ajaxurl from homepage HTML) (OPEN.)
- GAP-059 — Cookie audit missing (HttpOnly, Secure, SameSite flags) (OPEN.)
- GAP-062 — TLS/MX/SPF/DMARC infrastructure recon missing (OPEN.)

### Origin/CDN

- GAP-018 — RESOLVED 2026-08-08 (field-prove caught it, unit tests missed it) (FIXED (self-contained, `recon/origin_resolver.py`).)
- GAP-019 — Per-host origin-resolution cache (RESOLVED 2026-08-08) (FIXED (`agents/alpha/scout.py`, `_bound_origin` per-host cache).)
- GAP-038 — Cooperative mode short-circuits origin discovery (no binding proof) (FIXED 2026-08-09 (merged PR #381).)
- GAP-039 — CompositeOriginDiscovery exact-host filter drops apex intel for subdomain binding (FIXED 2026-08-10 (fix branch fix/gap-039-composite-apex-scope).)
- GAP-040 — Ownership gate rejects consented subdomains (origin-direct crash) (FIXED 2026-08-10 (fix branch fix/gap-040-subdomain-ownership-gate).)
- GAP-041 — Cooperative soft-binding emits PROVEN for unprobed (stale) candidates (FIXED 2026-08-10 (fix branch fix/gap-041-false-soft-binding).)
- GAP-042 — Origin probe bypasses stealth HttpClient (opsec debt) (OPEN 2026-08-10 (identified by CodeRabbit review on PR #384).)
- GAP-043 — CDN edge IP filter only covers Cloudflare (Sucuri/Incapsula/Akamai false proof) (OPEN 2026-08-10 (identified during busonlineticket.co.th re-run).)
- GAP-044 — Soft-404 false positives: exact-hash dedup misses reflected/varying error pages (FIXED via GAP-048 (#388, two-probe differential — format-agnostic).)
- GAP-045 — CF-ceiling honest-outcome classification (Omega/Conductor) (OPEN 2026-08-11. LOW effort, HIGH product value.)

### Recon Quality

- GAP-020 — Mid-engagement pattern-group exhaustion (OPEN, next slice) (OPEN. ADR §12.57 point 2.)
- GAP-021 — Fingerprint-driven path hard-filter (OPEN) (OPEN. ADR §12.57 point 3.)
- GAP-022 — Deterministic rule coverage + finding correlation (OPEN) (OPEN. ADR §12.57 points 1 & 4 (recon-side).)
- GAP-026 — StealthPacer gate inverted: code exists, default OFF (violates §12.49) (OPEN. Doctrine §12.49: "Stealth by default from the 1st request (curl_cffi, Header)
- GAP-027 — Probing order: sensitive files before legitimate endpoints (OPEN.)
- GAP-028 — Origin-direct response validation (generic homepage detection) (OPEN.)
- GAP-029 — Unreachable subdomain still probed for all 12 paths (OPEN.)
- GAP-030 — auth_surface regex misses Vue.js / framework-bound password inputs (DONE (PR #391 Slice 1a merged `2b85fed` + PR #392 Slice 1b merged `5554e8d`).)
- GAP-032 — OTX timeout 30s blocks sequential OSINT chain (OPEN.)
- GAP-036 — LLM tool-pick fires on auth-surface pages (no deterministic RULE) (OPEN, LOW priority (efficiency/OPSEC noise, NOT correctness).)
- GAP-037 — Mid-run host death not detected (consecutive-failure threshold) (FIXED 2026-08-11 (merged PR #385). Stop-on-block egress death detection.)
- GAP-048 — Soft-404 signature is format-fragile: regex normalization is whack-a-mole (MERGED (#388). SUPERSEDES the GAP-044 regex normalizer. Tier-1 (7 tests)
- GAP-049 — STEALTH_BROWSER header contradiction (UA=Windows, sec-ch-ua-platform=macOS) (DONE (PR #396, merged `96f716d`).)

### Beta/Access

- GAP-031 — Beta crashes on OriginUnreachableError when no origin binding exists (PARTIALLY FIXED 2026-08-09 (crash FIXED — graceful decline + Omega handoff,)
- GAP-033 — Subdomain pivot path not designed (subdomain as entry to main domain) (OPEN (design gap, not yet implemented).)
- GAP-034 — Entry-selection has no node-level reachability signal (BUILT 2026-08-11 (HOST_ABANDONED-only demote read-model; WAF_BLOCKED NOT excluded). Detail → docs/Session_Handoff.md.)
- GAP-035 — Entry-selection strikes ONE candidate; multi-surface not iterated (BUILT FRESH 2026-08-11 (own slice; multi-candidate dispatch loop). Build/status/seal detail → docs/Session_Handoff.md.)
- GAP-067 — OdooAccessTool only speaks XML-RPC, no JSON-RPC fallback (CF-blocked targets fail) (OPEN (re-scoped 2026-08-12 — original entry incorrectly)
- GAP-068 — RETRACTED (OdooAccessTool already has hardcoded candidates) (RETRACTED (2026-08-12). Original entry claimed Odoo default)

### Cognition & Planning (ADR-locked)

- GAP-004 — Planner/World Model — Moved to ADR §12.29 (LOCKED in ADR §12.29 (2026-07-15))
- GAP-008 — Curiosity-Driven Exploration — Moved to ADR §12.30 (LOCKED in ADR §12.30 (2026-07-15))
- GAP-009 — Cross-Validation Between Tools — Moved to ADR §12.31 (LOCKED in ADR §12.31 (2026-07-15))
- GAP-010 — Goal-Completion Detection — Moved to ADR §12.29 (LOCKED in ADR §12.29 (2026-07-15))
- GAP-011 — Authenticated Crawl / Post-Access Re-Discovery — Moved to ADR §12.32 (LOCKED in ADR §12.32 (2026-07-15))
- GAP-012 — Adaptive Evasion — Moved to ADR §12.33 (LOCKED in ADR §12.33 (2026-07-15))
- GAP-013 — Credential Pattern Mutation Within Engagement — Moved to ADR §12.34 (LOCKED in ADR §12.34 (2026-07-15))

### Memory & Intelligence (wiring)

- GAP-002 — Scratchpad/SessionStore — CLOSED (CLOSED — Wired in PR #192 (2026-07-18))
- GAP-003 — IntelligenceBase — Protocol Saja, Semua Method Return InsufficientData (OPEN)
- GAP-007 — OSINT / External Context Gathering — Tidak Ada Sama Sekali (OPEN)
- GAP-016 — Wayback Machine Pre-Intel — Archive-Driven Probe Selection (OPEN)
- GAP-017 — PassiveIntelMap Enrichment Dead-End — Consumer Not Wired (PARTIALLY — origin_ip_candidates consumer wired; protection_detected consumer (Slice A/B/C) still OPEN)
- GAP-050 — IntelligenceBase wiring gap: data exists but never reaches memory (OPEN.)
- GAP-051 — `try_harder` is path-recovery only, not strategic pivot (D2-c unbuilt) (OPEN.)

### Policy & Tooling (wiring + new tools)

- GAP-001 — Missing Tools & Playbooks for Broader Coverage (OPEN)
- GAP-005 — PolicyEnforcer — Partially Wired (slice-1 done, slice-2 OPEN) (PARTIALLY WIRED — slice-1 (blast-radius gate) DONE (#184), slice-2 (agent execution path) OPEN)
- GAP-006 — Attack Graph Analytics — Partially Wired (slice-1 done, slice-2 OPEN) (PARTIALLY WIRED — slice-1 (blast-radius → decision) DONE (#184), slice-2 (critical paths → planner) OPEN (needs GAP-004))
- GAP-014 — Fan-Out Parallel Worker Wiring — Shape A Not Wired (OPEN)
- GAP-015 — Credential Spray Tool — Harvested Usernames × Common Passwords (CLOSED — Implemented as `UserDerivedCredsTool` (derive-not-spray, not `cred_spray` with static password list))
- GAP-046 — HTTP Basic Auth applicator absent (cred-acquisition breadth) (OPEN 2026-08-11. Deferred (after §12.61 slices).)
- GAP-047 — Username harvest WP-REST-only (producer breadth, non-WP surfaces) (OPEN 2026-08-11. Deferred (relates to GAP-015).)

---

# WP Recon

## GAP-052 — WooCommerce version not extracted (system_status endpoint not fetched)

- **Status**: OPEN.
- **Priority**: P0 — blocks CVE lookup (CVE-2026-3589 affects WooCommerce 5.4.0-10.5.2, range very wide).
- **What**: Alpha detects WooCommerce API is exposed (`_handle_woocommerce` mints a
  `woocommerce_exposed` VULNERABILITY node) but does NOT extract the WooCommerce
  version. Without version, IntelligenceBase cannot check CVE-2026-3589 (CSRF →
  admin creation, affects 5.4.0-10.5.2) or CVE-2026-8457 (Social Login auth bypass).

  WooCommerce exposes `/wp-json/wc/v3/system_status` which returns (without auth
  on many misconfigured installs):
  - PHP version (exact)
  - MySQL version
  - WordPress version
  - Active plugin list + version
  - Theme list + version
  - Server info (LiteSpeed version, Apache version)
  - PHP config (memory_limit, max_execution_time, upload_max_filesize)

  This is a SINGLE request that gives more version info than all other probes
  combined. Alpha does not fetch it.

- **Evidence (solusibersama.co.id, 2026-08-12)**: Alpha fetched `/wp-json/wc/v3`
  (200, 178176 bytes) and minted `woocommerce_exposed` finding. But:
  - WooCommerce version: NOT in graph
  - Plugin list: NOT in graph
  - PHP exact version: NOT in graph (only `php/7.4.33` from x-powered-by header)
  - system_status: NOT fetched

  CVE-2026-3589 affects WooCommerce 5.4.0-10.5.2. Without version, Agent-Alpha
  cannot determine if solusibersama is vulnerable. This is a FALSE NEGATIVE risk:
  the target may be vulnerable but Agent-Alpha reports "no known CVE."

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py:1714-1768` — `_handle_woocommerce` (mints finding, no version extraction)
  - `agent_alpha/recon/capability_probe.py:104-107` — `woocommerce` CapabilitySpec (no system_status seed)
  - `agent_alpha/graph/nodes.py:86-91` — `ServiceProperties` has `version` field but it's never populated for WooCommerce

- **Effort**: Low-Medium. 1 new handler + 1 frontier_seed + CVE lookup per
  extracted version. The system_status endpoint is already in scope (same host).

- **Cross-reference**: §12.61 — WooCommerce version menentukan apakah axis B
  (perimeter-skip via credential) atau axis A (origin discovery) lebih relevan.
  Jika CVE-2026-3589 (CSRF → admin creation) applicable → axis B5 credential-
  stuff tidak diperlukan — exploit langsung via unauthenticated CSRF. Tanpa
  version (GAP-052), Agent-Alpha tidak tahu axis mana yang applicable.

---

## GAP-053 — WP plugin handler exists but never fires (LLM orient fails on wp-admin pages)

- **Status**: OPEN.
- **Priority**: P0 — plugin CVE is #1 WordPress attack vector.
- **What**: `_handle_wp_plugins` (`scout.py:1844`) extracts plugin slug + version
  from page HTML via regex `/wp-content/plugins/([a-z0-9\-]+)/[^\"']*?[?&]ver=([0-9][0-9.]*)`
  and checks each against the CVE catalogue. The handler is CORRECT.

  But it NEVER FIRES in live runs because:
  1. The `wp_plugins` tool is never selected by the orient tier
  2. wp-admin pages (`update-core.php`, `import.php`) are fetched but LLM
     decision fails ("Could not orient on ...: LLM decision failed; non-analyzable")
  3. The `auth_surface_probe` tool is selected instead, which only mints an
     auth surface finding — it does NOT extract plugin list from the body
  4. The homepage body (178852 bytes) ALSO contains `/wp-content/plugins/`
     paths but `wp_fingerprint` handler does not extract plugins

  Result: plugin list + versions are in the fetched HTML but never extracted.
  This is Lyndon #2 (dead code treated as done): the handler exists, is tested,
  but is never reached in the live autonomous path.

- **Evidence (solusibersama.co.id, 2026-08-12)**:
  - `update-core.php` fetched (200, 10695 bytes) → `auth_surface_probe` selected → plugin list NOT extracted
  - `import.php` fetched (200, 10685 bytes) → `auth_surface_probe` selected → plugin list NOT extracted
  - Homepage fetched (200, 178852 bytes) → `wp_fingerprint` selected → plugin list NOT extracted
  - `_handle_wp_plugins` never called → 0 plugin nodes → 0 plugin CVE checks

  APT operator view-source on any of these pages would see:
  ```
  /wp-content/plugins/contact-form-7/...?ver=5.x
  /wp-content/plugins/litespeed-cache/...?ver=6.x
  /wp-content/plugins/woocommerce/...?ver=9.x
  ```

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py:1844-1896` — `_handle_wp_plugins` (exists, never called)
  - `agent_alpha/recon/capability_probe.py:81-92` — `wp_fingerprint` CapabilitySpec (no `wp_plugins` follow-up)
  - `agent_alpha/agents/base.py` — orient tier (LLM decision fails on wp-admin pages)

- **Effort**: Low. Move the regex extraction from `_handle_wp_plugins` into a
  body post-processing step that runs on every WP-host HTML response.

- **Cross-reference**: §12.61 — plugin CVE menentukan flank strategy. Plugin
  dengan unauthenticated RCE → skip-Beta (axis A tidak diperlukan, exploit
  langsung). Plugin dengan authenticated CVE → butuh credential (axis B5).
  Tanpa plugin list (GAP-053), Agent-Alpha tidak tahu plugin CVE mana yang
  applicable → tidak bisa pilih flank axis.

---

## GAP-054 — WP REST user fields truncated (slug only, drops email/roles)

- **Status**: OPEN.
- **Priority**: P0 — email is required for credential breach OSINT (GAP-051 RECON_EXHAUSTED pivot).
- **What**: `_handle_wp_rest_users` (`scout.py:1639`) parses `/wp-json/wp/v2/users`
  response and extracts ONLY the `slug` field → USER node with `username=slug`.

  The WP REST users response contains much more:
  ```json
  {
    "id": 1,
    "name": "Site Admin",
    "slug": "admin",
    "email": "admin@example.com",        // sometimes exposed
    "roles": ["administrator"],           // sometimes exposed
    "avatar_urls": {"96": "...", "48": "..."},
    "url": "https://personal-blog.com",
    "description": "WordPress developer"
  }
  ```

  Alpha drops: `id`, `name`, `email`, `roles`, `avatar_urls`, `url`, `description`.

  Impact:
  - `roles` missing → Beta cannot prioritize admin accounts for credential attack
  - `email` missing → GAP-051 RECON_EXHAUSTED pivot to Dehashed/HIBP cannot fire
    (breach OSINT needs email, not slug)
  - `url` missing → personal site pivot (GAP-033 cross-host) loses a candidate
  - `description` missing → OSINT context lost

- **Evidence (solusibersama.co.id, 2026-08-12)**: 9 USER nodes created, all with
  `username` only. 0 email, 0 roles, 0 avatar, 0 description. The 59198-byte
  response was fetched but mostly discarded.

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py:1639-1712` — `_handle_wp_rest_users` (extracts slug only)
  - `agent_alpha/graph/nodes.py:110-119` — `UserProperties` (has username + source only, no email/roles)

- **Effort**: Low. Schema extension + JSON field extraction. No new HTTP requests.

- **Cross-reference**: §12.61 axis B5 ("Leaked credentials — breach data for the
  org email domain → credential-stuff the CF-fronted login"). Email dari GAP-054
  adalah **prerequisite input** untuk §12.61 B5. Tanpa email di graph, breach
  OSINT tidak punya apa-apa untuk dicari di Dehashed/HIBP. §12.61 B5 adalah
  doctrine; GAP-054 adalah foundation yang membuat doctrine executable.

---

## GAP-057 — XML-RPC not checked

- **Status**: OPEN.
- **Priority**: P1 — XML-RPC is a brute force multiplier (system.multicall = 1000 attempts per request).
- **What**: WordPress XML-RPC (`/xmlrpc.php`) is not checked by Alpha. If enabled:
  - `system.listMethods` → enumerate all available methods
  - `wp.getUsersBlogs` → username enumeration (alternative to REST API)
  - `system.multicall` → 1 request = 1000 password attempts (bypass rate limit)
  - Pingback → DDoS amplification vector
  - `wp.getComments` → data harvest without auth

  XML-RPC is often left enabled even when REST API user enumeration is disabled.
  It's a parallel attack surface that Alpha completely ignores.

- **Evidence (solusibersama.co.id, 2026-08-12)**: Not checked. Alpha does not
  know if XML-RPC is enabled or disabled on solusibersama.

- **Affected files**:
  - `agent_alpha/recon/capability_probe.py` — no xmlrpc CapabilitySpec
  - `agent_alpha/agents/alpha/scout.py` — no xmlrpc handler

- **Effort**: Low. 1 request + XML parse + node creation.

---

## GAP-060 — WooCommerce endpoint enumeration missing (orders, customers, products)

- **Status**: OPEN.
- **Priority**: P2 — data exposure assessment (customer PII, order data).
- **What**: Alpha detects WooCommerce API is exposed but does NOT enumerate
  individual endpoints. The `/wp-json/wc/v3` response lists available endpoints:
  - `/wc/v3/orders` — customer order data (PII: name, email, address, payment)
  - `/wc/v3/customers` — customer accounts (PII: name, email, billing address)
  - `/wc/v3/products` — product catalog
  - `/wc/v3/payment_gateways` — payment gateway config
  - `/wc/v3/system_status` — server config (covered by GAP-052)

  Without fetching these, Alpha cannot assess data exposure. A misconfigured
  WooCommerce may return customer PII without auth.

- **Evidence (solusibersama.co.id, 2026-08-12)**: `/wp-json/wc/v3` fetched
  (178176 bytes) but individual endpoints not probed.

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py:1714-1768` — `_handle_woocommerce` (no endpoint enumeration)

- **Effort**: Medium. 3-5 requests + JSON parse + DATA node creation.

---

## GAP-061 — WP REST other endpoints not probed (posts, pages, comments, media)

- **Status**: OPEN.
- **Priority**: P2 — data harvest surface (post content, comments, media metadata).
- **What**: Alpha fetches `/wp-json/` (route index) and `/wp-json/wp/v2/users`
  but does NOT probe other WP REST endpoints that may expose data:
  - `/wp-json/wp/v2/posts` — post content, author IDs, dates
  - `/wp-json/wp/v2/pages` — page content (may include draft/private pages)
  - `/wp-json/wp/v2/comments` — comment data (names, emails sometimes)
  - `/wp-json/wp/v2/media` — media file URLs (directory listing possible)
  - `/wp-json/wp/v2/taxonomies` — category/tag structure
  - `/wp-json/wp/v2/users/<id>` — individual user detail (more fields than list)

  These are listed in the route index that Alpha already fetches. They are
  data-derived discoveries, not new probe paths.

- **Evidence (solusibersama.co.id, 2026-08-12)**: Route index fetched (969277
  bytes) but only `wp/v2/users` was escalated (via `WP_REST_INTERESTING_ROUTES`).
  Other endpoints not probed.

- **Affected files**:
  - `agent_alpha/constants.py` — `WP_REST_INTERESTING_ROUTES` (limited set)
  - `agent_alpha/agents/alpha/scout.py:1632-1637` — route escalation logic

- **Effort**: Medium. 4-6 requests + JSON parse + DATA node creation.

---

# Odoo Recon

## GAP-063 — Odoo database list not extracted from DB manager page

- **Status**: OPEN.
- **Priority**: P1 — database names are Beta ammo (cred-stuff target selection).
- **What**: Alpha fetches `/web/database/manager` (51677 bytes on quantum) and
  correctly mints `odoo_dbmanager_exposed` finding. But the page contains a
  **database list** — every database name visible on the page. Alpha does NOT
  extract this list.

  Database names are high-value recon:
  - Database name = Beta's target for cred-stuff (e.g. `erp`, `prod`, `test`)
  - Database name = intelligence about the target's infrastructure
  - Database name can be used in `/web?db=<name>` to pre-fill the login form
  - Multiple databases = multiple attack surfaces (test DBs often have weaker
    creds than prod)

  The DB manager page HTML contains database names in a structured format
  (Odoo's QWeb template renders them as `<option>` or `<tr>` elements). Alpha
  has the HTML but only checks for action markers (create/backup/drop) — it
  does not parse the database list.

- **Evidence (quantum-laboratories.com, 2026-08-12)**: `/web/database/manager`
  fetched (200, 51677 bytes) → `odoo_dbmanager_exposed` finding minted. But:
  - Database list: NOT in graph
  - Database name "erp" (visible from `/web?db=erp` URL): NOT captured as DATA node
  - Alpha knows DB manager is exposed but doesn't know WHAT databases exist

- **Affected files**:
  - `agent_alpha/recon/odoo_dbmanager_probe.py:83-184` — `process_odoo_dbmanager_hit` (checks EXPOSED, doesn't parse DB list)
  - `agent_alpha/graph/nodes.py` — no DATA node for database names

- **Effort**: Low. HTML parse (regex or BeautifulSoup) + DATA node creation.
  No new HTTP requests — parse existing response body.

- **Cross-reference**: §12.61 axis B5 — database names help Beta select cred-
  stuff targets. `erp` DB likely has different cred policy than `test` DB.

---

## GAP-064 — Odoo XML-RPC not checked (/xmlrpc/2/common, /xmlrpc/2/db)

- **Status**: OPEN.
- **Priority**: P1 — XML-RPC is Odoo's parallel attack surface (like WP XML-RPC).
- **What**: Odoo exposes XML-RPC endpoints that Alpha does not check:
  - `/xmlrpc/2/common` — `version()` gives Odoo version without auth;
    `authenticate()` is the cred-stuff endpoint (Beta territory)
  - `/xmlrpc/2/db` — database list without auth (same data as GAP-063, different
    vector)
  - `/xmlrpc/2/object` — model access (requires auth, but endpoint existence
    confirms XML-RPC is enabled)

  XML-RPC is often left enabled even when the web UI is hardened. It's a
  parallel attack surface — same as WP XML-RPC (GAP-057). Beta already uses
  Odoo XML-RPC for cred reuse (proven on alpha-ai.web.id), but Alpha does NOT
  probe it during recon.

  If Alpha doesn't know XML-RPC is enabled, Beta can't be routed to it. The
  cred-reuse chain on alpha-ai worked because the runner hardcoded XML-RPC —
  but the autonomous path doesn't discover it.

- **Evidence (quantum-laboratories.com, 2026-08-12)**: Not checked. Alpha does
  not know if XML-RPC is enabled on quantum-laboratories.com.

- **Affected files**:
  - `agent_alpha/recon/capability_probe.py:72-74` — `odoo_fingerprint` CapabilitySpec (only `/web/database/manager` seed)
  - `agent_alpha/agents/alpha/scout.py` — no XML-RPC handler for Odoo

- **Effort**: Low. 1 request + XML parse + node creation. Same pattern as
  GAP-057 (WP XML-RPC).

- **Cross-reference**: Beta's cred-reuse chain uses Odoo XML-RPC
  (`/xmlrpc/2/common` + `/xmlrpc/2/object`). Alpha discovering XML-RPC = Beta
  can be routed to it autonomously (not just via runner hardcode).

---

## GAP-065 — Odoo /website/info not fetched (version + module list)

- **Status**: OPEN.
- **Priority**: P2 — version + module list for CVE lookup.
- **What**: Odoo exposes `/website/info` (if website module is installed) which
  returns:
  - Odoo version (exact)
  - Installed module list
  - Server info (Python version, PostgreSQL version, OS)

  This is Odoo's equivalent of WP's `/wp-json/wc/v3/system_status` (GAP-052) —
  a single endpoint that gives full version info. Alpha does not fetch it.

  Alpha already has `verify_odoo_version` which POSTs to
  `/web/webclient/version_info` for version — but this only gives version, not
  module list. `/website/info` gives both.

- **Evidence (quantum-laboratories.com, 2026-08-12)**: `/website/info` fetched
  by `curl` (manual check) returns 200 with HTML. Alpha does not fetch it.

- **Affected files**:
  - `agent_alpha/recon/capability_probe.py:72-74` — `odoo_fingerprint` CapabilitySpec (no `/website/info` seed)
  - `agent_alpha/agents/alpha/scout.py` — no `/website/info` handler

- **Effort**: Low-Medium. 1 request + HTML parse + CVE lookup per module.

---

## GAP-066 — Odoo database name from URL not captured (/web?db=erp)

- **Status**: OPEN.
- **Priority**: P2 — database name is Beta context (cred-stuff target).
- **What**: Alpha fetches `/web?db=erp` (200, 16576 bytes on quantum) and mints
  an auth_surface finding. But the URL parameter `db=erp` is NOT captured as a
  DATA node. The database name "erp" is visible in the URL but discarded.

  This is the same pattern as GAP-054 (WP REST user fields truncated) — Alpha
  fetches the right response but discards data that's in the URL itself.

  Database name from URL is valuable because:
  - It confirms which database the target uses for production
  - Beta can pre-fill the login form with the correct DB name
  - Multiple `db=` values across pages = multiple databases discovered

- **Evidence (quantum-laboratories.com, 2026-08-12)**: `/web?db=erp` fetched
  (200, 16576 bytes) → `auth_surface` finding. Database name "erp" NOT in graph.

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py:1329+` — `_detect_auth_surface` (doesn't parse URL params)

- **Effort**: Low. URL parse + DATA node creation. ~10 lines.

---

# Universal Recon

## GAP-055 — Security headers not audited

- **Status**: OPEN.
- **Priority**: P1 — missing headers = attack surface (clickjacking, XSS, MIME sniffing).
- **What**: Alpha fetches the homepage (200) and parses `x-powered-by` for tech_stack
  but does NOT audit security headers. Missing security headers are findings:
  - `strict-transport-security` missing → no HSTS → SSL strip possible
  - `x-frame-options` missing → clickjacking on login form
  - `content-security-policy` missing → stored XSS easier
  - `x-content-type-options` missing → MIME sniffing
  - `referrer-policy` missing → referrer leak to third parties
  - `permissions-policy` missing → feature abuse (camera, mic, geolocation)

  These are detectable from the SAME response Alpha already fetches (homepage).
  Zero additional HTTP requests.

- **Evidence (solusibersama.co.id, 2026-08-12)**: Homepage fetched (200). Response
  headers include `x-powered-by`, `cache-control`, `x-litespeed-cache` but NO
  security headers visible. Alpha did not audit or report this.

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py` — no security header audit handler
  - `agent_alpha/recon/capability_probe.py` — no security header CapabilitySpec

- **Effort**: Low. Header parsing + VULNERABILITY node creation. ~50 lines.

---

## GAP-056 — robots.txt + sitemap.xml not fetched

- **Status**: OPEN.
- **Priority**: P1 — robots.txt reveals hidden paths, sitemap reveals full URL list.
- **What**: Alpha does not fetch `/robots.txt` or `/sitemap.xml`. These are:
  - `robots.txt`: admin's "do not crawl" list → every `Disallow` is interesting
  - `sitemap.xml`: complete URL list → endpoints Alpha might not discover otherwise

  APT operators check robots.txt FIRST — it's a free map of what the admin
  is trying to hide. `/wp-sitemap.xml` is WordPress's native sitemap (since 5.5).

- **Evidence (solusibersama.co.id, 2026-08-12)**: Neither fetched. Alpha discovered
  URLs only through wp-json route index + leak path probes.

- **Affected files**:
  - `agent_alpha/recon/capability_probe.py` — no robots/sitemap CapabilitySpec
  - `agent_alpha/agents/alpha/scout.py` — no robots/sitemap handler

- **Effort**: Low. 2 requests + XML/txt parsing + URL enqueue.

---

## GAP-058 — JS secret extraction missing (api_key, nonce, ajaxurl from homepage HTML)

- **Status**: OPEN.
- **Priority**: P1 — JS files often expose API keys, nonces, AJAX endpoints.
- **What**: Alpha fetches the homepage HTML (178852 bytes for solusibersama) but
  does NOT extract `<script src="...">` URLs or analyze JS content. JavaScript
  files frequently contain:
  - API keys (Google Maps, Stripe, reCAPTCHA, Firebase)
  - WordPress `wp_localize_script` data (ajaxurl, nonce, rest_url)
  - Hardcoded credentials (rare but happens)
  - AJAX endpoint URLs (not in wp-json index)
  - Third-party script URLs (deprecated/vulnerable libs like polyfill.io)

  ADR charter says Alpha should deliver `js_secrets` to Beta. This is not done.

- **Evidence (solusibersama.co.id, 2026-08-12)**: Homepage fetched (178852 bytes).
  0 JS files extracted. 0 JS secrets. The HTML certainly contains `<script>` tags
  with plugin/theme JS URLs and `wp_localize_script` inline data.

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py` — no JS extraction handler
  - `agent_alpha/recon/capability_probe.py` — no JS CapabilitySpec
  - ADR §5 line 153: "js_secrets" in Alpha→Beta handoff contract (not delivered)

- **Effort**: Medium. JS URL extraction + fetch per JS file + secret grep.
  Budget: cap at N JS files per host (anti-#3 over-probe).

- **Cross-reference**: §12.61 axis B6 ("Exposed secrets in public code — API
  keys, DB creds, .env, hardcoded origin IPs"). GAP-058 extract secrets dari
  target's own JS files — ini **complement** B6 (B6 = external GitHub/GitLab
  repos, GAP-058 = target's served JS). Keduanya menghasilkan CREDENTIAL nodes
  yang Beta pakai untuk cred-stuff login yang reachable through CF.

---

## GAP-059 — Cookie audit missing (HttpOnly, Secure, SameSite flags)

- **Status**: OPEN.
- **Priority**: P2 — cookie security flags affect session theft/CSRF assessment.
- **What**: Alpha does not audit `Set-Cookie` response headers. Cookie flags
  determine attack surface:
  - `HttpOnly` missing → XSS can steal session via `document.cookie`
  - `Secure` missing → cookie sent over HTTP (interceptable)
  - `SameSite=None` → CSRF possible
  - `SameSite=Lax` → partial CSRF protection
  - `__Host-` prefix missing → cookie injection possible

  WordPress sets `wp_woocommerce_session_*`, `woocommerce_cart_hash`,
  `litespeed_hash`, `wordpress_test_cookie` etc. Their flag config is a finding.

- **Evidence (solusibersama.co.id, 2026-08-12)**: Cookies not audited.

- **Affected files**:
  - `agent_alpha/agents/alpha/scout.py` — no cookie audit handler

- **Effort**: Low. Header parsing + node creation. ~30 lines.

---

## GAP-062 — TLS/MX/SPF/DMARC infrastructure recon missing

- **Status**: OPEN.
- **Priority**: P3 — infrastructure assessment (SSL downgrade, phishing, IPv6 bypass).
- **What**: Alpha's recon_runner does subdomain enumeration via crt.sh/VT/OTX but
  does NOT assess:
  - **TLS config**: SSL/TLS version, cipher suites, cert SANs, cert validity.
    Weak TLS = downgrade attack. Cert SANs = subdomain discovery alternative.
  - **MX records**: mail server infrastructure. Missing MX = no email, present
    MX = email server attack surface.
  - **SPF/DMARC records**: email spoofing assessment. Missing SPF/DMARC =
    phishing domain spoofing possible (attacker can send email as client domain).
  - **AAAA records**: IPv6 attack surface. IPv6 often bypasses IPv4-only firewalls.
  - **CAA records**: certificate authority authorization. Misconfigured CAA =
    unauthorized cert issuance possible.

  These are passive DNS queries (zero touch to target). They align with §12.48
  passive-first doctrine.

- **Evidence (solusibersama.co.id, 2026-08-12)**: DNS A record resolved
  (45.80.182.6) but MX/SPF/DMARC/AAAA/TLS not assessed.

- **Affected files**:
  - `agent_alpha/conductor/recon_runner.py` — subdomain enum exists, infra recon does not
  - `agent_alpha/agents/alpha/scout.py` — no TLS/MX/SPF handler

- **Effort**: Medium. DNS queries (dnspython) + TLS scan (ssl module) + node
  creation. All passive, zero target touch.

- **Cross-reference**: §12.61 axis A2 ("Mail/MX/SPF — mail servers usually on
  origin infra, not CF → origin netblock"). GAP-062 adalah **prerequisite data
  source** untuk §12.61 A2. Alpha query MX records → mint SERVICE nodes untuk
  mail servers → §12.61 A2 pakai IP mail server untuk origin netblock discovery.
  Alpha kasih data, §12.61 pakai data untuk flank strategy. Pemisahan sesuai
  ADR §5: Alpha = surface map, Beta/§12.61 = foothold strategy.

---

# Origin/CDN

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

---

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

---

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

---

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

---

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

---

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

---

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

---

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

---

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

---

# Recon Quality

## GAP-020 — Mid-engagement pattern-group exhaustion (OPEN, next slice)

- **Status**: OPEN. ADR §12.57 point 2.
- **What**: N consecutive 404 on a path pattern-group (`.env*`, `wp-config.php.*`) → emit
  `PATTERN_GROUP_EXHAUSTED` → skip the remaining variants (this host; other hosts when stack
  differs). Deterministic counter, extends `EvasionPlanner` (anti-#6). NOT LLM, NOT
  cross-engagement (IntelligenceBase stays deferred).
- **Why**: field log — 7× `.env*` 404 re-probed on every host = pure waste + WAF-noise (Bug #26
  family). Highest-leverage gate-safe recon-precision fix.

---

## GAP-021 — Fingerprint-driven path hard-filter (OPEN)

- **Status**: OPEN. ADR §12.57 point 3.
- **What**: a confirmed stack REMOVES irrelevant generic paths, not only adds stack-specific ones.
  Currently `_handle_capability_fingerprint` ADDS `frontier_seeds`; the initial generic seed still
  fires. Fingerprint (e.g. WP, Odoo) → filter out API/other-stack paths before probing. Static
  filter, deterministic (no dynamic path generation).
- **Why**: field log — API paths (`openapi.json`, `graphql`) sprayed at WP/Odoo hosts.

---

## GAP-022 — Deterministic rule coverage + finding correlation (OPEN)

- **Status**: OPEN. ADR §12.57 points 1 & 4 (recon-side).
- **What**: (a) extend the deterministic rule-tier catalog so known exposures fire WITHOUT the LLM
  (`install.php`/`upgrade.php` 200 = WP-setup-exposed) — the rule-tier exists, its catalog is thin;
  (b) finding correlation — combine `wp-config.php.bak` DB creds + enumerated WP users into a
  single prioritised CREDENTIAL/USER hand-off for Beta (findings currently persist independently).

---

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

---

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

---

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

---

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

---

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

---

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

---

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

---

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

---

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

---

# Beta/Access

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

---

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

---

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

---

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

---

## GAP-067 — OdooAccessTool only speaks XML-RPC, no JSON-RPC fallback (CF-blocked targets fail)

- **Status**: OPEN (re-scoped 2026-08-12 — original entry incorrectly
  claimed "no Odoo applicator"; OdooAccessTool exists and is wired).
- **Priority**: P1 — blocks Beta on CF-fronted Odoo targets (XML-RPC blocked).
- **What**: `OdooAccessTool` (`odoo_access.py`, 480 lines) IS wired in
  Beta's candidate list (`strike.py:337-341`) and speaks XML-RPC:
  - `db.list()` via POST to `/xmlrpc/2/db`
  - `authenticate(db, login, password)` via POST to `/xmlrpc/2/common`
  - Hardcoded candidates: `admin/admin`, `admin/password` + harvested creds
  - `applies_to()` returns 0.85 for Odoo (ranked above DefaultCredsTool 0.7)

  **The gap:** OdooAccessTool only speaks XML-RPC. If Cloudflare blocks
  XML-RPC POST (text/xml content-type, non-standard endpoint), there is
  NO fallback to JSON-RPC (`/web/session/authenticate`). Odoo's web login
  form uses JSON-RPC — that endpoint is reachable through CF because it's
  the same endpoint the login form uses.

  Additionally, `DefaultCredsTool` (which runs second at 0.7) uses
  `HttpFormApplicator` which POSTs form fields — Odoo web login expects
  JSON-RPC, not form POST. So DefaultCredsTool also fails on Odoo.

- **Evidence (quantum-laboratories.com, 2026-08-12)**: Beta FAILED (status=3).
  OdooAccessTool ran first (0.85 rank) but XML-RPC POSTs to `/xmlrpc/2/*`
  likely blocked by CF (or admin/admin wrong for production). DefaultCredsTool
  ran second (0.7) but form POST to `/web/login` rejected by Odoo (expects
  JSON-RPC). Both tools failed → Beta FAILED.

  Root cause trace (corrected):
  - OdooAccessTool: XML-RPC POST → CF block OR admin/admin wrong → fail
  - DefaultCredsTool: form POST → Odoo expects JSON-RPC → fail
  - CredReuseTool: 0 CREDENTIAL nodes → skipped
  - UserDerivedCredsTool: 0 USER nodes → skipped
  - All 4 tools failed → Beta FAILED

- **Affected files**:
  - `agent_alpha/tools/internal/access/odoo_access.py:120-211` — `run()` only uses XML-RPC, no JSON-RPC fallback
  - `agent_alpha/tools/internal/access/default_creds.py:247-249` — `HttpFormApplicator` wrong for Odoo JSON-RPC

- **Test contract**:
  1. Odoo + XML-RPC reachable → XML-RPC authenticate works (current behavior)
  2. Odoo + XML-RPC blocked + JSON-RPC reachable → JSON-RPC fallback works
  3. Odoo + both blocked → fail gracefully (no false success)
  4. WP host → OdooAccessTool skipped (applies_to=0.15)

- **Effort**: Medium. Add JSON-RPC transport to OdooAccessTool (~80 lines)
  + test fixture with mock Odoo JSON-RPC endpoint.

---

## GAP-068 — RETRACTED (OdooAccessTool already has hardcoded candidates)

- **Status**: RETRACTED (2026-08-12). Original entry claimed Odoo default
  creds missing from `_DEFAULT_CREDENTIALS` dict. But `OdooAccessTool`
  has its own hardcoded candidates (`admin/admin`, `admin/password` at
  `odoo_access.py:254-257`) — it does NOT use `_DEFAULT_CREDENTIALS`.
  Adding `"odoo"` to that dict is irrelevant. No fix needed.

---

# Cognition & Planning (ADR-locked)

## GAP-004: Planner/World Model — Moved to ADR §12.29

- **Status**: LOCKED in ADR §12.29 (2026-07-15)
- **Severity**: Critical
- **ADR Reference**: `docs/ADR.md` §12.29 *"Goal-directed cognition: Objective + Planner/World-Model + goal-completion"*
- **Summary**: Replaces the reactive 1-step cognitive loop with `EngagementObjective`, `Planner`/`Executor`, `WorldModel`, and a `GOAL_COMPLETED` stop condition.
- **Prerequisites**: ~~GAP-002 (scratchpad wiring)~~ ✅ CLOSED #192, Bug #18/#19/#20 (graph quality).
- **Note**: Full root-cause, proposed fix, and confidence notes are now in ADR §12.29.

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

# Memory & Intelligence (wiring)

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
- **Cross-reference**: ADR §12.11 (IntelligenceBase). Bug #7 (Engagement Memory tidak persist) — prerequisite: engagement memory harus persist dulu sebelum IntelligenceBase bisa query.

> **Catatan L2 — Confidence Calibration**: `ToolResult.confidence` (0.0-1.0) ada tapi never calibrated vs historical FP rates. Bug #2 (Odoo greedy) terjadi karena rule match = confidence tanpa kalibrasi. Wiring IntelligenceBase (GAP-003 fix) juga menyelesaikan confidence calibration — tool confidence harus weighted oleh historical FP rate dari IntelligenceBase.

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
- **Cross-reference**: ADR §8o-3 (Knowledge Ingestion — threat-intel RAG, BUKAN OSINT). ADR §8e (Phishing Impact Test profile). GAP-004 (Planner) — OSINT findings harus masuk ke planner untuk prioritisasi.

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

## GAP-017: PassiveIntelMap Enrichment Dead-End — Consumer Not Wired

- **Status**: PARTIALLY — origin_ip_candidates consumer wired; protection_detected consumer (Slice A/B/C) still OPEN
- **Severity**: Medium — enrichment data written to event store but read by nobody
- **Effort**: Medium (3-slice fix: World Model ingestion, planner scoring, reach pivot)

### Context

§12.48 slice-3 fills `protection_detected`, `mx_records`, `nameservers` in `PassiveIntelMap`. Slice-4 adds CertSpotter subdomains. Slice-5 adds OTX origin-IP candidates + historical paths. But NO consumer reads these fields:

1. **World Model** does not ingest `PassiveIntelMap` — no protection awareness
2. **Planner** does not use `protection_detected` for scoring — Bug #26 stays OPEN
3. **`choose_reach()`** cannot pre-emptive pivot from passive intel — reactive only

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

## GAP-050 — IntelligenceBase wiring gap: data exists but never reaches memory

- **Status**: OPEN.
- **What**: `IntelligenceBase` Protocol (`memory/intelligence.py`) has 4 query
  methods locked since Phase 1, but 3 of 4 always return `InsufficientData`
  against live records. Root cause is NOT "Phase 6 feature" — it is 4 wiring
  gaps where data exists in the live path but never bridges to
  `EngagementMemoryRecord`:

  1. **tech_stack — data in events, not extracted by projector.** `scout.py`
     fingerprints tech_stack for every host (17+ `merge_asset_node` calls)
     and emits `NodeDiscovered` events that carry `tech_stack` in the payload
     properties. PostgreSQL confirms **1,289 events with tech_stack** in
     `agent_events`. But `EngagementMemoryProjector._build_record` does not
     extract tech_stack from `NodeDiscovered` payloads, and
     `EngagementMemoryRecord` has no `tech_stack` field. Result:
     `what_worked_for_similar_targets(tech_stack, target_type)` always
     returns `InsufficientData`.

  2. **target_type / industry / region — not captured anywhere.**
     `EngagementProfile` has `targets`, `scope_targets`, `client_id` but NO
     `target_type`, `industry`, or `region` field. `engagement.yaml` also
     lacks these. Data is trivially derivable from target domain (e.g.
     `niagamas.com` → e-commerce, Indonesia) but nothing captures it.
     `credential_patterns(industry, region)` and
     `false_positive_rate(tool, target_type)` always return
     `InsufficientData`.

  3. **Outcome tags — event types defined but never emitted (dead events).**
     `EXPLOIT_CONFIRMED` and `EXPLOIT_FAILED` exist in `EventType` enum and
     are handled in `_build_record`, but grep confirms ZERO emit sites in
     the entire codebase. PostgreSQL confirms **0 rows** for both event
     types. Beta strike results (e.g. default creds valid on alpha-ai
     Odoo) are saved as graph findings but never emit `EXPLOIT_CONFIRMED`
     events. `tool_success_rates` is always `{}`. `tool_reliability()` and
     `false_positive_rate()` always return `InsufficientData`. This is
     Lyndon #2 — dead code treated as done.

  4. **Runner path uses InMemoryEventStore — field-prove data lost on exit.**
     All 15 runners in `live_fire/` hardcode `InMemoryEventStore()` instead
     of calling `build_event_store()` (which routes to `PostgresEventStore`
     when `AGENT_ALPHA_PG_DSN` is set). Field-prove engagements (niagamas,
     alpha-ai chain, bernofarm, ibudanbalita) run via runner path — their
     events are lost when the process exits. PostgreSQL only has data from
     the API/Celery path (`conductor/main.py` which correctly uses
     `build_event_store()`). Verified: `niagamas.com` does NOT appear in
     any `agent_events` row, while `bernofarm.com` and `hashmicro.com` DO
     (they were run via API path at some point).

- **Evidence**: Verified against PostgreSQL on Oracle ARM64 (tenant='default'):
  - `agent_events`: 6,994 rows (API/Celery path only).
  - `NodeDiscovered` events with `tech_stack` in payload: 1,289.
  - `ExploitConfirmed` / `ExploitFailed`: **0 rows** (dead events).
  - `engagement_memory`: **0 rows** (projector never runs or has no output).
  - `vault_secrets`: 258 rows (secrets ARE persisted via API path).
  - Hosts in PostgreSQL: bernofarm.com, hashmicro.com, ibudanbalita.com,
    gamota.com, luminaaesthetics.com, platinumcredit.co.ke, pyfa.co.id,
    quantum-laboratories.com, senyumworldhotel.com, solusibersama.co.id,
    unibis.co.id, www.megajaya.co.id, www.omegahms.com, balijiwa.com.
  - `niagamas.com`: **NOT in PostgreSQL** (ran via runner path, lost).
  - `EngagementCreated` events in PostgreSQL: all test fixtures
    (`target=10.0.0.0/24, client_id=client_a`), NOT real client engagements.
  - 15 runners in `live_fire/` all hardcode `InMemoryEventStore()`.
  - `build_event_store()` in `config/stores.py` correctly routes to
    `PostgresEventStore` when DSN is set — but runners never call it.

- **Impact**: Agent-Alpha cannot learn across engagements. Every engagement
  starts from zero — no "Laravel+CF → origin-direct worked last time"
  recall. This is the core differentiator (§4, ADR line 121: "governance +
  cross-engagement memory + regional templates. NOT toolkit breadth.")
  and it is structurally non-functional. The moat is defined in doctrine
  but not wired in code. Additionally, field-prove engagements (the most
  valuable test data) are lost because runners use in-memory storage.

- **Architecture gap (the bridge)**:
  ```
  API/Celery path → PostgresEventStore → PostgreSQL (6,994 events saved)
                    ↓
  EngagementMemoryProjector (never runs — 0 memory records)
                    ↓
  IntelligenceBase → InsufficientData (3 of 4 methods)

  Runner path → InMemoryEventStore (RAM, lost on exit)
                ↓
  PostgreSQL: 0 events from runner path (niagamas, alpha-ai chain, etc.)
  ```

- **Fix (4 wiring slices, not 4 new features)**:
  1. **Runner EventStore wiring**: Replace `InMemoryEventStore()` with
     `build_event_store()` in all 15 `live_fire/` runners. This is a
     one-line change per runner — `build_event_store()` already exists and
     already routes to `PostgresEventStore` when DSN is set. After this,
     all field-prove engagements automatically persist to PostgreSQL
     without any runner-specific logic. Anti-Lyndon #7: `build_event_store()`
     is the single source — runners just call it.
  2. **tech_stack extraction**: Add `tech_stack: list[str]` field to
     `EngagementMemoryRecord`. In `_build_record`, extract tech_stack from
     `NodeDiscovered` event payloads (1,289 events already have it). No
     new event type needed — data is already in the event stream.
  3. **target metadata capture**: Add `target_type`, `industry`, `region`
     to `EngagementProfile` (sourced from `engagement.yaml`). Add same
     fields to `EngagementMemoryRecord`. Projector copies from
     `ENGAGEMENT_CREATED` event payload.
  4. **outcome event emission**: Emit `EXPLOIT_CONFIRMED` / `EXPLOIT_FAILED`
     from Beta strike path when credential validation succeeds/fails.
     `cred_finding_catalog.py` already defines
     `validated_event_type="default_credential_validated"` — wire this to
     emit the canonical `EXPLOIT_CONFIRMED` event. Projector then populates
     `tool_success_rates` from the event payload.

- **Priority**: HIGH — after Slice B (SPA-login applicator). Slice 1
  (runner wiring) is the highest leverage: it ensures all future
  field-prove data is automatically persisted without any manual step.
  Slices 2-4 build the memory bridge on top of the persisted data.

- **Anti-Lyndon**: #2 (dead code — event types defined but never emitted,
  treated as "done" because the enum exists). #3 (false success —
  IntelligenceBase "implemented" but always returns InsufficientData,
  giving the appearance of cross-engagement learning without any). #7
  (single source — `build_event_store()` is the canonical store factory,
  runners should call it instead of hardcoding `InMemoryEventStore()`).
  #9 (this gap was masked by "Phase 6" label — in reality the data exists
  today and the bridge is the missing piece, not a future feature).

- **Effort**: Medium (4 slices: runner wiring + record schema + projector
  branches + outcome emission). Slice 1 is trivial (one-line per runner).
  Slices 2-4 are self-contained and testable.

---

## GAP-051 — `try_harder` is path-recovery only, not strategic pivot (D2-c unbuilt)

- **Status**: OPEN.
- **What**: Alpha's `try_harder` (`planner.py:43-101`) is a **path-level
  dead-end recovery**, not a **strategic pivot**. When Alpha exhausts its
  frontier, `try_harder` only re-seeds leak paths on hosts already in the
  graph — it never changes strategy. The D2-c extension point
  (HTN-style replan) is explicitly marked "NOT built here" (`planner.py:13`).

  Current `try_harder` behavior:
  1. Read graph → list known hosts + tech_stack
  2. For each host → select leak paths by tech_stack (wp→wp-config.bak, laravel→.env)
  3. Filter already-probed URLs
  4. Return remaining paths → Alpha re-probes same hosts

  The ADR §7 line 220 describes the intended "Try Harder agent" as:
  > "when stuck (e.g., RECON_EXHAUSTED), GenAI generates next-best-step
  > hypothesis from graph facts (not web_search). Elegant resolution for
  > dead-end."

  This is a **GenAI-driven strategic replan from graph facts** — not a
  deterministic path re-seed. The current implementation is D2-b (path
  recovery), the intended design is D2-c (strategic replan). The gap is
  the missing D2-c layer.

- **Correction (2026-08-12): original 4-classification design was wrong.**
  The original GAP-051 proposed 4 dead-end types. After review, only 2
  are genuinely `try_harder` responsibilities. The other 2 were
  misattributed:

  | Dead-end type | Originally proposed pivot | Actual owner | Status |
  |---------------|--------------------------|--------------|--------|
  | RECON_EXHAUSTED | credential breach OSINT | try_harder (genuinely new) | **§12.54 not built** |
  | WAF_BLOCKED_ALL | origin IP discovery | try_harder (genuinely new) | **§12.33 built but reactive only** |
  | LOGIN_FOUND_NO_CREDS | hand off to Beta | **Conductor router** (already does this) | **Already handled — not a try_harder gap** |
  | PARTIAL_SUCCESS | path re-seed | **current try_harder** | **Already correct — no change needed** |

  What was removed from the original proposal and why:
  - **"Subdomain enumeration" as try_harder pivot**: REDUNDANT.
    `recon_runner.py:327-449` already discovers subdomains via crt.sh/VT/OTX
    BEFORE Alpha runs, and adds them to the targets list. Alpha already
    probes all subdomains. try_harder re-doing this would be duplicate work.
  - **"Subdomain side-door" as try_harder pivot**: MISATTRIBUTED.
    This is GAP-033 (cross-host credential reuse: attack accessible
    subdomain → use creds on blocked main domain). That is a graph
    architecture problem (cross-host edge tracking), not a try_harder
    decision problem. It belongs to GAP-033, not here.
  - **"LOGIN_FOUND_NO_CREDS" as try_harder dead-end**: NOT A DEAD-END.
    Finding a login surface IS a successful recon outcome. The Conductor
    router (`router.py:227-234`) already routes ALPHA→BETA when
    `has_web_auth_surface(graph_store)` is true. This is not a try_harder
    gap — it's already wired.

- **What `try_harder` SHOULD be (corrected — 2 pivots, not 4)**:

  ```
  Dead-end detected (frontier empty)
    ↓
  Classify the dead-end:
    ├─ WAF_BLOCKED_ALL: CF/WAF blocks every probe on this host
    │   → Pivot: PROACTIVE origin IP discovery (crt.sh, DNS history, VT)
    │   → Currently origin discovery only fires REACTIVELY in
    │     _handle_waf_block (per-path). try_harder should fire it
    │     PROACTIVELY when the ENTIRE host is WAF-blocked, not per-path.
    │   → If origin found: re-probe via origin (existing §12.33 mechanism)
    │   → If no origin: honest BLOCKED handoff to Conductor
    │
    ├─ RECON_EXHAUSTED: all paths probed, all 404/200-no-finding, no WAF
    │   → Pivot: credential breach OSINT (Dehashed/HIBP) for this domain
    │   → This is genuinely new — §12.54 not yet implemented
    │   → If creds found: hand off to Beta with harvested credentials
    │   → If no creds: honest "no surface found" handoff to Conductor
    │
    └─ PARTIAL_SUCCESS: some findings, more surface possible
        → Continue with expanded path set (CURRENT try_harder behavior)
        → This is ALREADY correct — no change needed
  ```

  The key insight: **current `try_harder` treats ALL dead-ends as
  PARTIAL_SUCCESS** (re-seed paths). It should classify the dead-end and
  choose a strategy appropriate to the classification. But only 2
  classifications need new behavior — the third already works.

- **Why it matters**: Without strategic pivot, Alpha has exactly two
  outcomes: (a) find something on the first pass, or (b) re-probe the same
  paths on the same hosts until timeout. There is no "I'm stuck, let me
  try a completely different approach." This means:
  - CF-protected targets: Alpha probes → CF blocks → try_harder re-probes
    same paths → CF blocks again → timeout. Origin discovery only fires
    per-path in `_handle_waf_block`, not as a proactive try_harder strategy
    when the ENTIRE host is blocked.
  - Targets with no leaks: Alpha probes all paths → all 404 → try_harder
    re-probes same paths → all 404 → timeout. No pivot to credential OSINT.
  - Note: subdomain enumeration is NOT a try_harder gap — it already
    happens upfront in `recon_runner.py`. And login-found is NOT a
    dead-end — Conductor already routes to Beta.

- **How APT operators handle this (from MITRE ATT&CK + red team tradecraft)**:
  APT operators do NOT re-try the same vector when blocked. They pivot:
  1. **T1008 (Fallback Channels)**: "If primary channel fails, switch to
     alternate" — OilRig switches HTTP→DNS tunneling, JHUHUGIT switches
     direct→proxy→browser-injection. Each fallback is a DIFFERENT strategy,
     not a retry of the same one.
  2. **Red team planning**: "Plan multiple initial access scenarios. If
     phishing is detected early, have an alternative." (Red Team Operations
     Guide 2026). Alternatives are structurally different vectors, not
     the same vector with different parameters.
  3. **Replan, don't retry** (agent design pattern): "The right default
     for a tool error in an agent is not retry. It is replan." Error
     recovery splits into: transient (retry) vs persistent (replan) vs
     semantic (replan with different strategy). `try_harder` treats all
     dead-ends as transient (retry same paths) when they are actually
     persistent/semantic (need different strategy).

- **How Devin handles this**: Devin uses a **replan-on-failure** pattern:
  when a tool fails or a step doesn't produce expected results, Devin
  doesn't retry the same approach. It re-evaluates the situation from
  current state and generates a new plan. The key principles:
  1. **Failure context is passed to the planner** — the new plan includes
     lessons from the failed attempt (what was tried, what didn't work).
  2. **Partial progress is preserved** — replan doesn't throw away graph
     state; it builds on it.
  3. **Replan triggers are explicit** — not every error triggers replan;
     only persistent/semantic failures (not transient infra errors).
  4. **Thrash prevention** — naive replan-on-every-error thrashes; the
     system needs explicit triggers and a maximum replan budget.

- **Affected files**:
  - `agent_alpha/agents/planner.py:13` — D2-c extension point (empty)
  - `agent_alpha/agents/planner.py:43-101` — `try_harder` (path recovery only)
  - `agent_alpha/agents/alpha/scout.py:2322-2345` — `_try_harder_recovery`
  - `agent_alpha/agents/alpha/scout.py:648-679` — `_handle_waf_block` (reactive only, not proactive)
  - `docs/ADR.md:220` — "Try Harder agent" described but not built
  - `docs/ADR.md:616` — Phase 6 includes "Try Harder agent" (deferred)

- **Related gaps (corrected — not all are try_harder dependencies)**:
  - §12.33 (adaptive evasion — partially built): origin discovery fires
    reactively in `_handle_waf_block` per-path. GAP-051 would make it
    fire proactively in `try_harder` when the entire host is blocked.
    This is the genuine try_harder dependency.
  - §12.54 (credential breach OSINT — not implemented): try_harder
    should pivot to credential OSINT when RECON_EXHAUSTED. This is the
    other genuine try_harder dependency.
  - GAP-033 (subdomain pivot — NOT a try_harder dependency): cross-host
    credential reuse is a graph architecture problem, not a try_harder
    decision. Removed from try_harder scope.
  - GAP-050 (IntelligenceBase wiring): cross-engagement TTPs would tell
    `try_harder` "Laravel+CF → origin-direct worked last time, try that
    first" instead of blindly re-seeding paths. Enhancement, not dependency.

- **Priority**: MEDIUM — after Bug #34 fix (reset) and Slice B (SPA-login).
  The current `try_harder` is not broken (it works as designed for
  PARTIAL_SUCCESS), but it's incomplete (no classification, no pivot for
  WAF_BLOCKED_ALL and RECON_EXHAUSTED). Bug #34 fix will stop the cycling;
  GAP-051 will make Alpha actually converge with a productive outcome
  instead of a timeout.

- **Anti-Lyndon**:
  - #1 (feature before foundation): D2-c was marked "will be added HERE"
    in Phase 1, never built. The extension point is a placeholder that
    looks like progress.
  - #2 (dead code treated as done): `try_harder` is "implemented" but
    only covers 1 of 3 dead-end classifications. The other 2 are silently
    absent.
  - #3 (false success): Alpha "completes" recon by timing out — the
    timeout looks like "recon done, handing off" but it's actually
    "recon stuck, no more ideas." The Conductor receives a FAILED status
    but doesn't know it was a strategic dead-end, not a real failure.
  - #5 (scope creep): the ORIGINAL GAP-051 proposal had 4 classifications
    including subdomain pivot and login-found — both already handled by
    other code paths. Corrected to 2 genuine try_harder pivots to avoid
    scope creep into GAP-033 and Conductor router territory.
  - #7 (duplicate canonical types): the original proposal risked
    duplicating subdomain enumeration (already in recon_runner) and
    login routing (already in Conductor router) as try_harder
    responsibilities. Corrected — each capability has ONE owner.

- **Effort**: Medium. The 2 pivot strategies:
  - WAF_BLOCKED_ALL → proactive origin discovery: §12.33 origin discovery
    already exists as `_handle_waf_block` + `LiveOriginDiscovery`. The
    work is calling it from `try_harder` when the entire host is blocked,
    not just per-path. Small wiring change.
  - RECON_EXHAUSTED → credential OSINT: §12.54 not yet implemented. This
    is a genuinely new capability (Dehashed/HIBP integration). Larger
    effort, but self-contained.
  - PARTIAL_SUCCESS → no change needed (current behavior is correct).

- **What this is NOT**: This is NOT building the Phase 6 "Try Harder agent"
  (GenAI-generated next-best-step hypothesis from graph facts). That is
  a future capability. This gap is about wiring 2 EXISTING/PLANNED pivot
  strategies (proactive origin discovery, credential OSINT) into the
  CURRENT `try_harder` decision point, so Alpha doesn't just re-probe
  the same paths when stuck. Subdomain enumeration (already upfront in
  recon_runner) and login-found routing (already in Conductor) are
  explicitly NOT part of this gap.

---

# Policy & Tooling (wiring + new tools)

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
- **Nuance**: Review mengatakan "tidak pernah dipanggil di conductor/agent path" — ini BENAR. Tapi perlu ditambahkan: `find_critical_paths` dan `calculate_blast_radius` DIPANGGIL di report generation path (`Omega.generate_report()` → `to_narrative()` → `_to_executive_narrative()`). Jadi mereka bukan dead code — mereka **ter-wire ke report, tidak ter-wire ke decision**.
- **Cross-reference**: ADR §1 (blast-radius gate). GAP-005 (PolicyEnforcer) — blast-radius gate butuh PolicyEnforcer untuk enforce. GAP-004 (Planner) — critical paths harus masuk ke planner untuk prioritisasi.

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

---

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

---

