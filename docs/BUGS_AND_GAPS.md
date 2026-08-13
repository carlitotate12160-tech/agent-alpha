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
| 069 | Trust Graph — organizational intelligence nodes missing | OPEN | High | RG | High | Beta gets technical graph only, no people/vendor/trust context |
| 070 | Credential-to-Asset correlation missing | OPEN | High | RG | Med | Breach credentials not mapped to discovered assets via graph edges |
| 071 | Recon freshness / liveness check missing | OPEN | Med | RG | Med | Beta uses stale recon data; no temporal validation policy |
| 072 | Entry-vector ranking + strategic approach not in graph | OPEN | Med | RG | Med | Beta gets raw nodes, no ranked entry vectors or approach recommendation |
| 073 | WAF/CDN capability fingerprinting (beyond vendor hint) | OPEN | High | RM | Med | Alpha knows vendor but not rule set, bot management mode, rate limit threshold |
| 074 | Authentication mechanism fingerprinting (form/JWT/SAML/OAuth) | OPEN | High | RM | Med | Auth-surface label is binary; Beta can't attack what it doesn't understand mechanistically |
| 075 | Subdomain takeover check (dangling DNS CNAME) | OPEN | Med | SS | Low | Classic external finding; dangling CNAME to deleted service not checked |
| 076 | Cloud storage / shadow-IT discovery (S3/GCP/Azure) | OPEN | Med | SS | Med | S3 buckets, GCP storage associated with target domain not discovered |
| 077 | Authentication bypass testing (SQLi/NoSQLi/LDAPi in login) | OPEN | High | SS | Med | Beta only tries cred-reuse + default-creds; no injection-based auth bypass |
| 078 | User enumeration via auth response differential | OPEN | Med | RM | Low | Login error messages leak valid vs invalid usernames; not captured |
| 079 | Post-access validation (agentless — access level proof) | OPEN | High | RG | Med | Beta reports "login OK" but doesn't prove what access level was achieved |
| 080 | Session management analysis (post-login stability) | OPEN | Med | RM | Low | After login: cookie attrs, fixation, timeout, concurrency not analyzed |

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

### Agentless APT-Style External Red Team (NEW — post current slice)

22. **GAP-074** — Auth mechanism fingerprinting (HIGH — root cause of GAP-067, GAP-046, GAP-047; prerequisite for GAP-077)
23. **GAP-073** — WAF/CDN capability fingerprinting (HIGH — Beta strategy depends on WAF mode, not just vendor)
24. **GAP-078** — User enumeration via auth response differential (MED — 2 requests, reduces cred-stuff waste 90%)
25. **GAP-075** — Subdomain takeover check (MED — DNS only, classic finding, 0 target HTTP touch)
26. **GAP-079** — Post-access validation (HIGH — "login OK" → "admin access proven" = payable report)
27. **GAP-077** — Auth bypass testing (HIGH — 1-day SQLi/NoSQLi payloads, gated by GAP-074)
28. **GAP-070** — Credential-to-Asset correlation (HIGH — graph edges for cred-reuse prioritization)
29. **GAP-071** — Recon freshness / liveness check (MED — pre-Beta validation, stops stale data)
30. **GAP-072** — Entry-vector ranking (MED — strategic entry selection, not label-binary)
31. **GAP-080** — Session management analysis (MED — post-login stability for Gamma)
32. **GAP-076** — Cloud storage / shadow-IT discovery (MED — S3/GCP, passive, scoped)
33. **GAP-069** — Trust Graph / organizational intelligence (HIGH effort — v1 public OSINT only, defer LinkedIn/vishing/phishing)

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
- GAP-077 — Authentication bypass testing (SQLi/NoSQLi/LDAPi in login) (OPEN.)
- GAP-078 — User enumeration via auth response differential (OPEN.)
- GAP-079 — Post-access validation (agentless — access level proof without implant) (OPEN.)
- GAP-080 — Session management analysis (post-login stability for Gamma handoff) (OPEN.)

### Trust Graph & Organizational Intelligence (NEW)

- GAP-069 — Trust Graph — organizational intelligence nodes missing (OPEN.)
- GAP-070 — Credential-to-Asset correlation missing (OPEN.)
- GAP-071 — Recon freshness / liveness check missing (OPEN.)
- GAP-072 — Entry-vector ranking + strategic approach not in graph (OPEN.)

### External Attack Surface (NEW)

- GAP-073 — WAF/CDN capability fingerprinting (beyond vendor hint) (OPEN.)
- GAP-074 — Authentication mechanism fingerprinting (form/JWT/SAML/OAuth) (OPEN.)
- GAP-075 — Subdomain takeover check (dangling DNS CNAME) (OPEN.)
- GAP-076 — Cloud storage / shadow-IT discovery (S3/GCP/Azure) (OPEN.)

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
- Status: OPEN.
- Priority: P0 — blocks CVE lookup (CVE-2026-3589 affects WooCommerce 5.4.0-10.5.2, range very wide).
- Category: RM
- Stack: WP
- What: Alpha detects WooCommerce API is exposed (`_handle_woocommerce` mints a `woocommerce_exposed` VULNERABILITY node) but does NOT extract the WooCommerce version. Without version, IntelligenceBase cannot check CVE-2026-3589 (CSRF → admin creation, affects 5.4.0-10.5.2) or CVE-2026-8457 (Social Login au...
- Evidence: Alpha fetched `/wp-json/wc/v3` (200, 178176 bytes) and minted `woocommerce_exposed` finding. But:; WooCommerce version: NOT in graph; Plugin list: NOT in graph; PHP exact version: NOT in graph (only `php/7.4.33` from x-powered-by header); system_status: NOT fetched CVE-2026-3589 affects WooCommerce ...
- Files: agents/alpha/scout.py:1714-1768 — _handle_woocommerce (mints finding, no version extraction); recon/capability_probe.py:104-107 — woocommerce CapabilitySpec (no system_status seed); graph/nodes.py:86-...
- Cross-ref: §12.61 — WooCommerce version menentukan apakah axis B (perimeter-skip via credential) atau axis A (origin discovery) lebih relevan. Jika CVE-2026-3589 (CSRF → admin creation) applicable → axis B5 cred...
- Effort: Low-Medium. 1 new handler + 1 frontier_seed + CVE lookup per

---

## GAP-053 — WP plugin handler exists but never fires (LLM orient fails on wp-admin pages)
- Status: OPEN.
- Priority: P0 — plugin CVE is #1 WordPress attack vector.
- Category: DC
- Stack: WP
- What: `_handle_wp_plugins` (`scout.py:1844`) extracts plugin slug + version from page HTML via regex `/wp-content/plugins/([a-z0-9\-]+)/[^\"']*?[?&]ver=([0-9][0-9.]*)` and checks each against the CVE catalogue. The handler is CORRECT. But it NEVER FIRES in live runs because: 1. The `wp_plugins` tool is ne...
- Evidence: - `update-core.php` fetched (200, 10695 bytes) → `auth_surface_probe` selected → plugin list NOT extracted; `import.php` fetched (200, 10685 bytes) → `auth_surface_probe` selected → plugin list NOT extracted; Homepage fetched (200, 178852 bytes) → `wp_fingerprint` selected → plugin list NOT extracte...
- Files: agents/alpha/scout.py:1844-1896 — _handle_wp_plugins (exists, never called); recon/capability_probe.py:81-92 — wp_fingerprint CapabilitySpec (no wp_plugins follow-up); agents/base.py — orient tier (LL...
- Cross-ref: §12.61 — plugin CVE menentukan flank strategy. Plugin dengan unauthenticated RCE → skip-Beta (axis A tidak diperlukan, exploit langsung). Plugin dengan authenticated CVE → butuh credential (axis B5). ...
- Effort: Low. Move the regex extraction from `_handle_wp_plugins` into a

---

## GAP-054 — WP REST user fields truncated (slug only, drops email/roles)
- Status: OPEN.
- Priority: P0 — email is required for credential breach OSINT (GAP-051 RECON_EXHAUSTED pivot).
- Category: DD
- Stack: WP
- What: `_handle_wp_rest_users` (`scout.py:1639`) parses `/wp-json/wp/v2/users` response and extracts ONLY the `slug` field → USER node with `username=slug`. The WP REST users response contains much more: ```json { "id": 1, "name": "Site Admin", "slug": "admin", "email": "admin@example.com", // sometimes ex...
- Evidence: 9 USER nodes created, all with `username` only. 0 email, 0 roles, 0 avatar, 0 description. The 59198-byte response was fetched but mostly discarded.
- Files: agents/alpha/scout.py:1639-1712 — _handle_wp_rest_users (extracts slug only); graph/nodes.py:110-119 — UserProperties (has username + source only, no email/roles)
- Cross-ref: §12.61 axis B5 ("Leaked credentials — breach data for the org email domain → credential-stuff the CF-fronted login"). Email dari GAP-054 adalah **prerequisite input** untuk §12.61 B5. Tanpa email di g...
- Effort: Low. Schema extension + JSON field extraction. No new HTTP requests.

---

## GAP-057 — XML-RPC not checked
- Status: OPEN.
- Priority: P1 — XML-RPC is a brute force multiplier (system.multicall = 1000 attempts per request).
- Category: SS
- Stack: WP
- What: WordPress XML-RPC (`/xmlrpc.php`) is not checked by Alpha. If enabled:; `system.listMethods` → enumerate all available methods; `wp.getUsersBlogs` → username enumeration (alternative to REST API); `system.multicall` → 1 request = 1000 password attempts (bypass rate limit); Pingback → DDoS amplificat...
- Evidence: Not checked. Alpha does not know if XML-RPC is enabled or disabled on solusibersama.
- Files: recon/capability_probe.py — no xmlrpc CapabilitySpec; agents/alpha/scout.py — no xmlrpc handler
- Effort: Low. 1 request + XML parse + node creation.

---

## GAP-060 — WooCommerce endpoint enumeration missing (orders, customers, products)
- Status: OPEN.
- Priority: P2 — data exposure assessment (customer PII, order data).
- Category: SS
- Stack: WP
- What: Alpha detects WooCommerce API is exposed but does NOT enumerate individual endpoints. The `/wp-json/wc/v3` response lists available endpoints:; `/wc/v3/orders` — customer order data (PII: name, email, address, payment); `/wc/v3/customers` — customer accounts (PII: name, email, billing address); `/wc...
- Evidence: `/wp-json/wc/v3` fetched (178176 bytes) but individual endpoints not probed.
- Files: agents/alpha/scout.py:1714-1768 — _handle_woocommerce (no endpoint enumeration)
- Effort: Medium. 3-5 requests + JSON parse + DATA node creation.

---

## GAP-061 — WP REST other endpoints not probed (posts, pages, comments, media)
- Status: OPEN.
- Priority: P2 — data harvest surface (post content, comments, media metadata).
- Category: SS
- Stack: WP
- What: Alpha fetches `/wp-json/` (route index) and `/wp-json/wp/v2/users` but does NOT probe other WP REST endpoints that may expose data:; `/wp-json/wp/v2/posts` — post content, author IDs, dates; `/wp-json/wp/v2/pages` — page content (may include draft/private pages); `/wp-json/wp/v2/comments` — comment ...
- Evidence: Route index fetched (969277 bytes) but only `wp/v2/users` was escalated (via `WP_REST_INTERESTING_ROUTES`). Other endpoints not probed.
- Files: constants.py — WP_REST_INTERESTING_ROUTES (limited set); agents/alpha/scout.py:1632-1637 — route escalation logic
- Effort: Medium. 4-6 requests + JSON parse + DATA node creation.

---


# Odoo Recon

## GAP-063 — Odoo database list not extracted from DB manager page
- Status: OPEN.
- Priority: P1 — database names are Beta ammo (cred-stuff target selection).
- Category: DD
- Stack: Odoo
- What: Alpha fetches `/web/database/manager` (51677 bytes on quantum) and correctly mints `odoo_dbmanager_exposed` finding. But the page contains a **database list** — every database name visible on the page. Alpha does NOT extract this list. Database names are high-value recon:; Database name = Beta's tar...
- Evidence: `/web/database/manager` fetched (200, 51677 bytes) → `odoo_dbmanager_exposed` finding minted. But:; Database list: NOT in graph; Database name "erp" (visible from `/web?db=erp` URL): NOT captured as DATA node; Alpha knows DB manager is exposed but doesn't know WHAT databases exist
- Files: recon/odoo_dbmanager_probe.py:83-184 — process_odoo_dbmanager_hit (checks EXPOSED, doesn't parse DB list); graph/nodes.py — no DATA node for database names
- Cross-ref: §12.61 axis B5 — database names help Beta select cred- stuff targets. `erp` DB likely has different cred policy than `test` DB.
- Effort: Low. HTML parse (regex or BeautifulSoup) + DATA node creation.

---

## GAP-064 — Odoo XML-RPC not checked (/xmlrpc/2/common, /xmlrpc/2/db)
- Status: OPEN.
- Priority: P1 — XML-RPC is Odoo's parallel attack surface (like WP XML-RPC).
- Category: SS
- Stack: Odoo
- What: Odoo exposes XML-RPC endpoints that Alpha does not check:; `/xmlrpc/2/common` — `version()` gives Odoo version without auth; `authenticate()` is the cred-stuff endpoint (Beta territory); `/xmlrpc/2/db` — database list without auth (same data as GAP-063, different vector); `/xmlrpc/2/object` — model ...
- Evidence: Not checked. Alpha does not know if XML-RPC is enabled on quantum-laboratories.com.
- Files: recon/capability_probe.py:72-74 — odoo_fingerprint CapabilitySpec (only /web/database/manager seed); agents/alpha/scout.py — no XML-RPC handler for Odoo
- Cross-ref: Beta's cred-reuse chain uses Odoo XML-RPC (`/xmlrpc/2/common` + `/xmlrpc/2/object`). Alpha discovering XML-RPC = Beta can be routed to it autonomously (not just via runner hardcode).
- Effort: Low. 1 request + XML parse + node creation. Same pattern as

---

## GAP-065 — Odoo /website/info not fetched (version + module list)
- Status: OPEN.
- Priority: P2 — version + module list for CVE lookup.
- Category: SS
- Stack: Odoo
- What: Odoo exposes `/website/info` (if website module is installed) which returns:; Odoo version (exact); Installed module list; Server info (Python version, PostgreSQL version, OS) This is Odoo's equivalent of WP's `/wp-json/wc/v3/system_status` (GAP-052) — a single endpoint that gives full version info....
- Evidence: `/website/info` fetched by `curl` (manual check) returns 200 with HTML. Alpha does not fetch it.
- Files: recon/capability_probe.py:72-74 — odoo_fingerprint CapabilitySpec (no /website/info seed); agents/alpha/scout.py — no /website/info handler
- Effort: Low-Medium. 1 request + HTML parse + CVE lookup per module.

---

## GAP-066 — Odoo database name from URL not captured (/web?db=erp)
- Status: OPEN.
- Priority: P2 — database name is Beta context (cred-stuff target).
- Category: DD
- Stack: Odoo
- What: Alpha fetches `/web?db=erp` (200, 16576 bytes on quantum) and mints an auth_surface finding. But the URL parameter `db=erp` is NOT captured as a DATA node. The database name "erp" is visible in the URL but discarded. This is the same pattern as GAP-054 (WP REST user fields truncated) — Alpha fetches...
- Evidence: `/web?db=erp` fetched (200, 16576 bytes) → `auth_surface` finding. Database name "erp" NOT in graph.
- Files: agents/alpha/scout.py:1329+ — _detect_auth_surface (doesn't parse URL params)
- Effort: Low. URL parse + DATA node creation. ~10 lines.

---


# Universal Recon

## GAP-055 — Security headers not audited
- Status: OPEN.
- Priority: P1 — missing headers = attack surface (clickjacking, XSS, MIME sniffing).
- Category: UN
- Stack: Universal
- What: Alpha fetches the homepage (200) and parses `x-powered-by` for tech_stack but does NOT audit security headers. Missing security headers are findings:; `strict-transport-security` missing → no HSTS → SSL strip possible; `x-frame-options` missing → clickjacking on login form; `content-security-policy`...
- Evidence: Homepage fetched (200). Response headers include `x-powered-by`, `cache-control`, `x-litespeed-cache` but NO security headers visible. Alpha did not audit or report this.
- Files: agents/alpha/scout.py — no security header audit handler; recon/capability_probe.py — no security header CapabilitySpec
- Effort: Low. Header parsing + VULNERABILITY node creation. ~50 lines.

---

## GAP-056 — robots.txt + sitemap.xml not fetched
- Status: OPEN.
- Priority: P1 — robots.txt reveals hidden paths, sitemap reveals full URL list.
- Category: UN
- Stack: Universal
- What: Alpha does not fetch `/robots.txt` or `/sitemap.xml`. These are:; `robots.txt`: admin's "do not crawl" list → every `Disallow` is interesting; `sitemap.xml`: complete URL list → endpoints Alpha might not discover otherwise APT operators check robots.txt FIRST — it's a free map of what the admin is t...
- Evidence: Neither fetched. Alpha discovered URLs only through wp-json route index + leak path probes.
- Files: recon/capability_probe.py — no robots/sitemap CapabilitySpec; agents/alpha/scout.py — no robots/sitemap handler
- Effort: Low. 2 requests + XML/txt parsing + URL enqueue.

---

## GAP-058 — JS secret extraction missing (api_key, nonce, ajaxurl from homepage HTML)
- Status: OPEN.
- Priority: P1 — JS files often expose API keys, nonces, AJAX endpoints.
- Category: UN
- Stack: Universal
- What: Alpha fetches the homepage HTML (178852 bytes for solusibersama) but does NOT extract `<script src="...">` URLs or analyze JS content. JavaScript files frequently contain:; API keys (Google Maps, Stripe, reCAPTCHA, Firebase); WordPress `wp_localize_script` data (ajaxurl, nonce, rest_url); Hardcoded ...
- Evidence: Homepage fetched (178852 bytes). 0 JS files extracted. 0 JS secrets. The HTML certainly contains `<script>` tags with plugin/theme JS URLs and `wp_localize_script` inline data.
- Files: agents/alpha/scout.py — no JS extraction handler; recon/capability_probe.py — no JS CapabilitySpec; ADR §5 line 153: "js_secrets" in Alpha→Beta handoff contract (not delivered)
- Cross-ref: §12.61 axis B6 ("Exposed secrets in public code — API keys, DB creds, .env, hardcoded origin IPs"). GAP-058 extract secrets dari target's own JS files — ini **complement** B6 (B6 = external GitHub/Git...
- Effort: Medium. JS URL extraction + fetch per JS file + secret grep.

---

## GAP-059 — Cookie audit missing (HttpOnly, Secure, SameSite flags)
- Status: OPEN.
- Priority: P2 — cookie security flags affect session theft/CSRF assessment.
- Category: UN
- Stack: Universal
- What: Alpha does not audit `Set-Cookie` response headers. Cookie flags determine attack surface:; `HttpOnly` missing → XSS can steal session via `document.cookie`; `Secure` missing → cookie sent over HTTP (interceptable); `SameSite=None` → CSRF possible; `SameSite=Lax` → partial CSRF protection; `__Host-`...
- Evidence: Cookies not audited.
- Files: agents/alpha/scout.py — no cookie audit handler
- Effort: Low. Header parsing + node creation. ~30 lines.

---

## GAP-062 — TLS/MX/SPF/DMARC infrastructure recon missing
- Status: OPEN.
- Priority: P3 — infrastructure assessment (SSL downgrade, phishing, IPv6 bypass).
- Category: UN
- Stack: Universal
- What: Alpha's recon_runner does subdomain enumeration via crt.sh/VT/OTX but does NOT assess:; **TLS config**: SSL/TLS version, cipher suites, cert SANs, cert validity. Weak TLS = downgrade attack. Cert SANs = subdomain discovery alternative.; **MX records**: mail server infrastructure. Missing MX = no ema...
- Evidence: DNS A record resolved (45.80.182.6) but MX/SPF/DMARC/AAAA/TLS not assessed.
- Files: conductor/recon_runner.py — subdomain enum exists, infra recon does not; agents/alpha/scout.py — no TLS/MX/SPF handler
- Cross-ref: §12.61 axis A2 ("Mail/MX/SPF — mail servers usually on origin infra, not CF → origin netblock"). GAP-062 adalah **prerequisite data source** untuk §12.61 A2. Alpha query MX records → mint SERVICE node...
- Effort: Medium. DNS queries (dnspython) + TLS scan (ssl module) + node

---


# Origin/CDN

## GAP-018 — RESOLVED 2026-08-08 (field-prove caught it, unit tests missed it)
- Status: FIXED (self-contained, `recon/origin_resolver.py`).
- Priority: —
- Category: RG
- Stack: Origin/CDN
- What: `candidates()` called `discover_origin_ips(...)` WITHOUT `seed_hosts`; the in-scope authorized domains (an origin-candidate source independent of crt.sh, §12.44) were never seeded.
- Effort: —

---

## GAP-019 — Per-host origin-resolution cache (RESOLVED 2026-08-08)
- Status: FIXED (`agents/alpha/scout.py`, `_bound_origin` per-host cache).
- Priority: —
- Category: CW
- Stack: Origin/CDN
- Evidence: field-prove timed out (~29 min, 10-min kill). Root cause: `_reach_attempted` is
- Effort: —

---

## GAP-038 — Cooperative mode short-circuits origin discovery (no binding proof)
- Status: FIXED 2026-08-09 (merged PR #381).
- Priority: —
- Category: RG
- Stack: Origin/CDN
- What: `resolve_and_bind_origin` (origin_binding.py L90-92) requires `token_for(profile, host)` to return a non-None ownership token before invoking `discovery.candidates()`. Cooperative mode sets `ownership_tokens={}` (no DNS-TXT, operator-approved SOW) → `token_for` returns None → `resolve_and_bind_origi...
- Evidence: ibudanbalita — `ORIGIN_DIRECT_ATTEMPT events: 0`, `Applicator calls: [2]` (both failed), `ENGAGEMENT_RUN_FAILED reason='beta_failed'`. Trace: token_for returns None karena ownership_tokens=frozenset() di cooperative profile.
- Effort: Low (~10 lines di resolve_and_bind_origin + test).

---

## GAP-039 — CompositeOriginDiscovery exact-host filter drops apex intel for subdomain binding
- Status: FIXED 2026-08-10 (fix branch fix/gap-039-composite-apex-scope).
- Priority: —
- Category: RM
- Stack: Origin/CDN
- What: `CompositeOriginDiscovery.candidates()` (origin_discovery.py) scoped event-sourced OTX/VT `origin_ip_candidates` with an EXACT host match (`payload.domain == fronted_host`). Passive intel is gathered per APEX domain (one `PASSIVE_INTEL_GATHERED` per engagement target), but origin binding is requeste...
- Evidence: niagamas re-run 2026-08-10 with `.env.runtime` keys loaded (VT/OTX/CERTSPOTTER all SET): direct API query proves OTX+VT hold origin candidates (`206.189.93.100` for niagamas, `216.106.184.20` for bernofarm), yet `ORIGIN_DIRECT_ATTEMPT events: 0`, `beta_failed`. WAF_BLOCKED on `pos.niagamas.com` path...
- Effort: Low (filter change + 2 tests).

---

## GAP-040 — Ownership gate rejects consented subdomains (origin-direct crash)
- Status: FIXED 2026-08-10 (fix branch fix/gap-040-subdomain-ownership-gate).
- Priority: —
- Category: RG
- Stack: Origin/CDN
- What: TWO defects on the origin-direct path for subdomains: 1. `_assert_fronted_host_owned` (engagement_profile.py) demanded an EXACT `scope_targets` hit (apex only). Subdomains discovered via VT/crt.sh pass Gate 1 (`is_in_scope`, `allow_subdomains` suffix match) and get probed, but on WAF block → binding...
- Evidence: niagamas re-run 2026-08-10 post-GAP-039 — `ORIGIN_BINDING_PROVEN` emitted for the first time, then immediate `OriginNotAuthorizedError` traceback; `status: failed`, `AGENT_DISPATCHED=0`, engagement aborted mid-recon.
- Effort: Low (gate + crash guard + 3 tests).

---

## GAP-041 — Cooperative soft-binding emits PROVEN for unprobed (stale) candidates
- Status: FIXED 2026-08-10 (fix branch fix/gap-041-false-soft-binding).
- Priority: —
- Category: FS
- Stack: Origin/CDN
- What: The cooperative soft-binding branch (GAP-038 Option A) assumed `discover_origin_ips` already confirmed every candidate via `_probe_as_origin`. That holds for `LiveOriginDiscovery` (base candidates are pre-probed). But `CompositeOriginDiscovery` unions event-sourced OTX/VT historical IPs that were NE...
- Evidence: niagamas re-run 2026-08-10 (post-GAP-039+040) — `ORIGIN_BINDING_PROVEN` for `206.189.93.100` (VT historical, 2025), then all 3 `ORIGIN_DIRECT_ATTEMPT` fetches failed with `origin_direct_fetch failed` (connection refused — server moved). False proof: PROVEN event with zero confirming traffic.
- Effort: Low (probe call + rename + 2 new tests + 2 updated tests).

---

## GAP-042 — Origin probe bypasses stealth HttpClient (opsec debt)
- Status: OPEN 2026-08-10 (identified by CodeRabbit review on PR #384).
- Priority: —
- Category: WI
- Stack: Origin/CDN
- What: `probe_as_origin` → `origin_direct_fetch` builds its own `httpx.Client` with only `{"Host": host}`, without `curl_cffi` TLS impersonation, header ordering, or `acquire()`/`sleep()` pacing controls. The live Alpha path uses `HttpClient` for all other recon traffic (§12.49 proactive evasion), but the ...
- Evidence: CodeRabbit inline review on `agent_alpha/recon/origin_binding.py:131` (PR #384, 2026-08-10). Pre-existing — not introduced by GAP-041; GAP-041 extended the call surface from base discovery only to also cooperative path.
- Impact: Origin-direct probes to client infrastructure are fingerprintable by WAF/IDS (vanilla httpx TLS signature, no pacing). For engagements with `opsec_stealth=True` this violates §12.49 (stealth by defaul...
- Effort: Medium (cross-module transport refactor + stealth test fixtures).
- Note: Not blocking PR #384 — GAP-041 fix is correct independent of this

---

## GAP-043 — CDN edge IP filter only covers Cloudflare (Sucuri/Incapsula/Akamai false proof)
- Status: OPEN 2026-08-10 (identified during busonlineticket.co.th re-run).
- Priority: After GAP-037 (host death detection). Not a blocker for
- Category: RM
- Stack: Origin/CDN
- What: `is_cloudflare_ip()` (reach_strategy.py) is the ONLY CDN edge IP filter in the origin-discovery pipeline. It checks 14 Cloudflare CIDR ranges (`CF_IP_RANGES` in constants.py). Origin candidates from VT/OTX that resolve to Sucuri/Incapsula/Akamai/Fastly edge IPs pass the filter (not CF range) → treat...
- Evidence: busonlineticket.co.th re-run 2026-08-10 — `CompositeOriginDiscovery.candidates()` returned [] (crt.sh down + VT/OTX empty for .co.th), so the bug did NOT fire (no IP reached the filter). But if VT/OTX had returned a Sucuri edge IP, it would have passed `is_cloudflare_ip` (not CF range) → false proof...
- Impact: Any non-CF CDN/WAF target with VT/OTX historical IPs → potential false `ORIGIN_BINDING_PROVEN` → wasted `ORIGIN_DIRECT_ATTEMPT` to edge IP → no actual bypass. Audit trail polluted with false proof eve...
- Effort: Medium (3-4 files: `constants.py`, `reach_strategy.py`,

---

## GAP-044 — Soft-404 false positives: exact-hash dedup misses reflected/varying error pages
- Status: FIXED via GAP-048 (#388, two-probe differential — format-agnostic).
- Priority: BLOCKER — false positives violate Lyndon #3. **DONE** (GAP-048 #388).
- Category: FS
- Stack: Origin/CDN
- What: The identical-body dedup (`test_identical_body_dedup.py`) uses exact body hash to suppress repeated catch-all responses. But many targets serve VARYING error pages — reflected path in body, dynamic timestamp, session token, CSRF nonce — so the hash differs per request even though the page is a soft-...
- Evidence: ingco.co.id + ibudanbalita — 93858-byte catch-all SPA shell served 200 for every path. Body varies slightly (reflected path in meta tag) → hash differs → dedup does not fire → 10+ "findings" on non-existent paths. seven-retail.com datalab.seven-retail.com — Vite React SPA, 1016-byte index.html for a...
- Impact: False positives in report (Lyndon #3). Wasted LLM tokens analyzing catch-all bodies. OPSEC noise from probing "unique" paths that are all the same page.
- Effort: Medium (1 file: scout.py — replaces the GAP-044 helper block).

---

## GAP-045 — CF-ceiling honest-outcome classification (Omega/Conductor)
- Status: OPEN 2026-08-11. LOW effort, HIGH product value.
- Priority: LOW effort, HIGH product value. After GAP-044.
- Category: RG
- Stack: Origin/CDN
- What: When a full-CF target yields NO exposed origin (crt.sh fails, VT/OTX empty, no historical DNS), the engagement ends with `beta_failed` or `alpha_complete` — neither communicates "CF ceiling reached, defensive-validation deliverable." Omega has no classification for "edge held N techniques from datac...
- Evidence: ibudanbalita — Beta correctly declined (fail-closed), but the outcome was logged as `beta_failed`, not `cf_ceiling_defensive_validation`. Client sees "failed" instead of "your edge held."
- Impact: SEA market product value lost. Client pays for "seberapa kuat proteksi kami" but gets "failed" instead of a defensive-validation report.
- Effort: Low (1-2 files: router.py + omega template).

---


# Recon Quality

## GAP-020 — Mid-engagement pattern-group exhaustion (OPEN, next slice)
- Status: OPEN. ADR §12.57 point 2.
- Priority: —
- Category: CW
- Stack: Universal
- What: N consecutive 404 on a path pattern-group (`.env*`, `wp-config.php.*`) → emit `PATTERN_GROUP_EXHAUSTED` → skip the remaining variants (this host; other hosts when stack differs). Deterministic counter, extends `EvasionPlanner` (anti-#6). NOT LLM, NOT cross-engagement (IntelligenceBase stays deferred...
- Effort: —

---

## GAP-021 — Fingerprint-driven path hard-filter (OPEN)
- Status: OPEN. ADR §12.57 point 3.
- Priority: —
- Category: CW
- Stack: Universal
- What: a confirmed stack REMOVES irrelevant generic paths, not only adds stack-specific ones. Currently `_handle_capability_fingerprint` ADDS `frontier_seeds`; the initial generic seed still fires. Fingerprint (e.g. WP, Odoo) → filter out API/other-stack paths before probing. Static filter, deterministic (...
- Effort: —

---

## GAP-022 — Deterministic rule coverage + finding correlation (OPEN)
- Status: OPEN. ADR §12.57 points 1 & 4 (recon-side).
- Priority: —
- Category: RM
- Stack: Universal
- What: (a) extend the deterministic rule-tier catalog so known exposures fire WITHOUT the LLM (`install.php`/`upgrade.php` 200 = WP-setup-exposed) — the rule-tier exists, its catalog is thin; (b) finding correlation — combine `wp-config.php.bak` DB creds + enumerated WP users into a single prioritised CRED...
- Effort: —

---

## GAP-026 — StealthPacer gate inverted: code exists, default OFF (violates §12.49)
- Status: OPEN. Doctrine §12.49: "Stealth by default from the 1st request (curl_cffi, Header
- Priority: —
- Category: WI
- Stack: Universal
- What: `StealthPacer` (§12.50) is fully implemented — multi-modal burst-and-pause, Gaussian jitter, adaptive backoff on 429/503. BUT the gate in `recon_runner.py:156` requires `engagement_profile.opsec_stealth=True` to activate it. The API default in `main.py:152` is `opsec_stealth: bool = False`. All 3 ru...
- Evidence: niagamas.com field-prove — Run 1 (83 events, natural pacing from crt.sh 30s timeouts) → wp-json/wp/v2/users accessible via CF DIRECT → 4 users + 2 vulns. Run 2 (247 events, zero pacing) → CF challenge on wp-json → origin-direct fallback → origin returns homepage (~98KB) → 0 users, 0 vulns.
- Impact: Cascade — no pacing → CF bot detection → wp-json challenged → origin-direct → homepage → 0 users → 0 credentials → Beta never dispatches. Root cause of "0 findings" on aggressive runs.
- Effort: —

---

## GAP-027 — Probing order: sensitive files before legitimate endpoints
- Status: OPEN.
- Priority: —
- Category: CW
- Stack: Universal
- What: Agent probes sensitive files (`.env`, `.git/config`, `wp-config.php.bak`) BEFORE legitimate endpoints (`wp-json`, `wp-admin`). Sensitive file probes trigger CF bot detection, which then blocks legitimate endpoints that were previously accessible.
- Evidence: niagamas.com — `.env` and `.git/config` probed early → CF switches to challenge mode → wp-json/wp/v2/users (probed later) gets challenged → origin-direct fallback → homepage.
- Impact: Legitimate endpoint data (wp-json users, woocommerce API) lost because CF already in bot-detection mode from sensitive file probes.
- Effort: —

---

## GAP-028 — Origin-direct response validation (generic homepage detection)
- Status: OPEN.
- Priority: —
- Category: RM
- Stack: Universal
- What: Origin server `139.59.255.22` returns WordPress homepage (~98KB) for ALL paths including `.env`, `.git/config`, `wp-json/wp/v2/users`. Agent treats this as real content, runs probes against homepage body → 0 findings. No baseline comparison to detect that origin-direct returns generic homepage inste...
- Evidence: niagamas.com field-prove — ALL origin-direct fetches return ~98KB body (98766-98789 bytes, ±23 bytes variance). wp-json/wp/v2/users via CF = 5,903 bytes (real JSON), via origin-direct = 98,785 bytes (homepage). Agent does not detect this.
- Impact: Origin-direct probes waste LLM tokens analyzing homepage body. False "HTTP 200" on sensitive files that don't exist (origin returns homepage, not 404).
- Effort: —

---

## GAP-029 — Unreachable subdomain still probed for all 12 paths
- Status: OPEN.
- Priority: —
- Category: CW
- Stack: Universal
- What: `run_recon` seeds probe paths (leak paths + surface discovery paths) for EVERY target before the homepage is fetched. If a subdomain is unreachable (DNS fail, connection timeout, host down), the agent still probes 12+ paths against it — each timing out at 15-30s. 4 unreachable subdomains × 12 paths ...
- Evidence: bernofarm.com field-prove (2026-08-09) — `apifinger.bernofarm.com`, `apifingeris2.bernofarm.com`, `apifingernew2.bernofarm.com`, `att3a2.bernofarm.com` all unreachable, each probed for 12 paths. Total run time ~16 minutes for recon alone. niagamas.com same pattern: `ainotulensi.niagamas.com`, `notul...
- Impact: Massif time waste. APT operator skips dead hosts immediately. Agent does not.
- Effort: Low (1 file, scout.py — track + skip predicate).

---

## GAP-030 — auth_surface regex misses Vue.js / framework-bound password inputs
- Status: DONE (PR #391 Slice 1a merged `2b85fed` + PR #392 Slice 1b merged `5554e8d`).
- Priority: —
- Category: RM
- Stack: Universal
- What: `detect_auth_surface_labels` regex `<input[^>]*type\s*=\s*['\"]?password\b['\"]?>` matches only static `type="password"`. Modern frameworks (Vue, React, Alpine) use dynamic bindings: `:type="showPassword ? 'text' : 'password'"` or `:type="password"`. These do NOT match the regex, so login forms with...
- Evidence: niagamas.com field-prove — `pos.niagamas.com/admin/login` has `<input :type="showPassword ? 'text' : 'password'" name="password">`. Regex does not match. `pos.niagamas.com` never persisted as ASSET with `login-form` label. Router never saw it.
- Impact: Login forms using Vue/React/Alpine bindings are invisible to the agent. Beta never dispatches for these targets. Missed attack surface. (Pre-fix: bare 401 also routed a basic-auth strike at a non-basi...
- Effort: DONE. Slice 1a = `auth_surface.py` + tests. Slice 1b = `auth_surface.py` +

---

## GAP-032 — OTX timeout 30s blocks sequential OSINT chain
- Status: OPEN.
- Priority: —
- Category: CW
- Stack: Universal
- What: OSINT sources run sequentially: CertSpotter → crt.sh → HackerTarget → DNS → OTX → VT. OTX has 30s timeout. If OTX is down (frequently from Oracle), 30s wasted before VT runs. No parallel execution.
- Evidence: bernofarm.com + niagamas.com field-prove — OTX timeout 30s every run. VT runs after OTX timeout, adding 30s to every engagement.
- Impact: 30s wasted per engagement. Not critical, but unnecessary.
- Effort: Medium (recon_runner.py — parallel execution or timeout reduction).

---

## GAP-036 — LLM tool-pick fires on auth-surface pages (no deterministic RULE)
- Status: OPEN, LOW priority (efficiency/OPSEC noise, NOT correctness).
- Priority: —
- Category: RM
- Stack: Universal
- What: LLMOrchestrator = RULE→SINGLE_LLM. No playbook RULE matches a login/auth-surface page, so DECIDE falls to the LLM tier, which picks the nearest framework-vuln tool (laravel_debug_probe) → success=False → 0 nodes + a wasted probe. Violates §12.57 (DECIDE must be deterministic; LLM stays in ORIENT). D...
- Evidence: niagamas — `[ALPHA/ORIENT] Selected tool 'laravel_debug_probe' via the single_llm tier` on pos.niagamas.com/admin/login, /signup, /forget-password. Verified in code: no login-form RULE exists; _detect_auth_surface records the label anyway (scout.py:559).
- Impact: 1 wasted probe per auth URL + misleading logs + minor OPSEC noise. Correctness unaffected once GAP-030 lands (label persists regardless of tool).
- Effort: Low (1 playbook rule + test). Do AFTER GAP-030 + entry-selection close.

---

## GAP-037 — Mid-run host death not detected (consecutive-failure threshold)
- Status: FIXED 2026-08-11 (merged PR #385). Stop-on-block egress death detection.
- Priority: —
- Category: CW
- Stack: Universal
- What: GAP-029 fix only marks a host dead on ROOT transport failure (path `/` or `""`). If the root succeeded early but the host goes unreachable MID-RUN (WAF rate-limit block, IP ban, transient network failure), non-root path failures emit "unreachable" but do NOT trigger dead-host abandonment. The agent ...
- Evidence: busonlineticket.co.th — root fetched 200 (line 48), 37 requests succeeded, then Sucuri WAF triggered IP rate-limit block. From line 133 onward, 30+ requests all timed out (30s each = 15+ min waste). GAP-029 did NOT fire because root already succeeded. `apps.busonlineticket.co.th` (root unreachable f...
- Impact: 15+ minutes wasted probing a blocked host. Each timeout = 30s. OPSEC noise from repeated failed connection attempts to a WAF that already blocked the source IP.
- Effort: Low (counter dict + threshold check in except block, ~15 lines + test).

---

## GAP-048 — Soft-404 signature is format-fragile: regex normalization is whack-a-mole
- Status: MERGED (#388). SUPERSEDES the GAP-044 regex normalizer. Tier-1 (7 tests
- Priority: —
- Category: RM
- Stack: Universal
- What: GAP-044 (#386) normalized the catch-all body with per-format REGEXES — reflected path, then HTML attribute values, then digit runs. Each only covers ONE token shape. Field showed the pattern is whack-a-mole: a CSRF **hex** token inside a JS object (`'csrf_token_name': '<32hex>'`, colon-delimited) is...
- Evidence: ingco.co.id catch-all — diff between the baseline probe and `/config/database.yml.bak` was exactly 2 lines, both the per-request CSRF token (`value="0a12ffca…"` at L1453 handled by the attr regex; `'csrf_token_name': '0a12ffca…'` at L1866 NOT handled — colon context). 32-char hex changes per request...
- Impact: BLOCKER re-opened — false positives persist (Lyndon #3) on any target whose catch-all carries a per-request token the current regexes miss. Blocks the GAP-044 field-prove (`catchall.lab`, #387).
- Effort: Medium (1 file: scout.py — replaces the GAP-044 helper block). DONE.

---

## GAP-049 — STEALTH_BROWSER header contradiction (UA=Windows, sec-ch-ua-platform=macOS)
- Status: DONE (PR #396, merged `96f716d`).
- Priority: —
- Category: RM
- Stack: Universal
- What: `constants.STEALTH_BROWSER` set a Windows `User-Agent` but omitted `sec-ch-ua-platform`. curl_cffi's `chrome124` impersonate preset sends `sec-ch-ua-platform: "macOS"` by default. The result: every request carried `User-Agent: ...Windows NT 10.0...` alongside `sec-ch-ua-platform: "macOS"` — a finger...
- Evidence: Verified via `https://tls.peet.ws/api/all` (canonical TLS fingerprint check). Before fix: `UA=Windows`, `sec-ch-ua-platform="macOS"`, `Accept` stripped. After fix: `UA=Windows`, `sec-ch-ua-platform="Windows"`, `Accept` complete. JA4 and Akamai HTTP/2 fingerprints matched Chrome 124 in both cases (TL...
- Impact: STEALTH-DEGRADED — any WAF that cross-checks `sec-ch-ua-platform` against `User-Agent` OS (Cloudflare bot management, Akamai BMP) could flag Agent-Alpha traffic as bot despite correct JA4/Akamai TLS f...
- Effort: Small (3 files: constants.py, http_client.py, test_http_client.py).

---


# Beta/Access

## GAP-031 — Beta crashes on OriginUnreachableError when no origin binding exists
- Status: PARTIALLY FIXED 2026-08-09 (crash FIXED — graceful decline + Omega handoff,
- Priority: —
- Category: RG
- Stack: Beta
- What: Beta uses `OriginAwareHttpClient` which is fail-closed: if no proven/authorized origin exists for a host, it raises `OriginUnreachableError` instead of falling back to CF DIRECT. This crashes Beta's `step()` at `self.http_client.get(self._entry_point)`.
- Evidence: niagamas.com field-prove (2026-08-09) — Beta dispatched (GAP-023 fix works), but crashed immediately: ``` OriginUnreachableError: no proven/authorized origin for 'niagamas.com'; refusing naked reach (fail-closed; would hit the CDN edge and burn the technique) ``` Beta never tried CF DIRECT as fallba...
- Impact: Beta dispatch (GAP-023 fix) is wasted if Beta crashes on entry. The deadlock is broken but Beta can't act.
- Effort: Crash fix = DONE. Residual = doctrine (§12.61), not a code slice.

---

## GAP-033 — Subdomain pivot path not designed (subdomain as entry to main domain)
- Status: OPEN (design gap, not yet implemented).
- Priority: —
- Category: RG
- Stack: Beta
- What: Agent discovers subdomains and probes them independently, but never uses accessible subdomains as pivot points to the main domain. APT operator: if main domain is CF-protected but `pos.niagamas.com/admin/login` is accessible, attack via subdomain → pivot to main domain via shared infrastructure (ses...
- Evidence: niagamas.com field-prove — `pos.niagamas.com/admin/login` accessible (Laravel), `niagamas.com` CF-protected. Agent probes both independently, never connects them. No concept of "subdomain access → main domain pivot" in the architecture.
- Impact: Missed attack paths. Subdomain access is treated as end goal, not as stepping stone to main domain.
- Effort: High (architectural — multiple files, design first).

---

## GAP-034 — Entry-selection has no node-level reachability signal
- Status: BUILT 2026-08-11 (HOST_ABANDONED-only demote read-model; WAF_BLOCKED NOT excluded). Detail → docs/Session_Handoff.md.
- Priority: —
- Category: RG
- Stack: Beta
- What: `select_strike_entry` (conductor/router.py) picks Beta's entry_point by auth-surface-label presence on ASSET nodes (reuses `_AUTH_SURFACE_LABELS`). Label presence is used as a *reachability proxy* — you cannot fingerprint `http_basic_auth` / `login-form` on a host Alpha never reached. This proxy hol...
- Evidence: `agent_alpha/graph/nodes.py` `AssetProps` = `host`, `tech_stack` only (no reachability field). `WAF_BLOCKED` is an event, not projected onto the node. Verified HEAD 3c3127e.
- Impact: Entry-selection cannot deterministically DEMOTE a dead-but-labelled host below a live one. Slice-1 is correct for the field topology but not fully general.
- Effort: Medium (design first; multi-file). Promote alongside instinct #2 (cred-reuse)

---

## GAP-035 — Entry-selection strikes ONE candidate; multi-surface not iterated
- Status: BUILT FRESH 2026-08-11 (own slice; multi-candidate dispatch loop). Build/status/seal detail → docs/Session_Handoff.md.
- Priority: —
- Category: RG
- Stack: Beta
- What: `select_strike_entry` returns a SINGLE best entry_point, and Beta's `run_strike` contract is single-entry_point. When a target exposes MORE than one in-scope auth surface (e.g. `hub` 401 basic-auth AND `pos` login-form), only the top-ranked one is struck; the rest are never attacked. Session_Handoff...
- Evidence: `conductor/main.py` run_beta dispatches one `run_strike(engagement_id, strike_entry)`; `agents/beta/strike.py` builds ctx for a single `self._entry_point`. Verified HEAD 3c3127e.
- Impact: Second/third reachable login surface on the same engagement goes unstruck = missed payable finding.
- Effort: Medium (dispatch-seam loop + per-candidate ctx/gate; no strike.py rewrite).

---

## GAP-067 — OdooAccessTool only speaks XML-RPC, no JSON-RPC fallback (CF-blocked targets fail)
- Status: OPEN (re-scoped 2026-08-12 — original entry incorrectly
- Priority: P1 — blocks Beta on CF-fronted Odoo targets (XML-RPC blocked).
- Category: TM
- Stack: Beta
- What: `OdooAccessTool` (`odoo_access.py`, 480 lines) IS wired in Beta's candidate list (`strike.py:337-341`) and speaks XML-RPC:; `db.list()` via POST to `/xmlrpc/2/db`; `authenticate(db, login, password)` via POST to `/xmlrpc/2/common`; Hardcoded candidates: `admin/admin`, `admin/password` + harvested cr...
- Evidence: Beta FAILED (status=3). OdooAccessTool ran first (0.85 rank) but XML-RPC POSTs to `/xmlrpc/2/*` likely blocked by CF (or admin/admin wrong for production). DefaultCredsTool ran second (0.7) but form POST to `/web/login` rejected by Odoo (expects JSON-RPC). Both tools failed → Beta FAILED. Root cause...
- Files: tools/internal/access/odoo_access.py:120-211 — run() only uses XML-RPC, no JSON-RPC fallback; tools/internal/access/default_creds.py:247-249 — HttpFormApplicator wrong for Odoo JSON-RPC
- Effort: Medium. Add JSON-RPC transport to OdooAccessTool (~80 lines)

---

## GAP-068 — RETRACTED (OdooAccessTool already has hardcoded candidates)
- Status: RETRACTED (2026-08-12). Original entry claimed Odoo default
- Priority: —
- Category: —
- Stack: Beta
- Effort: —

---


# Cognition & Planning (ADR-locked)

## GAP-004 — Planner/World Model — Moved to ADR §12.29
- Status: LOCKED in ADR §12.29 (2026-07-15)
- Priority: Critical
- Category: RG
- Stack: Cognition
- What: Replaces the reactive 1-step cognitive loop with `EngagementObjective`, `Planner`/`Executor`, `WorldModel`, and a `GOAL_COMPLETED` stop condition.
- Cross-ref: `docs/ADR.md` §12.29 *"Goal-directed cognition: Objective + Planner/World-Model + goal-completion"*
- Effort: —
- Note: Full root-cause, proposed fix, and confidence notes are now in ADR §12.29.
- Prerequisites: ~~GAP-002 (scratchpad wiring)~~ ✅ CLOSED #192, Bug #18/#19/#20 (graph quality).

---

## GAP-008 — Curiosity-Driven Exploration — Moved to ADR §12.30
- Status: LOCKED in ADR §12.30 (2026-07-15)
- Priority: Medium
- Category: —
- Stack: Cognition
- What: Adds deterministic `curiosity_score(observation)` in ORIENT, bounded to existing capabilities and scope, feeding the planner/scratchpad.
- Cross-ref: `docs/ADR.md` §12.30 *"Bounded curiosity-driven exploration"*
- Effort: —
- Note: Full rationale and envelope rules are now in ADR §12.30.
- Prerequisites: GAP-004 (planner), ~~GAP-002 (scratchpad)~~ ✅ CLOSED #192.

---

## GAP-009 — Cross-Validation Between Tools — Moved to ADR §12.31
- Status: LOCKED in ADR §12.31 (2026-07-15)
- Priority: Medium
- Category: —
- Stack: Cognition
- What: Introduces `self_verified` vs `cross_verified` tiers; high-FP tools require an independent second opinion before a finding is confirmed.
- Cross-ref: `docs/ADR.md` §12.31 *"Cross-tool verification tiers"*
- Effort: —
- Note: Full decision details are now in ADR §12.31.
- Prerequisites: GAP-003 (IntelligenceBase for FP rates).

---

## GAP-010 — Goal-Completion Detection — Moved to ADR §12.29
- Status: LOCKED in ADR §12.29 (2026-07-15)
- Priority: Medium
- Category: —
- Stack: Cognition
- What: Adds `GOAL_COMPLETED` to `StopReason`; completion criteria flow from planner-defined objectives.
- Cross-ref: `docs/ADR.md` §12.29 *"Goal-directed cognition: Objective + Planner/World-Model + goal-completion"* (Decision 4)
- Effort: —
- Note: Full rationale and criteria are now in ADR §12.29.
- Prerequisites: GAP-004 (planner/objective definition).

---

## GAP-011 — Authenticated Crawl / Post-Access Re-Discovery — Moved to ADR §12.32
- Status: LOCKED in ADR §12.32 (2026-07-15)
- Priority: Medium
- Category: —
- Stack: Cognition
- What: After Beta obtains `valid_credentials`, re-crawl with an active session; diff unauth vs auth surfaces. Exploitation remains Gamma-gated.
- Cross-ref: `docs/ADR.md` §12.32 *"Post-access authenticated re-recon"*
- Effort: —
- Note: Full boundary rules are now in ADR §12.32.
- Prerequisites: GAP-004 (planner), GAP-010 (next-objective handling).

---

## GAP-012 — Adaptive Evasion — Moved to ADR §12.33
- Status: LOCKED in ADR §12.33 (2026-07-15)
- Priority: Medium
- Category: —
- Stack: Cognition
- What: On repeated `BLOCKED`, switch rate/UA/TLS-fingerprint techniques; implement `cf_curl_cffi` template; wire through PolicyEnforcer/Planner.
- Cross-ref: `docs/ADR.md` §12.33 *"Adaptive evasion"*
- Effort: —
- Note: Full technique boundaries are now in ADR §12.33.
- Prerequisites: GAP-005 (PolicyEnforcer wiring), GAP-004 (planner re-plan).

---

## GAP-013 — Credential Pattern Mutation Within Engagement — Moved to ADR §12.34
- Status: LOCKED in ADR §12.34 (2026-07-15)
- Priority: Low-Medium
- Category: —
- Stack: Cognition
- What: `CredentialPatternMutator` extracts patterns from harvested credentials, generates bounded variants, and tries them only after literal reuse fails and under the lockout governor.
- Cross-ref: `docs/ADR.md` §12.34 *"Within-engagement credential mutation"*
- Effort: —
- Note: Full mutation and gating rules are now in ADR §12.34.
- Prerequisites: ~~GAP-002 (scratchpad pattern tracking)~~ ✅ CLOSED #192.

---


# Memory & Intelligence (wiring)

## GAP-002 — Scratchpad/SessionStore — CLOSED
- Status: CLOSED — Wired in PR #192 (2026-07-18)
- Priority: High — agent berjalan tanpa working memory (RESOLVED)
- Category: WI
- Stack: Memory
- Files: memory/session.py — SessionStore Protocol, InMemorySessionStore, RedisSessionStore (239 lines, fully implemented); conductor/main.py — tidak ada instantiation SessionStore; conductor/recon_runner.py —...
- Impact: Agent berjalan tanpa working memory. Inner monologue tidak di-persist. Resume step-level tidak mungkin. Setiap engagement mulai dari blank state — tidak ada scratchpad yang mengalir antar step.
- Cross-ref: ADR §12.11 (SessionMemory). Bug #7 (Engagement Memory tidak persist) — terkait tapi berbeda: SessionMemory = volatile scratchpad, EngagementMemory = persistent cross-engagement learning.
- Effort: —
- Resolution: `SessionStore` wired into production path:; `main.py`: `_ensure_session()` helper + `session_store_for()` tenant-aware instantiation; `run_cognitive_loop`: `session_store` + `event_store` + `engagemen...

---

## GAP-003 — IntelligenceBase — Protocol Saja, Semua Method Return InsufficientData
- Status: OPEN
- Priority: High — agent tidak belajar dari engagement sebelumnya
- Category: WI
- Stack: Memory
- What: `IntelligenceBase` Protocol + `RecordBackedIntelligenceBase` ada di `memory/intelligence.py` (312 lines). `tool_success_rates` selalu `{}` — confirmed di `engagement.py:187` dengan comment: "Phase 2 scope". `_collect_tool_rates()` di `intelligence.py:295-311` selalu return `[]` terhadap live records...
- Files: memory/intelligence.py — IntelligenceBase Protocol + RecordBackedIntelligenceBase (312 lines); memory/engagement.py:187 — tool_success_rates selalu {} (comment: "Phase 2 scope"); tools/registry.py:37 ...
- Impact: Agent tidak belajar dari engagement sebelumnya. Tool selection tidak mempertimbangkan historical reliability, false positive rates, atau success rates. Setiap engagement menggunakan ranking tool yang ...
- Cross-ref: ADR §12.11 (IntelligenceBase). Bug #7 (Engagement Memory tidak persist) — prerequisite: engagement memory harus persist dulu sebelum IntelligenceBase bisa query. > **Catatan L2 — Confidence Calibratio...
- Effort: —

---

## GAP-007 — OSINT / External Context Gathering — Tidak Ada Sama Sekali
- Status: OPEN
- Priority: Medium — agent langsung HTTP probe target tanpa intelligence gathering
- Category: RG
- Stack: Memory
- What: `recon_runner.py` langsung mulai dengan crt.sh subdomain discovery → HTTP probe. Grep `OSINT|open.source.intel|social.engineer|phishing|pastebin|breach|github.*secret` di seluruh `agent_alpha/` = **0 hasil**. ADR §8o-3 (Knowledge Ingestion Pipeline) me-reference CVE feeds, exploit-db, nuclei templat...
- Files: conductor/recon_runner.py:218-236 — build_passive_discovery() hanya crt.sh CT log lookup; recon/passive_discovery.py — PassiveDiscovery.discover() hanya query crt.sh untuk subdomain enumeration; Tidak...
- Impact: Agent tidak melakukan intelligence gathering sebelum technical recon. Tidak mencari leaked credentials di pastebin/GitHub, tidak profiling employee untuk social engineering, tidak checking breach data...
- Cross-ref: ADR §8o-3 (Knowledge Ingestion — threat-intel RAG, BUKAN OSINT). ADR §8e (Phishing Impact Test profile). GAP-004 (Planner) — OSINT findings harus masuk ke planner untuk prioritisasi.
- Effort: —

---

## GAP-016 — Wayback Machine Pre-Intel — Archive-Driven Probe Selection
- Status: OPEN
- Priority: Medium — Agent probes blind paths, causing 404 noise and WAF/CF blocks (Bug #26)
- Category: RG
- Stack: Memory
- Effort: Low-Medium (single module + CDX API query, no target interaction)

---

## GAP-017 — PassiveIntelMap Enrichment Dead-End — Consumer Not Wired
- Status: PARTIALLY — origin_ip_candidates consumer wired; protection_detected consumer (Slice A/B/C) still OPEN
- Priority: Medium — enrichment data written to event store but read by nobody
- Category: WI
- Stack: Memory
- Effort: Medium (3-slice fix: World Model ingestion, planner scoring, reach pivot)

---

## GAP-050 — IntelligenceBase wiring gap: data exists but never reaches memory
- Status: OPEN.
- Priority: HIGH — after Slice B (SPA-login applicator). Slice 1
- Category: WI
- Stack: Memory
- What: `IntelligenceBase` Protocol (`memory/intelligence.py`) has 4 query methods locked since Phase 1, but 3 of 4 always return `InsufficientData` against live records. Root cause is NOT "Phase 6 feature" — it is 4 wiring gaps where data exists in the live path but never bridges to `EngagementMemoryRecord...
- Evidence: Verified against PostgreSQL on Oracle ARM64 (tenant='default'):; `agent_events`: 6,994 rows (API/Celery path only).; `NodeDiscovered` events with `tech_stack` in payload: 1,289.; `ExploitConfirmed` / `ExploitFailed`: **0 rows** (dead events).; `engagement_memory`: **0 rows** (projector never runs or...
- Impact: Agent-Alpha cannot learn across engagements. Every engagement starts from zero — no "Laravel+CF → origin-direct worked last time" recall. This is the core differentiator (§4, ADR line 121: "governance...
- Effort: Medium (4 slices: runner wiring + record schema + projector

---

## GAP-051 — `try_harder` is path-recovery only, not strategic pivot (D2-c unbuilt)
- Status: OPEN.
- Priority: MEDIUM — after Bug #34 fix (reset) and Slice B (SPA-login).
- Category: RG
- Stack: Memory
- What: Alpha's `try_harder` (`planner.py:43-101`) is a **path-level dead-end recovery**, not a **strategic pivot**. When Alpha exhausts its frontier, `try_harder` only re-seeds leak paths on hosts already in the graph — it never changes strategy. The D2-c extension point (HTN-style replan) is explicitly ma...
- Files: agents/planner.py:13 — D2-c extension point (empty); agents/planner.py:43-101 — try_harder (path recovery only); agents/alpha/scout.py:2322-2345 — _try_harder_recovery; agents/alpha/scout.py:648-679 —...
- Effort: Medium. The 2 pivot strategies:

---


# Policy & Tooling (wiring + new tools)

## GAP-001 — Missing Tools & Playbooks for Broader Coverage
- Status: OPEN
- Priority: Medium — no playbook for ASP.NET/JSP/SPA/Classic ASP; Alpha only effective on Laravel/WP/Odoo
- Category: SS
- Stack: Policy/Tooling
- Effort: —

---

## GAP-005 — PolicyEnforcer — Partially Wired (slice-1 done, slice-2 OPEN)
- Status: PARTIALLY WIRED — slice-1 (blast-radius gate) DONE (#184), slice-2 (agent execution path) OPEN
- Priority: High — OPSEC, technique check, scope check masih dead code di production agent path
- Category: WI
- Stack: Policy/Tooling
- Files: conductor/policy.py — PolicyEnforcer class (152 lines, fully implemented); conductor/main.py:62 — policy = PolicyEnforcer() instantiated; conductor/main.py — policy variable tidak pernah direferensika...
- Impact: OPSEC profile (rate limit, user-agent rotation, timing), technique check (blocked techniques), scope check (out-of-scope targets), time-window enforcement, human approval gating, blast-radius gate — s...
- Cross-ref: ADR §12.20/21/22 (Policy-as-Code). GAP-006 (Graph Analytics) — blast-radius gate butuh `calculate_blast_radius()` yang juga tidak ter-wire. > **Catatan L5 — Adversarial Reasoning (Game-Theoretic)**: O...
- Effort: —

---

## GAP-006 — Attack Graph Analytics — Partially Wired (slice-1 done, slice-2 OPEN)
- Status: PARTIALLY WIRED — slice-1 (blast-radius → decision) DONE (#184), slice-2 (critical paths → planner) OPEN (needs GAP-004)
- Priority: Medium — blast-radius gate sudah aktif; critical paths untuk prioritisasi masih hanya di report
- Category: WI
- Stack: Policy/Tooling
- What: `find_critical_paths()` dan `calculate_blast_radius()` fully implemented di `narrative.py`. Grep di seluruh codebase: 5 file match — `narrative.py` (definisi + 2 call di `_to_executive_narrative`), 3 test files. **Call chain production:** `Omega.generate_report()` → `to_narrative()` → `_to_executive...
- Files: graph/narrative.py:44-80 — find_critical_paths() (graph path-finding ASSET→DATA/ACCESS_LEVEL); graph/narrative.py:83-137 — calculate_blast_radius() (BFS reachable nodes + HVT identification); agents/o...
- Impact: Graph analytics hanya untuk laporan, bukan untuk mengarahkan agent. Agent tidak tahu critical paths atau blast radius saat membuat decision. Blast-radius gate (ADR §1) tidak aktif — agent bisa execute...
- Cross-ref: ADR §1 (blast-radius gate). GAP-005 (PolicyEnforcer) — blast-radius gate butuh PolicyEnforcer untuk enforce. GAP-004 (Planner) — critical paths harus masuk ke planner untuk prioritisasi.
- Effort: —

---

## GAP-014 — Fan-Out Parallel Worker Wiring — Shape A Not Wired
- Status: OPEN
- Priority: Medium — multi-target engagements run sequential, ~Nx latency vs design intent
- Category: WI
- Stack: Policy/Tooling
- Cross-ref: `docs/ADR.md` §12.13 *"Agent scaling model — Hybrid orchestrated fan-out"*
- Effort: —

---


## GAP-015 — Credential Spray Tool — Harvested Usernames × Common Passwords
- Status: CLOSED — Implemented as `UserDerivedCredsTool` (derive-not-spray, not `cred_spray` with static password list)
- Priority: High — Beta can't use USER nodes from Alpha recon for credential spray
- Category: RG
- Stack: Policy/Tooling
- Effort: —

---

## GAP-046 — HTTP Basic Auth applicator absent (cred-acquisition breadth)
- Status: OPEN 2026-08-11. Deferred (after §12.61 slices).
- Priority: Deferred — after §12.61 historical DNS slice (origin discovery opens
- Category: SS
- Stack: Policy/Tooling
- What: Beta's credential applicator handles form-login (POST username/password) and session-cookie auth, but NOT HTTP Basic Auth (401 + WWW-Authenticate: Basic). When Alpha discovers a basic-auth surface (e.g. `hub.niagamas.com` returns 401 Basic), Beta cannot apply harvested/default credentials to it — th...
- Evidence: niagamas.com field-prove — `hub.niagamas.com` returns 401 with `WWW-Authenticate: Basic realm="Restricted"`. Alpha correctly detected auth_surface (http_basic_auth). Beta dispatched but could not attempt credentials — no basic-auth applicator in the cred application pipeline.
- Impact: Basic-auth-protected surfaces are detected but never attacked. Cred-reuse chain broken at the applicator step for basic-auth targets.
- Effort: Medium (1 new tool + test fixtures).

---

## GAP-047 — Username harvest WP-REST-only (producer breadth, non-WP surfaces)
- Status: OPEN 2026-08-11. Deferred (relates to GAP-015).
- Priority: Deferred — after GAP-046 (basic-auth applicator) and §12.61 slices.
- Category: SS
- Stack: Policy/Tooling
- What: Username harvesting (`user_derived_creds.py`) only enumerates users via WP-REST API (`/wp-json/wp/v2/users`). Non-WP surfaces (Odoo, custom login forms, email patterns from OSINT, breach data) are not harvested. Cred-reuse chain is limited to WP-derived usernames.
- Evidence: niagamas.com — `pos.niagamas.com` is a Vue.js login form (not WP). Username harvest returned 0 users (WP-REST only). No cred-reuse possible without usernames to pair with harvested/default passwords.
- Impact: Cred-reuse chain broken at the username-producer step for non-WP targets.
- Effort: High (multiple producers + test fixtures).

---


# Trust Graph & Organizational Intelligence

## GAP-069 — Trust Graph — organizational intelligence nodes missing
- Status: OPEN.
- Priority: HIGH — Beta receives technical graph only; no people, vendor, or trust-relationship context for strategic entry selection.
- Category: RG
- Stack: Universal
- What: `graph/nodes.py` defines 7 node types (ASSET, VULNERABILITY, CREDENTIAL, SERVICE, DATA, ACCESS_LEVEL, USER). `USER` is a WP-REST slug, not an organizational persona. There are no node types for `EMPLOYEE` (LinkedIn/GitHub persona, role, department), `VENDOR` (SaaS/CDN/third-party with access to target infrastructure), or `TRUST_RELATIONSHIP` (employee→asset access, vendor→asset integration). An agentless APT-style red team needs to know **who** has access, **what** they trust, and **how** they connect — not just **what** is exposed. Without this, Beta can only attempt technical cred-reuse, never strategic entry via trust paths (e.g. vendor admin portal, employee SSO, third-party API key).
- Evidence: `graph/nodes.py:13-21` — NodeType enum has no EMPLOYEE, VENDOR, or TRUST_RELATIONSHIP. `scout.py` emits no organizational intelligence events. All 6,994 rows in `agent_events` are technical (NodeDiscovered, WAF_BLOCKED, ORIGIN_DIRECT_ATTEMPT, etc.) — 0 rows for people or vendor relationships.
- Files: `agent_alpha/graph/nodes.py:13-21` — NodeType enum; `agent_alpha/events/event_types.py` — no EMPLOYEE_DISCOVERED or VENDOR_RELATIONSHIP event types; `agent_alpha/agents/alpha/scout.py` — no organizational OSINT handler
- Cross-ref: GAP-007 (OSINT), GAP-070 (Credential-to-Asset correlation). ADR §12.48 (Passive-First Recon) — organizational intelligence is passive, zero target touch.
- Impact: Beta's entry selection is purely technical (auth-surface label + reachability). No "path of least resistance" via human/vendor trust. Agent-Alpha cannot emulate APT-style strategic entry.
- Effort: HIGH (new node types + event types + OSINT sources + graph projection). Must be event-sourced — NOT a handoff DTO (anti-Lyndon #4, #7). Defer LinkedIn/vishing/phishing to client-authorized slice; v1 = public sources only (GitHub, WHOIS, public CT, job postings).
- Constraint: LinkedIn scraping, vishing, phishing, dark web = DEFERRED to client-authorized social-engineering slice with legal review. v1 uses only public OSINT (GitHub commits, WHOIS registrant, public CT SANs, job posting tech stack).

---

## GAP-070 — Credential-to-Asset correlation missing
- Status: OPEN.
- Priority: HIGH — breach credentials exist in vault but are not mapped to specific assets via graph edges.
- Category: RG
- Stack: Universal
- What: `CredentialProperties` has a `service: str` field (free-text), but there is no graph edge `CREDENTIAL -> ENABLES -> ASSET`. Breach data from Dehashed/HIBP (§12.54, not yet wired) and harvested credentials from leak files (`wp-config.php.bak`, `.env`) are stored as CREDENTIAL nodes with `secret_ref` in the vault, but the graph does not encode **which asset** those credentials are valid for. Beta's cred-reuse logic (`cred_reuse.py`) iterates all credentials against all auth surfaces — it does not use a graph edge to prioritize "this credential was harvested from WP config → try it on WP login first, then Odoo XML-RPC". The correlation is implicit in tool logic, not explicit in the graph.
- Evidence: `graph/nodes.py:78-83` — CredentialProperties has `username`, `secret_ref`, `service`, `access_level` — no `valid_for_asset_id` or graph edge. `tools/internal/access/cred_reuse.py:84` — iterates credentials × surfaces without graph-based prioritization. `security/credential_assembly.py` — assembles credentials but does not emit `CREDENTIAL -> ENABLES -> ASSET` edges.
- Files: `agent_alpha/graph/nodes.py:78-83` — CredentialProperties; `agent_alpha/graph/nodes.py:29-36` — RelationshipType (no ENABLES_FOR or VALID_ON); `agent_alpha/tools/internal/access/cred_reuse.py`; `agent_alpha/security/credential_assembly.py`
- Cross-ref: GAP-054 (WP REST user email — prerequisite for breach OSINT correlation), GAP-069 (Trust Graph — credentials are part of trust graph), §12.54 (Dehashed/HIBP breach integration, not yet wired).
- Impact: Beta's cred-reuse is brute-force-ish (try all creds on all surfaces). No graph-based "credential X was leaked from asset Y → try Y first, then trust-relationship Z". Misses strategic cred-reuse paths; wastes attempts on irrelevant credential/asset pairs.
- Effort: MEDIUM (new RelationshipType + edge emission in credential_assembly + Beta reads edge for prioritization). Event-sourced: Alpha emits `CREDENTIAL_CORRELATED` event, Beta reads projection.

---

## GAP-071 — Recon freshness / liveness check missing
- Status: OPEN.
- Priority: MEDIUM — Beta uses stale recon data without temporal validation.
- Category: RG
- Stack: Universal
- What: Each `AttackNode` has `timestamp_utc` and `VerificationTier` (UNVERIFIED / SELF_VERIFIED / CROSS_VERIFIED), but there is no **freshness policy** — no rule that says "if recon data is older than X minutes, re-validate before Beta uses it". A real APT operator checks: is the port still open? Is the credential still valid? Has the WAF rule changed since recon? Agent-Alpha has no `FreshnessScore`, no `last_validation` timestamp, no `LivenessProbe` that runs between Alpha completion and Beta dispatch. Beta trusts Alpha's data blindly.
- Evidence: `graph/nodes.py:136-140` — `timestamp_utc` and `verified` exist but no `last_validated` or `freshness_score`. `conductor/main.py` — no liveness probe between Alpha handoff and Beta dispatch. `VerificationTier` is about proof quality (self vs cross-verified), NOT about temporal freshness.
- Files: `agent_alpha/graph/nodes.py:122-153` — AttackNode (no freshness fields); `agent_alpha/conductor/main.py` — no pre-Beta validation step; `agent_alpha/events/event_types.py` — no FRESHNESS_CHECKED event
- Cross-ref: GAP-017 (PassiveIntelMap consumer not wired — protection_detected could change between recon and strike). §12.49 (stealth by default — liveness probe must be stealthy).
- Impact: Beta may attempt cred-reuse on a login form that was removed. Beta may target an origin IP that was rotated. Beta may hit a WAF rule that was tightened since recon. False negatives from stale data, not from logic errors.
- Effort: MEDIUM (freshness field in AttackNode + FRESHNESS_CHECKED event + micro-interaction probe: HTTP banner grab, DNS re-resolution, single credential check — NOT brute force). Must be stealthy (§12.49): 1-3 requests max, long delay, curl_cffi.

---

## GAP-072 — Entry-vector ranking + strategic approach not in graph
- Status: OPEN.
- Priority: MEDIUM — Beta receives raw nodes without ranked entry vectors or approach recommendation.
- Category: RG
- Stack: Universal
- What: Alpha emits nodes (ASSET, VULNERABILITY, CREDENTIAL, USER, etc.) into the graph. Beta's `select_strike_entry` (`conductor/router.py`) picks an entry point by auth-surface label presence. But there is no **ranked entry-vector list** in the graph — no node or edge that says "vector 1: cred-reuse via WP login (ease=0.8, stealth=0.9, impact=0.7), vector 2: origin-direct bypass (ease=0.5, stealth=0.3, impact=0.9), vector 3: Odoo XML-RPC default cred (ease=0.6, stealth=0.8, impact=0.5)". A real APT operator ranks entry vectors by ease + stealth + impact before choosing. Agent-Alpha's entry selection is label-presence binary, not strategic.
- Evidence: `conductor/router.py` — `select_strike_entry` ranks by auth-surface label, not by multi-factor vector scoring. No `EntryVector` node type or `RECOMMENDS_VECTOR` edge in graph. `strategic_gaps_roadmap.md` G5 — "No adversary emulation / threat-actor TTP modeling."
- Files: `agent_alpha/graph/nodes.py` — no EntryVector node; `agent_alpha/conductor/router.py` — select_strike_entry (label-based, not vector-ranked); `agent_alpha/events/event_types.py` — no ENTRY_VECTOR_RANKED event
- Cross-ref: GAP-034 (entry-selection reachability signal), GAP-035 (multi-surface iteration), GAP-069 (Trust Graph — trust paths are input to vector ranking), GAP-070 (credential correlation — cred-asset edges feed vector scoring). ADR §12.58 (Strategic Entry Selection).
- Impact: Beta may strike the "most visible" entry (login form) instead of the "most strategic" entry (origin bypass + cred-reuse chain). Suboptimal entry selection = wasted attempts + missed chains.
- Effort: MEDIUM (new EntryVector concept in graph + scoring algorithm + Beta reads ranked vectors). Event-sourced: Alpha emits `ENTRY_VECTOR_RANKED` event with score breakdown. NOT a handoff DTO (anti-Lyndon #7).
- Constraint: Scoring must be deterministic (rule-based), NOT LLM-generated. LLM may suggest vectors but scoring is rule-tier (anti-#3 false success).

---


# External Attack Surface

## GAP-073 — WAF/CDN capability fingerprinting (beyond vendor hint)
- Status: OPEN.
- Priority: HIGH — Alpha knows WAF vendor but not capability; Beta's strategy depends on capability, not just vendor.
- Category: RM
- Stack: Universal
- What: `passive_intel.py:classify_protection()` maps NS records to a vendor hint ("cloudflare", "akamai", "sucuri", "imperva"). But this is a **vendor label**, not a **capability fingerprint**. A real external red team needs to know: Is Cloudflare Bot Management with ML enabled? Is it just rate limiting? Is there a JS challenge? Is there a CAPTCHA? What is the rate limit threshold (10 req/min? 100 req/min?)? Is there an IP reputation block? Alpha's `response_classifier.py` detects CF challenge responses (200 interstitial, 403, 503) but does not fingerprint the **WAF rule set** or **bot management mode**. Without this, Beta cannot choose between "slow cred-spray with long delays" vs "origin-direct bypass" vs "JS challenge solve".
- Evidence: `passive_intel.py:173-193` — `classify_protection` returns vendor string only. `recon/response_classifier.py` — classifies challenge responses but does not fingerprint WAF mode. niagamas.com field-prove — Run 1 (natural pacing) → wp-json accessible via CF. Run 2 (aggressive) → CF challenge. Alpha did not detect the mode change or record the WAF's rate-limit threshold.
- Files: `agent_alpha/recon/passive_intel.py:173-193` — classify_protection (vendor only); `agent_alpha/recon/response_classifier.py` — challenge detection (no capability fingerprint); `agent_alpha/graph/nodes.py:52-66` — AssetProperties (no `waf_capability` field)
- Cross-ref: GAP-026 (StealthPacer gate inverted — stealth not default), GAP-027 (probing order triggers WAF), §12.49 (proactive evasion), §12.33 (adaptive evasion — LOCKED).
- Impact: Beta's access strategy is chosen blind to WAF capability. On a CF Bot Management target, cred-spray triggers IP ban. On a rate-limit-only target, slow cred-spray works. Alpha doesn't tell Beta which mode is active.
- Effort: MEDIUM (WAF capability probe: 3-5 calibrated requests to measure response pattern + rate limit threshold + challenge type. Must be stealthy — low rate, curl_cffi. New `waf_capability` field in AssetProperties + WAF_CAPABILITY_FINGERPRINTED event).

---

## GAP-074 — Authentication mechanism fingerprinting (form/JWT/SAML/OAuth)
- Status: OPEN.
- Priority: HIGH — auth-surface label is binary; Beta can't attack what it doesn't understand mechanistically.
- Category: RM
- Stack: Universal
- What: Alpha's `_detect_auth_surface` (`scout.py`) labels auth surfaces as `login-form` or `http_basic_auth`. But this is too coarse for Beta to choose the right attack tool. A real red team fingerprints the auth mechanism: Is it form-based POST? JSON-RPC? JWT bearer? SAML SSO? OAuth 2.0? OpenID Connect? Session cookie? CSRF token structure (synchronizer token, double-submit, encrypted)? Does it use a nonce? Is there a CAPTCHA? Is there a "remember me" token? Beta's `OdooAccessTool` speaks XML-RPC, `DefaultCredsTool` speaks form POST, `cred_reuse.py` tries form POST — but none of these know **what mechanism the target actually uses** until they fail. GAP-067 (Odoo JSON-RPC fallback) is a symptom of this root cause: Beta tried XML-RPC on a JSON-RPC target because Alpha didn't fingerprint the mechanism.
- Evidence: `scout.py:1329+` — `_detect_auth_surface` returns labels (`login-form`, `http_basic_auth`), not mechanism details. `graph/nodes.py:52-66` — AssetProperties has no `auth_mechanism` field. niagamas.com — `pos.niagamas.com/admin/login` is a Vue.js SPA login (likely JSON/REST POST with CSRF token), but Alpha labelled it `login-form` only. Beta tried form POST → failed.
- Files: `agent_alpha/agents/alpha/scout.py:1329+` — _detect_auth_surface (label only, no mechanism); `agent_alpha/graph/nodes.py:52-66` — AssetProperties (no auth_mechanism); `agent_alpha/recon/capability_probe.py` — no auth-mechanism probe
- Cross-ref: GAP-030 (Vue.js :type password regex — fixed for detection, but mechanism still not fingerprinted), GAP-067 (Odoo JSON-RPC fallback — symptom of missing mechanism fingerprint), GAP-046 (HTTP Basic Auth applicator — another mechanism Beta can't handle), GAP-047 (username harvest WP-REST-only — mechanism-specific harvesting).
- Impact: Beta attempts the wrong tool for the target's auth mechanism. XML-RPC tool on JSON-RPC target. Form POST on SAML SSO target. Every mismatch = wasted attempt + potential WAF trigger + no access. This is the root cause of multiple Beta failures across stacks.
- Effort: MEDIUM (auth mechanism probe: parse login form action/method/enctype, check for JWT/SAML/OAuth indicators in response headers and JS, detect CSRF token structure. New `auth_mechanism` field in AssetProperties + AUTH_MECHANISM_FINGERPRINTED event).

---

## GAP-075 — Subdomain takeover check (dangling DNS CNAME)
- Status: OPEN.
- Priority: MEDIUM — classic external red team finding; not checked at all.
- Category: SS
- Stack: Universal
- What: Alpha enumerates subdomains via crt.sh/VT/OTX but does NOT check for **subdomain takeover** — a dangling CNAME record pointing to a deleted/deprovisioned service (Heroku, GitHub Pages, S3, Azure, etc.). This is a textbook external finding: `sub.example.com CNAME example.herokuapp.com` where the Heroku app has been deleted → attacker registers the Heroku app name → controls `sub.example.com`. The check is passive (DNS CNAME lookup + HTTP response pattern), zero target touch beyond the subdomain itself.
- Evidence: `recon/passive_discovery.py` — enumerates subdomains but does not resolve CNAME records or check for dangling references. `recon/origin_resolver.py` — resolves A records for origin discovery, not CNAME for takeover. No takeover check in any recon module. `strategic_gaps_roadmap.md` G19 — "Passive Supply Chain Attack (Subdomain takeover) is deferred" — but it has no GAP entry.
- Files: `agent_alpha/recon/passive_discovery.py` — subdomain enumeration only; `agent_alpha/recon/origin_resolver.py` — A record focus; `agent_alpha/graph/nodes.py` — no VULNERABILITY type for subdomain takeover
- Cross-ref: GAP-007 (OSINT), GAP-016 (Wayback — historical CNAME records can reveal past takeover). Strategic roadmap G19.
- Impact: Missed payable finding. Subdomain takeover is a high-severity finding that conventional scanners (Nuclei) DO detect — if Agent-Alpha misses it, it fails the success condition ("finds something a scanner missed" — but also must not miss what a scanner finds).
- Effort: LOW (CNAME resolution per subdomain + check against known dangling-service patterns: Heroku, GitHub Pages, S3, Azure, Tumblr, Shopify. ~100 lines + pattern list. 0 target HTTP touch — DNS only).

---

## GAP-076 — Cloud storage / shadow-IT discovery (S3/GCP/Azure)
- Status: OPEN.
- Priority: MEDIUM — cloud storage misconfiguration is a common external finding.
- Category: SS
- Stack: Universal
- What: Alpha does not discover cloud storage assets associated with the target domain. Real external red teams check: S3 buckets named after the target (`niagamas-backups`, `niagamas-assets`), GCP storage buckets, Azure blob containers, DigitalOcean Spaces. These are often misconfigured (public read, public write) and contain sensitive data (backups, database dumps, customer PII). The check is passive (DNS + bucket name guessing + HTTP HEAD), zero target infrastructure touch.
- Evidence: No cloud storage discovery in any recon module. `recon/passive_intel.py` — no cloud asset discovery. `recon/osint_sources.py` — no S3/GCP/Azure enumeration. `strategic_gaps_roadmap.md` — not mentioned.
- Files: `agent_alpha/recon/passive_intel.py` — no cloud asset enrichment; `agent_alpha/recon/osint_sources.py` — no cloud storage source; `agent_alpha/graph/nodes.py` — no CLOUD_ASSET node type
- Cross-ref: GAP-007 (OSINT), GAP-069 (Trust Graph — cloud assets are shadow IT nodes). §12.48 (Passive-First Recon — cloud storage discovery is passive).
- Impact: Missed data exposure finding. S3 bucket with public read = direct data harvest without any access attempt. This is a finding a client would pay for that Agent-Alpha currently cannot discover.
- Effort: MEDIUM (bucket name generation from domain + HTTP HEAD check + public-read verification. Must be scoped — only check buckets derived from in-scope domain, not brute-force mass enumeration. Legal: checking bucket ACL is not an attack, it's a configuration audit).
- Constraint: Only check buckets derived from in-scope domain stems (`niagamas-*`, `*-niagamas`). No mass brute-force. Bucket existence check = HTTP HEAD, not data download. Public-read confirmation = 1 request, not data exfiltration.

---


# Beta Access Strategy (NEW)

## GAP-077 — Authentication bypass testing (SQLi/NoSQLi/LDAPi in login)
- Status: OPEN.
- Priority: HIGH — Beta only tries cred-reuse + default-creds; no injection-based auth bypass.
- Category: SS
- Stack: Universal
- What: Beta's access tools are: `OdooAccessTool` (XML-RPC cred-stuff), `DefaultCredsTool` (form POST cred-stuff), `cred_reuse.py` (form POST cred-reuse), `UserDerivedCredsTool` (derived cred-spray). ALL are credential-based. A real external red team also tests **authentication bypass**: SQL injection in login form (`admin'--`, `' OR 1=1--`), NoSQL injection (`{"$ne": null}`), LDAP injection (`*)(uid=*`), parameter pollution (`user=admin&user=guest`), HTTP verb tampering (GET instead of POST), URL path normalization (`/admin/login/../dashboard`), auth bypass via race condition. These are **not credential attacks** — they bypass the auth mechanism entirely. Agent-Alpha has ZERO capability for this.
- Evidence: `tools/internal/access/` — all tools are cred-based. No injection payload generator. No auth bypass tool. `strategic_gaps_roadmap.md` G10 — "High-value vuln classes absent: IDOR, business logic, SSRF, injection, auth-flow, API fuzzing" — but no GAP entry for auth bypass specifically.
- Files: `agent_alpha/tools/internal/access/` — all tools cred-based; `agent_alpha/agents/beta/strike.py` — no auth bypass dispatch; `agent_alpha/tools/playbooks/` — no auth bypass playbook
- Cross-ref: GAP-074 (auth mechanism fingerprinting — prerequisite: must know mechanism to craft bypass), strategic roadmap G10 (injection absent). ADR §12.55 (1-Day Weaponizer — auth bypass via known CVE is in scope; novel injection is Gamma-gated).
- Impact: Auth bypass is a primary external red team technique. If a login form is SQLi-vulnerable, cred-reuse is unnecessary — bypass gives direct access. Agent-Alpha cannot find this. Misses high-severity findings that conventional scanners (SQLMap) DO find.
- Effort: MEDIUM (new AuthBypassTool: SQLi/NoSQLi/LDAPi payload set + form/JSON-RPC transport + response differential detection. Must be gated by auth mechanism fingerprint from GAP-074. Payloads = known 1-day patterns, NOT novel injection — §12.55).
- Constraint: 1-day payloads only (known SQLi patterns from public cheat sheets). No novel injection research. No data exfiltration via injection — proof = auth bypass response (redirect to dashboard, session cookie set). Gamma-gated for deeper injection exploitation.

---

## GAP-078 — User enumeration via auth response differential
- Status: OPEN.
- Priority: MEDIUM — login error messages leak valid vs invalid usernames; not captured.
- Category: RM
- Stack: Universal
- What: Many login forms reveal whether a username exists via **response differential**: valid username + wrong password → "Invalid password" (or different response time, different redirect, different error code). Invalid username → "User not found". This is a classic username enumeration vector. Alpha does not capture this, and Beta does not exploit it. Beta's cred-reuse tries all harvested usernames blindly — but if the target reveals which usernames are valid, Beta can **filter** the username list to only valid accounts before attempting passwords, reducing attempts by 90%+ and avoiding lockout.
- Evidence: `agents/alpha/scout.py` — no auth response differential probe. `tools/internal/access/cred_reuse.py` — tries all usernames × all passwords, no pre-filtering. `tools/internal/access/cred_lockout.py` — lockout governor exists but doesn't benefit from username pre-filtering.
- Files: `agent_alpha/agents/alpha/scout.py` — no auth differential handler; `agent_alpha/tools/internal/access/cred_reuse.py` — no username pre-filter; `agent_alpha/graph/nodes.py:110-119` — UserProperties (no `validated_on_target` field)
- Cross-ref: GAP-054 (WP REST user fields — email/roles needed for breach correlation, but username validation is separate), GAP-047 (username harvest WP-REST-only — this GAP extends harvesting to auth-response differential), GAP-070 (credential correlation — validated usernames feed the credential map).
- Impact: Beta wastes attempts on invalid usernames. On a target with 9 harvested usernames where only 3 are valid, Beta tries 9×N passwords instead of 3×N. 6×N wasted attempts = lockout risk + WAF trigger + time waste.
- Effort: LOW (2 probe requests: valid-looking username + invalid-looking username → compare response. 1 handler + UserProperties field update. Must be stealthy — 2 requests only, long delay).

---

## GAP-079 — Post-access validation (agentless — access level proof without implant)
- Status: OPEN.
- Priority: HIGH — Beta reports "login OK" but doesn't prove what access level was achieved.
- Category: RG
- Stack: Beta
- What: When Beta successfully authenticates (cred-reuse, default-cred, or auth bypass), it reports `status=COMPLETE` with a `CREDENTIAL` node and proof artifact (screenshot). But it does NOT validate **what access level was achieved**: Can I access the admin dashboard? Can I see other users' data? Can I modify settings? Can I create/delete content? Is the session read-only or full-admin? This is the boundary between Beta (access) and Gamma (exploitation), but the **validation step** is missing — Beta claims access but doesn't prove the access is meaningful. A real red team validates: "I logged in as admin → I can see /wp-admin/admin.php → I can create a new admin user → proof." Agent-Alpha stops at "I logged in."
- Evidence: `agents/beta/strike.py` — on successful auth, reports COMPLETE with screenshot. No post-access probe. No access-level validation. `graph/nodes.py:102-107` — AccessLevelProperties exists (`level`, `user_context`, `shell_type`, `interactive`) but is never populated by Beta. `conductor/main.py` — no post-Beta validation step before Gamma dispatch.
- Files: `agent_alpha/agents/beta/strike.py` — no post-access validation; `agent_alpha/graph/nodes.py:102-107` — AccessLevelProperties (never populated); `agent_alpha/conductor/main.py` — no validation between Beta and Gamma
- Cross-ref: ADR §12.32 (Authenticated Crawl / Post-Access Re-Discovery — LOCKED, but this GAP is about validation, not re-crawl). GAP-080 (session management — related post-access analysis). §12.43 (screenshot proof — current proof, but screenshot of login ≠ proof of access level).
- Impact: Client receives "login successful" but no proof of what the attacker can DO with that access. Report is weak. "I logged in as admin" is not a payable finding — "I logged in as admin and could create a new admin user" is. This is the difference between a scanner report and a red team report.
- Effort: MEDIUM (post-access probe: 3-5 authenticated requests to known admin endpoints + response analysis + AccessLevelProperties population. Agentless — HTTP requests only, no code execution on target. Must stay within Beta scope — no data modification, no exploitation. Proof = screenshot of admin dashboard + AccessLevel node).

---

## GAP-080 — Session management analysis (post-login stability for Gamma handoff)
- Status: OPEN.
- Priority: MEDIUM — after login, session stability is not analyzed; Gamma may inherit an unstable session.
- Category: RM
- Stack: Beta
- What: After Beta achieves authenticated access, it does not analyze the **session management characteristics** that determine whether the access is stable enough for Gamma to use: Session cookie attributes (HttpOnly, Secure, SameSite — GAP-059 is pre-auth, this is post-auth), session fixation potential (can I set the session ID before login?), session timeout (how long until the session expires?), concurrent session policy (does a second login invalidate the first?), session token format (sequential? predictable? JWT with weak secret?). A real red team analyzes these before deciding whether to escalate to Gamma — an unstable session (5-minute timeout, single-session) makes Gamma exploitation impractical.
- Evidence: `agents/beta/strike.py` — no post-auth session analysis. `graph/nodes.py` — no session management fields in AccessLevelProperties or CredentialProperties. GAP-059 (cookie audit) is pre-auth from response headers; this GAP is post-auth session behavior analysis.
- Files: `agent_alpha/agents/beta/strike.py` — no session analysis; `agent_alpha/graph/nodes.py:78-107` — CredentialProperties + AccessLevelProperties (no session fields)
- Cross-ref: GAP-059 (cookie audit — pre-auth, this is post-auth), GAP-079 (post-access validation — related, but access-level vs session-stability), ADR §12.32 (authenticated crawl — needs stable session).
- Impact: Gamma may be dispatched on a session that expires in 5 minutes, or that is invalidated by a second request. Gamma's exploitation fails not because the exploit is wrong, but because the session died mid-exploit. No diagnostic data to explain the failure.
- Effort: LOW (parse post-auth Set-Cookie headers + 1-2 timed re-requests to measure timeout + session token format analysis. ~50 lines. Agentless — HTTP only).

---

