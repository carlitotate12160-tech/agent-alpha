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

## GAP → ADR Classification (2026-07-15)

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

> ToolComposer (review GAP 8) sengaja tidak dimasukkan — akan di-build nantinya sebagai bagian dari Gamma phase.
> GAP 7 (4 agents missing: Gamma/Delta/Epsilon) sengaja tidak dimasukkan — sedang dalam proses.
> Item berikut sudah di ADR sebagai future phase, BUKAN GAP (belum dibangun, bukan kelewat dibangun):
> - Structured decision explanation (ADR §8j-2, Phase 2) — monologue sudah ada, structured reasoning trace = future enhancement
> - Team coordination / blackboard (ADR §8o-5, Phase 5) — parallel agent coordination, scheduled for Delta/Epsilon phase
> - HVT / objective-based engagement (ADR §8i, Phase 6) — crown-jewel targeting, belum dibangun
> - SPA / Camoufox rendering (ADR §12.16.1) — shared capability untuk Alpha+Beta, belum dibangun
> - Hypothesis→verify loop (ADR §8j-2 + §12.16.3) — prerequisite untuk external RAG, belum dibangun
> - Engagement teardown/restore (ADR §12.22 Decision 3) — cleanup tool, build setelah IntelligenceBase
