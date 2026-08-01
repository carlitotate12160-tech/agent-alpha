# Engagement Report: quantum-laboratories.com

| Field | Value |
|-------|-------|
| **Engagement ID** | `eng_ba9f0d8b` |
| **Target** | `quantum-laboratories.com` |
| **Client ID** | `quantum` |
| **Authorization** | RECON_ONLY (signed profile, evasion consent) |
| **Origin IPs** | `104.21.31.151`, `172.67.177.206` (Cloudflare) |
| **Browser Solve** | Viable (endpoint `http://127.0.0.1:8080/solve`) |
| **Origin Direct** | Wired (`104.21.31.151`, `172.67.177.206`) |
| **Duration (Alpha)** | 181.5s |
| **Duration (Beta)** | 7.9s |
| **Total Duration** | ~189.4s |
| **Graph Nodes** | 3 |
| **Findings** | 2 vulnerabilities |
| **Beta Result** | FAILED (0 proofs — no credentials to spray) |
| **Date** | 2026-07-31 |

---

## PRs Verified in This Engagement

| PR | Title | Change | Verified |
|----|-------|--------|----------|
| **#297** | Odoo DB manager CVSS + proof | `odoo_dbmanager_exposed` now mints CVSS 7.5 (was 0.0) with reproducible proof artifact | ✅ CVSS 7.5 + proof artifact present in event store |
| **#298** | Organic crawl budget | `MAX_ORGANIC_CRAWL_PER_HOST=25` caps organic hrefs per host; catalog seeds bypass | ✅ ~16 organic hrefs crawled (under cap), catalog seeds unfiltered |

---

## Findings

### 1. Odoo DB Manager Exposed — HIGH (CVSS 7.5)

| Field | Value |
|-------|-------|
| **Node ID** | `vuln:quantum-laboratories.com:odoo_dbmanager_exposed` |
| **CVSS** | 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **Confidence** | 0.85 |
| **Exploit Available** | False (honest — master-password-gated, unproven at RECON tier) |
| **Proof Artifact** | Yes — `http_response` type |

**Evidence:**

```
Odoo /web/database/manager EXPOSED (HTTP 200) at
https://quantum-laboratories.com/web/database/manager;
live management actions present:
['/web/database/create', '/web/database/duplicate',
 '/web/database/backup', '/web/database/restore',
 '/web/database/drop', 'master password'].
Create/backup/drop is master-password-gated and UNPROVEN at RECON tier.
```

**Artifact IDs:**
- `b6ea3369-b71d-4d67-b836-26832871b513` (first probe)
- `4aa31a12-cf9b-45cb-85f6-204b7ffa62cb` (second probe via odoo fingerprint)

**CVSS Justification:** I/A stay N because create/backup/drop is master-password-gated and unproven at RECON tier. Escalates to CRITICAL only once the master_pwd oracle proves it (Improvement 2, future OFFENSIVE slice).

---

### 2. Odoo Version Disclosure — LOW (CVSS 3.1)

| Field | Value |
|-------|-------|
| **Node ID** | `vuln:quantum-laboratories.com:odoo_version_disclosure` |
| **CVSS** | 3.1 |
| **Confidence** | 0.80 |
| **Exploit Available** | False |
| **Affected Service** | `Odoo 12.0-20221012` |
| **Proof Artifact** | None (version disclosure = informational) |

**Source:** Parsed from live JSON-RPC response via `POST /web/webclient/version_info` → `payload.result.server_version = "12.0-20221012"`. Not hardcoded — value comes from the target server's response.

---

## Graph Structure

```
asset:quantum-laboratories.com (confidence=0.50, tech_stack=[odoo, cloudflare])
  │
  ├──exploits──► vuln:quantum-laboratories.com:odoo_dbmanager_exposed (CVSS 7.5, confidence=0.85)
  │
  └──exploits──► vuln:quantum-laboratories.com:odoo_version_disclosure (CVSS 3.1, confidence=0.80)
```

**Attack chains:** None found. Both findings are RECON-tier exposure detections, not exploit chains. Beta (STRIKE) attempted credential spray but found 0 credentials to spray → FAILED (expected).

---

## Crawl Budget Analysis (PR #298)

| Metric | Value |
|--------|-------|
| **Organic hrefs crawled** | ~16 (visi-misi, total-quality, ethicals, generic, otc, medical-device, business, manufacturing, jobs, article, contactus, web/login, web?db=erp, allergy-and-immune-system-generic, medical-devices-generic, intravenous-and-other-sterile-solutions-generic) |
| **Budget cap** | 25 (`MAX_ORGANIC_CRAWL_PER_HOST`) |
| **Hrefs rejected by budget** | 0 (host has fewer than 25 organic links) |
| **Catalog seeds probed** | All (`.git/config`, `.env.bak`, `.env~`, `.env.old`, `.env.orig`, `.env.save`, `config/database.yml.bak`, `wp-config.txt`, `actuator/env`, `env`, `openapi.json`, `swagger.json`, `v2/api-docs`, `api-docs`, `graphql`, `graphiql`) — unfiltered, bypass budget |
| **CDN paths** | Excluded (`/cdn-cgi/*` filtered by `CDN_INFRA_EXCLUDE_PREFIXES`) |

**Conclusion:** Crawl budget is active but not binding for this host. For hosts with >25 organic links (e.g., unibis.co.id with 30+ product pages), the budget will cap at 25.

---

## Comparison: Before vs After PR #297 + #298

| Metric | Before (eng_487559df) | After (eng_ba9f0d8b) |
|--------|------------------------|----------------------|
| **Duration** | 90s | 181.5s |
| **Nodes** | 2 | 3 |
| **Findings** | 0 (DB manager detected as ASSET only) | 2 (DB manager CVSS 7.5 + version disclosure CVSS 3.1) |
| **DB Manager CVSS** | 0.0 (buried as trivial) | 7.5 (rated HIGH) |
| **Proof Artifacts** | 0 | 2 (reproducible evidence strings) |
| **Crawl Budget** | Not implemented (unbounded) | Active (cap=25, not binding for this host) |

---

## Event Log Summary (22 events)

| # | Event Type | Key Data |
|---|-----------|----------|
| 1 | EngagementCreated | target=quantum-laboratories.com, state=0 |
| 2 | EngagementAuthorized | RECON_ONLY, evasion consent, signed |
| 3 | StateTransitioned | 0→1 (RECON_ONLY enabled) |
| 4 | PassiveDiscovery | in_scope=[quantum-laboratories.com] |
| 5-6 | NodeDiscovered | asset:quantum-laboratories.com (odoo, confidence=0.9) |
| 7 | NodeDiscovered | vuln:odoo_version_disclosure (CVSS 3.1, Odoo 12.0-20221012) |
| 8 | EdgeDiscovered | asset→vuln:odoo_version_disclosure (exploits) |
| 9-10 | NodeDiscovered | asset + vuln:odoo_dbmanager_exposed (CVSS 7.5, proof artifact) |
| 11 | EdgeDiscovered | asset→vuln:odoo_dbmanager_exposed (exploits) |
| 12-18 | NodeDiscovered | asset re-merges (odoo fingerprint, cloudflare detected, organic crawl) |
| 19-20 | NodeDiscovered | vuln:odoo_version_disclosure + edge (re-probed via fingerprint) |
| 21-22 | NodeDiscovered | vuln:odoo_dbmanager_exposed (CVSS 7.5, second proof artifact) + edge |
| 23 | StateTransitioned | 1→2 (ACTIVE_APPROVED for Beta) |

---

## Beta (STRIKE) Result

Beta attempted credential spray after Alpha found 2 findings. Result: **FAILED, 0 proofs**. This is expected — both findings are exposure disclosures (no credentials harvested), so there are no creds to spray. Beta correctly attempted and honestly reported failure.

---

## Recommendations

1. **Restrict `/web/database/manager`** — disable or require authentication at the reverse proxy level.
2. **Set `list_db = False`** in Odoo configuration to prevent database enumeration.
3. **Upgrade Odoo** — version 12.0-20221012 is end-of-life and has known security issues.
4. **Re-test** after remediation to confirm the DB manager is no longer exposed.
