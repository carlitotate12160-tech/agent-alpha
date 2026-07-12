# Agent-Alpha — Operational Reference (Kill Chain Detail)

> **Routing notice (K21).** This document contains TARGET tool references and
> capability descriptions for future implementation. When payload-level offensive
> detail is added (by DeepSeek), that section becomes **DeepSeek-facing**, NOT
> Claude-facing. The capability-level summary for architecture discussion lives
> in `KNOWLEDGE.md` §K1.

> **Legal & Authorization Notice.** Agent-Alpha is an authorized commercial
> red-team platform. Every engagement requires a signed SOW + written
> authorization, verified by a non-bypassable authorization gate (Conductor)
> before any offensive action. Testing is performed ONLY against client-owned
> systems with explicit consent. Template names denote system categories, not
> specific organizations.

**Version:** 3.0 (updated 2026-07-12 — reconciled with actual codebase state through PR #147)

> **NOTE:** Alpha (SCOUT), Beta (STRIKE), and Omega (ROASTER) are IMPLEMENTED.
> Layer V (passive discovery + Odoo chain) is SEALED. git_exposure slice-1c-i (GitDumper WRAP) SEALED.
> Gamma (ANCHOR), Delta (HUNTER), and Epsilon (SCOUT-HUNTER) are NOT YET IMPLEMENTED.
> Tools marked [TARGET] are placeholders for future implementation.
>
> **Phase mapping:** Each agent section below is cross-referenced to the
> corresponding phase in `ADR.md` §9. The wrap-vs-build decision for
> each tool is governed by `ADR.md` §12.22 Decision 1.

---

## O1. Kill Chain Reference (Agent → Technique → Tool)

### Alpha (SCOUT) — Techniques & Tools ✅ IMPLEMENTED  `→ ADR.md Phase 2 + Phase 4`
```
Subdomain Enumeration: [IMPLEMENTED] Passive crt.sh discovery (passive_discovery.py)
                       — Layer V-A/V-B SEALED; injectable crtsh_url_template seam
                       — autonomous discovery: root seed → crt.sh → 7+ siblings → vuln.<apex>
                       [TARGET] subfinder, dnsenum, DNS brute (WRAP, not yet built)
Port Scanning:         [NOT IMPLEMENTED] nmap (top 30 ports, stealth SYN scan) — WRAP
Tech Detection:        [IMPLEMENTED] Laravel debug exposure template (laravel_finding.py)
                       [IMPLEMENTED] Odoo DB manager exposure (odoo_dbmanager_probe.py)
                       [IMPLEMENTED] WP config exposure (wp_config_probe.py)
                       [IMPLEMENTED] git_exposure (git_exposure_probe.py + GitDumper WRAP)
                       [TARGET] whatweb, wafw00f — WRAP
Directory Enum:        [NOT IMPLEMENTED] feroxbuster, ffuf — WRAP
Reverse IP Lookup:     [NOT IMPLEMENTED] hackertarget, rapiddns.io — WRAP
HTTP Operations:       [IMPLEMENTED] HttpClient (httpx-backed)
JS Intelligence:       [IMPLEMENTED] JS bundle secret extraction (js_secret_probe.py)
                       — graph-aware secret extraction (BUILD, not WRAP)
DB Service Detection:  [IMPLEMENTED] MySQL/MariaDB handshake probe (db_service_probe.py)
                       — TCP greeting parse, proof-of-service (anti-#3)
Credential Harvest:    [IMPLEMENTED] Laravel env leak parsing + credential assembly
                       (iter_env_leaks → assemble_leaked_credentials → SecretsManager vault)
                       [IMPLEMENTED] git_exposure → GitDumper → tracked file recovery
                       [IMPLEMENTED] WP config leak → credential harvest
                       [IMPLEMENTED] JS secret extraction → vault
Response Classification: [IMPLEMENTED] Verdict enum (response_classifier.py)
                       — OK / WAF_BLOCKED / NOT_FOUND / ERROR (kills false-negatives)
Current Output:        {laravel_debug_findings, leaked_credentials, asset_nodes,
                        subdomains, odoo_findings, wp_findings, git_exposure_findings,
                        js_secrets, db_services}
Target Output:         {hosts, ports, services, tech_stack, js_secrets, api_endpoints}
```

### Beta (STRIKE) — Techniques & Tools ✅ IMPLEMENTED  `→ ADR.md Phase 3`
```
Credential Reuse:      [IMPLEMENTED] CredReuseTool (vaulted credential reuse via CredentialApplicator)
Default Credentials:   [IMPLEMENTED] DefaultCredsTool (generic + 6 platforms: WordPress, Tomcat,
                       Jenkins, phpMyAdmin, Grafana, Joomla)
Credential Applicator: [IMPLEMENTED] CredentialApplicator seam
                       - HttpFormApplicator (HTTP form login)
                       - MySqlApplicator (MySQL protocol auth, safety-guarded)
                       - OdooAccessTool (Odoo DB manager auth + enumeration)
                       - select_applicator() for service-agnostic dispatch
Browser Automation:    [NOT IMPLEMENTED] Playwright + stealth patches — WRAP
Proxy Infrastructure:  [NOT IMPLEMENTED] BrightData Web Unlocker + Residential proxies — WRAP
CAPTCHA Bypass:        [NOT IMPLEMENTED] 2Captcha integration — WRAP
Protocol Spray:        [NOT IMPLEMENTED] SSH spray, FTP spray, IMAP spray — WRAP
Current Output:        {valid_credentials, session_tokens, access_level, entry_point}
```

### Gamma (ANCHOR) — Techniques & Tools ⬜ NOT IMPLEMENTED  `→ ADR.md Phase 4`
```
ToolComposer:          [TARGET] compose(base_template, ctx) — BUILD INTERNAL (§12.22)
                       — plan-not-execute; Template.verify() mandatory
Blast-Radius Gate:     [TARGET] Scope/blast-radius governor — BUILD INTERNAL (§12.22 Decision 3)
                       — pre-execution SOW check; co-host/out-of-scope DENIED
SQLi:                  [TARGET] Automated SQLi detection + exploitation — WRAP: sqlmap
File Upload Bypass:    [TARGET] Double extension, MIME type, path traversal bypass
RCE Chains:            [TARGET] SQLi-to-RCE, LFI-to-RCE chains
CMS Exploitation:      [TARGET] Per-CMS exploit templates
CVE Exploitation:      [TARGET] CVE matching + exploit execution
Webshell Deploy:       [TARGET] Webshell deployment + persistence
Target Output:         {shell_access, webshell_path, server_context, writable_paths}
```

> **STOP-GATE:** Gamma is STOP-gated until ToolComposer + blast-radius gate are built.
> Gate = Claude lane; destructive bodies = DeepSeek lane (ADR §12.22).

### Delta (HUNTER) — Techniques & Tools ⬜ NOT IMPLEMENTED  `→ ADR.md Phase 5`
```
Shell:                 [TARGET] Interactive encrypted PTY shell — WRAP: GSocket
Persistence:           [TARGET] Deployment + persistence modules
                       — requires explicit SOW clause + guaranteed teardown (§12.22 Decision 2)
Credential Harvest:    [TARGET] Config file harvesting + cross-host credential reuse
Data Exfiltration:     [TARGET] Database dumping — proof-of-access, not bulk theft
                       — minimize + redact + encrypt (§12.22 Decision 2)
Cleanup Awareness:     [TARGET] Pre-persistence cleanup scanner
Teardown/Restore:      [TARGET] Engagement teardown/restore tool — BUILD INTERNAL (§12.22 Decision 3)
Manual Enum:           [TARGET] Filesystem enumeration
Hash Cracking:         [TARGET] unshadow + john — WRAP
Target Output:         {harvested_creds, db_access, internal_network_map}
```

### Epsilon (SCOUT-HUNTER) — Techniques & Tools ⬜ NOT IMPLEMENTED  `→ ADR.md Phase 5`
```
Access:                [TARGET] PTY shell from compromised host
Internal Scanning:     [TARGET] Internal network scanning (172.16.x.x, 192.168.x.x, 10.x.x.x)
Co-host Pivot:         [TARGET] Pivot to co-hosted domains
                       — default-DENY gate (§12.22 Decision 2); per-target scope check
                       — cohost_pivot assert_pivot_target SEALED (A7-c, Phase 3 exit)
Shared Hosting:        [TARGET] Shared hosting symlink pivot — default-DENY (§12.22)
Network Tools:         [TARGET] ssh, nmap from compromised host
Tunneling:             [TARGET] VPN/VPS tunneling
AD Techniques:         [TARGET] Kerberoasting, AS-REP Roasting
Target Output:         {compromised_hosts, pivoted_networks, additional_findings}
```

### Omega (ROASTER) — Output ✅ IMPLEMENTED  `→ ADR.md Phase 2 + Phase 6`
```
Database:              [TARGET] SQLite findings storage
Evidence:              [TARGET] Evidence collection module
Report Build:          [IMPLEMENTED] Omega.generate_report() + Report.export_pdf() (reportlab)
Verification:          [TARGET] Text verification module
Proof Artifacts:       [IMPLEMENTED] EventStore PROOF_ARTIFACT_RECORDED events (redacted)
Formats:               [IMPLEMENTED] PDF (executive + technical)
                       [TARGET] JSON, SARIF, MD
Standards:             [IMPLEMENTED] MITRE ATT&CK mapping
                       [TARGET] PCI/NIS2 compliance mapping
Time-to-Proof:         [IMPLEMENTED] format_duration() + time_to_proof_headline() in PDF
Chain Finding:         [IMPLEMENTED] summarize_chain_finding() from GraphStore
```

### Conductor — Auth Gate + Observability ✅ IMPLEMENTED  `→ ADR.md Phase 3 exit`
```
Auth Gate:             [IMPLEMENTED] SOW → RECON_ONLY → ACTIVE → OFFENSIVE_APPROVED
                       — non-bypassable authorization gate (Conductor)
Run Trace:             [IMPLEMENTED] A7-a run-trace projection + GET /trace endpoint
Queue Health:          [IMPLEMENTED] A7-c queue-health probe + GET /health/queue
Cohost Pivot Gate:     [IMPLEMENTED] assert_pivot_target default-DENY (A7-c SEALED)
                       — co-host target MUST pass per-target scope check
```

### Chain Runners — Live-Fire Proofs ✅ IMPLEMENTED
```
Alpha→Beta Chain:      [IMPLEMENTED] chain_runner.py — Laravel debug leak → cred_reuse
                       CHAIN PROVEN: True, db_root, critical vs real MySQL 8.4 on Oracle ARM64
DB Chain:              [IMPLEMENTED] db_chain_runner.py — direct-DB (db_root) payable chain
                       — cred-reuse (HIGH) field-proven
WP Chain:              [IMPLEMENTED] wp_chain_runner.py — WordPress config leak → cred_reuse
                       — WP + JS-secret recon vectors field-proven
Odoo Chain:            [IMPLEMENTED] odoo_chain_runner.py — Layer V-B live
                       — root seed → crt.sh → 7+ siblings → vuln.<apex> → odoo_dbmanager
                       — CHAIN PROVEN: True (leak_creds=2, access=admin, db_enumerated=True)
Layer V Runner:        [IMPLEMENTED] layer_v_runner.py — passive discovery + autonomous chaining
SPA Secret Prove:      [IMPLEMENTED] spa_secret_field_prove.py — SPA secret field field-prove
Lab Guard:             [IMPLEMENTED] lab_guard.py — self-owned target allowlisting
Mock Target:           [IMPLEMENTED] mock_laravel_debug.py — HTTP server mock
```

---

## Implementation Status Summary

| Agent | Status | Notes |
|-------|--------|-------|
| **Alpha (SCOUT)** | ✅ IMPLEMENTED | Laravel, Odoo, WP, git_exposure, JS secret, DB service, crt.sh discovery |
| **Beta (STRIKE)** | ✅ IMPLEMENTED | CredReuseTool, DefaultCredsTool, OdooAccessTool, CredentialApplicator seam |
| **Gamma (ANCHOR)** | ⬜ NOT IMPLEMENTED | STOP-gated: ToolComposer + blast-radius gate FIRST |
| **Delta (HUNTER)** | ⬜ NOT IMPLEMENTED | Placeholder only |
| **Epsilon (SCOUT-HUNTER)** | ⬜ NOT IMPLEMENTED | cohost_pivot default-DENY gate SEALED (A7-c) |
| **Omega (ROASTER)** | ✅ IMPLEMENTED | Report generation, PDF export, time-to-proof headline |
| **Conductor** | ✅ IMPLEMENTED | Auth gate, run-trace (A7-a), queue-health (A7-c), cohost pivot gate |

| Tool Category | Status | Notes |
|---------------|--------|-------|
| **Recon Tools** | ✅ MOSTLY COMPLETE | Laravel, Odoo, WP, git_exposure, JS secret, DB service, crt.sh; nmap/feroxbuster/whatweb still TARGET |
| **Access Tools** | ✅ IMPLEMENTED | CredReuseTool, DefaultCredsTool, OdooAccessTool, CredentialApplicator seam |
| **Exploit Tools** | ⬜ NOT IMPLEMENTED | STOP-gated: ToolComposer + blast-radius gate FIRST |
| **Post-Exploit Tools** | ⬜ NOT IMPLEMENTED | GSocket, config_harvest, db_dump not implemented |
| **Lateral Movement** | 🟡 PARTIAL | cohost_pivot default-DENY gate SEALED; internal_scan not implemented |
| **Reporting** | ✅ IMPLEMENTED | PDF export, MITRE mapping, time-to-proof headline |
| **Tool Infrastructure** | ✅ IMPLEMENTED | ToolRegistry + contracts.py (Tool Protocol, ToolResult, TargetContext) |

---

## Currently Implemented Components

### Alpha (SCOUT) - agent_alpha/agents/alpha/scout.py
- Cognitive loop with BoundedAutonomy
- Laravel debug exposure template (laravel_finding.py)
- HttpClient for HTTP operations
- Credential assembly from leaked env vars
- EngagementMemory projection (time_to_first_proof_s, time_to_first_exploit_s)
- Passive crt.sh subdomain discovery (passive_discovery.py) — Layer V SEALED
- git_exposure probe (git_exposure_probe.py) — GitDumper WRAP (slice-1c-i, PR #147)
- Odoo DB manager exposure probe (odoo_dbmanager_probe.py)
- WP config leak probe (wp_config_probe.py)
- JS bundle secret extraction (js_secret_probe.py)
- DB service handshake probe (db_service_probe.py)
- Response classifier (response_classifier.py) — Verdict enum (OK/WAF_BLOCKED/NOT_FOUND/ERROR)

### Beta (STRIKE) - agent_alpha/agents/beta/strike.py
- Cognitive loop with BoundedAutonomy
- CredReuseTool (vaulted credential reuse via CredentialApplicator)
- DefaultCredsTool (generic + 6 platforms)
- OdooAccessTool (Odoo DB manager auth + enumeration)
- Ranked tool selection via ToolRegistry.applies_to()
- Deep redaction of proof artifacts
- False-success guard (anti-Lyndon #3)

### Omega (ROASTER) - agent_alpha/agents/omega/roaster.py
- Report generation with narrative, MITRE techniques
- PDF export via reportlab
- Time-to-proof headline (format_duration formatter)
- Chain finding summarization

### Conductor - agent_alpha/conductor/
- Auth gate: SOW → RECON_ONLY → ACTIVE → OFFENSIVE_APPROVED (non-bypassable)
- A7-a: run-trace projection + GET /trace endpoint
- A7-c: queue-health probe + GET /health/queue
- cohost_pivot default-DENY gate (assert_pivot_target) — A7-c SEALED

### Tools - agent_alpha/tools/
- **contracts.py** - Tool protocol (Template, Tool, TargetContext, ResourceBudget, ToolResult)
- **registry.py** - ToolRegistry: ranked selection via applies_to(), replaces old #99 if-ladder (K11)
- **templates/cms/laravel_finding.py** - Laravel debug exposure template
- **internal/access/cred_reuse.py** - Vaulted credential reuse tool
- **internal/access/default_creds.py** - Default credentials check tool (generic + 6 platforms)
- **internal/access/applicator.py** - CredentialApplicator seam
  - HttpFormApplicator (HTTP form login: POST username+password, session cookie verification)
  - MySqlApplicator (MySQL protocol auth, safety-guarded: refuse empty-username)
  - select_applicator() for service-agnostic dispatch
- **internal/access/odoo_access.py** - Odoo DB manager auth + enumeration tool
- **playbooks/** - YAML rule files: laravel_debug, git_exposure, js_secret, odoo_dbmanager, wp_config, default_credentials_login

### Recon Probes - agent_alpha/recon/
- **git_exposure_probe.py** - .git exposure detection + GitDumper WRAP (commodity git-dumper)
- **odoo_dbmanager_probe.py** - Odoo DB manager exposure detection
- **wp_config_probe.py** - WordPress config file leak detection
- **js_secret_probe.py** - JS bundle secret extraction (graph-aware, BUILD not WRAP)
- **db_service_probe.py** - MySQL/MariaDB TCP handshake probe (proof-of-service)
- **passive_discovery.py** - crt.sh subdomain discovery (Layer V, injectable CT source)
- **response_classifier.py** - Verdict enum (OK/WAF_BLOCKED/NOT_FOUND/ERROR)

### Chain Runners - agent_alpha/live_fire/
- **chain_runner.py** - Alpha→Beta chain (Laravel debug → cred_reuse) — CHAIN PROVEN
- **db_chain_runner.py** - Direct-DB (db_root) payable chain — field-proven
- **wp_chain_runner.py** - WordPress config leak → cred_reuse chain — field-proven
- **odoo_chain_runner.py** - Layer V-B Odoo chain — CHAIN PROVEN (leak_creds=2, access=admin)
- **layer_v_runner.py** - Passive discovery + autonomous chaining runner
- **spa_secret_field_prove.py** - SPA secret field field-prove
- **lab_guard.py** - Self-owned target allowlisting
- **mock_laravel_debug.py** - Mock HTTP server for field-prove

---

## Future Implementation Targets

> **Cross-reference:** Phase numbers below match `ADR.md` §9.
> Wrap-vs-build decisions per `ADR.md` §12.22 Decision 1.

### Priority 1 (Phase 4 — Alpha Recon Breadth remaining + git_exposure field-prove)
- git_exposure slice-1c-ii: install git-dumper on Oracle ARM64 + field-prove on self-owned lab
- backup_file probe (same pattern as git_exposure, append to WELL_KNOWN_LEAK_PATHS)
- Port scanning (WRAP: nmap top-30)
- Directory enumeration (WRAP: feroxbuster/ffuf)
- Reverse IP lookup (WRAP: hackertarget, rapiddns.io)
- Tech detection (WRAP: whatweb, wafw00f)
- Subdomain enum expansion (WRAP: subfinder, dnsenum, DNS brute) — crt.sh already built

### Priority 2 (Phase 3 Completion — Beta Expansion)
- Browser automation (WRAP: Playwright + stealth)
- Proxy infrastructure (WRAP: BrightData Web Unlocker)
- CAPTCHA bypass (WRAP: 2Captcha)
- Protocol spray (WRAP: SSH, FTP, IMAP)

### Priority 3 (Phase 4 — Gamma/ANCHOR) ⬜ STOP-GATED
- ToolComposer.compose(base_template, context) — BUILD INTERNAL (§12.22)
- Scope/blast-radius governor — BUILD INTERNAL (§12.22 Decision 3)
- SQLi (WRAP: sqlmap), file upload bypass, RCE chains
- CMS exploit templates, CVE matching + exploit execution
- Webshell deploy + persistence
- TransportResilience capability — WAF/CF-block discriminator (§12.22 Decision 3)

### Priority 4 (Phase 5 — Delta + Epsilon)
- Delta (HUNTER): GSocket shell (WRAP), persistence, credential harvest
- Epsilon (SCOUT-HUNTER): Internal scanning, lateral movement
- Pivot-chain state tracking in AttackGraph — BUILD INTERNAL
- OS-as-tools / LOLBin catalog — BUILD INTERNAL
- Co-host pivot / symlink — default-DENY (§12.22 Decision 2) — gate already SEALED
- Engagement teardown/restore tool — BUILD INTERNAL (§12.22 Decision 3)

### Priority 5 (Phase 6 — IntelligenceBase + Hardening)
- pgvector embeddings
- Similar target queries
- Advanced strategy inference
- Cross-engagement learning + circuit-breaker tool reliability
- VERIFY/re-test mode, continuous/scheduled engagement
- Additional engagement profiles (Cloud, AD, Phishing, Endpoint)

