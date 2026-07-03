# Agent-Alpha — Operational Reference (Kill Chain Detail)

> **Routing notice (K21).** This document contains payload-level / operational
> offensive detail. It is **DeepSeek-facing**, NOT Claude-facing. Do not paste
> this file into a Claude/Sonnet/Opus/GPT session — per the K21 routing rule,
> reasoning models never handle payload bodies. The capability-level summary
> for architecture discussion lives in `KNOWLEDGE.md` §K1.

> **Legal & Authorization Notice.** Agent-Alpha is an authorized commercial
> red-team platform. Every engagement requires a signed SOW + written
> authorization, verified by a non-bypassable authorization gate (Conductor)
> before any offensive action. Testing is performed ONLY against client-owned
> systems with explicit consent. Template names denote system categories, not
> specific organizations.

**Version:** 2.0 (updated 2026-07-03 — reflects actual implementation status)

> **NOTE:** This document is a TARGET reference for future implementation.
> Only Alpha (SCOUT), Beta (STRIKE), and Omega (ROASTER) are currently implemented.
> Gamma (ANCHOR), Delta (HUNTER), and Epsilon (SCOUT-HUNTER) are NOT YET IMPLEMENTED.
> Most tools listed below are placeholders for future DeepSeek implementation.

---

## O1. Kill Chain Reference (Agent → Technique → Tool)

### Alpha (SCOUT) — Techniques & Tools ✅ IMPLEMENTED
```
Subdomain Enumeration: [NOT IMPLEMENTED] subfinder, crt.sh, dnsenum, DNS brute
Port Scanning:         [NOT IMPLEMENTED] nmap (top 30 ports, stealth SYN scan)
Tech Detection:        [IMPLEMENTED] Laravel debug exposure template (laravel_finding.py)
Directory Enum:        [NOT IMPLEMENTED] feroxbuster, ffuf
Reverse IP Lookup:     [NOT IMPLEMENTED] hackertarget, rapiddns.io
HTTP Operations:       [IMPLEMENTED] HttpClient (httpx-backed)
JS Intelligence:       [NOT IMPLEMENTED] JS bundle crawler
Output:                {hosts, ports, services, tech_stack, js_secrets, api_endpoints}
```

### Beta (STRIKE) — Techniques & Tools ✅ IMPLEMENTED
```
Credential Spray:      [IMPLEMENTED] CredReuseTool (vaulted credential reuse)
Default Credentials:   [IMPLEMENTED] DefaultCredsTool (19 platforms)
Browser Automation:    [NOT IMPLEMENTED] Playwright + stealth patches
Proxy Infrastructure:  [NOT IMPLEMENTED] BrightData Web Unlocker + Residential proxies
CAPTCHA Bypass:        [NOT IMPLEMENTED] 2Captcha integration
Protocol Spray:        [NOT IMPLEMENTED] SSH spray, FTP spray, IMAP spray
Output:                {valid_credentials, session_tokens, access_level, entry_point}
```

### Gamma (ANCHOR) — Techniques & Tools ⬜ NOT IMPLEMENTED
```
SQLi:                  [NOT IMPLEMENTED] sqlmap, manual SQLi via curl
File Upload Bypass:    [NOT IMPLEMENTED] upload_bypass.py
RCE Chains:            [NOT IMPLEMENTED] sqli_rce.py, lfi_poison.py
CMS Exploitation:      [NOT IMPLEMENTED] cms_exploiter.py
CVE Exploitation:      [NOT IMPLEMENTED] cve_exploiter.py, cve_match.py
Webshell Deploy:       [NOT IMPLEMENTED] deploy.py, gs_deploy.py
Special Techniques:    [NOT IMPLEMENTED] pma5_outfile_v3.py
Output:                {shell_access, webshell_path, server_context, writable_paths}
```

### Delta (HUNTER) — Techniques & Tools ⬜ NOT IMPLEMENTED
```
Shell:                 [NOT IMPLEMENTED] GSocket PTY shell
Persistence:           [NOT IMPLEMENTED] gs_deploy.py, gs_persist.py
Credential Harvest:    [NOT IMPLEMENTED] config_harvest.py, cred_reuse.py
Data Exfiltration:     [NOT IMPLEMENTED] db_dump.py
Cleanup Awareness:     [NOT IMPLEMENTED] cleanup_scan.py
Manual Enum:           [NOT IMPLEMENTED] find /var/www, grep, cat
Hash Cracking:         [NOT IMPLEMENTED] unshadow + john
Persistence Detection: [NOT IMPLEMENTED] crontab, ls -la /etc/cron.d
Output:                {harvested_creds, db_access, internal_network_map}
```

### Epsilon (SCOUT-HUNTER) — Techniques & Tools ⬜ NOT IMPLEMENTED
```
Access:                [NOT IMPLEMENTED] GSocket PTY from compromised host
Internal Scanning:     [NOT IMPLEMENTED] internal_scan.py
Co-host Pivot:         [NOT IMPLEMENTED] cohost_pivot.py
Shared Hosting:        [NOT IMPLEMENTED] symlink.py
Network Tools:         [NOT IMPLEMENTED] ssh, nmap (from compromised host)
Tunneling:             [NOT IMPLEMENTED] VPN/VPS tools
AD Techniques:         [NOT IMPLEMENTED] Kerberoasting, AS-REP Roasting
Output:                {compromised_hosts, pivoted_networks, additional_findings}
```

### Omega (ROASTER) — Output ✅ IMPLEMENTED
```
Database:              [NOT IMPLEMENTED] findings_db.py (SQLite findings storage)
Evidence:              [NOT IMPLEMENTED] evidence_collect.py
Report Build:          [IMPLEMENTED] Omega.generate_report() + Report.export_pdf()
Verification:          [NOT IMPLEMENTED] verify_txt.py
Proof Artifacts:       [IMPLEMENTED] EventStore PROOF_ARTIFACT_RECORDED events
Formats:               [IMPLEMENTED] PDF (executive + technical) via reportlab
Standards:             [IMPLEMENTED] MITRE ATT&CK mapping
Time-to-Proof:         [IMPLEMENTED] format_duration() + time_to_proof_headline()
```

---

## Implementation Status Summary

| Agent | Status | Notes |
|-------|--------|-------|
| **Alpha (SCOUT)** | ✅ IMPLEMENTED | Laravel debug template, HttpClient, cognitive loop |
| **Beta (STRIKE)** | ✅ IMPLEMENTED | CredReuseTool, DefaultCredsTool, CredentialApplicator seam |
| **Gamma (ANCHOR)** | ⬜ NOT IMPLEMENTED | Placeholder only |
| **Delta (HUNTER)** | ⬜ NOT IMPLEMENTED | Placeholder only |
| **Epsilon (SCOUT-HUNTER)** | ⬜ NOT IMPLEMENTED | Placeholder only |
| **Omega (ROASTER)** | ✅ IMPLEMENTED | Report generation, PDF export, time-to-proof headline |

| Tool Category | Status | Notes |
|---------------|--------|-------|
| **Recon Tools** | 🟡 PARTIAL | Laravel template only; nmap, subfinder, etc. not implemented |
| **Access Tools** | ✅ IMPLEMENTED | CredReuseTool, DefaultCredsTool, CredentialApplicator seam |
| **Exploit Tools** | ⬜ NOT IMPLEMENTED | sqlmap, upload_bypass, RCE chains not implemented |
| **Post-Exploit Tools** | ⬜ NOT IMPLEMENTED | GSocket, config_harvest, db_dump not implemented |
| **Lateral Movement** | ⬜ NOT IMPLEMENTED | internal_scan, cohost_pivot not implemented |
| **Reporting** | ✅ IMPLEMENTED | PDF export, MITRE mapping, time-to-proof headline |

---

## Currently Implemented Components

### Alpha (SCOUT) - agent_alpha/agents/alpha/scout.py
- Cognitive loop with BoundedAutonomy
- Laravel debug exposure template (laravel_finding.py)
- HttpClient for HTTP operations
- Credential assembly from leaked env vars
- EngagementMemory projection (time_to_first_proof_s, time_to_first_exploit_s)

### Beta (STRIKE) - agent_alpha/agents/beta/strike.py
- Cognitive loop with BoundedAutonomy
- CredReuseTool (vaulted credential reuse via CredentialApplicator)
- DefaultCredsTool (19 platforms default credentials)
- Ranked tool selection via applies_to()
- Deep redaction of proof artifacts
- False-success guard (anti-Lyndon #3)

### Omega (ROASTER) - agent_alpha/agents/omega/roaster.py
- Report generation with narrative, MITRE techniques
- PDF export via reportlab
- Time-to-proof headline (format_duration formatter)
- Chain finding summarization

### Tools - agent_alpha/tools/
- **contracts.py** - Tool protocol (Template, Tool, TargetContext, ResourceBudget, ToolResult)
- **templates/cms/laravel_finding.py** - Laravel debug exposure template
- **internal/access/cred_reuse.py** - Vaulted credential reuse tool
- **internal/access/default_creds.py** - Default credentials check tool
- **internal/access/applicator.py** - CredentialApplicator seam (HttpFormApplicator, MySqlApplicator)

---

## Future Implementation Targets

### Priority 1 (Phase 3 Completion)
- C6b: Per-unit fan-out execution + live-fire FP<20%
- C7: No regression + CI
- C8: Anti-Lyndon gates

### Priority 2 (Phase 4 - Beta Expansion)
- Browser automation (Playwright)
- Proxy infrastructure
- CAPTCHA bypass
- Protocol spray (SSH, FTP, IMAP)

### Priority 3 (Phase 4 - Gamma/Delta/Epsilon)
- Gamma (ANCHOR): SQLi, file upload bypass, RCE chains
- Delta (HUNTER): GSocket shell, persistence, credential harvest
- Epsilon (SCOUT-HUNTER): Internal scanning, lateral movement

### Priority 4 (Phase 5 - Multi-Engagement)
- Multi-tenant orchestration
- Priority queue
- Cross-engagement learning

### Priority 5 (Phase 6 - IntelligenceBase)
- pgvector embeddings
- Similar target queries
- Advanced strategy inference

