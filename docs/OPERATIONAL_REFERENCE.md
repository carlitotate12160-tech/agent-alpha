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

**Version:** 2.1 (updated 2026-07-07 — cross-referenced to ADR_ROADMAP §9 phases)

> **NOTE:** This document is a TARGET reference for future implementation.
> Only Alpha (SCOUT), Beta (STRIKE), and Omega (ROASTER) are currently implemented.
> Gamma (ANCHOR), Delta (HUNTER), and Epsilon (SCOUT-HUNTER) are NOT YET IMPLEMENTED.
> Most tools listed below are placeholders for future DeepSeek implementation.
>
> **Phase mapping:** Each agent section below is cross-referenced to the
> corresponding phase in `ADR_ROADMAP.md` §9. The wrap-vs-build decision for
> each tool is governed by `ADR.md` §12.22 Decision 1.

---

## O1. Kill Chain Reference (Agent → Technique → Tool)

### Alpha (SCOUT) — Techniques & Tools ✅ IMPLEMENTED  `→ ADR_ROADMAP Phase 2`
```
Subdomain Enumeration: [NOT IMPLEMENTED] subfinder, crt.sh, dnsenum, DNS brute
Port Scanning:         [NOT IMPLEMENTED] nmap (top 30 ports, stealth SYN scan)
Tech Detection:        [IMPLEMENTED] Laravel debug exposure template (laravel_finding.py)
Directory Enum:        [NOT IMPLEMENTED] feroxbuster, ffuf
Reverse IP Lookup:     [NOT IMPLEMENTED] hackertarget, rapiddns.io
HTTP Operations:       [IMPLEMENTED] HttpClient (httpx-backed)
JS Intelligence:       [NOT IMPLEMENTED] JS bundle crawler
Credential Harvest:    [IMPLEMENTED] Laravel env leak parsing + credential assembly
                       (iter_env_leaks → assemble_leaked_credentials → SecretsManager vault)
Current Output:        {laravel_debug_findings, leaked_credentials, asset_nodes}
Target Output:         {hosts, ports, services, tech_stack, js_secrets, api_endpoints}
```

### Beta (STRIKE) — Techniques & Tools ✅ IMPLEMENTED  `→ ADR_ROADMAP Phase 3`
```
Credential Reuse:      [IMPLEMENTED] CredReuseTool (vaulted credential reuse via CredentialApplicator)
Default Credentials:   [IMPLEMENTED] DefaultCredsTool (generic + 6 platforms: WordPress, Tomcat,
                       Jenkins, phpMyAdmin, Grafana, Joomla)
Credential Applicator: [IMPLEMENTED] CredentialApplicator seam
                       - HttpFormApplicator (HTTP form login)
                       - MySqlApplicator (MySQL protocol auth, safety-guarded)
                       - select_applicator() for service-agnostic dispatch
Browser Automation:    [NOT IMPLEMENTED] Playwright + stealth patches
Proxy Infrastructure:  [NOT IMPLEMENTED] BrightData Web Unlocker + Residential proxies
CAPTCHA Bypass:        [NOT IMPLEMENTED] 2Captcha integration
Protocol Spray:        [NOT IMPLEMENTED] SSH spray, FTP spray, IMAP spray
Current Output:        {valid_credentials, session_tokens, access_level, entry_point}
```

### Gamma (ANCHOR) — Techniques & Tools ⬜ NOT IMPLEMENTED  `→ ADR_ROADMAP Phase 4`
```
SQLi:                  [TARGET] Automated SQLi detection + exploitation
File Upload Bypass:    [TARGET] Double extension, MIME type, path traversal bypass
RCE Chains:            [TARGET] SQLi-to-RCE, LFI-to-RCE chains
CMS Exploitation:      [TARGET] Per-CMS exploit templates
CVE Exploitation:      [TARGET] CVE matching + exploit execution
Webshell Deploy:       [TARGET] Webshell deployment + persistence
Target Output:         {shell_access, webshell_path, server_context, writable_paths}
```

### Delta (HUNTER) — Techniques & Tools ⬜ NOT IMPLEMENTED  `→ ADR_ROADMAP Phase 5`
```
Shell:                 [TARGET] Interactive encrypted PTY shell
Persistence:           [TARGET] Deployment + persistence modules
Credential Harvest:    [TARGET] Config file harvesting + cross-host credential reuse
Data Exfiltration:     [TARGET] Database dumping
Cleanup Awareness:     [TARGET] Pre-persistence cleanup scanner
Manual Enum:           [TARGET] Filesystem enumeration
Hash Cracking:         [TARGET] unshadow + john
Target Output:         {harvested_creds, db_access, internal_network_map}
```

### Epsilon (SCOUT-HUNTER) — Techniques & Tools ⬜ NOT IMPLEMENTED  `→ ADR_ROADMAP Phase 5`
```
Access:                [TARGET] PTY shell from compromised host
Internal Scanning:     [TARGET] Internal network scanning (172.16.x.x, 192.168.x.x, 10.x.x.x)
Co-host Pivot:         [TARGET] Pivot to co-hosted domains
Shared Hosting:        [TARGET] Shared hosting symlink pivot
Network Tools:         [TARGET] ssh, nmap from compromised host
Tunneling:             [TARGET] VPN/VPS tunneling
AD Techniques:         [TARGET] Kerberoasting, AS-REP Roasting
Target Output:         {compromised_hosts, pivoted_networks, additional_findings}
```

### Omega (ROASTER) — Output ✅ IMPLEMENTED  `→ ADR_ROADMAP Phase 2 + Phase 6`
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

### Chain Runner — Alpha→Beta Chain ✅ IMPLEMENTED
```
Chain Runner:          [IMPLEMENTED] Single-process Alpha→Beta chain live-fire runner
                       (agent_alpha/live_fire/chain_runner.py)
Chain Flow:            Alpha recon (Laravel debug leak) → vault credentials →
                       Beta cred_reuse → access → ENABLES edge in AttackGraph
Chain Edge Verification: [IMPLEMENTED] Test verifies ENABLES edge originates from
                       Alpha's vaulted credential, not Beta-minted default
Field-Prove:           [IMPLEMENTED] CHAIN PROVEN: True, db_root, critical
                       lawan real MySQL 8.4 di Oracle ARM64 (commit 73203b6)
Mock Target:           [IMPLEMENTED] Mock Laravel debug page HTTP server
                       (serve /trigger-error leak + /login for field-prove)
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
- **internal/access/default_creds.py** - Default credentials check tool (generic + 6 platforms)
- **internal/access/applicator.py** - CredentialApplicator seam
  - HttpFormApplicator (HTTP form login: POST username+password, session cookie verification)
  - MySqlApplicator (MySQL protocol auth, safety-guarded: refuse empty-username)
  - select_applicator() for service-agnostic dispatch

### Chain Runner - agent_alpha/live_fire/chain_runner.py
- Single-process Alpha→Beta chain live-fire runner dengan shared SecretsManager
- Alpha: recon → Laravel debug leak → vault credentials → CREDENTIAL node
- Beta: cred_reuse → resolve vaulted secret → CredentialApplicator → access → ENABLES edge
- Chain Edge Verification: ENABLES edge originates from Alpha's vaulted credential
- Field-Proven: CHAIN PROVEN: True, db_root, critical lawan real MySQL 8.4 di Oracle ARM64
- Mock Target: HTTP server mock yang serve /trigger-error (leak env vars) + /login

---

## Future Implementation Targets

> **Cross-reference:** Phase numbers below match `ADR_ROADMAP.md` §9.
> Wrap-vs-build decisions per `ADR.md` §12.22 Decision 1.

### Priority 1 (Phase 2 Completion — Alpha Recon Breadth)
- Subdomain enumeration (WRAP: subfinder, crt.sh)
- Port scanning (WRAP: nmap top-30)
- Directory enumeration (WRAP: feroxbuster/ffuf)
- Reverse IP lookup (WRAP: hackertarget, rapiddns.io)
- JS bundle crawler (BUILD: graph-aware secret extraction)
- Tech detection (WRAP: whatweb, wafw00f)
- URL discovery in handlers → append to `_work_queue`
- Raise `ALPHA_RECON_NO_PROGRESS_ITERS` from 1 to 3-5

### Priority 2 (Phase 3 Completion — Beta Expansion)
- C6b: Per-unit fan-out execution + live-fire FP<20%
- C7: No regression + CI
- C8: Anti-Lyndon gates
- Browser automation (WRAP: Playwright + stealth)
- Proxy infrastructure (WRAP: BrightData Web Unlocker)
- CAPTCHA bypass (WRAP: 2Captcha)
- Protocol spray (WRAP: SSH, FTP, IMAP)

### Priority 3 (Phase 4 — Gamma/ANCHOR)
- ToolComposer.compose(base_template, context) — BUILD INTERNAL
- SQLi (WRAP: sqlmap), file upload bypass, RCE chains
- CMS exploit templates, CVE matching + exploit execution
- Webshell deploy + persistence
- Blast-radius gate before ANCHOR

### Priority 4 (Phase 5 — Delta + Epsilon)
- Delta (HUNTER): GSocket shell (WRAP), persistence, credential harvest
- Epsilon (SCOUT-HUNTER): Internal scanning, lateral movement
- Pivot-chain state tracking in AttackGraph — BUILD INTERNAL
- OS-as-tools / LOLBin catalog — BUILD INTERNAL
- Co-host pivot / symlink — default-DENY (§12.22 Decision 2)

### Priority 5 (Phase 6 — IntelligenceBase + Hardening)
- pgvector embeddings
- Similar target queries
- Advanced strategy inference
- Cross-engagement learning + circuit-breaker tool reliability
- VERIFY/re-test mode, continuous/scheduled engagement
- Additional engagement profiles (Cloud, AD, Phishing, Endpoint)

