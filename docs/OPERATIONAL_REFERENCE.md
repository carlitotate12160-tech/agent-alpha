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

**Version:** 1.0 (extracted from KNOWLEDGE.md §K1, 2026-06-16)

---

## O1. Kill Chain Reference (Agent → Technique → Tool)

### Alpha (SCOUT) — Techniques & Tools
```
Subdomain Enumeration: subfinder, crt.sh, dnsenum, DNS brute (359-prefix wordlist)
Port Scanning:         nmap (top 30 ports, stealth SYN scan)
Tech Detection:        whatweb, wafw00f, nuclei (tech templates only)
Directory Enum:        feroxbuster, ffuf
Reverse IP Lookup:     hackertarget, rapiddns.io
HTTP Operations:       curl (all HTTP ops), curl_cffi (CF bypass)
JS Intelligence:       JS bundle crawler — grep for API keys, tokens, credentials
Output:                {hosts, ports, services, tech_stack, js_secrets, api_endpoints}
```

### Beta (STRIKE) — Techniques & Tools
```
Credential Spray:      spray_browser.py (Playwright anti-detect),
                       spray_engine.py (raw HTTP, proxy rotation)
Default Credentials:   default_creds.py (19 platforms)
Browser Automation:    Playwright + stealth patches
Proxy Infrastructure:  BrightData Web Unlocker + Residential proxies,
                       FreeProxyPool, VPS Indo SOCKS5 tunnel
CAPTCHA Bypass:        2Captcha integration
Protocol Spray:        SSH spray, FTP spray, IMAP spray
Output:                {valid_credentials, session_tokens, access_level, entry_point}
```

### Gamma (ANCHOR) — Techniques & Tools
```
SQLi:                  sqlmap (if no CF, check CF-RAY header first),
                       manual SQLi via curl (time-blind, union, error-based)
File Upload Bypass:    upload_bypass.py (double extension, MIME type, path traversal)
RCE Chains:            sqli_rce.py, lfi_poison.py
CMS Exploitation:      cms_exploiter.py (per-CMS), CMS_DATABASE.md reference
CVE Exploitation:      cve_exploiter.py, cve_match.py
Webshell Deploy:       deploy.py, gs_deploy.py (GSocket deployment)
Special Techniques:    pma5_outfile_v3.py (phpMyAdmin INTO OUTFILE RCE)
Output:                {shell_access, webshell_path, server_context, writable_paths}
```

### Delta (HUNTER) — Techniques & Tools
```
Shell:                 GSocket PTY shell (interactive, encrypted)
Persistence:           gs_deploy.py, gs_persist.py
Credential Harvest:    config_harvest.py (.env/config files),
                       cred_reuse.py (cross-host reuse)
Data Exfiltration:     db_dump.py (database dumping)
Cleanup Awareness:     cleanup_scan.py (pre-persistence scanner)
Manual Enum:           find /var/www, grep, cat
Hash Cracking:         unshadow + john
Persistence Detection: crontab, ls -la /etc/cron.d
Output:                {harvested_creds, db_access, internal_network_map}
```

### Epsilon (SCOUT-HUNTER) — Techniques & Tools
```
Access:                GSocket PTY from compromised host
Internal Scanning:     internal_scan.py (172.16.x.x, 192.168.x.x, 10.x.x.x)
Co-host Pivot:         cohost_pivot.py (pivot to co-hosted domains)
Shared Hosting:        symlink.py (shared hosting symlink pivot)
Network Tools:         ssh, nmap (from compromised host)
Tunneling:             VPN/VPS tools for tunneling
AD Techniques:         Kerberoasting, AS-REP Roasting
Output:                {compromised_hosts, pivoted_networks, additional_findings}
```

### Omega (ROASTER) — Output
```
Database:              findings_db.py (SQLite findings storage)
Evidence:              evidence_collect.py
Report Build:          summary_builder.py, report_gen.py (HTML/MD)
Verification:          verify_txt.py
Proof Artifacts:       request/response pairs, screenshots, redacted data samples
Formats:               PDF (executive + technical), JSON, SARIF, MD
Standards:             MITRE ATT&CK mapping, PCI/NIS2 compliance mapping
```
