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
| 34 | `run_recon` resets engagement state across targets → thrash | OPEN | High | CW | Low | Egress-block/dead-host/dedup reset per target → never converges; burns HTTP + LLM tokens |
| 35 | `LLM_TOOL_SELECT_MAX_TOKENS=512` too small | FIXED (Oracle-sealed) | — | RM | Low | Reasoning model truncates → OrientationError |
| 36 | `/wp-admin/*` login-gated pages enter frontier | OPEN | Med | CW | Low | Token burn for predictable non-findings |
| 37 | Non-WP hosts have no crawl allowlist | OPEN | High | CW | Low | Alpha crawls 20+ content pages, 0 findings |
| 38 | Host-keyed caches reset per target, not engagement-scoped | OPEN | Med | CW | Med | soft-404 / reach / origin-binding re-computed for every sibling target sharing a host → redundant HTTP + LLM (efficiency follow-up to #34) |

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
| 074 | Authentication mechanism fingerprinting (form/JWT/SAML/OAuth) | PARTIAL | High | RM | Med | Slices 1, 2a, 2b merged. Root cause of GAP-067/046; gates GAP-077 |
| 075 | Subdomain takeover check (dangling DNS CNAME) | OPEN | Med | SS | Low | Classic external finding; dangling CNAME to deleted service not checked |
| 076 | Cloud storage / shadow-IT discovery (S3/GCP/Azure) | OPEN | Med | SS | Med | S3 buckets, GCP storage associated with target domain not discovered |
| 077 | Authentication bypass testing (SQLi/NoSQLi/LDAPi in login) | OPEN | High | SS | Med | Beta only tries cred-reuse + default-creds; no injection-based auth bypass |
| 078 | User enumeration via auth response differential | OPEN | Med | RM | Low | Login error messages leak valid vs invalid usernames; not captured |
| 079 | Post-access validation (agentless — access level proof) | OPEN | High | RG | Med | Beta reports "login OK" but doesn't prove what access level was achieved |
| 080 | Session management analysis (post-login stability) | OPEN | Med | RM | Low | After login: cookie attrs, fixation, timeout, concurrency not analyzed |
| 081 | Port scanning / non-HTTP service discovery | OPEN | High | RM | Med-High | SSH/RDP/SMTP/Redis/DB exposed but Alpha only scans HTTP |
| 082 | SMTP enumeration (VRFY/EXPN/RCPT) | OPEN | Med | SS | Low | Mail server username enumeration not checked |
| 083 | Virtual host discovery (Host header enumeration) | OPEN | Low | SS | Med | Other sites on same origin IP not discovered |
| 084 | CORS analysis (Access-Control-Allow-Origin) | OPEN | High | RM | Low | `*` + `Allow-Credentials: true` = classic misconfig; 0 new requests |
| 085 | HTTP method enumeration (OPTIONS) | OPEN | Med | RM | Low | PUT/DELETE/TRACE enabled = attack surface; 1 request |
| 086 | Favicon hash fingerprinting (mmh3) | OPEN | Low | RM | Low | Framework/version ID via favicon hash; Shodan/Censys use this |
| 087 | Generic backup file patterns (backup.zip, db.sql, dump.sql) | OPEN | High | RM | Low | Shared hosting SEA commonly exposes site/DB backups |
| 088 | Technology version extraction (universal, beyond WP) | OPEN | P0 | RM | Low | nginx/Apache/PHP/DB versions in headers but not captured as SERVICE nodes |
| 089 | CVE catalog comprehensiveness (only 1 entry today) | OPEN | P0 | RG | Med | Version extraction is useless without CVE lookup; catalog has 1 entry |
| 090 | Email pattern inference (firstname@, first.last@, flast@) | OPEN | Med | RG | Low | One known email → generate candidates for breach correlation + cred-spray |
| 091 | GitHub/GitLab public code search (employee repos) | OPEN | Med | RG | Med | Developers commit .env/API keys to public repos; classic OSINT |
| 092 | ASN/netblock discovery (sister infrastructure) | OPEN | Low | RG | Med | Same ASN = other in-scope IPs, staging, internal services |
| 093 | Certificate SAN extraction (live cert, not CT log) | OPEN | Med | RM | Low | TLS handshake SANs reveal internal hostnames not in CT log |
| 094 | DNS zone transfer attempt (AXFR) | OPEN | Low | SS | Low | Rarely succeeds but jackpot when it does; 1 DNS query |
| 095 | Social media company page recon (FB/IG/Twitter) | OPEN | Med | RG | Med | Company page admin list, post history, employee comments = org intel |
| 096 | CSRF token extraction for form-login applicators | OPEN | High | RM | Med | Laravel/Spring/Django login POST fails without CSRF token; not extracted |
| 097 | JSON API login applicator (SPA/REST login) | OPEN | High | SS | Med | Vue/React SPA login via JSON POST /api/login; no applicator exists |
| 098 | reCAPTCHA / hCaptcha solving for login forms | OPEN | Med | RM | High | Only CF Turnstile handled; reCAPTCHA v2/v3 + hCaptcha not solved |
| 099 | MFA/2FA challenge detection and honest classification | OPEN | High | RG | Med | Beta reports FAILED on MFA; no "first factor valid, MFA required" outcome |
| 100 | Account lockout detection (target-side) | OPEN | Med | RM | Low | Governor prevents over-attempts but doesn't detect target lockout response |
| 101 | API key authentication applicator | OPEN | Med | SS | Med | api_auth label exists but no applicator; leaked API keys not tried |
| 102 | Session cookie riding (harvested cookie reuse) | OPEN | Med | SS | Low | Alpha may harvest session cookies from leaks; Beta can't ride them |
| 103 | Cross-service credential reuse (SSH/Redis/SMTP) | OPEN | Med | SS | Med | Harvested DB creds not tried on SSH/Redis; MySqlApplicator is SOW-gated only |
| 104 | Breach credential tool (Dehashed/HIBP integration) | OPEN | High | RG | Med | §12.54 breach data not wired; no tool to try breach creds |
| 105 | Beta CVE consumption for exploit-based entry | OPEN | Med | RG | Med | Alpha finds CVE but Beta only tries cred-based access; no exploit entry |
| 106 | Login redirect chain following | OPEN | Med | RM | Low | Multi-hop login redirects (SSO/callback) not followed to verify final landing |
| 107 | First-login password change detection | OPEN | Low | RM | Low | Forced password change on first login = Beta reports FAILED, not "change required" |
| 108 | Password reset flow user enumeration | OPEN | Med | RM | Med | Reset endpoint reveals valid emails; not probed by Beta |
| 109 | Beta entry selection ignores WAF capability | OPEN | Med | RG | Low | Beta strikes WAF-protected surface without considering WAF mode (GAP-073) |
| 110 | Beta credential prioritization lacks graph edges | OPEN | Med | RG | Med | cred_reuse iterates all creds × all surfaces; no graph-based priority (GAP-070) |
| 111 | DB dump hash extraction (MySQL/wp_users/phpass) | OPEN | Med | RG | Med | Alpha finds db.sql leak but doesn't parse hash from mysql.user/wp_users |
| 112 | Offline hash cracking tool (hashcat/john integration) | OPEN | High | SS | High | No offline crack capability; online spray risks lockout |
| 113 | Password reset abuse (host header injection, token prediction) | OPEN | Med | SS | Med | Reset endpoint abuse to change password without knowing old password |
| 114 | OAuth/SAML/JWT token theft and forgery | OPEN | Med | SS | High | Token-based auth bypass via open redirect, weak signing key, JWT crack |
| 115 | Historical DNS origin discovery (SecurityTrails/DNSHistory) | OPEN | High | RG | Med | ADR §12.61 A1 — biggest missing signal; crt.sh/VT/OTX failed on full-CF targets |
| 116 | Authenticated crawl / post-access re-recon implementation (§12.32) | OPEN | High | RG | Med | ADR LOCKED but code NOT BUILT; 0 auth-vs-unauth diff in codebase |
| 117 | Credential pattern mutation implementation (§12.34) | OPEN | Med | SS | Med | ADR LOCKED but CredentialPatternMutator NOT BUILT; cred_reuse literal only |
| 118 | Proof standard oracle — auth-vs-unauth diff (§12.43) | OPEN | High | RG | Med | CredReuseAttestor is provenance check, NOT independent oracle per §12.43 |
| 119 | Credential-result semantics — negative outcome classification (§12.45) | OPEN | Med | RG | Low | Beta reports FAILED without methodology caveat per §12.45 |
| 120 | IPv6 attack surface recon (forgotten hardening) | OPEN | Med | RG | Low | Many targets forget to harden IPv6 stack; Alpha is IPv4-only implicit |
| 121 | DNSSEC zone walking (NSEC record enumeration) | OPEN | Low | RG | Low | NSEC records leak subdomains without brute force; passive, 0 target touch |
| 122 | SMTP bounce-back analysis (internal infra leak) | OPEN | Low | RG | Low | SMTP 550 error messages leak Exchange version, internal routing, mail config |
| 123 | Certificate Transparency delay analysis (post-CF origin leak) | OPEN | Med | RG | Med | Certs issued 2 days after apex CF fronting often leak origin IP in SAN history |
| 124 | Job posting / tech stack mining (infrastructure inference) | OPEN | Low | RG | Low | Job descriptions reveal stack (nginx, Kafka, Kubernetes) = attack surface intel |
| 125 | Deception detection (honeypot / canary token / sinkhole) | OPEN | Low | RG | Med | APT detects honeypot before touching; Alpha has no deception awareness |
| 126 | Document metadata intel (PDF/DOCX/EXIF from public files) | OPEN | Med | RM | Med | Alpha fetches only .env/wp-config/.git; no document discovery or metadata parsing |
| 127 | SaaS vendor integration map (DNS TXT verification records) | OPEN | Med | RM | Low | DNS TXT reveals Zendesk/Atlassian/Google/Slack integrations; 0 target touch |
| 128 | Timezone-aware pacing (SOC-hours targeting) | OPEN | Med | RM | Low | StealthPacer has no timezone awareness; attack runs regardless of target SOC hours |
| 129 | VPN/Remote Access fingerprinting (expand GAP-081) | OPEN | High | RM | Med | GAP-081 is top-20 HTTP-only; no VPN/RA fingerprinting (IKEv2, OpenVPN, TeamViewer) |
| 130 | OAuth app enumeration (trust boundary mapping) | OPEN | Med | RM | Med | Target's OAuth apps (Slack/Google/GitHub) = trust boundary; APT29 Nobelium pattern |
| 131 | Refresh token abuse (OAuth session persistence) | OPEN | Med | SS | Low | No refresh token handling; expired OAuth session = dead; APT uses refresh to persist |
| 132 | Mobile app attack surface (APK/IPA decompile) | OPEN | High | RM | High | SEA = mobile-first; APK = hardcoded origin IP, API keys, Firebase; bypass CF |
| 133 | Business logic RISK detection (DETECTION only, NOT exploitation) | OPEN | High | RM | Med | Flag cart price/qty params, IDOR candidate, role param, coupon race; EXPLOITATION = §12.51 Gamma DEFERRED Phase 5/6; this = Phase 4 surface risk for Gamma |
| 134 | API enumeration beyond login (REST endpoint discovery) | OPEN | High | RM | Med | GAP-097 = login only; /api/v1/users, /api/internal/*, Swagger as discovery target |
| 135 | GraphQL introspection + field suggestion | OPEN | Med | RM | Med | /graphql in soft-404 suppression list = SUPPRESSED not probed; __schema = full API map |
| 136 | SSRF + cloud metadata (IMDS) exposure | OPEN | Med | SS | Med | Image proxy / URL fetch → 169.254.169.254 = AWS IAM creds; #1 cloud vector |
| 137 | File upload abuse (webshell/SVG XSS/path traversal) | OPEN | Med | SS | Med | WooCommerce/SEA e-commerce upload surface; content-type bypass |
| 138 | HTTP request smuggling (CL.TE / TE.CL) | OPEN | Med | SS | High | CF + origin desync; bypass WAF, cache poisoning, session hijack |
| 139 | Web cache poisoning (unkeyed header) | OPEN | Med | SS | Med | CDN cache key manipulation; poison cache for all users |
| 140 | WebSocket attack surface (ws:// bypass WAF) | OPEN | Med | RM | Med | WAF often does not inspect WebSocket frames; auth bypass via WS |
| 141 | JavaScript dependency CVE (jQuery/Angular/moment.js) | OPEN | Med | RM | Low | GAP-058 = secrets only; dependency version → CVE chain not captured |
| 142 | Source map exposure (.js.map = full source) | OPEN | Med | RM | Low | app.js.map = unminified source; internal API routes, business logic leak |
| 143 | Database direct exposure enumeration (Mongo/ES/Redis) | OPEN | High | RM | Med | Expand GAP-081; Shodan confirms thousands exposed in ID/VN/TH; no-auth = data leak |
| 144 | FTP/SFTP anonymous access (shared hosting SEA) | OPEN | Med | SS | Low | Port 21 anonymous on Hostinger/Niagahoster; source/backup leak |
| 145 | SNMP enumeration (community string public) | OPEN | Low | RM | Low | Port 161 UDP; system info, processes, internal hostname leak |
| 146 | Hidden parameter discovery (admin=true, debug=1) | OPEN | Med | RM | Med | Arjun/param-miner style; hidden params not in UI but server accepts |
| 147 | Race condition / TOCTOU testing (e-commerce) | OPEN | Med | SS | High | Coupon 2x, withdraw 2x, vote manipulation; concurrent request tooling |
| 148 | Error message information disclosure (stack trace) | OPEN | Low | RM | Low | 500 = framework version, file paths; SQL error = table/column names |
| 149 | Open redirect enumeration (standalone) | OPEN | Med | RM | Low | /redirect?url=evil.com; phishing, OAuth token theft, SSRF bypass |
| 150 | CSP analysis for attack surface mapping | OPEN | Low | RM | Low | GAP-055 = presence only; script-src trusted external = attack surface |
| 151 | CDN origin shield bypass (Argo/CloudFront shield) | OPEN | Med | RM | Med | Shield IP discovery = bypass edge entirely |
| 152 | DNS rebinding for SSRF bypass | OPEN | Low | SS | Med | Domain resolves to 127.0.0.1 after first DNS check; bypass SSRF allowlist |

### Out of Scope — Documented (bounds GAP-045 claim)

| # | Name | Status | Priority | Cat | Effort | Notes |
|----|------|--------|----------|-----|--------|-------|
| OOS-1 | Phishing / pretexting for credentials | OUT OF SCOPE | — | — | — | Human interaction + legal exposure; real APT #1 vector but deferred indefinitely |
| OOS-2 | Vishing (voice phishing) | OUT OF SCOPE | — | — | — | Phone-based social engineering; legal + human interaction |
| OOS-3 | Physical access (office/USB/lock) | OUT OF SCOPE | — | — | — | On-site, not remote SaaS |
| OOS-4 | Wireless (WiFi/evil twin/deauth) | OUT OF SCOPE | — | — | — | On-site, not remote SaaS |
| OOS-5 | Supply chain compromise (vendor attack) | OUT OF SCOPE | — | — | — | Different engagement type; SolarWinds/Kaseya/3CX pattern |
| OOS-6 | Social engineering (LinkedIn/impersonation) | OUT OF SCOPE | — | — | — | Human manipulation, legal exposure |
| OOS-7 | Insider threat (disgruntled employee) | OUT OF SCOPE | — | — | — | Requires insider access, different scope |

### Existing GAP Expansion Tracking

| # | Parent | Expansion needed | New GAP |
|----|--------|------------------|---------|
| EXP-1 | GAP-081 | DB-specific protocol enumeration | GAP-143 |
| EXP-2 | GAP-055 | CSP trust-boundary analysis | GAP-150 |
| EXP-3 | GAP-058 | Dependency version → CVE chain | GAP-141 |
| EXP-4 | GAP-085 | WebDAV verbs (PROPFIND/MOVE/COPY) | — |
| EXP-5 | GAP-087 | Directory patterns (/backup/, /db/, /sql/) | — |
| EXP-6 | GAP-062 | DMARC policy analysis (p=none vs reject) | — |
| EXP-7 | GAP-099 | MFA bypass (SIM swap/push fatigue/RTOP) | — |

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

### Recon Completeness Slice (NEW — 0 request multiplier + passive discovery)

34. **GAP-089** — CVE catalog comprehensiveness (P0 multiplier — version→CVE→finding chain)
35. **GAP-088** — Technology version extraction universal (P0 — 0 new requests, parse existing headers)
36. **GAP-084** — CORS analysis (HIGH — 0 new requests, classic misconfig)
37. **GAP-087** — Generic backup file patterns (HIGH — shared hosting SEA, add paths)
38. **GAP-093** — Certificate SAN extraction (MED — 0 new requests, TLS handshake reuse)
39. **GAP-085** — HTTP method enumeration (MED — 1 OPTIONS request)
40. **GAP-081** — Port scanning / non-HTTP service (HIGH — but Med-High effort, stealth concern)
41. **GAP-082** — SMTP enumeration (MED — depends on GAP-081)
42. **GAP-090** — Email pattern inference (MED — 0 requests, but needs breach data source)
43. **GAP-091** — GitHub/GitLab public code search (MED — classic OSINT, needs API token)
44. **GAP-086** — Favicon hash fingerprinting (LOW — nice-to-have)
45. **GAP-092** — ASN/netblock discovery (LOW — niche infrastructure)
46. **GAP-083** — Virtual host discovery (LOW — niche, origin IP only)
47. **GAP-094** — DNS zone transfer AXFR (LOW — rarely succeeds, jackpot when it does)
48. **GAP-095** — Social media company page recon (MED — overlaps GAP-069 Trust Graph)

### Beta Initial-Access Completeness (NEW — Alpha findings → Beta consumption)

49. **GAP-096** — CSRF token extraction (HIGH — Laravel/Spring/Django login fails without it)
50. **GAP-097** — JSON API login applicator (HIGH — SPA/Vue/React login via JSON POST)
51. **GAP-099** — MFA/2FA challenge detection (HIGH — false negative: valid cred reported as FAILED)
52. **GAP-104** — Breach credential tool (HIGH — real leaked passwords, highest-value cred-reuse)
53. **GAP-098** — reCAPTCHA / hCaptcha solving (MED — or detect + honest blocked outcome)
54. **GAP-100** — Account lockout detection (MED — stop wasting attempts on locked accounts)
55. **GAP-101** — API key authentication applicator (MED — leaked API keys not tried)
56. **GAP-102** — Session cookie riding (MED — harvested cookie = instant access)
57. **GAP-103** — Cross-service cred reuse SSH/Redis (MED — DB password = SSH password)
58. **GAP-105** — Beta CVE consumption for exploit entry (MED — Alpha finds CVE, Beta ignores)
59. **GAP-106** — Login redirect chain following (MED — SSO multi-hop redirect misclassified)
60. **GAP-107** — First-login password change detection (LOW — honest outcome classification)
61. **GAP-108** — Password reset flow user enumeration (MED — reset endpoint = enum vector)
62. **GAP-109** — Beta entry selection ignores WAF capability (MED — strike WAF-protected first)
63. **GAP-110** — Beta credential prioritization lacks graph edges (MED — graph-based cred priority)
64. **GAP-111** — DB dump hash extraction (MED — prerequisite for offline crack)
65. **GAP-112** — Offline hash cracking tool (HIGH — avoids lockout, 0 target touch, but HIGH effort)
66. **GAP-113** — Password reset abuse (MED — bypass cred entirely, host header injection + token prediction)
67. **GAP-114** — OAuth/SAML/JWT token theft and forgery (MED — modern auth bypass, HIGH effort)

### ADR §12.61 Flank-when-CF-hard (NEW — origin discovery + perimeter skip)

Per ADR §12.61 recommended order: "(1) Historical DNS → (2) cert/favicon pivot → (3) leaked-cred stuffing."

68. **GAP-115** — Historical DNS origin discovery (HIGH — ADR §12.61 A1, biggest missing signal, 4 field targets failed without it)
69. **GAP-093** — Certificate SAN extraction (MED — ADR §12.61 A3, cert pivot, 0 new requests)
70. **GAP-086** — Favicon hash fingerprinting (LOW — ADR §12.61 A3, favicon pivot via Shodan/Censys)
71. **GAP-104** — Breach credential tool (HIGH — ADR §12.61 B5, #1 real-APT vector, valid creds walk through CF)
72. **GAP-054** — WP REST user email/roles (LOW — ADR §12.61 B5 prerequisite, email = breach query input)
73. **GAP-090** — Email pattern inference (LOW — ADR §12.61 B5 prerequisite, generate candidates)
74. **GAP-091** — GitHub/GitLab public code search (MED — ADR §12.61 B6, exposed secrets in public repos)
75. **GAP-076** — Cloud storage / shadow-IT discovery (MED — ADR §12.61 B7, S3/GCS, no CF protection)
76. **GAP-075** — Subdomain takeover check (LOW — ADR §12.61 A4+B8, dangling CNAME, DNS only)
77. **GAP-062** — TLS/MX/SPF/DMARC (LOW — ADR §12.61 A2, MX = origin netblock, passive)

### ADR-LOCKED Implementation Gaps (NEW — design decided, code NOT built)

78. **GAP-116** — Authenticated crawl / post-access re-recon (HIGH — §12.32 LOCKED, code NOT BUILT, 0 auth-vs-unauth diff in codebase)
79. **GAP-117** — Credential pattern mutation (MED — §12.34 LOCKED, CredentialPatternMutator NOT BUILT, cred_reuse literal only)
80. **GAP-118** — Proof standard oracle — auth-vs-unauth diff (HIGH — §12.43, CredReuseAttestor is provenance not oracle, findings NOT payable per §12.43)
81. **GAP-119** — Credential-result semantics — negative outcome (MED — §12.45, Beta reports FAILED without methodology caveat, false assurance risk)

### APT Emulation Gaps (NEW — from APT architect assessment 2026-08-13)

82. **GAP-120** — IPv6 attack surface recon (MED — forgotten IPv6 hardening, AAAA record bypass CF)
83. **GAP-121** — DNSSEC zone walking (LOW — passive NSEC subdomain enum, DNSSEC-only zones)
84. **GAP-122** — SMTP bounce-back analysis (LOW — 550 error leaks Exchange version, internal infra)
85. **GAP-123** — Certificate Transparency delay analysis (MED — pre-CF certs leak origin IP in SAN)
86. **GAP-124** — Job posting / tech stack mining (LOW — passive OSINT, low value for SEA market)
87. **GAP-125** — Deception detection (LOW-MED — honeypot/canary/sinkhole awareness, APT-grade)

### APT Architect Assessment — Slice 3+4 (2026-08-13)

88. **GAP-126** — Document metadata intel (MED — employee names, internal hostname, software version from PDF/DOCX/EXIF; needs document discovery + fetch + parse)
89. **GAP-127** — SaaS vendor integration map (MED — DNS TXT reveals Zendesk/Atlassian/Google/Slack; 0 target touch, 1 DNS query)
90. **GAP-128** — Timezone-aware pacing (MED — StealthPacer adjust to target SOC hours; from HTTP Date header or geo-IP; ~20 lines)
91. **GAP-129** — VPN/Remote Access fingerprinting (HIGH — expand GAP-081 beyond HTTP; IKEv2/OpenVPN/WireGuard/TeamViewer/AnyDesk; primary APT entry vector)
92. **GAP-130** — OAuth app enumeration (MED — target's OAuth apps = trust boundary; APT29 Nobelium pattern; passive platform API)
93. **GAP-131** — Refresh token abuse (MED — OAuth refresh token regenerates access token after expiry; complement GAP-114)

### Ledger Completeness Audit (2026-08-13) — Missing Holes from APT parity review

> Audit context: 131 GAPs reviewed against MITRE ATT&CK external red team tradecraft + SEA market specifics. Ledger completeness ~35% of APT parity. Missing holes below are NOT in any prior section. They are registered here so GAP-045 (CF-ceiling honest-outcome) can enumerate "tested vs untested" honestly — without this, the defensive-validation report cannot bound its own claim.

#### A. Genuinely missing — must be built for APT parity

94. **GAP-132** — Mobile app attack surface (HIGH — SEA = mobile-first; APK/IPA decompile via apktool/jadx reveals hardcoded origin IPs, API keys, Firebase config, OAuth client secrets; bypasses CF entirely; Play Store/App Store = public, 5-min reverse)
95. **GAP-133** — Business logic RISK detection (Phase 4 recon — DETECTION only, NOT exploitation; HIGH — flag cart endpoint accepts price/qty params, sequential order IDs = IDOR candidate, role parameter in POST = priv-esc candidate, coupon endpoint = race candidate; scanner CANNOT find this = MOAT; EXPLOITATION = §12.51 Gamma ExploitSynthesizer, DEFERRED to Phase 5/6 per doctrine line 2521; this GAP = surface risk for Gamma, does NOT change state)
96. **GAP-134** — API enumeration beyond login (HIGH — /api/v1/users, /api/v1/admin, /api/internal/*; GAP-097 = login only, not endpoint enumeration; Swagger/OpenAPI spec as discovery target, not soft-404 suppression)
97. **GAP-135** — GraphQL introspection + field suggestion (MED-HIGH — /graphql with introspection = full schema dump; currently /graphql is in soft-404 suppression list = SUPPRESSED not probed; __schema/__type queries)
98. **GAP-136** — SSRF + cloud metadata (IMDS) exposure (MED-HIGH — image proxy / URL fetch / PDF generator → 169.254.169.254 = AWS IAM creds; #1 cloud attack vector; not in any existing GAP)
99. **GAP-137** — File upload abuse (MED — avatar/document upload: .php webshell, .svg XSS+SSRF, path traversal in filename, content-type bypass; WooCommerce/SEA e-commerce = common upload surface)
100. **GAP-138** — HTTP request smuggling (MED-HIGH — CL.TE / TE.CL desync between CF edge and origin; bypass WAF, cache poisoning, session hijack; CF + origin mismatch = classic vector)
101. **GAP-139** — Web cache poisoning (MED — unkeyed header → poison CDN cache for all users; X-Forwarded-Host reflected → cached; CDN-target interaction)
102. **GAP-140** — WebSocket attack surface (MED — ws:// / wss:// often bypass WAF inspection; auth bypass via WebSocket frame; real-time chat/notification endpoints)
103. **GAP-141** — JavaScript dependency CVE (MED — jQuery <3.5 prototype pollution, Angular <1.8 XSS bypass, moment.js ReDoS; GAP-058 = secrets only, NOT dependency version → CVE chain)
104. **GAP-142** — Source map exposure (MED — app.js.map / vendor.js.map = full unminified source; reveals internal API routes, component names, business logic)
105. **GAP-143** — Database direct exposure enumeration (HIGH — expand GAP-081: MongoDB 27017, Elasticsearch 9200, Redis 6379, CouchDB 5984, Cassandra 9042, Memcached 11211; Shodan confirms thousands exposed in ID/VN/TH; no-auth = data leak/RCE)
106. **GAP-144** — FTP/SFTP anonymous access (MED — port 21 FTP anonymous login on shared hosting SEA (Hostinger/Niagahoster); browsable directory = source/backup leak; port 22 SFTP cred-stuff)
107. **GAP-145** — SNMP enumeration (LOW-MED — port 161 UDP, community string public/default = system info, processes, network config, internal hostname)
108. **GAP-146** — Hidden parameter discovery (MED — Arjun/param-miner style: ?admin=true, ?debug=1, hidden params not in UI but server accepts; admin panel activation)
109. **GAP-147** — Race condition / TOCTOU testing (MED — coupon apply 2x, withdraw 2x, vote manipulation; e-commerce logic gap; requires concurrent request tooling)
110. **GAP-148** — Error message information disclosure (LOW-MED — 500 stack trace = framework version, file paths, DB type; SQL error = table/column names; PHP debug = full config)
111. **GAP-149** — Open redirect enumeration (MED — /redirect?url=https://evil.com; phishing vector, OAuth token theft via redirect_uri, SSRF filter bypass; GAP-113 = host header only, not standalone redirect)
112. **GAP-150** — CSP analysis for attack surface mapping (LOW-MED — script-src trusted external = attack surface; connect-src = allowed backend origins = origin discovery; GAP-055 = presence check only, not trust-boundary analysis)
113. **GAP-151** — CDN origin shield bypass (MED — Cloudflare Argo Tunnel, AWS CloudFront origin shield; shield IP discovery = bypass edge entirely)
114. **GAP-152** — DNS rebinding for SSRF bypass (LOW-MED — domain resolves to 127.0.0.1 after first DNS check; access internal services via "external" URL; bypass SSRF allowlists)

#### B. Intentionally OUT OF SCOPE — DOCUMENTED (not to build, but to bound GAP-045 claim)

> These are deliberately excluded from Agent-Alpha's remote SaaS model. They are recorded here so the GAP-045 defensive-validation report can enumerate "tested vs untested vs out-of-scope" honestly. Without this section, a reviewer cannot distinguish "deliberate exclusion" from "oversight."

115. **OOS-1** — Phishing / pretexting for credentials (OUT OF SCOPE — human interaction + legal exposure; real APT #1 vector but requires human target contact; deferred indefinitely)
116. **OOS-2** — Vishing (voice phishing) (OUT OF SCOPE — phone-based social engineering; legal + human interaction)
117. **OOS-3** — Physical access (office entry, USB drop, lock picking) (OUT OF SCOPE — on-site, not remote SaaS)
118. **OOS-4** — Wireless (WiFi near target office, evil twin, deauth) (OUT OF SCOPE — on-site, not remote SaaS)
119. **OOS-5** — Supply chain compromise (vendor/plugin/theme attack) (OUT OF SCOPE — different engagement type; SolarWinds/Kaseya/3CX pattern; requires vendor access)
120. **OOS-6** — Social engineering (LinkedIn manipulation, impersonation) (OUT OF SCOPE — human manipulation, legal exposure; GAP-069 defers LinkedIn OSINT but not active manipulation)
121. **OOS-7** — Insider threat (disgruntled employee, credential sale) (OUT OF SCOPE — requires insider access, different engagement scope)

#### C. Partially covered — existing GAPs need expansion (registered for tracking)

122. **EXP-1 (GAP-081)** — Port scan does not enumerate DB-specific protocols per-service (MongoDB, Elasticsearch, Redis, CouchDB, Cassandra, Memcached) — see GAP-143
123. **EXP-2 (GAP-055)** — Security headers does not include CSP trust-boundary analysis — see GAP-150
124. **EXP-3 (GAP-058)** — JS secret extraction does not include dependency version → CVE chain — see GAP-141
125. **EXP-4 (GAP-085)** — HTTP methods does not include WebDAV-specific verbs (PROPFIND, MOVE, COPY, MKCOL on /webdav)
126. **EXP-5 (GAP-087)** — Backup file patterns does not include directory patterns (/backup/, /db/, /sql/, /dump/, /tmp/)
127. **EXP-6 (GAP-062)** — TLS/MX/SPF/DMARC does not include DMARC policy analysis (p=none vs quarantine vs reject; p=none = email spoofing possible)
128. **EXP-7 (GAP-099)** — MFA detection does not include MFA bypass (SIM swap, TOTP reuse, push fatigue, RTOP)

### Enhancements to existing GAPs (2026-08-13)

94. **ENH-1 (GAP-113)** — Automated token entropy analysis: request 3 reset tokens, analyze randomness. Predictable token = critical finding
95. **ENH-2 (GAP-108)** — Response time differential for user enum: valid user = 200ms, invalid = 50ms. More accurate than message differential
96. **ENH-3 (GAP-116)** — TOTP secret exposure detection: after authenticated crawl, check if profile page displays valid TOTP QR code = critical finding

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
- GAP-096 — CSRF token extraction for form-login applicators (OPEN.)
- GAP-097 — JSON API login applicator (SPA/REST login) (OPEN.)
- GAP-098 — reCAPTCHA / hCaptcha solving for login forms (OPEN.)
- GAP-099 — MFA/2FA challenge detection and honest classification (OPEN.)
- GAP-100 — Account lockout detection (target-side) (OPEN.)
- GAP-101 — API key authentication applicator (OPEN.)
- GAP-102 — Session cookie riding (harvested cookie reuse) (OPEN.)
- GAP-103 — Cross-service credential reuse (SSH/Redis/SMTP) (OPEN.)
- GAP-104 — Breach credential tool (Dehashed/HIBP integration) (OPEN.)
- GAP-105 — Beta CVE consumption for exploit-based entry (OPEN.)
- GAP-106 — Login redirect chain following (OPEN.)
- GAP-107 — First-login password change detection (OPEN.)
- GAP-108 — Password reset flow user enumeration (OPEN.)
- GAP-109 — Beta entry selection ignores WAF capability (OPEN.)
- GAP-110 — Beta credential prioritization lacks graph edges (OPEN.)
- GAP-111 — DB dump hash extraction (MySQL/wp_users/phpass) (OPEN.)
- GAP-112 — Offline hash cracking tool (hashcat/john integration) (OPEN.)
- GAP-113 — Password reset abuse (host header injection, token prediction) (OPEN.)
- GAP-114 — OAuth/SAML/JWT token theft and forgery (OPEN.)
- GAP-115 — Historical DNS origin discovery / ADR §12.61 A1 (OPEN.)
- GAP-116 — Authenticated crawl / post-access re-recon implementation (§12.32 ADR LOCKED, code NOT BUILT) (OPEN.)
- GAP-117 — Credential pattern mutation implementation (§12.34 ADR LOCKED, code NOT BUILT) (OPEN.)
- GAP-118 — Proof standard oracle — auth-vs-unauth diff (§12.43) (OPEN.)
- GAP-119 — Credential-result semantics — negative outcome classification (§12.45) (OPEN.)
- GAP-120 — IPv6 attack surface recon (forgotten hardening) (OPEN.)
- GAP-121 — DNSSEC zone walking (NSEC record enumeration) (OPEN.)
- GAP-122 — SMTP bounce-back analysis (internal infra leak) (OPEN.)
- GAP-123 — Certificate Transparency delay analysis (post-CF origin leak) (OPEN.)
- GAP-124 — Job posting / tech stack mining (infrastructure inference) (OPEN.)
- GAP-125 — Deception detection (honeypot / canary token / sinkhole) (OPEN.)
- GAP-126 — Document metadata intel (PDF/DOCX/EXIF from public files) (OPEN.)
- GAP-127 — SaaS vendor integration map (DNS TXT verification records) (OPEN.)
- GAP-128 — Timezone-aware pacing (SOC-hours targeting) (OPEN.)
- GAP-129 — VPN/Remote Access fingerprinting (expand GAP-081) (OPEN.)
- GAP-130 — OAuth app enumeration (trust boundary mapping) (OPEN.)
- GAP-131 — Refresh token abuse (OAuth session persistence) (OPEN.)

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

### Service Discovery & Infrastructure (NEW)

- GAP-081 — Port scanning / non-HTTP service discovery (OPEN.)
- GAP-082 — SMTP enumeration (VRFY/EXPN/RCPT) (OPEN.)
- GAP-083 — Virtual host discovery (Host header enumeration) (OPEN.)
- GAP-092 — ASN/netblock discovery (sister infrastructure) (OPEN.)
- GAP-093 — Certificate SAN extraction (live cert, not CT log) (OPEN.)
- GAP-094 — DNS zone transfer attempt (AXFR) (OPEN.)

### HTTP Content & Configuration (NEW)

- GAP-084 — CORS analysis (Access-Control-Allow-Origin) (OPEN.)
- GAP-085 — HTTP method enumeration (OPTIONS) (OPEN.)
- GAP-086 — Favicon hash fingerprinting (mmh3) (OPEN.)
- GAP-087 — Generic backup file patterns (backup.zip, db.sql, dump.sql) (OPEN.)
- GAP-088 — Technology version extraction (universal, beyond WP) (OPEN.)
- GAP-089 — CVE catalog comprehensiveness (only 1 entry today) (OPEN.)

### OSINT & Organizational (NEW)

- GAP-090 — Email pattern inference (firstname@, first.last@, flast@) (OPEN.)
- GAP-091 — GitHub/GitLab public code search (employee repos) (OPEN.)
- GAP-095 — Social media company page recon (FB/IG/Twitter) (OPEN.)

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
- Status: ADR LOCKED in §12.32 (2026-07-15). Implementation = OPEN (see GAP-116).
- Priority: Medium
- Category: —
- Stack: Cognition
- What: After Beta obtains `valid_credentials`, re-crawl with an active session; diff unauth vs auth surfaces. Exploitation remains Gamma-gated.
- Cross-ref: `docs/ADR.md` §12.32 *"Post-access authenticated re-recon"*, **GAP-116** (implementation gap — ADR is design decision, code is NOT BUILT)
- Effort: —
- Note: Full boundary rules are now in ADR §12.32. **MOVED ≠ IMPLEMENTED.** ADR is locked (design decided) but `grep "AuthenticatedCrawl" ` = 0 results in codebase. Implementation tracked as GAP-116.
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
- Status: ADR LOCKED in §12.34 (2026-07-15). Implementation = OPEN (see GAP-117).
- Priority: Low-Medium
- Category: —
- Stack: Cognition
- What: `CredentialPatternMutator` extracts patterns from harvested credentials, generates bounded variants, and tries them only after literal reuse fails and under the lockout governor.
- Cross-ref: `docs/ADR.md` §12.34 *"Within-engagement credential mutation"*, **GAP-117** (implementation gap — ADR is design decision, code is NOT BUILT)
- Effort: —
- Note: Full mutation and gating rules are now in ADR §12.34. **MOVED ≠ IMPLEMENTED.** ADR is locked (design decided) but `grep "CredentialPatternMutator" ` = 0 results in codebase. Implementation tracked as GAP-117.
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


# Service Discovery & Infrastructure

## GAP-081 — Port scanning / non-HTTP service discovery
- Status: OPEN.
- Priority: HIGH — external red team must know ALL exposed services, not just HTTP.
- Category: RM
- Stack: Universal
- What: Alpha only performs HTTP recon. `AssetProperties.open_ports` exists in the schema but is only populated for SOW-declared DB endpoints via `db_service_probe.py`. No port scanning of common service ports (SSH 22, RDP 3389, SMTP 25/465/587, FTP 21, Redis 6379, MongoDB 27017, PostgreSQL 5432, MySQL 3306, Elasticsearch 9200, Docker 2375/2376). A real external red team scans ALL ports first — an exposed Redis without auth, an open RDP, or a Docker API on 2375 are immediate high-severity findings. Agent-Alpha is blind to these.
- Evidence: `grep "nmap|masscan|portscan"` in `agent_alpha/` = 0 results. `AssetProperties.open_ports` only populated by `db_service_probe.py` for SOW-declared endpoints. No TCP connect scan, no SYN scan, no banner grab on non-HTTP ports.
- Files: `agent_alpha/graph/nodes.py:52-66` — AssetProperties (open_ports field exists, mostly empty); `agent_alpha/recon/db_service_probe.py` — only non-HTTP probe, SOW-gated only; no general port scanner module
- Cross-ref: GAP-082 (SMTP enum — depends on port 25 being discovered), GAP-062 (TLS/MX/SPF — related infrastructure recon). ADR §8g (OS-as-a-Tools — nmap is operator-side tooling, not Agent-Alpha dependency).
- Impact: Target can have Redis exposed without auth (classic RCE), Docker API on 2375 (full host compromise), or RDP open (cred-stuff target). Alpha never discovers these. Missed high-severity findings that Nuclei/Nmap DO find.
- Effort: MED-HIGH (TCP connect scan on top-20 ports + banner grab. Stealth concern: must be slow (1 port per 5-10s), must use stealth timing. Cannot use nmap subprocess — must be Python socket-based per §8g. New module + AssetProperties population).
- Constraint: Must respect §12.49 (stealth by default). Port scan rate must be throttled. Scope gate: only scan IPs in `is_in_scope`. No full 65535-port scan — top-20 common service ports only.

---

## GAP-082 — SMTP enumeration (VRFY/EXPN/RCPT)
- Status: OPEN.
- Priority: MEDIUM — mail server username enumeration, depends on GAP-081.
- Category: SS
- Stack: Universal
- What: If port 25/465/587 is open (discovered by GAP-081), SMTP servers often support `VRFY` (verify user exists), `EXPN` (expand mailing list), and `RCPT TO` (recipient validation). These reveal valid email addresses and usernames — direct input for cred-spray and breach correlation. A real external red team always checks SMTP enumeration on open mail servers.
- Evidence: `grep "SMTP|VRFY|EXPN|RCPT"` in `agent_alpha/` = 0 results. No SMTP client module.
- Files: No SMTP module exists. `agent_alpha/recon/` — no smtp_probe.py
- Cross-ref: GAP-081 (port scan — prerequisite), GAP-090 (email pattern inference — SMTP validates generated candidates), GAP-047 (username harvest — SMTP is another harvest source).
- Impact: Missed username enumeration vector. Valid email addresses from SMTP = cred-spray targets = potential access.
- Effort: LOW (smtplib + VRFY/EXPN commands + response parsing. ~80 lines. Depends on GAP-081 discovering port 25).
- Constraint: Max 5 VRFY commands per server (anti-lockout). Must be stealthy (long delay between commands). Only on in-scope IPs.

---

## GAP-083 — Virtual host discovery (Host header enumeration)
- Status: OPEN.
- Priority: LOW — niche, only relevant when origin IP hosts multiple sites.
- Category: SS
- Stack: Universal
- What: When Alpha discovers an origin IP (e.g. `168.110.192.62`), it probes it with the target's `Host` header. But the same IP may host OTHER sites — virtual hosts. By sending different `Host:` headers (`Host: admin`, `Host: staging`, `Host: test`, `Host: localhost`), the origin may respond with different content, revealing hidden admin panels, staging environments, or internal tools that have no public DNS record.
- Evidence: `grep "vhost|virtual.*host|Host.*header.*enum"` in `agent_alpha/` = 0 results. Origin probe only uses the target's own hostname.
- Files: `agent_alpha/recon/origin_binding.py` — origin probe uses target Host only; no vhost enumeration
- Cross-ref: GAP-033 (subdomain pivot — related concept: attack via alternative hostname), GAP-093 (cert SAN — SANs reveal vhost candidates).
- Impact: Missed hidden virtual hosts on origin IP. Staging/admin panels without DNS = high-value findings.
- Effort: MED (Host header wordlist + differential response analysis. Must compare response body/hash per Host header. Stealth: 5-10 headers max, slow pacing).

---

## GAP-092 — ASN/netblock discovery (sister infrastructure)
- Status: OPEN.
- Priority: LOW — infrastructure discovery, niche value.
- Category: RG
- Stack: Universal
- What: Target IP `45.80.182.6` belongs to an ASN (Autonomous System). Other IPs in the same netblock may host sister domains, staging servers, internal services, or backup infrastructure — all potentially in-scope. Alpha resolves the target IP but does not query ASN/netblock information (via RDAP/BGP APIs like `bgp.he.net` or `ipinfo.io`) to discover adjacent infrastructure.
- Evidence: `grep "ASN|netblock|BGP|RDAP"` in `agent_alpha/` — ASN only used in authorization scope validation (`models.py:83`), not for recon. No netblock discovery module.
- Files: `agent_alpha/conductor/models.py:83` — ASN in scope validation only; no recon module for netblock discovery
- Cross-ref: GAP-081 (port scan — scan discovered netblock IPs), GAP-007 (OSINT — ASN is infrastructure OSINT).
- Impact: Missed sister infrastructure. Same netblock may host `staging.niagamas.com` (no DNS, no CT log) that is more vulnerable than production.
- Effort: MED (RDAP/BGP API query + netblock CIDR extraction + reverse DNS per IP. Passive, 0 target touch. But result volume can be large — needs filtering).

---

## GAP-093 — Certificate SAN extraction (live cert, not CT log)
- Status: OPEN.
- Priority: MEDIUM — reveals internal hostnames not in CT logs.
- Category: RM
- Stack: Universal
- What: Alpha uses crt.sh/CertSpotter (CT logs) for subdomain discovery. But internal certificates (self-signed, private CA, or internal-only SANs) are NOT in CT logs. The live TLS certificate served by the target may contain SANs (Subject Alternative Names) like `erp.niagamas.internal`, `admin.niagamas.local`, or `staging.niagamas.com` that CT logs never recorded. A TLS handshake to the target (which Alpha already does for HTTPS) can extract these SANs.
- Evidence: `grep "SAN|subject.*alternative|cert.*extract"` in `agent_alpha/` = 0 results. No certificate SAN extraction in any recon module. crt.sh is used but live cert SANs are not.
- Files: `agent_alpha/recon/origin_resolver.py` — TLS connection made but cert not parsed for SANs; `agent_alpha/recon/passive_discovery.py` — CT log only
- Cross-ref: GAP-016 (Wayback — historical URLs), GAP-075 (subdomain takeover — SANs reveal subdomain candidates). §12.48 (Passive-First Recon — cert SANs are passive).
- Impact: Missed internal hostnames. `erp.niagamas.internal` in SAN = internal ERP server hostname revealed. No CT log, no DNS, but the cert tells you it exists.
- Effort: LOW (Python `ssl` module — connect to target, get cert, parse `cert.extensions` for SANs. ~30 lines. 0 additional requests — reuse existing TLS connection).

---

## GAP-094 — DNS zone transfer attempt (AXFR)
- Status: OPEN.
- Priority: LOW — rarely succeeds but jackpot when it does.
- Category: SS
- Stack: Universal
- What: DNS zone transfer (AXFR) is a misconfiguration where the authoritative nameserver allows anyone to download the entire DNS zone file — revealing ALL subdomains, internal records, TXT records, MX records, and internal hostnames in one query. It rarely succeeds on modern infrastructure (most NS are configured to refuse AXFR), but when it does, it's a jackpot. A real external red team always tries. The check is a single DNS query to the authoritative NS — zero target HTTP touch.
- Evidence: `grep "AXFR|zone.*transfer"` in `agent_alpha/` = 0 results. No AXFR attempt in any DNS module.
- Files: `agent_alpha/recon/passive_intel.py` — DNS enrichment (MX/NS/TXT) but no AXFR; no zone transfer module
- Cross-ref: GAP-075 (subdomain takeover — AXFR reveals all CNAME records), GAP-093 (cert SAN — complementary subdomain source).
- Impact: Missed "jackpot" finding. Successful AXFR = entire DNS zone = all internal hostnames, all CNAMEs (subdomain takeover candidates), all TXT records (SPF/DKIM/verification tokens).
- Effort: LOW (dnspython `resolver.resolve(domain, "AXFR")` against each authoritative NS. ~20 lines. 1 DNS query per NS. Fail-open: most will refuse, that's OK).

---


# HTTP Content & Configuration

## GAP-084 — CORS analysis (Access-Control-Allow-Origin)
- Status: OPEN.
- Priority: HIGH — classic misconfig, 0 new requests, Nuclei detects this.
- Category: RM
- Stack: Universal
- What: Alpha fetches the homepage and API endpoints but does NOT analyze CORS headers. `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` is a critical misconfiguration — it allows any website to make authenticated cross-origin requests, enabling data theft from a victim's browser. Other CORS issues: reflected origin, null origin (exploitable via sandboxed iframes). These are textbook findings that conventional scanners detect.
- Evidence: `grep "CORS|Access-Control-Allow"` in `agent_alpha/` = 0 results. No CORS analysis in any handler. Headers are fetched but CORS headers are not parsed.
- Files: `agent_alpha/agents/alpha/scout.py` — no CORS handler; `agent_alpha/recon/capability_probe.py` — no CORS probe
- Cross-ref: GAP-055 (security headers — CORS is related but distinct: security headers = missing defensive headers, CORS = permissive cross-origin policy).
- Impact: Missed misconfiguration finding. `*` + `Allow-Credentials: true` = high-severity. Nuclei detects this — Agent-Alpha must also.
- Effort: LOW (parse `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods` from existing responses. Send `Origin: https://test.com` header on 1 probe to test reflected origin. ~40 lines. 0-1 new requests).

---

## GAP-085 — HTTP method enumeration (OPTIONS)
- Status: OPEN.
- Priority: MEDIUM — PUT/DELETE/TRACE enabled = attack surface; 1 request.
- Category: RM
- Stack: Universal
- What: Alpha does not send `OPTIONS /` to discover allowed HTTP methods. Enabled dangerous methods: `PUT` (potential file upload/overwrite), `DELETE` (potential file deletion), `TRACE` (XST — Cross-Site Tracing, reflects cookies), `CONNECT` (proxy tunneling). These are misconfigurations that expand the attack surface. A real external red team always checks allowed methods.
- Evidence: `grep "OPTIONS|allowed_methods|verb.*tamper"` in `agent_alpha/` = 0 results. No HTTP method enumeration.
- Files: `agent_alpha/agents/alpha/scout.py` — no OPTIONS handler; `agent_alpha/recon/capability_probe.py` — no method probe
- Cross-ref: GAP-077 (auth bypass via verb tampering — GET instead of POST on login).
- Impact: Missed dangerous method exposure. PUT enabled = potential webshell upload. TRACE = cookie theft via XST.
- Effort: LOW (1 `OPTIONS /` request + parse `Allow` header. ~20 lines. Stealth: 1 request only).

---

## GAP-086 — Favicon hash fingerprinting (mmh3)
- Status: OPEN.
- Priority: LOW — nice-to-have, framework/version identification.
- Category: RM
- Stack: Universal
- What: The favicon (`/favicon.ico`) of a web application can be hashed (mmh3 hash) to identify the specific framework, application, or version. Shodan and Censys use this extensively — same favicon hash = same application instance. For example, a specific Odoo version has a specific favicon hash; a Jenkins instance has a recognizable favicon. Alpha does not fetch `/favicon.ico` or compute its hash.
- Evidence: `grep "favicon|mmh3|icon.*hash"` in `agent_alpha/` = 0 results. No favicon fetch or hash.
- Files: `agent_alpha/agents/alpha/scout.py` — no favicon handler; no mmh3 dependency
- Cross-ref: GAP-088 (version extraction — favicon hash is another version ID vector), GAP-089 (CVE catalog — favicon hash can map to known-vulnerable versions).
- Impact: Missed framework/version identification vector. Useful for correlating "same app on different subdomains" and for version fingerprinting when headers are stripped.
- Effort: LOW (fetch `/favicon.ico`, compute mmh3 hash, compare against known hash database. ~40 lines. 1 request. Needs mmh3 dependency).

---

## GAP-087 — Generic backup file patterns (backup.zip, db.sql, dump.sql)
- Status: OPEN.
- Priority: HIGH — very common in shared hosting SEA; direct data exposure.
- Category: RM
- Stack: Universal
- What: `BACKUP_FILE_PATHS` in `constants.py` covers `.env.bak`, `.env.save`, `.env~`, `.env.old`, `.env.orig`, `config/database.yml.bak`, and `wp-config.php.bak` variants. But it does NOT cover generic backup file patterns common in shared hosting (especially Indonesia/SEA): `backup.zip`, `backup.tar.gz`, `backup.tar`, `site.zip`, `web.zip`, `www.zip`, `db.sql`, `dump.sql`, `database.sql`, `backup.sql`, `data.sql`. These files, when exposed, contain full site source + database dumps = direct credential and PII exposure.
- Evidence: `constants.py:394-402` — `BACKUP_FILE_PATHS` only covers `.env` and `wp-config` variants. No generic backup archive patterns.
- Files: `agent_alpha/config/constants.py:394-402` — BACKUP_FILE_PATHS (incomplete); `agent_alpha/recon/path_probe.py` — probes these paths
- Cross-ref: GAP-058 (JS secret extraction — backup files may contain JS with secrets too), Bug #26 (blind probing — these paths must be stack-gated, not blindly probed).
- Impact: Missed database dump or site backup exposure. `db.sql` on a shared hosting target = full database = all user credentials, PII, admin passwords. High-severity payable finding.
- Effort: LOW (add ~10 paths to `BACKUP_FILE_PATHS`. Must be stack-gated: only probe generic backups on shared-hosting targets (cPanel/Hostinger signatures), not on every target — anti-Bug #26).

---

## GAP-088 — Technology version extraction (universal, beyond WP)
- Status: OPEN.
- Priority: P0 — version extraction is useless without CVE lookup (GAP-089); this is the prerequisite.
- Category: RM
- Stack: Universal
- What: Alpha extracts WP version and PHP version (via `x-powered-by` header → tech_stack). But it does NOT extract versions for: nginx (`Server: nginx/1.18.0`), Apache (`Server: Apache/2.4.41`), MariaDB/MySQL (from DB handshake), Odoo (from `/website/info` — GAP-065), Laravel (from `Whoops` debug page or `X-Laravel` header). These versions are already in response headers that Alpha fetches but discards. Without version extraction as SERVICE nodes, CVE lookup (GAP-089) cannot fire for non-WP stacks.
- Evidence: `agents/alpha/scout.py:1532` — `x-powered-by` parsed for tech_stack only, not as SERVICE node with version. `Server` header parsed for tech_stack but version number dropped. `graph/nodes.py:86-91` — ServiceProperties has `version` field but rarely populated for non-WP.
- Files: `agent_alpha/agents/alpha/scout.py:1532` — header parsing (version dropped); `agent_alpha/graph/nodes.py:86-91` — ServiceProperties (version field exists, underused); `agent_alpha/recon/capability_probe.py` — no version extraction
- Cross-ref: GAP-089 (CVE catalog — version is prerequisite for CVE lookup), GAP-052 (WC version — stack-specific instance of this universal gap), GAP-065 (Odoo /website/info — stack-specific version source).
- Impact: Alpha knows "nginx is present" but not "nginx 1.18.0 which has CVE-2021-23017". CVE lookup cannot fire. Version → CVE → exploit chain is broken at the version step for all non-WP stacks.
- Effort: LOW (parse `Server` and `X-Powered-By` headers for version string → create SERVICE node with version. ~30 lines. 0 new requests — reuse existing responses).

---

## GAP-089 — CVE catalog comprehensiveness (only 1 entry today)
- Status: OPEN.
- Priority: P0 — version extraction (GAP-052, GAP-088) is useless without CVE lookup. This is the multiplier.
- Category: RG
- Stack: Universal
- What: `plugin_cve_catalog.py` contains exactly ONE CVE entry (`wp-file-manager` CVE-2020-25213). The catalog is supposed to map plugin/module/package versions to known CVEs, but it is effectively empty. Alpha can extract "contact-form-7 v5.6" or "nginx 1.18.0" but cannot determine if that version is vulnerable because the catalog has no data. A real external red team cross-references every extracted version against NVD, WPScan, ExploitDB, and nuclei templates. Without a comprehensive CVE catalog, version extraction is half-complete — Alpha knows the version but not the risk.
- Evidence: `recon/plugin_cve_catalog.py:14-23` — `_CATALOG` dict has 1 entry. No NVD feed integration, no WPScan DB, no ExploitDB, no nuclei template CVE list.
- Files: `agent_alpha/recon/plugin_cve_catalog.py` — 1 entry only; no NVD/WPScan/ExploitDB feed integration
- Cross-ref: GAP-052 (WC version — needs CVE catalog for CVE-2026-3589), GAP-053 (WP plugin handler — needs CVE catalog for plugin CVEs), GAP-088 (universal version extraction — needs CVE catalog), GAP-065 (Odoo /website/info — needs CVE catalog for Odoo module CVEs).
- Impact: Version extraction produces versions but no risk assessment. "nginx 1.18.0" in graph → no CVE match → no VULNERABILITY node → no finding. The entire version→CVE→exploit chain is broken at the catalog step.
- Effort: MED (data-tier: import NVD JSON feed + WPScan vulnerability DB + curated high-impact CVE list. Not code — data refresh. Catalog must be versioned and refreshable as data, not code. ~500-1000 entries for top WP plugins + nginx/Apache/PHP/Odoo/Laravel).

---


# OSINT & Organizational

## GAP-090 — Email pattern inference (firstname@, first.last@, flast@)
- Status: OPEN.
- Priority: MEDIUM — prerequisite for breach correlation (needs breach data source first).
- Category: RG
- Stack: Universal
- What: Alpha harvests usernames from WP REST (slug only — GAP-054) but does not infer email patterns. From one known email (`yudha@niagamas.com` from metadata/Wayback), Alpha can infer the company's email naming convention: `firstname@`, `first.last@`, `flast@`, `firstinitial+lastname@`, `firstname.lastname@`. This pattern, once inferred, generates candidate emails for ALL harvested usernames: `admin` → `admin@niagamas.com`, `siti` → `siti@niagamas.com`. These candidates are then cross-referenced against breach data (Dehashed/HIBP §12.54) to find leaked passwords.
- Evidence: `grep "email.*pattern|email.*infer|naming.*convention"` in `agent_alpha/` = 0 results. No email pattern inference module.
- Files: No email inference module. `agent_alpha/tools/internal/access/user_derived_creds.py` — derives creds from username + domain stem, but not email pattern inference.
- Cross-ref: GAP-054 (WP REST user email — if email is directly available, no inference needed), GAP-070 (credential-to-asset correlation — inferred emails feed the credential map), §12.54 (Dehashed/HIBP — breach data source, not yet wired).
- Impact: Without email pattern inference, breach correlation is limited to emails directly found in metadata. If metadata has `yudha@niagamas.com` but breach data has `y.niagamas@gmail.com`, the correlation fails. Pattern inference bridges this gap.
- Effort: LOW (pattern detection from known email + candidate generation for harvested usernames. ~60 lines. 0 requests — pure data manipulation. Depends on breach data source being wired).

---

## GAP-091 — GitHub/GitLab public code search (employee repos)
- Status: OPEN.
- Priority: MEDIUM — classic OSINT, developers leak credentials to public repos.
- Category: RG
- Stack: Universal
- What: Alpha does not search GitHub/GitLab for public repositories belonging to the target organization or its employees. Developers frequently commit sensitive files to public repos: `.env` files with API keys, `config/database.yml` with DB credentials, SSH private keys, internal API documentation, infrastructure Terraform files. This is distinct from GAP-058 (JS secret extraction from target's own website) — GAP-091 searches code that employees committed to PUBLIC repos, not the target's website. A real external red team always GitHub-dorks the target organization (`org:niagamas`, `niagamas.com password`, `niagamas.com API_KEY`).
- Evidence: `grep "github.*secret|github.*search|gitlab|public.*repo"` in `agent_alpha/` = 0 results. No GitHub code search module.
- Files: No GitHub search module. `agent_alpha/recon/osint_sources.py` — no GitHub source.
- Cross-ref: GAP-069 (Trust Graph — employee GitHub repos are part of organizational intelligence), GAP-058 (JS secrets — target's own JS, not employee repos), GAP-007 (OSINT — GitHub is an OSINT source).
- Impact: Missed credential leak via employee's public repos. Classic finding: developer pushes `.env` to public GitHub repo → DB credentials exposed → cred-reuse into production. Payable finding.
- Effort: MED (GitHub code search API + org/employee repo enumeration + file content scan for secrets. Needs GitHub API token (rate limit). ~200 lines. Legal: searching public repos is legal; using found credentials is SOW-gated).

---

## GAP-095 — Social media company page recon (FB/IG/Twitter)
- Status: OPEN.
- Priority: MEDIUM — organizational intelligence from public company pages.
- Category: RG
- Stack: Universal
- What: Alpha does not recon social media company pages. From the niagamas OSINT we already found Facebook (`facebook.com/ptniagamas`) and Instagram (`instagram.com/niagamaslestarigemilang`) via Wayback metadata. But there is no handler that captures these as graph nodes or extracts intelligence from them. Company social media pages reveal: admin list (who manages the page), post history (may screenshot internal tools), employee comments (may reveal tech stack complaints, VPN issues, password policy complaints), contact info (phone numbers, email addresses for help desk). This is public company page recon, NOT personal profile scraping — legal and ToS-compliant.
- Evidence: `grep "facebook|instagram|twitter.*recon|social.*media"` in `agent_alpha/` = 0 results (except in lab fixtures). No social media recon module. FB/IG links found in Wayback metadata but not captured as graph nodes.
- Files: No social media recon module. `agent_alpha/recon/osint_sources.py` — no FB/IG/Twitter source.
- Cross-ref: GAP-069 (Trust Graph — social media admins are employees with potential system access), GAP-007 (OSINT — social media is OSINT source).
- Impact: Missed organizational intelligence. Social media admin = potential WP admin = cred-reuse target. Post history may reveal internal tooling. Employee comments may reveal tech stack and IT complaints.
- Effort: MED (FB/IG Graph API for company page metadata + post history + admin detection. Twitter API for company handle. Needs API tokens. Legal: company page data is public, NOT personal profile scraping).
- Constraint: Company page ONLY. No personal profile scraping. No vishing, no phishing, no social engineering. v1 = metadata + post history only. Deferred items (per GAP-069 constraint): LinkedIn scraping, vishing, phishing = client-authorized slice with legal review.

---


# Beta Access — Alpha Finding Consumption Gaps

## GAP-096 — CSRF token extraction for form-login applicators
- Status: OPEN.
- Priority: HIGH — Laravel/Spring/Django login POST fails with 419/403 without CSRF token, even with valid credentials.
- Category: RM
- Stack: Universal (Laravel, Spring, Django, Express, custom)
- What: `HttpFormApplicator.apply()` and `WpLoginApplicator.apply()` POST username/password directly to the login endpoint. Many modern frameworks require a CSRF token in the POST body or header (Laravel: `_token` field from `<meta name="csrf-token">`, Spring: `_csrf` from session, Django: `csrfmiddlewaretoken` from form). Without extracting and including the CSRF token, the login POST returns 419 (Laravel), 403 (Spring/Django), or similar — even with VALID credentials. Beta reports FAILED when the credential is actually correct. This is a false-negative failure mode.
- Evidence: `applicator.py:116-191` — `HttpFormApplicator.apply()` does GET baseline then POST username/password. No CSRF token extraction from baseline response. `WpLoginApplicator.apply()` — same pattern, no CSRF extraction. WP doesn't use CSRF on login (uses nonce differently), but Laravel/Spring/Django DO.
- Files: `agent_alpha/tools/internal/access/applicator.py:92-191` — HttpFormApplicator (no CSRF); `agent_alpha/tools/internal/access/applicator.py:194-290` — WpLoginApplicator (no CSRF, but WP doesn't need it)
- Cross-ref: GAP-074 (auth mechanism fingerprinting — CSRF structure is part of mechanism), GAP-097 (JSON API login — JSON login may also need CSRF). laravel_real_lab — Laravel login requires `_token` field.
- Impact: Beta cannot log into ANY Laravel/Spring/Django target even with valid credentials. Login POST returns 419/403. False negative. The entire cred-reuse chain breaks for non-WP, non-Odoo frameworks.
- Effort: MED (extract CSRF token from baseline GET: parse `<meta name="csrf-token">`, `<input name="_token">`, `<input name="csrfmiddlewaretoken">`, or cookie `XSRF-TOKEN` → include in POST body/header. ~80 lines. Must be framework-aware: Laravel uses `_token`, Django uses `csrfmiddlewaretoken`, Spring uses `_csrf`).

---

## GAP-097 — JSON API login applicator (SPA/REST login)
- Status: OPEN.
- Priority: HIGH — Vue/React SPA login via JSON POST; no applicator exists.
- Category: SS
- Stack: Universal (Vue, React, Angular, custom REST API)
- What: `SPA_LOGIN_FORM` label exists in `auth_surface.py:60` but is NOT in `STRIKABLE_AUTH_LABELS` — Beta cannot strike it. The comment says "striking it needs a future SPA-login applicator." SPA login works via JSON POST to `/api/login` or `/api/auth/login` with `{"username": "...", "password": "..."}` body, NOT form-encoded POST. `HttpFormApplicator` sends `application/x-www-form-urlencoded` — wrong content type for JSON API. niagamas.com `pos.niagamas.com/admin/login` is a Vue.js SPA that logs in via JSON API. Beta tried form POST → failed.
- Evidence: `auth_surface.py:50` — `STRIKABLE_AUTH_LABELS = {HTTP_BASIC_AUTH, LOGIN_FORM}` — SPA_LOGIN_FORM excluded. `auth_surface.py:56-59` — comment: "needs a future SPA-login applicator." No `JsonLoginApplicator` in `applicator.py` or `applicator_factory.py`.
- Files: `agent_alpha/recon/auth_surface.py:50,60` — SPA_LOGIN_FORM not strikable; `agent_alpha/tools/internal/access/applicator.py` — no JSON applicator; `agent_alpha/conductor/applicator_factory.py:57-69` — beta_web_applicators only has WP + HttpForm
- Cross-ref: GAP-030 (SPA login detection — DONE for detection, but no applicator), GAP-074 (auth mechanism fingerprinting — JSON API is a mechanism), GAP-096 (CSRF — JSON login may also need CSRF via header).
- Impact: Beta cannot log into ANY SPA target (Vue, React, Angular). All modern web apps increasingly use JSON API login. Misses a growing category of targets.
- Effort: MED (new `JsonLoginApplicator`: POST `{"username": "...", "password": "..."}` with `Content-Type: application/json`, parse JSON response for `token`/`session`/`access_level`. ~100 lines. Must be added to `STRIKABLE_AUTH_LABELS` and `beta_web_applicators`).

---

## GAP-098 — reCAPTCHA / hCaptcha detection and solving for login forms
- Status: OPEN (split into two slices — 098a code-only, 098b infra+cost).
- Priority: MEDIUM — only CF Turnstile handled; reCAPTCHA v2/v3 + hCaptcha not detected or solved.
- Category: RM
- Stack: Universal
- What: `browser_solve_service.py` handles Cloudflare Turnstile (clicks checkbox via Playwright frame_locator). But reCAPTCHA v2 ("I'm not a robot" checkbox), reCAPTCHA v3 (invisible score-based), and hCaptcha are NOT handled. Many login forms use reCAPTCHA to prevent automated login attempts. When Beta encounters a reCAPTCHA-protected login form, the POST fails with "reCAPTCHA verification required" — Beta reports FAILED even with valid credentials. This is a false-negative. This GAP has two distinct slices with different effort/cost profiles.

### Slice 098a — CAPTCHA detection + honest blocked outcome (PURE CODE, ~40 lines)
- Status: OPEN — do first.
- Priority: HIGH (within 098) — menutup false negative tanpa infra.
- What: Detect reCAPTCHA/hCaptcha presence in login form HTML (`<script src=".../recaptcha.js">`, `class="g-recaptcha"`, `data-sitekey`, `class="h-captcha"`). Classify as `CAPTCHA_PROTECTED` outcome. Beta reports BLOCKED with reason `captcha_protected` instead of FAILED. Conductor routes to Omega for honest report: "credential may be valid, but CAPTCHA blocks automated verification." This is the honest-blocked principle (§12.60): a blocked target produces a classified outcome, not a bare "FAILED."
- Effort: LOW (~40 lines, pure code. Parse HTML for reCAPTCHA/hCaptcha indicators → new `CAPTCHA_PROTECTED` status → Beta handoff with `reason=captcha_protected`. No external service, no GPU, no cost.)
- Constraint: Tidak menyelesaikan captcha. Hanya deteksi + klasifikasi honest. Beta give up pada captcha-protected target tapi dengan outcome yang benar (BLOCKED + reason), bukan false FAILED.

### Slice 098b — CAPTCHA solving via paid service (INFRA + RECURRING COST, client opt-in)
- Status: OPEN — deferred, client opt-in.
- Priority: MEDIUM (within 098) — akses ke captcha-protected target, tapi butuh biaya.
- What: Setelah 098a mendeteksi captcha, jika `engagement.config.captcha_solving_enabled = true`, Beta mengirim sitekey + page URL ke 2Captcha API (atau Anti-Captcha/CapMonster). Service return `g-recaptcha-response` token (15-30 detik). Beta submit login form dengan token. Cost: ~$3/1000 captcha (2Captcha), ~$2/1000 (Anti-Captcha).
- Effort: MED (~80 lines code + API key infra + cost tracking). Butuh: 2Captcha API key (engagement config), HTTP client ke 2Captcha endpoint, polling untuk result (15-30s), cost tracking di engagement budget, timeout handling.
- Infra dependency: 2Captcha/Anti-Captcha account + API key + recurring cost ($3/1000). Tidak ada GPU. Tidak ada ML model. Service external.
- Legal: 2Captcha ToS mengizinkan automated solving. Google reCAPTCHA ToS melarang automated solving — ini adalah risiko legal yang harus di-disclose ke klien sebelum enable. Client opt-in via engagement config.
- Constraint: Feature flag `captcha_solving_enabled` default FALSE. Hanya aktif jika klien eksplisit setuju di SOW. Cost tracking wajib (engagement budget). Tidak boleh aktif untuk engagement tanpa explicit opt-in.

### Slice 098c — reCAPTCHA v3 score manipulation (CODE + Playwright, unreliable)
- Status: OPEN — low priority, unreliable.
- What: reCAPTCHA v3 tidak ada checkbox. Google beri score 0.0-1.0 berdasarkan browser behavior. Score tinggi = human. Untuk dapat score tinggi: `curl_cffi` TLS fingerprint (sudah ada) + header ordering (sudah ada) + human-like pacing (StealthPacer, sudah ada) + `grecaptcha.execute()` via Playwright. Tapi Google terus update model deteksi — score manipulation unreliable (40-60% success).
- Effort: MED (~150 lines + Playwright browser). Tidak butuh GPU atau paid service. Tapi unreliable — Google update model, score manipulation break.
- Constraint: Low priority. Tidak reliable untuk SaaS production. Skip sampai ada breakthrough di browser fingerprinting.

### Slice 098d — ML self-hosted captcha solver (INFRA BERAT, skip)
- Status: RETRACTED — tidak praktis untuk SaaS.
- What: YOLOv8 + ResNet untuk klasifikasi gambar captcha. Butuh GPU server, model training, maintenance saat Google update.
- Constraint: Skip. Infra berat, maintenance tinggi, reliability 60-80%. Tidak praktis untuk SaaS startup. Jika dibutuhkan di masa depan, gunakan 098b (paid service) sebagai alternative yang lebih murah dan lebih reliable.

- Evidence: `browser_solve_service.py:159` — `.cf-turnstile` selector. No reCAPTCHA or hCaptcha selectors or solving logic. `grep "recaptcha|hcaptcha"` in `agent_alpha/` = 0 results outside browser_solve.
- Files: `agent_alpha/live_fire/browser_solve_service.py:156-162` — `_CHALLENGE_SELECTORS` only has CF selectors; `agent_alpha/tools/internal/access/applicator.py` — no CAPTCHA detection in applicators; `agent_alpha/agents/beta/strike.py` — no CAPTCHA_PROTECTED status
- Cross-ref: GAP-073 (WAF capability fingerprinting — CAPTCHA type is part of WAF capability), GAP-074 (auth mechanism fingerprinting — CAPTCHA is part of auth mechanism), GAP-099 (MFA detection — similar "first factor valid but blocked" pattern), §12.60 (honest blocked outcome principle).
- Impact: Beta cannot log into reCAPTCHA/hCaptcha-protected login forms. Many enterprise targets use reCAPTCHA. False negative with valid credentials. Slice 098a menutup false negative (honest BLOCKED). Slice 098b memberi akses (paid, opt-in).

---

## GAP-099 — MFA/2FA challenge detection and honest classification
- Status: OPEN.
- Priority: HIGH — Beta reports FAILED on MFA; no "first factor valid, MFA required" outcome.
- Category: RG
- Stack: Universal
- What: When Beta successfully submits username+password but the target requires MFA (OTP, TOTP, SMS, email code, push notification), Beta's `_has_positive_auth_signal` returns False (no session cookie, no redirect to dashboard — instead redirect to `/mfa/verify` or `/2fa/enter`). Beta reports FAILED. But the first factor WAS valid — the credential IS correct. This is a critical false negative: Beta had a valid credential but reports failure. A real red team classifies this as "first factor valid, MFA challenge issued" — this is itself a payable finding (valid credential confirmed) and routes to Gamma (MFA bypass) or reports as "credential valid, MFA blocks access."
- Evidence: `default_creds.py:148-179` — `_has_positive_auth_signal` checks for session cookie, 302 redirect, or login form disappearance. MFA challenge: 302 to `/mfa/verify` → signal 2 (redirect) returns True, BUT the redirect is to MFA page, not dashboard. No MFA detection logic. No `MFA_CHALLENGE` outcome in A2A status.
- Files: `agent_alpha/tools/internal/access/default_creds.py:148-179` — _has_positive_auth_signal (no MFA detection); `agent_alpha/agents/beta/strike.py:241-244` — status COMPLETE only if access_level != NONE (MFA = no access = FAILED)
- Cross-ref: GAP-079 (post-access validation — MFA is pre-access validation), GAP-074 (auth mechanism fingerprinting — MFA type is part of mechanism).
- Impact: Beta has a valid credential but reports FAILED. Client never learns the credential was valid. Misses payable finding ("we confirmed your admin password is `X` — MFA is the only barrier"). False negative.
- Effort: MED (detect MFA challenge: 302 to `/mfa/*`, `/2fa/*`, `/otp/*`, `/verify*`, or JSON response `{"mfa_required": true}`. New outcome: `MFA_CHALLENGED` with `first_factor_valid=True`. Route to Conductor for Gamma MFA-bypass decision or honest report. ~60 lines).

---

## GAP-100 — Account lockout detection (target-side)
- Status: OPEN.
- Priority: MEDIUM — governor prevents over-attempts but doesn't detect target lockout response.
- Category: RM
- Stack: Universal
- What: `CredentialLockoutGovernor` (§12.22 D2) prevents Beta from making too many attempts per (host, username). But it does NOT detect when the TARGET has locked the account. If the target locks after 3 failed attempts and returns "Account locked due to too many failed attempts" or "Too many login attempts, try again in 15 minutes", Beta continues trying (governor allows up to its limit) — wasting attempts on a locked account. Worse: Beta may interpret the lockout page as "login form still present = failed" without understanding the account is locked, missing the opportunity to switch to a different username.
- Evidence: `cred_lockout.py` — governor tracks attempts per (host, username) but does not parse target responses for lockout indicators. `default_creds.py:148-179` — `_has_positive_auth_signal` returns False for lockout page (no session cookie, no redirect) — but doesn't classify WHY it failed.
- Files: `agent_alpha/tools/internal/access/cred_lockout.py` — governor (prevents, doesn't detect); `agent_alpha/tools/internal/access/default_creds.py:148-179` — no lockout response parsing
- Cross-ref: GAP-078 (user enumeration — lockout response is also a username enumeration vector: "account locked" = valid username), GAP-111 + GAP-112 (offline hash cracking — avoids lockout entirely; when hashes are available, offline crack is preferred over online spray. GAP-100 lockout detection is the fallback for when no hashes are available and online spray is the only option).
- Impact: Beta wastes attempts on locked accounts. May trigger permanent lockout. Doesn't switch strategy (try different username, wait for unlock, report lockout as finding). Note: offline hash cracking (GAP-112) avoids lockout entirely — when hashes are available, online spray should NOT be used. GAP-100 is the safety net for when offline crack is not possible (no hash source).
- Effort: LOW (parse response body for "locked", "too many attempts", "try again later", "account suspended" → classify as `LOCKED_OUT`, stop attempts on that username, report as finding. ~40 lines).

---

## GAP-101 — API key authentication applicator
- Status: OPEN.
- Priority: MEDIUM — api_auth label exists but no applicator; leaked API keys not tried.
- Category: SS
- Stack: Universal
- What: `auth_surface.py:37` defines `API_AUTH = "api_auth"` label, and `detect_auth_surface_labels` classifies JSON 401 responses as `api_auth`. But `STRIKABLE_AUTH_LABELS` does NOT include `api_auth` — Beta cannot strike it. Many targets expose API endpoints authenticated via API keys (`Authorization: Bearer <key>`, `X-API-Key: <key>`, `?api_key=<key>`). If Alpha harvests API keys from leaked `.env` files (`STRIPE_API_KEY=sk_live_...`, `AWS_ACCESS_KEY_ID=...`), Beta should try them against the target's API. No applicator exists for API key auth.
- Evidence: `auth_surface.py:50` — `STRIKABLE_AUTH_LABELS = {HTTP_BASIC_AUTH, LOGIN_FORM}` — API_AUTH excluded. No `ApiKeyApplicator` in any module. Alpha harvests API keys via `js_secret_probe.py` and `.env` leak but Beta has no tool to apply them.
- Files: `agent_alpha/recon/auth_surface.py:37,50` — API_AUTH defined but not strikable; `agent_alpha/tools/internal/access/` — no API key applicator
- Cross-ref: GAP-058 (JS secret extraction — Alpha finds API keys), GAP-070 (credential-to-asset correlation — API keys need asset edges), GAP-074 (auth mechanism fingerprinting — API key is a mechanism).
- Impact: Alpha harvests API keys from leaked `.env` but Beta can't use them. Missed access via API key. Many SaaS targets are API-first — the API key IS the access.
- Effort: MED (new `ApiKeyApplicator`: try harvested API keys as `Authorization: Bearer <key>`, `X-API-Key: <key>`, `?api_key=<key>` against classified `api_auth` endpoints. Verify via 200 response (not 401/403). ~80 lines).

---

## GAP-102 — Session cookie riding (harvested cookie reuse)
- Status: OPEN.
- Priority: MEDIUM — Alpha may harvest session cookies from leaks; Beta can't ride them.
- Category: SS
- Stack: Universal
- What: Alpha's `js_secret_probe.py` and `.env` leak probes may harvest session cookies from leaked files (`.env` with `SESSION_SECRET=...`, backup files with browser cookie dumps, JS with embedded `document.cookie`). But Beta has no tool to "ride" a harvested session cookie — to send it as `Cookie: session=<harvested_value>` and verify if the session is still valid. This is the simplest access path: no login needed, just reuse a valid session. A real red team always tries harvested cookies first.
- Evidence: No `SessionRidingTool` or `CookieApplicator` in `tools/internal/access/`. `cred_reuse.py` only handles username+password credentials, not session cookies. `CredentialProperties` has no `cookie_value` field.
- Files: `agent_alpha/tools/internal/access/` — no session riding tool; `agent_alpha/graph/nodes.py:78-83` — CredentialProperties (no cookie field)
- Cross-ref: GAP-058 (JS secret extraction — may find cookies), GAP-087 (backup files — may contain cookie dumps), GAP-070 (credential-to-asset correlation — cookies need asset edges).
- Impact: Missed easiest access path. A valid session cookie = instant access without login. If Alpha finds `session=abc123` in a leaked `.env` and the session is still valid, Beta should ride it. Currently impossible.
- Effort: LOW (new `SessionRidingTool`: read harvested cookie from vault, send as `Cookie:` header to target, verify via 200 response on authenticated endpoint. ~50 lines. Must check cookie freshness — sessions expire).

---

## GAP-103 — Cross-service credential reuse (SSH/Redis/SMTP)
- Status: OPEN.
- Priority: MEDIUM — harvested DB creds not tried on SSH/Redis; MySqlApplicator is SOW-gated only.
- Category: SS
- Stack: Universal
- What: Beta's `MySqlApplicator` exists but only binds to SOW-declared DB endpoints (`applicator_factory.py:191` — `_DB_SERVICES` check). If Alpha discovers port 22 (SSH, GAP-081) or port 6379 (Redis, GAP-081) open, and Alpha harvested DB credentials from `.env` leak, Beta should try those credentials on SSH and Redis too — credential reuse across services is a classic red team technique. A DB password `P@ssw0rd123` might be the same as the SSH password or Redis AUTH password. No applicator for SSH, Redis, PostgreSQL, SMTP, or FTP cred-reuse exists.
- Evidence: `applicator_factory.py:54` — `_DB_SERVICES = {"mysql", "mariadb"}` — only MySQL. No SSH, Redis, PostgreSQL, SMTP, FTP applicators. `cred_reuse.py` iterates applicators but only HttpForm + WpLogin + MySql are available.
- Files: `agent_alpha/conductor/applicator_factory.py:54` — _DB_SERVICES (MySQL only); `agent_alpha/tools/internal/access/` — no SSH/Redis/Postgres/SMTP applicator
- Cross-ref: GAP-081 (port scanning — prerequisite: must discover non-HTTP ports first), GAP-070 (credential-to-asset correlation — creds should be tried on all services with trust edges), GAP-046 (HTTP Basic Auth applicator — another missing applicator).
- Impact: Missed cross-service cred-reuse. DB password = SSH password = full server access. Classic finding that Agent-Alpha cannot discover.
- Effort: MED (new applicators: `SshApplicator` via paramiko, `RedisApplicator` via redis-py AUTH check, `PostgresApplicator` via psycopg2, `SmtpApplicator` via smtplib AUTH. Each ~50 lines. Must be OFFENSIVE_APPROVED tier — direct service connection. Scope-gated).
- Constraint: OFFENSIVE_APPROVED tier required. Each service connection is an active auth attempt against a non-HTTP service. Must respect scope gate and lockout governor.

---

## GAP-104 — Breach credential tool (Dehashed/HIBP integration)
- Status: OPEN.
- Priority: HIGH — §12.54 breach data not wired; no tool to try breach creds.
- Category: RG
- Stack: Universal
- What: ADR §12.54 references Dehashed/HIBP breach data integration, but it is not wired. No tool exists to: (1) query breach databases for emails associated with the target domain, (2) extract leaked passwords from breach data, (3) try those passwords against the target's login form. This is the highest-value cred-reuse path: real leaked passwords from real breaches, not derived guesses. A real external red team always checks breach data. Beta's `UserDerivedCredsTool` derives passwords from username+domain stem (`niagamas123`) — but breach data has REAL passwords (`P@ssw0rd2024!`) that no derivation would guess.
- Evidence: `grep "dehashed|hibp|breach.*cred|breach.*password"` in `agent_alpha/` = 0 results. No breach data client module. `UserDerivedCredsTool` derives from patterns, not breach data.
- Files: No breach data module. `agent_alpha/tools/internal/access/user_derived_creds.py` — derives from patterns only.
- Cross-ref: GAP-054 (WP REST user email — prerequisite: need emails to query breach DB), GAP-090 (email pattern inference — generates candidate emails for breach query), GAP-070 (credential-to-asset correlation — breach creds need asset edges), §12.54 (Dehashed/HIBP — ADR reference, not wired).
- Impact: Missed highest-value cred-reuse path. Breach data has real passwords that no pattern derivation would guess. Without breach integration, Beta's cred-reuse is limited to: harvested creds (from leaks), default creds (admin/admin), derived creds (username123). Breach creds are the 4th and most powerful source.
- Effort: MED (Dehashed API client + email-to-breach query + password extraction + new `BreachCredTool` that tries breach passwords against target login. ~200 lines. Needs Dehashed API key. Legal: querying breach data is legal; using found credentials is SOW-gated).
- Constraint: Dehashed/HIBP API key required. Must be scoped: only query breach data for emails derived from in-scope domain. No mass breach scraping.

---

## GAP-105 — Beta CVE consumption for exploit-based entry
- Status: OPEN.
- Priority: MEDIUM — Alpha finds CVE but Beta only tries cred-based access; no exploit entry.
- Category: RG
- Stack: Universal
- What: Alpha's `plugin_cve_catalog.py` (after GAP-089) maps versions to CVEs and creates VULNERABILITY nodes. But Beta's `_project_target_context` only reads CREDENTIAL, VULNERABILITY (as string label), and ACCESS_LEVEL nodes — it does NOT use CVE findings to choose an exploit-based entry. Beta always tries cred-based access (cred_reuse, default_creds, user_derived, odoo_access). If Alpha finds "WordPress 6.4 has CVE-2023-XXXX RCE" or "Spring Boot Actuator env disclosure", Beta doesn't use that to attempt exploit-based initial access. The CVE → exploit → access chain is broken at the Beta step.
- Evidence: `strike.py:100-115` — `_project_target_context` reads VULNERABILITY nodes as string labels in `prior_findings`, but `step()` only dispatches cred-based tools. No exploit tool in `candidates` list (strike.py:321-342). CVE findings are informational to Beta, not actionable.
- Files: `agent_alpha/agents/beta/strike.py:100-115,321-342` — prior_findings includes CVEs but tool list is cred-only; `agent_alpha/recon/plugin_cve_catalog.py` — CVE catalog (feeds Alpha, not Beta)
- Cross-ref: GAP-089 (CVE catalog — prerequisite: must have CVE data first), GAP-077 (auth bypass — a type of exploit-based entry), §12.55 (1-Day Weaponizer — Beta should weaponize 1-day CVEs for initial access).
- Impact: Alpha finds CVE but Beta ignores it. The entire version→CVE→exploit→access chain is broken at Beta. Misses exploit-based initial access that doesn't require credentials (e.g., unauthenticated RCE, auth bypass via CVE).
- Effort: MED (new `ExploitEntryTool`: read VULNERABILITY nodes with CVE IDs, match against 1-day exploit catalog (§12.55), attempt exploit-based access. Must be gated by CVE type: unauthenticated exploits = Beta scope, authenticated RCE = Gamma scope. ~150 lines + exploit catalog data).
- Constraint: 1-day exploits only (§12.55). Unauthenticated exploits (auth bypass, info disclosure → access) = Beta. Authenticated exploits (RCE, priv-esc) = Gamma. Must not attempt novel/0-day exploits.

---

## GAP-106 — Login redirect chain following
- Status: OPEN.
- Priority: MEDIUM — multi-hop login redirects (SSO/callback) not followed to verify final landing.
- Category: RM
- Stack: Universal
- What: `HttpFormApplicator.apply()` and `WpLoginApplicator.apply()` check for 302 redirect as a positive auth signal. But some login flows redirect through MULTIPLE hops: login → SSO redirect → callback URL → dashboard. The HTTP client may follow redirects but the applicator only checks the FIRST response. If the first redirect goes to an SSO intermediary (not the dashboard), the applicator may misclassify: (a) false positive — 302 to SSO = "access" when actually SSO challenge pending, or (b) false negative — redirect chain doesn't end at dashboard so "login form disappeared" check fails.
- Evidence: `applicator.py:177-179` — `if auth_resp.status_code in (301, 302): return True` — checks first response only. No redirect chain following to final landing page. `http_client.get()` may or may not follow redirects (depends on client config).
- Files: `agent_alpha/tools/internal/access/applicator.py:116-191` — HttpFormApplicator (first response only); `agent_alpha/tools/internal/access/applicator.py:194-290` — WpLoginApplicator (same)
- Cross-ref: GAP-074 (auth mechanism fingerprinting — SSO redirect is a mechanism), GAP-099 (MFA detection — MFA may redirect through multiple hops).
- Impact: False positive (302 to SSO = "access" when SSO challenge pending) or false negative (redirect chain not followed to dashboard). Misclassification of SSO-based login flows.
- Effort: LOW (follow redirect chain to final response, check final URL for dashboard indicators (`/admin`, `/dashboard`, `/home`) and login form absence. ~40 lines).

---

## GAP-107 — First-login password change detection
- Status: OPEN.
- Priority: LOW — forced password change on first login = Beta reports FAILED, not "change required".
- Category: RM
- Stack: Universal
- What: Some targets force a password change on first login: after successful username+password, the target redirects to `/password/change` or `/set-password` instead of the dashboard. Beta's `_has_positive_auth_signal` sees a 302 redirect → returns True (signal 2), but the redirect is to password change page, not dashboard. Beta may report COMPLETE with `access_level=user` when actually no dashboard access was achieved — the user is forced to change password first. Alternatively, Beta may report FAILED if the password change page has a password field (login form "still present"). Neither outcome is correct — the honest classification is "first factor valid, password change required."
- Evidence: `default_creds.py:177-179` — 302 = positive signal, but doesn't check WHERE the redirect goes. No password-change page detection. No `PASSWORD_CHANGE_REQUIRED` outcome.
- Files: `agent_alpha/tools/internal/access/default_creds.py:148-179` — no password change detection; `agent_alpha/agents/beta/strike.py:241-244` — no PASSWORD_CHANGE_REQUIRED status
- Cross-ref: GAP-079 (post-access validation — password change is a post-first-factor validation), GAP-099 (MFA detection — similar "first factor valid but blocked" pattern), GAP-106 (redirect chain following — password change is a redirect destination).
- Impact: False positive (reports COMPLETE when no dashboard access) or false negative (reports FAILED when first factor was valid). Misclassification of first-login password change flow.
- Effort: LOW (detect redirect to `/password/change`, `/set-password`, `/reset-password`, `/first-login` → classify as `PASSWORD_CHANGE_REQUIRED`. ~30 lines).

---

## GAP-108 — Password reset flow user enumeration
- Status: OPEN.
- Priority: MEDIUM — reset endpoint reveals valid emails; not probed by Beta.
- Category: RM
- Stack: Universal
- What: Password reset endpoints (`/forgot-password`, `/password-reset`, `/wp-login.php?action=lostpassword`) often reveal whether an email/username exists: "If that email exists, we've sent a reset link" (same message for all = no enum) vs "No account found with that email" (differential = enum). Some endpoints reveal more: "Reset link sent to y***@niagamas.com" (partial email disclosure). Beta has no tool to probe reset endpoints for user enumeration. This is distinct from GAP-078 (login response differential) — reset endpoints have different response patterns and are often less protected than login forms.
- Evidence: No password reset probe in `tools/internal/access/`. `cred_reuse.py` and `default_creds.py` only target login forms. No reset endpoint handler.
- Files: `agent_alpha/tools/internal/access/` — no password reset tool; `agent_alpha/agents/beta/strike.py` — no reset endpoint dispatch
- Cross-ref: GAP-078 (user enumeration via auth response — login form, this is reset form), GAP-047 (username harvest — reset endpoint is another harvest source), GAP-054 (WP REST user email — emails feed reset endpoint probe).
- Impact: Missed username enumeration vector. Reset endpoints often have weaker protection than login forms (no rate limit, no CAPTCHA). Valid emails from reset = cred-spray targets = potential access.
- Effort: MED (new `PasswordResetEnumTool`: POST email to reset endpoint, parse response differential ("sent" vs "not found"), extract partial email if disclosed. Must be stealthy — 1 request per email, long delay. ~80 lines).
- Constraint: Must NOT actually trigger password reset emails to real users (use non-existent email as control, then compare with candidate). Only enumerate, never reset.

---

## GAP-109 — Beta entry selection ignores WAF capability
- Status: OPEN.
- Priority: MEDIUM — Beta strikes WAF-protected surface without considering WAF mode.
- Category: RG
- Stack: Universal
- What: `select_strike_entry` (`conductor/router.py:117`) ranks entries by auth-surface label priority and reachability. It does NOT consider WAF capability (GAP-073). If the top-ranked entry is behind Cloudflare Bot Management with ML (aggressive), Beta's cred-spray will trigger IP ban. If a lower-ranked entry is behind rate-limit-only WAF (lenient), Beta's cred-spray would succeed. Beta strikes the "most visible" entry, not the "most accessible" entry. This is a subset of GAP-072 (entry-vector ranking) but specifically about WAF capability as a ranking factor.
- Evidence: `router.py:117-176` — `select_strike_entry` sorts by (unreachable, label_priority, host). No WAF capability in sort key. `applicator_factory.py` — no WAF-aware applicator selection.
- Files: `agent_alpha/conductor/router.py:117-176` — select_strike_entry (no WAF factor); `agent_alpha/conductor/main.py:600-676` — run_beta (no WAF-aware dispatch)
- Cross-ref: GAP-073 (WAF capability fingerprinting — prerequisite: must know WAF mode), GAP-072 (entry-vector ranking — general ranking, this is WAF-specific), GAP-026 (StealthPacer gate inverted — stealth not default).
- Impact: Beta may strike an aggressively-WAF-protected entry and get IP-banned, when a less-protected entry would have succeeded. Wasted strike budget + potential engagement failure (IP ban = no further access possible).
- Effort: LOW (add WAF capability as sort key in `select_strike_entry`: entries behind aggressive WAF ranked lower. Read `waf_capability` field from AssetProperties after GAP-073. ~20 lines. Depends on GAP-073).

---

## GAP-110 — Beta credential prioritization lacks graph edges
- Status: OPEN.
- Priority: MEDIUM — cred_reuse iterates all creds × all surfaces; no graph-based priority.
- Category: RG
- Stack: Universal
- What: `cred_reuse.py` iterates ALL CREDENTIAL nodes and tries each against ALL applicable surfaces via `select_applicator`. There is no graph-based prioritization: no "this credential was harvested from WP config → try WP login first" or "this credential has a TRUST_RELATIONSHIP edge to this asset → try that asset first." The credential-to-asset correlation (GAP-070) would create `CREDENTIAL → ENABLES → ASSET` edges, but `cred_reuse.py` does not read these edges for prioritization. Result: Beta tries DB password on WP login (wrong), WP password on Odoo (wrong), before trying the right combination. Wasted attempts + lockout risk.
- Evidence: `cred_reuse.py:82-100` — iterates all CREDENTIAL nodes, delegates to `select_applicator` by service field only. No graph edge traversal for prioritization. `CredentialProperties.service` is free-text, not a graph edge.
- Files: `agent_alpha/tools/internal/access/cred_reuse.py:82-100` — iterates all creds (no graph priority); `agent_alpha/graph/nodes.py:78-83` — CredentialProperties (service field, no edge)
- Cross-ref: GAP-070 (credential-to-asset correlation — creates the edges this GAP consumes), GAP-072 (entry-vector ranking — related ranking concept), GAP-078 (user enumeration — pre-filtering reduces cred attempts).
- Impact: Beta wastes attempts on wrong credential/asset pairs. 10 credentials × 3 surfaces = 30 attempts, when graph edges would reduce to 3 targeted attempts. Lockout risk + WAF trigger + time waste.
- Effort: MED (read `CREDENTIAL → ENABLES → ASSET` edges from graph, sort credential attempts by edge existence (edge = high priority, no edge = low priority). ~60 lines. Depends on GAP-070).

---


# Offline Credential Recovery (NEW)

## GAP-111 — DB dump hash extraction (MySQL/wp_users/phpass)
- Status: OPEN.
- Priority: MEDIUM — prerequisite for offline hash cracking (GAP-112). Without hash extraction, offline crack is impossible.
- Category: RG
- Stack: Universal (MySQL, WordPress, Laravel, custom)
- What: When Alpha discovers a database dump leak (`db.sql`, `dump.sql`, `backup.sql` — GAP-087), it does NOT parse the dump to extract password hashes. A MySQL dump contains `CREATE TABLE` + `INSERT INTO` statements with hashed passwords: `mysql.user` table has `authentication_string` (SHA1-based), WordPress `wp_users` table has `user_pass` (phpass MD5-based), Laravel `users` table has `password` (bcrypt). These hashes are the input for offline cracking (GAP-112). Without extracting them, offline crack cannot fire. Alpha currently treats `db.sql` as a generic leak file (proof artifact) but does not parse its contents for credential hashes.
- Evidence: `recon/path_probe.py` — probes `db.sql` path but only records existence + proof artifact. No SQL dump parser. `grep "mysql.user|wp_users|phpass|authentication_string|password.*hash" ` in `agent_alpha/` = 0 results. No hash extraction module.
- Files: `agent_alpha/recon/path_probe.py` — records leak existence, no content parse; `agent_alpha/graph/nodes.py:78-83` — CredentialProperties (no `hash_type`, `hash_value` fields); no SQL dump parser module
- Cross-ref: GAP-087 (backup file patterns — `db.sql` is the source), GAP-112 (offline hash cracking — consumer of extracted hashes), GAP-070 (credential-to-asset correlation — hashes need asset edges), GAP-054 (WP REST users — usernames pair with hashes from wp_users table).
- Impact: Without hash extraction, offline crack (GAP-112) cannot fire. Alpha finds `db.sql` but doesn't know it contains password hashes. The entire offline-crack chain is broken at the extraction step.
- Effort: MED (SQL dump parser: regex/SQL parser for `INSERT INTO mysql.user`, `INSERT INTO wp_users`, `INSERT INTO users` → extract (username, hash, hash_type) tuples. New `hash_type` + `hash_value` fields in CredentialProperties. ~150 lines. Must handle multiple SQL dialects — mysqldump, pg_dump, raw SQL).
- Constraint: Hash extraction is RECON tier (passive — reading a leaked file, not touching target). Offline crack (GAP-112) is OFFENSIVE tier (active — running hashcat). Extraction and cracking are separate phases with separate auth gates.

---

## GAP-112 — Offline hash cracking tool (hashcat/john integration)
- Status: OPEN.
- Priority: HIGH — offline crack avoids lockout entirely; 0 target requests. But HIGH effort (infra + tool integration).
- Category: SS
- Stack: Universal
- What: Agent-Alpha has no offline hash cracking capability. When hashes are extracted (GAP-111), they should be cracked offline using hashcat or John the Ripper — no target interaction, no lockout risk, no WAF trigger. Offline crack is the safest credential recovery method: 0 requests to target, unlimited attempts, no rate limit. A real external red team always cracks offline when hashes are available. Online cred-spray (current Beta) is the LAST resort, not the first — because online spray risks lockout (GAP-100), triggers WAF (GAP-073), and is rate-limited. Offline crack has none of these constraints.
- Evidence: `grep "hashcat|john.*ripper|hash.*crack|offline.*crack" ` in `agent_alpha/` = 0 results. No hash cracking module. No hashcat/john subprocess call. Per §8g, nmap/hashcat/john are operator-side tools, NOT Agent-Alpha dependencies — but Agent-Alpha should integrate with them via subprocess or API, not reimplement.
- Files: No hash cracking module. `agent_alpha/tools/internal/access/` — all tools are online (HTTP/TCP). No offline tool.
- Cross-ref: GAP-111 (hash extraction — prerequisite: must have hashes to crack), GAP-100 (lockout detection — offline crack avoids lockout entirely, making GAP-100 less critical when hashes available), GAP-104 (breach creds — complementary: breach data has plaintext, offline crack produces plaintext from hashes), GAP-087 (backup files — source of DB dumps), §8g (operator-side tools — hashcat/john available on Oracle lab, not Agent-Alpha dependency).
- Impact: Without offline crack, Beta must online-spray even when hashes are available. Online spray risks lockout, triggers WAF, rate-limited. Offline crack = unlimited attempts, 0 target touch, no lockout. Misses the safest credential recovery path.
- Effort: HIGH (hashcat/john subprocess integration + hash type detection (phpass, bcrypt, SHA1, MD5, argon2) + wordlist management + result parsing. ~300 lines + hashcat installed on Oracle (already per §8g). Must be OFFENSIVE_APPROVED tier — running hashcat is active processing, though 0 target touch. Or: RECON_ONLY tier since 0 target interaction — tier decision needed).
- Constraint: hashcat/john run on Oracle lab (§8g — already installed). NOT a new Agent-Alpha dependency. Wordlist: use existing rockyou.txt + generated wordlist from user_derived patterns. No GPU required for phpass/bcrypt/SHA1 — CPU crack sufficient for these hash types. GPU only needed for fast hashes (MD5) with large wordlists — defer GPU cracking.
- Tier question: Is offline hash cracking RECON_ONLY (0 target touch) or OFFENSIVE_APPROVED (active processing of harvested data)? ADR §12.26 says "DETECT=recon / ACT=Gamma" — but cracking a hash is neither detect nor act against target. Recommend: RECON_ONLY+ (passive processing, no target touch, but requires harvested hash from leak). Conductor decision needed.

---


# Alternative Access Vectors (NEW — beyond cred-spray and offline crack)

## GAP-113 — Password reset abuse (host header injection, token prediction, param pollution)
- Status: OPEN (split into 4 vectors with different autonomy profiles).
- Priority: MEDIUM — change password without knowing old password; bypasses cred-spray entirely.
- Category: SS
- Stack: Universal
- What: GAP-108 covers password reset endpoint user enumeration (detect valid emails). But password reset ABUSE goes further: actually changing the target user's password without knowing their current password. This bypasses credential-based access entirely — no cred-spray, no offline crack, no lockout risk. The reset flow works: (1) attacker triggers reset for victim email, (2) target generates token and emails reset link, (3) whoever has the token can set a new password. The abuse is in capturing or predicting the token. 4 vectors, each with different autonomy profile.

### Vector 1 — Host Header Injection (DEFERRED — requires admin interaction)
- Status: DEFERRED to social-engineering slice.
- Autonomy: NO — requires admin to open email and click link. Not autonomous.
- What: Target builds reset URL from `Host` header instead of server config. Attacker sends `Host: attacker.com` in reset request → reset link in email points to `attacker.com/reset?token=abc123` → admin clicks link → browser goes to attacker.com → attacker server logs token → attacker has token → attacker sets new password.
- Flow: `POST /forgot-password Host: attacker.com email=admin@niagamas.com` → target sends email with link `https://attacker.com/reset?token=abc123` → admin clicks → attacker captures token → `POST /reset?token=abc123 password=NewPass` → access.
- Why deferred: Attacker cannot capture token without admin clicking the link. This is social engineering, not autonomous. Agent-Alpha does not send phishing emails or wait for admin interaction. v1 = detect only (send Host: attacker.com, check if response or email template uses attacker.com — but cannot verify email content without inbox access). Detection-only is low value without exploitation.
- Google Workspace impact: Google Workspace does NOT protect from this. Email from niagamas.com (domain itself) passes Google spam filter. Link to attacker.com appears in Gmail inbox. Admin clicks → token captured. Google only protects from DNS-level email intercept (MX hijack), not application-level Host header bugs.

### Vector 2 — Token in Response Body (AUTONOMOUS — 2 requests, 0 admin interaction)
- Status: OPEN — autonomous-capable.
- Autonomy: YES — 2 requests, 0 admin interaction, 0 lockout risk.
- What: Target returns reset token in HTTP response body instead of only in email. Implementation bug: `{"status": "ok", "reset_token": "abc123xyz"}` in response to `POST /forgot-password`. Attacker reads token directly from response — no email access needed, no admin interaction needed.
- Flow: `POST /forgot-password email=admin@niagamas.com` → response body contains `reset_token: abc123xyz` → attacker has token → `POST /reset?token=abc123xyz password=NewPass` → access.
- Detection (v1, ACTIVE_APPROVED): POST reset request → parse response body for `token`, `reset_token`, `reset_link`, `url` fields → if token found, report as finding "Password reset token disclosed in response body." Do NOT use token to change password.
- Exploitation (v2, OFFENSIVE_APPROVED + client approval): Use token from response → set new password → login → proof. Destructive: changes admin password.
- Google Workspace impact: None. Vector 2 does not involve email at all. Token is in HTTP response, not email. Google Workspace is irrelevant.
- Rarity: Uncommon in modern implementations (most frameworks return only `{"status": "ok"}`). But found in custom PHP apps, legacy CodeIgniter, and junior-developer code — common in SEA market.

### Vector 3 — Token Prediction (AUTONOMOUS — 2 requests, 0 admin interaction)
- Status: OPEN — autonomous-capable.
- Autonomy: YES — 2 requests, 0 admin interaction, 0 lockout risk.
- What: Reset token is generated from predictable inputs: `MD5(timestamp + email)`, `substr(sha1(time()), 0, 8)`, sequential counter, or short hex (6-8 chars). Attacker knows timestamp (from response `Date` header), knows email (from GAP-078/108 enumeration), computes token independently.
- Flow: `POST /forgot-password email=admin@niagamas.com` → response `Date: Wed, 13 Sep 2026 10:38:10 GMT` → attacker converts to timestamp 1694567890 → attacker computes `MD5("1694567890admin@niagamas.com")` = `a1b2c3d4...` → `POST /reset?token=a1b2c3d4... password=NewPass` → access.
- Detection (v1, ACTIVE_APPROVED): POST reset request → extract token from response (if in body) or request reset for attacker-controlled email → compare token with timestamp-based prediction → if match, report "Reset token predictable (timestamp-based)." Also test token entropy: request 2-3 tokens, check if sequential or time-derived.
- Exploitation (v2, OFFENSIVE_APPROVED + client approval): Predict token for victim email → set new password → login → proof.
- Google Workspace impact: None. Vector 3 does not involve email. Token is predicted from timestamp + email, not from email content.
- Rarity: Found in legacy PHP apps, custom frameworks, and implementations that don't use `secrets.token_urlsafe()`. Modern frameworks (Laravel, Django) use cryptographically secure tokens — not vulnerable.

### Vector 4 — Email Parameter Pollution (AUTONOMOUS — 2 requests, 0 admin interaction)
- Status: OPEN — autonomous-capable.
- Autonomy: YES — 2 requests, 0 admin interaction, 0 lockout risk.
- What: Target parses duplicate email parameters ambiguously: `email=admin@niagamas.com&email=attacker@gmail.com`. Framework takes first email for user lookup, second email for sending reset link. Reset link sent to attacker's email → attacker has token.
- Flow: `POST /forgot-password email=admin@niagamas.com&email=attacker@gmail.com` → target finds admin user → sends reset link to attacker@gmail.com (second param) → attacker opens own email → has token → `POST /reset?token=abc123 password=NewPass` → access.
- Detection (v1, ACTIVE_APPROVED): POST reset with duplicate email params (victim + attacker-controlled) → check if reset email arrives at attacker-controlled email → if yes, report "Password reset vulnerable to email parameter pollution." Requires attacker-controlled email inbox (e.g. test Gmail account).
- Exploitation (v2, OFFENSIVE_APPROVED + client approval): Receive token at attacker email → set new password → login → proof.
- Google Workspace impact: None for victim. Attacker's email (attacker@gmail.com) is also Gmail — Google delivers it normally. Google does not inspect the reset request, only the email. Bug is in target's parameter parsing, not in email infrastructure.
- Rarity: Framework-dependent. PHP `$_POST['email']` takes last value. Some frameworks merge duplicate params. Found in custom PHP apps and misconfigured frameworks.

### Google Workspace analysis (all vectors)
- Google Workspace (Gmail for custom domain) changes WHO receives email, not HOW the reset flow works. All 4 vectors attack the TARGET SERVER's reset implementation, not the email infrastructure.
- Vector 1: Email passes Google spam filter (from own domain). Admin sees link in Gmail. Clicks → token captured. Google does NOT protect.
- Vector 2-3: No email involved. Token in response body or predicted. Google irrelevant.
- Vector 4: Attacker's email (attacker@gmail.com) receives reset link normally. Google does NOT inspect reset request content.
- Google Workspace ONLY protects from DNS-level email intercept (MX record hijack → redirect all email to attacker). Google validates domain ownership via TXT record before accepting MX changes. This is infrastructure-level protection, not application-level.
- Conclusion: Google Workspace does not mitigate application-level password reset bugs (GAP-113). It only mitigates DNS hijack-based email intercept (out of scope for GAP-113).

### Summary table

| Vector | Admin Interaction? | Autonomous? | Tier (detect) | Tier (exploit) | Google Workspace Protects? |
|--------|-------------------|-------------|----------------|-----------------|---------------------------|
| 1 (Host header) | YES (click link) | NO | ACTIVE_APPROVED (low value) | DEFERRED (social eng) | NO |
| 2 (Token in body) | NO | YES | ACTIVE_APPROVED | OFFENSIVE_APPROVED | NO (no email) |
| 3 (Token prediction) | NO | YES | ACTIVE_APPROVED | OFFENSIVE_APPROVED | NO (no email) |
| 4 (Param pollution) | NO | YES | ACTIVE_APPROVED | OFFENSIVE_APPROVED | NO |

- Evidence: No password reset abuse tool in `tools/internal/access/`. GAP-108 (reset enum) is detection-only. No host header injection test, no token prediction, no email parameter injection. `grep "reset.*token|forgot.*password|host.*header.*inject" ` in `agent_alpha/` = 0 results for abuse.
- Files: `agent_alpha/tools/internal/access/` — no reset abuse tool; `agent_alpha/agents/beta/strike.py` — no reset abuse dispatch; `agent_alpha/recon/auth_surface.py` — no reset endpoint classification
- Cross-ref: GAP-108 (reset enum — prerequisite: must know reset endpoint exists), GAP-077 (auth bypass — related: both bypass credential auth), GAP-074 (auth mechanism fingerprinting — must know reset flow to abuse it), GAP-075 (subdomain takeover — vector 1 deferred for same reason: requires human interaction).
- Impact: Missed access vector that bypasses credentials entirely. No lockout risk, no WAF trigger (reset is normal functionality). Vectors 2-4 are fully autonomous (2 requests, 0 admin interaction). Classic finding that conventional scanners (Nuclei) detect via templates. Common in SEA market (custom PHP, legacy CodeIgniter, junior developer code).
- Effort: MED (vector 2: parse response body for token fields ~30 lines. Vector 3: token entropy analysis + timestamp prediction ~60 lines. Vector 4: duplicate email param test + attacker inbox check ~50 lines. Vector 1: deferred. Total v1 detect: ~140 lines. v2 exploit: +60 lines per vector).
- Constraint: v1 = DETECT only (ACTIVE_APPROVED): trigger reset, check for token disclosure / predictability / param pollution. Do NOT change victim password. Report as finding. v2 = EXPLOIT (OFFENSIVE_APPROVED + client explicit approval): use token to set new password → login → proof. Destructive: changes target state (admin password). Client must agree to password change and must reset admin password after engagement. Vector 1 = DEFERRED to social-engineering slice (requires admin to click link — not autonomous).

---

## GAP-114 — OAuth/SAML/JWT token theft and forgery
- Status: OPEN.
- Priority: MEDIUM — token-based auth bypass via open redirect, weak signing key, JWT crack.
- Category: SS
- Stack: Universal (SaaS, enterprise SSO, modern web apps)
- What: Modern applications increasingly use token-based auth (OAuth 2.0, SAML, JWT) instead of session cookies. Beta has no capability for token-based auth bypass. Vectors: (1) OAuth open redirect — `redirect_uri` parameter accepts attacker URL → steal authorization code → exchange for access token. (2) JWT weak secret — HS256 with weak secret (`secret`, `password`) → offline crack JWT → forge admin token. (3) JWT algorithm confusion — RS256 → HS256 confusion → forge token with public key. (4) SAML signature wrapping — inject extra element inside signed SAML response → bypass auth. (5) OAuth scope escalation — request more scopes than authorized → access elevated data. (6) Token leakage via Referer — OAuth token in URL → leaked to third-party via Referer header.
- Evidence: `grep "oauth|saml|jwt.*crack|jwt.*forge|authorization_code|redirect_uri"` in `agent_alpha/` = 0 results for auth bypass. JWT only appears in `api_auth.py` (Agent-Alpha's own API auth, not target auth). No OAuth/SAML/JWT bypass tool.
- Files: `agent_alpha/tools/internal/access/` — no token bypass tool; `agent_alpha/recon/auth_surface.py:45` — `bearer` scheme classified as `TOKEN_AUTH` but not strikable
- Cross-ref: GAP-074 (auth mechanism fingerprinting — must know target uses OAuth/SAML/JWT), GAP-077 (auth bypass — token bypass is a category of auth bypass), GAP-101 (API key auth — related token-based access).
- Impact: Missed entire category of modern auth bypass. SaaS targets increasingly use OAuth/JWT. Enterprise targets use SAML SSO. Agent-Alpha cannot bypass any of these. As the market shifts to token-based auth, this gap grows in severity.
- Effort: HIGH (multiple sub-vectors: OAuth open redirect probe, JWT crack via hashcat mode 16500, JWT algorithm confusion test, SAML signature wrapping test. Each ~100-200 lines. JWT crack reuses GAP-112 hashcat integration. OAuth/SAML probes need active interaction with auth flow. ~500 lines total).
- Constraint: JWT crack = offline (RECON_ONLY+, reuse GAP-112 hashcat). OAuth open redirect = ACTIVE_APPROVED (send auth request with attacker redirect_uri). SAML signature wrapping = OFFENSIVE_APPROVED (forge SAML response). Each sub-vector has different tier. Must be gated individually.

---


# ADR §12.61 Flank-when-CF-hard Implementation

## GAP-115 — Historical DNS origin discovery (SecurityTrails/DNSHistory)
- Status: OPEN.
- Priority: HIGH — ADR §12.61 A1 explicitly calls this "the biggest missing signal."
- Category: RG
- Stack: Universal
- What: ADR §12.61 axis A1: "Historical DNS — the A-record BEFORE CF was fronted; origin IP often unchanged. HIGHEST leverage, passive." Agent-Alpha's current origin discovery uses crt.sh/VT/OTX (certificate transparency + threat intel) — which FAILED on 4 recent field targets (niagamas, bernofarm, ibudanbalita, busonlineticket). All 4 are full-Cloudflare apex targets where crt.sh yielded 0 origin candidates. Historical DNS (SecurityTrails, DNSHistory, DNSDB, ViewDNS) queries the A-record history BEFORE the domain was fronted by Cloudflare — the origin IP is often unchanged and still live. This is the #1 technique for origin discovery on full-CF targets, and it is completely absent.
- Evidence: `recon/origin_resolver.py` — uses crt.sh/VT/OTX composite. No historical DNS query. `grep "securitytrails|dnshistory|dnsdb|viewdns" ` in `agent_alpha/` = 0 results. ADR §12.61: "Agent today: only crt.sh/VT/OTX — which FAILED on these targets. This is the biggest missing signal."
- Files: `agent_alpha/recon/origin_resolver.py` — no historical DNS source; `agent_alpha/recon/passive_discovery.py` — no historical DNS; no SecurityTrails/DNSHistory client module
- Cross-ref: ADR §12.61 A1 (HIGHEST leverage per ADR), GAP-042 (origin binding — historical IP needs two-proof binding), GAP-062 (MX/SPF — axis A2 complement), GAP-093 (cert SAN — axis A3 complement), GAP-086 (favicon hash — axis A3 complement), GAP-075 (subdomain takeover — axis A4/B8 complement). niagamas.com + bernofarm.com field-prove: both full-CF, crt.sh failed, historical DNS is the missing technique.
- Impact: 4 recent field targets (niagamas, bernofarm, ibudanbalita, busonlineticket) are full-CF apex where origin discovery FAILED. Without historical DNS, Agent-Alpha cannot find the origin and cannot flank. The entire §12.61 axis A is blocked at the first step. This is the single highest-leverage GAP for the full-CF target class.
- Effort: MED (SecurityTrails API client + DNSHistory/ViewDNS fallback + historical A-record extraction + origin candidate emission. ~150 lines. Needs SecurityTrails API key (free tier: 50 queries/month, paid: $50/month for 5000). Fallback: ViewDNS.info free API (1 query/minute, no key). Must compose with existing two-proof origin binding (§12.46) — historical IP is a CANDIDATE, not a proven origin).
- Constraint: Historical IP is a CANDIDATE only — must pass two-proof binding (domain ownership + origin binding, §12.46) before Beta can strike. Passive, 0 target touch (query external DNS history API, not target). SecurityTrails free tier sufficient for low-volume engagements. Open question (ADR §12.61): external API dependency/cost policy — keyless fallback (ViewDNS) + budget tracking.

---


# ADR-LOCKED Implementation Gaps (design decided, code NOT built)

## GAP-116 — Authenticated crawl / post-access re-recon implementation (§12.32)
- Status: OPEN — ADR §12.32 LOCKED but code NOT BUILT.
- Priority: HIGH — without authenticated crawl, Beta cannot discover post-access surfaces (IDOR, admin panels, API endpoints visible only after login). The most valuable vulnerabilities (OWASP A01: Broken Access Control) are invisible without this.
- Category: RG
- Stack: Universal
- What: ADR §12.32 "Post-access authenticated re-recon" is LOCKED (2026-07-15) but NOT IMPLEMENTED. After Beta obtains valid credentials, there is no authenticated re-crawl to discover new surfaces. The ADR specifies: (1) AuthenticatedCrawlMode — re-crawl with active session, diff unauth vs auth (new endpoints/menus/APIs). (2) Boundary: DISCOVERING authenticated surfaces = recon (DETECT), EXPLOITING (testing IDOR, priv-esc) = Gamma-gated. (3) Wiring: post-access sub-objective in Planner (§12.29). GAP-011 was "MOVED to ADR §12.32" in the ledger, but MOVED ≠ IMPLEMENTED — the ADR is a design decision, not code. `grep "AuthenticatedCrawl|authenticated.*crawl|auth.*vs.*unauth.*diff" ` in `agent_alpha/` = 0 results. The `http_client` has a `cookies` kwarg but no authenticated-crawl mode.
- Evidence: `agents/beta/strike.py:335-337` — after successful auth, Beta persists nodes and returns. No re-crawl. `grep "AuthenticatedCrawl" ` = 0 results. `http_client.py` — has `cookies` kwarg but no crawl mode. ADR §12.32: "After Beta obtains `valid_credentials` there is no active-session re-discovery."
- Files: `agent_alpha/agents/beta/strike.py:335-337` — no post-access re-crawl; `agent_alpha/agents/http_client.py` — no authenticated crawl mode; no `authenticated_crawl.py` module
- Cross-ref: ADR §12.32 (LOCKED, design decision), GAP-011 (MOVED to ADR — this GAP clarifies implementation is OPEN), GAP-079 (post-access validation — related but different: validation = prove access level, crawl = discover new surfaces), GAP-080 (session management — needs stable session for crawl), GAP-118 (proof standard oracle — auth-vs-unauth diff is the oracle, authenticated crawl is how you get the diff), ADR §12.29 (Planner — post-access sub-objective wiring, STOP-gated Gamma).
- Impact: Without authenticated crawl, Beta finds access but cannot discover what the access reveals. Admin panel, API endpoints, user data — all invisible post-login. The most payable findings (IDOR, broken access control, priv-esc path) require authenticated crawl to discover. Agent-Alpha stops at "I logged in" but never asks "what can I see now that I couldn't before?"
- Effort: MED (authenticated crawl mode: re-fetch known URLs with session cookie → diff vs unauth responses → mint new ASSET/SERVICE nodes for auth-only surfaces. ~200 lines. Must stay RECON_ONLY — discovery, not exploitation. Boundary: IDOR testing = Gamma-gated. Needs stable session (GAP-080). Needs Planner wiring (§12.29, STOP-gated Gamma) — OR can run as Beta post-access step without Planner if scoped correctly.)
- Constraint: RECON_ONLY tier (discovery, not exploitation). Authenticated crawl = DETECT. Testing IDOR/priv-esc = ACT = Gamma-gated (OFFENSIVE_APPROVED). Must use existing session cookie from Beta success. Must not test state-changing endpoints (POST/DELETE) — GET only for discovery.

---

## GAP-117 — Credential pattern mutation implementation (§12.34)
- Status: OPEN — ADR §12.34 LOCKED but code NOT BUILT.
- Priority: MEDIUM — literal cred-reuse misses pattern variants. If `Company2025!` works on service A but B uses `Company2026!`, Beta won't find it.
- Category: SS
- Stack: Universal
- What: ADR §12.34 "Within-engagement credential mutation" is LOCKED (2026-07-15) but NOT IMPLEMENTED. `cred_reuse.py` only does literal reuse — it takes the harvested credential as-is and tries it. `default_creds.py` uses a static list. There is no `CredentialPatternMutator` — no analysis of harvested credentials to extract patterns (company+year+suffix) and generate variants (increment year, swap separator, case, common suffix). GAP-013 was "MOVED to ADR §12.34" but MOVED ≠ IMPLEMENTED. `grep "CredentialPatternMutator|pattern.*mutator|credential.*mutation" ` in `agent_alpha/` = 0 results.
- Evidence: `cred_reuse.py:82-100` — `run()` iterates CREDENTIAL nodes, delegates to applicator. No mutation, no pattern extraction. `default_creds.py` — static list, no mutation. `grep "CredentialPatternMutator" ` = 0 results. ADR §12.34: "If `Company2025!` works on service A but B uses `Company2026!`, the agent will not find it — a human would automatically try pattern variants."
- Files: `agent_alpha/tools/internal/access/cred_reuse.py:82-100` — literal reuse only; `agent_alpha/tools/internal/access/default_creds.py` — static list; no `cred_mutator.py` module
- Cross-ref: ADR §12.34 (LOCKED, design decision), GAP-013 (MOVED to ADR — this GAP clarifies implementation is OPEN), GAP-104 (breach creds — complementary: breach data has real passwords, mutation generates variants), GAP-112 (offline crack — complementary: crack produces plaintext, mutation generates variants), ADR §12.22 D2 (lockout governor — mutation is credential spray, must be bounded).
- Impact: Beta misses credential variants that a human would try. `Niagamas2024!` harvested from wp-config → `Niagamas2025!` not tried on Odoo. Pattern mutation is the simplest cred-reuse enhancement and is ADR-LOCKED but unbuilt.
- Effort: MED (CredentialPatternMutator: analyze harvested creds → extract pattern (company+year+suffix) → generate bounded variants (±1 year, swap separator, case, common suffix) → try via existing applicator roster under lockout governor. ~150 lines. Must be ACTIVE_APPROVED + lockout-governed. Used only after literal reuse fails.)
- Constraint: ACTIVE_APPROVED + lockout governor (§12.22 D2). Bounded variants (≤4 per harvested cred, anti-Lyndon #7). Used only after literal reuse fails (sequential, not parallel). Successful patterns tracked in scratchpad for reuse within engagement (GAP-002).

---


# Proof Standard & Outcome Classification Gaps

## GAP-118 — Proof standard oracle — auth-vs-unauth diff (§12.43)
- Status: OPEN — CredReuseAttestor is provenance check, NOT independent oracle per §12.43.
- Priority: HIGH — per §12.43, Beta's access findings are NOT payable without independent oracle. Current CROSS_VERIFIED promotion is provenance-based, not oracle-based.
- Category: RG
- Stack: Universal
- What: ADR §12.43 "Proof Standard" requires: "The zero-FP GATE for an access/login-class finding = with the harvested credential, an INDEPENDENT fresh session obtains an authenticated-only ground-truth marker the unauthenticated session did NOT (auth-vs-unauth diff §12.32)." The current `CredReuseAttestor` (`attestation/attestor.py:50-79`) checks PROVENANCE: (1) node is ACCESS_LEVEL, (2) ENABLES edge from CREDENTIAL exists, (3) credential has non-empty secret_ref, (4) proof_artifacts contain "authenticated_request", (5) does not rely on node.verified. This is NOT the §12.43 oracle — it checks that proof artifacts EXIST and are BOUND, but does NOT independently re-authenticate or obtain an auth-vs-unauth diff. A bug in the tool that produces a false "authenticated_request" proof artifact would pass provenance check but fail the §12.43 oracle. The attestor code explicitly says: "Perform live re-authentication (Phase-6, Conductor-auth-gated, credential-keyed lockout — NOT wired here)."
- Evidence: `attestation/attestor.py:9-15` — "This module does NOT: Perform live re-authentication (Phase-6, Conductor-auth-gated, credential-keyed lockout — NOT wired here)." `attestation/attestor.py:50-79` — CredReuseAttestor checks provenance (proof exists + bound), not independent oracle. `conductor/verification.py:20` — `verify_access_nodes` runs CredReuseAttestor → promotes to CROSS_VERIFIED. But this is provenance promotion, not oracle promotion. ADR §12.43: "A screenshot can render a login page, a cached page, or a soft-200 — pixels prove nothing alone."
- Files: `agent_alpha/attestation/attestor.py:9-15,50-79` — CredReuseAttestor (provenance, not oracle); `agent_alpha/conductor/verification.py:20` — verify_access_nodes (promotes based on provenance); `agent_alpha/agents/beta/strike.py:458,488,538` — all nodes minted as SELF_VERIFIED
- Cross-ref: ADR §12.43 (PROPOSED — proof standard), ADR §12.32 (authenticated crawl — the oracle mechanism), GAP-116 (authenticated crawl implementation — prerequisite for oracle), GAP-079 (post-access validation — related but different: validation = prove access level, oracle = prove access is real via independent signal), ADR §12.31 (verification tiers — SELF_VERIFIED vs CROSS_VERIFIED).
- Impact: Beta's access findings are promoted to CROSS_VERIFIED via provenance, not via independent oracle. Per §12.43, this does NOT meet the payable floor. A false-positive in the tool (soft-200, cached page, login form misclassified as dashboard) would pass provenance check but fail independent oracle. The entire proof chain is weaker than §12.43 mandates. Findings may be reported as "proven" when they are only "provenance-checked."
- Effort: HIGH (independent oracle: (1) fresh session re-authenticate with harvested credential, (2) fetch authenticated-only marker (user account ID, admin DOM element, session-bound CSRF token), (3) fetch same URL without session → compare diff, (4) if diff exists → CONFIRMED, if no diff → REFUTED. Needs live re-auth = ACTIVE_APPROVED + lockout governor. Needs authenticated crawl (GAP-116) for marker discovery. ~300 lines. Conductor-auth-gated per attestor.py:13.)
- Constraint: ACTIVE_APPROVED (live re-authentication). Lockout-governed (§12.22 D2 — re-auth counts as attempt). Must use FRESH session (not Beta's original session — different failure mode). Must obtain auth-vs-unauth diff (§12.32 authenticated crawl). Phase-6 per attestor.py:13 — but §12.43 is PROPOSED, not LOCKED. If §12.43 locks, this GAP becomes the implementation track.

---

## GAP-119 — Credential-result semantics — negative outcome classification (§12.45)
- Status: OPEN — Beta reports FAILED without methodology caveat per §12.45.
- Priority: MEDIUM — false assurance risk: negative reported as "failed" without context could be misread as "password is safe."
- Category: RG
- Stack: Universal
- What: ADR §12.45 "Credential-result semantics" requires: (1) Positive only is a finding — no "credential_safe" node ever. (2) Negatives carry a methodology caveat, never a verdict — "bounded online derivation (≤4 candidates/user, lockout-safe) found no reusable credential for user X — this is NOT a password-strength assessment; offline cracking, credential stuffing, and large wordlists were out of engagement scope." (3) Methodology transparency — every credential section states what WAS and WAS NOT tested. Beta currently reports `status=FAILED` when cred-spray doesn't work, with no methodology caveat. Omega could misread this as "password is safe" — a credibility-destroying false assurance per §12.45.
- Evidence: `agents/beta/strike.py:356-357` — `if result is None or not result.success: return {"discovered_nodes": 0, "cost_usd": cost_usd}`. No methodology caveat in the return. No "what was tested" metadata. No "what was NOT tested" disclaimer. The A2A handoff carries status + findings_count but no methodology context.
- Files: `agent_alpha/agents/beta/strike.py:356-357` — FAILED return (no methodology caveat); `agent_alpha/agents/beta/strike.py:564-592` — _build_handoff_message (no methodology context in handoff)
- Cross-ref: ADR §12.45 (PROPOSED — credential-result semantics), GAP-079 (post-access validation — related but different: validation = prove access, semantics = classify negative), GAP-099 (MFA detection — similar honest-outcome pattern: "first factor valid, MFA required" not "FAILED"), GAP-098a (CAPTCHA detection — similar: "BLOCKED, captcha protected" not "FAILED"), ADR §12.60 (two-tier proof — honest blocked outcome principle).
- Impact: Without methodology caveat, Omega report could phrase a negative as "password is safe" — false assurance. If a real attacker later cracks it, the report was falsely reassuring. §12.45 explicitly forbids this: "Omega is FORBIDDEN from emitting 'safe/secure/strong/not predictable' from a negative credential result." But Beta doesn't provide the methodology context that Omega needs to comply.
- Effort: LOW (add methodology metadata to Beta's FAILED return: what was tested (cred_reuse, default_creds, user_derived), what was NOT tested (offline crack, breach data, large wordlist), attempt count, lockout status. ~40 lines. Omega consumes this metadata to generate the methodology caveat in the report.)
- Constraint: No code change to Omega yet (§12.45 is PROPOSED, not LOCKED). Beta should emit the methodology metadata NOW so when §12.45 locks, Omega can consume it. The metadata is: `{"tested": ["cred_reuse", "default_creds", "user_derived"], "not_tested": ["offline_crack", "breach_data", "large_wordlist"], "attempts": N, "lockout_governor_limit": M}`.

---


# APT Emulation Gaps (NEW — from APT architect assessment 2026-08-13)

## GAP-120 — IPv6 attack surface recon (forgotten hardening)
- Status: OPEN.
- Priority: MEDIUM — many targets forget to harden IPv6 stack; Alpha is IPv4-only (implicit).
- Category: RG
- Stack: Universal
- What: Alpha's HTTP client and origin discovery implicitly assume IPv4. Many targets have AAAA records and IPv6 infrastructure that is less hardened than IPv4 (WAF rules often IPv4-only, origin firewall often IPv4-only, rate limiting often IPv4-only). APT operators check IPv6 as a flank: if target has AAAA record, the IPv6 stack may bypass Cloudflare (CF proxies IPv4 by default, AAAA may point direct to origin). Alpha does not query AAAA records, does not probe IPv6 endpoints, does not check if WAF rules cover IPv6.
- Evidence: `grep "AAAA|ipv6|AF_INET6" ` in `agent_alpha/` = 0 results for IPv6 handling. `origin_resolver.py` — A-record only, no AAAA. `http_client.py` — no IPv6 option.
- Files: `agent_alpha/recon/origin_resolver.py` — A-record only; `agent_alpha/agents/http_client.py` — no IPv6; `agent_alpha/recon/passive_discovery.py` — no AAAA query
- Cross-ref: GAP-062 (TLS/MX/SPF — AAAA should be queried alongside A), GAP-115 (historical DNS — historical AAAA may reveal origin), ADR §12.61 A4 (grey-cloud subdomains — IPv6 may be DNS-only/grey-cloud).
- Impact: Missed flank vector. Target behind CF on IPv4 but origin exposed on IPv6. WAF rules IPv4-only = IPv6 bypass. Common in SEA (many hosting providers default-enable IPv6 but admins forget to harden).
- Effort: LOW (query AAAA record alongside A, probe IPv6 endpoint if AAAA exists, check if WAF/CF covers IPv6. ~40 lines. dnspython supports AAAA natively.)

---

## GAP-121 — DNSSEC zone walking (NSEC record enumeration)
- Status: OPEN.
- Priority: LOW — passive, 0 target touch, but only works on DNSSEC-signed zones.
- Category: RG
- Stack: Universal
- What: DNSSEC-signed zones use NSEC records to prove non-existence of a name. These NSEC records contain the next valid hostname in the zone — walking the NSEC chain enumerates ALL subdomains without brute force. This is passive (DNS query only, 0 target touch) and cannot be rate-limited by the target (DNS server responds to standard queries). Alpha currently uses brute-force subdomain enumeration (wordlist + crt.sh). NSEC walking is more comprehensive and stealthier.
- Evidence: `grep "NSEC|DNSSEC|zone.*walk" ` in `agent_alpha/` = 0 results. Subdomain enumeration uses wordlist + crt.sh/VT, not NSEC walking.
- Files: `agent_alpha/recon/passive_discovery.py` — no NSEC walking; `agent_alpha/recon/subdomain_enum.py` — wordlist-based
- Cross-ref: GAP-094 (DNS AXFR — related DNS enumeration, but AXFR is active and often blocked; NSEC walking is passive and works on DNSSEC zones), GAP-075 (subdomain takeover — NSEC walking discovers more subdomains to check).
- Impact: Missed passive subdomain enumeration vector. NSEC walking finds subdomains that wordlist misses (internal hostnames, random subdomains). Only works on DNSSEC-signed zones (~10% of domains), but when it works, it's comprehensive and stealthy.
- Effort: LOW (NSEC walking: query DNSSEC records, parse NSEC chain, extract subdomains. ~80 lines. dnspython supports DNSSEC. Must check if zone is DNSSEC-signed first — if not, skip.)

---

## GAP-122 — SMTP bounce-back analysis (internal infra leak)
- Status: OPEN.
- Priority: LOW — passive (send email, analyze bounce), but requires email interaction.
- Category: RG
- Stack: Universal (Exchange, Postfix, Sendmail, custom SMTP)
- What: SMTP bounce-back messages (550 errors) often leak internal infrastructure details: Exchange version (`Microsoft ESMTP MAIL Service ready at...`), internal routing headers (`Received: from internal-mail.corp.local`), internal hostnames, mail server software/version, internal IP addresses in headers. APT operators send emails to non-existent addresses (`aaaaaaa@target.com`) and analyze the bounce response for internal infra intelligence. Alpha does not send emails or analyze bounce responses.
- Evidence: `grep "SMTP|smtp|bounce|550|EHLO" ` in `agent_alpha/` = 0 results for bounce analysis. No SMTP client module for recon.
- Files: No SMTP recon module. `agent_alpha/recon/` — no smtp_probe.py
- Cross-ref: GAP-082 (SMTP enumeration — related but different: GAP-082 is about user enum via SMTP VRFY/EXPN, this is about infra leak via bounce analysis), GAP-062 (MX/SPF — prerequisite: must know MX records to know where to send).
- Impact: Missed internal infra intelligence. Bounce messages reveal Exchange version (CVE matching), internal hostnames (origin discovery), internal IP ranges (network mapping). Passive — 1 email, no active probe.
- Effort: LOW (send email to non-existent address, parse bounce response for version/host/IP leaks. ~60 lines. smtplib standard library. Must use engagement-controlled email sender, not target's domain.)
- Constraint: RECON_ONLY (send 1 email, analyze response). Must NOT spam (1 bounce per target). Must use engagement-controlled sender address. Bounce analysis is passive intelligence, not active exploitation.

---

## GAP-123 — Certificate Transparency delay analysis (post-CF origin leak)
- Status: OPEN.
- Priority: MEDIUM — complement to GAP-093 (cert SAN) and GAP-115 (historical DNS).
- Category: RG
- Stack: Universal
- What: GAP-093 extracts SAN from current certificates. But Certificate Transparency logs contain HISTORICAL certificates — certs issued BEFORE the target fronted Cloudflare. These pre-CF certs often contain the origin IP or internal hostname in SAN. The timing is key: if a cert was issued 2 days before the apex moved behind CF, the SAN from that cert likely contains the origin IP (the cert was issued for the origin, not the CF edge). Alpha's crt.sh query (in origin_resolver) fetches current certs but does not analyze the TIMING of cert issuance relative to CF fronting.
- Evidence: `origin_resolver.py` — queries crt.sh for SAN extraction but does not analyze cert issuance date vs CF fronting date. No temporal analysis of CT logs. `grep "not_before|not_after|cert.*date|issuance.*date" ` in `agent_alpha/` = 0 results for temporal cert analysis.
- Files: `agent_alpha/recon/origin_resolver.py` — crt.sh query (no temporal analysis); no CT log temporal analysis module
- Cross-ref: GAP-093 (cert SAN extraction — this GAP adds temporal dimension), GAP-115 (historical DNS — complementary: historical DNS + historical cert = origin discovery pre-CF), ADR §12.61 A3 (cert pivot — temporal analysis enhances cert pivot).
- Impact: Missed origin discovery vector. Pre-CF certs in CT logs may contain origin IP in SAN. Without temporal analysis, Alpha sees the SAN but doesn't know which cert is pre-CF (origin-bearing) vs post-CF (CF-edge-bearing). Timing is the differentiator.
- Effort: MED (query CT logs, parse cert issuance dates, compare with CF fronting date (from historical DNS GAP-115), flag pre-CF certs for SAN origin extraction. ~100 lines. crt.sh API returns cert issuance dates. Must compose with GAP-115 for CF fronting date.)

---

## GAP-124 — Job posting / tech stack mining (infrastructure inference)
- Status: OPEN.
- Priority: LOW — passive OSINT, but low value for SEA market (job postings rarely reveal infra detail).
- Category: RG
- Stack: Universal
- What: Job postings often reveal technology stack: "Looking for DevOps engineer with experience in Kubernetes, Kafka, Redis, PostgreSQL" = target uses K8s + Kafka + Redis + Postgres. "Looking for WordPress developer" = target uses WP. Senior-level postings reveal more: "Experience with Cloudflare Workers, AWS S3, Lambda" = target uses CF Workers + AWS. APT operators mine job postings to build a tech stack profile before touching the target. Alpha does not mine job postings.
- Evidence: `grep "job.*posting|job.*board|linkedin.*job|glassdoor|tech.*stack.*mining" ` in `agent_alpha/` = 0 results. No job posting OSINT module.
- Files: No job posting OSINT module. `agent_alpha/recon/` — no job_probe.py
- Cross-ref: GAP-069 (Trust Graph — job postings reveal org structure: who's hiring, what team), GAP-091 (GitHub/GitLab — related OSINT, but code-focused not hiring-focused), GAP-095 (social media — related org intel).
- Impact: Low for SEA market. Indonesian job postings (JobStreet, Kalibrr) rarely reveal specific infra detail. Higher value for enterprise/US targets. Passive, 0 target touch.
- Effort: LOW (scrape job postings from LinkedIn/JobStreet for target company, extract tech keywords, mint ASSET tech_stack hints. ~80 lines. LinkedIn API or scraping. Legal: public job postings are public data.)
- Constraint: RECON_ONLY. Public job postings only. No personal data collection (no candidate profiles, no recruiter names). Company-level tech stack inference only.

---

## GAP-125 — Deception detection (honeypot / canary token / sinkhole)
- Status: OPEN.
- Priority: LOW-MEDIUM — APT detects deception before touching; Alpha has no deception awareness.
- Category: RG
- Stack: Universal
- What: Advanced targets deploy deception: honeypots (fake services that alert on touch), canary tokens (fake .env files, fake API keys that alert when accessed), sinkholes (DNS that redirects to analyst sandbox). APT operators test for deception before interacting: check if a discovered .env file is too convenient (canary), check if an open port behaves like a real service or a honeypot, check if a discovered subdomain resolves to a known sandbox IP range. Alpha has no deception awareness — it treats all discovered surfaces as real and touches them, potentially alerting the target's SOC.
- Evidence: `grep "honeypot|canary|deception|sinkhole|tripwire" ` in `agent_alpha/` = 0 results. No deception detection module. Alpha treats all findings as real.
- Files: No deception detection module. `agent_alpha/recon/` — no deception_check.py
- Cross-ref: GAP-028 (origin-direct response validation — related: validate that origin is real, not sandbox), ADR §12.58 (strategic situation reasoning — deception detection is part of adversarial reasoning), ADR §12.59 (hybrid cognition — LLM advisor may help with deception detection).
- Impact: Alpha may touch honeypots/canaries and alert target SOC. In a real APT emulation, this burns the engagement. For SaaS red team (engagement is announced), this is less critical — but for "stealth assessment" engagements, deception detection is valuable.
- Effort: MED (canary token detection: check if .env file contains canary patterns (Canarytokens.org patterns, Thinkst patterns). Honeypot detection: check if open port behaves like real service (banner analysis, protocol fingerprinting). Sinkhole detection: check if resolved IP is in known sandbox/analyst IP ranges. ~150 lines. Needs canary pattern database + sandbox IP range list.)
- Constraint: RECON_ONLY (detection, not avoidance — Alpha should REPORT deception detected, not silently avoid it. The engagement report should include "deception infrastructure detected: honeypot on port X, canary token in .env file" as a finding.)

---


# APT Architect Assessment — New GAPs (2026-08-13)

## GAP-126 — Document metadata intel (PDF/DOCX/EXIF from public files)
- Status: OPEN.
- Priority: MEDIUM — employee names, internal hostname, software version, timezone from public documents. High intel value but requires new document discovery + fetch capability.
- Category: RM (RECON_MISS — Alpha doesn't capture data available in public documents)
- Stack: Universal (any target with public PDF/DOCX/images)
- What: PDF, DOCX, XLSX, and image files published on target websites contain embedded metadata: author names (employees), creator software + version (CVE match), template paths (internal hostnames like `\\FILESERVER\Templates\`), company name, timezone, GPS coordinates (images). This metadata is physically embedded in the file bytes per international standards (PDF ISO 32000, OOXML ECMA-376, EXIF JEITA CP-3451). Tools like Metagoofil and FOCA have exploited this for years. Alpha currently fetches ONLY `.env.bak`, `wp-config.php.bak`, `.git/config`, and actuator endpoints — it does NOT discover, fetch, or parse public documents (PDF/DOCX/XLSX/images). This is a 3-step gap: (1) document discovery (crawl HTML, extract href/src with document extensions), (2) document fetch (GET the document URL), (3) metadata parse (extract embedded metadata from file bytes).
- Evidence: `grep "\.pdf|\.docx|\.xlsx|\.jpg|\.png" ` in `agent_alpha/recon/` = 0 results. `constants.BACKUP_FILE_PATHS` contains only `.env.bak`, `wp-config.php.bak`, `database.yml.bak` — no document extensions. `WELL_KNOWN_LEAK_PATHS` = GIT + BACKUP + ACTUATOR only. No document discovery, no document fetch, no metadata parser in codebase.
- Files: `agent_alpha/config/constants.py` — BACKUP_FILE_PATHS (no document extensions); `agent_alpha/recon/path_probe.py` — processes only leak paths, not documents; `agent_alpha/agents/alpha/scout.py` — crawl extracts href for frontier expansion, does NOT filter for document extensions; no `doc_metadata_probe.py` module exists.
- Cross-ref: GAP-069 (Trust Graph — employee names from metadata feed USER nodes), GAP-104 (breach data — employee names enable breach query), GAP-088/089 (version extraction + CVE — software version from metadata feeds CVE match), GAP-115 (historical DNS — internal hostname from template path enables DNS query), GAP-120 (IPv6 — internal hostname may have AAAA record), GAP-128 (timezone-aware pacing — timezone from metadata feeds pacing).
- Impact: Missed free intelligence. Public documents are published by the target intentionally — fetching them is passive RECON_ONLY. Metadata leaks are well-documented (NSA advisory, SANS FOR572, Metagoofil, FOCA). UKM/SEA targets frequently upload documents without stripping metadata. Employee names → breach data query → credential reuse. Internal hostname → origin discovery. Software version → CVE match.
- Effort: MED (~200 lines total). Document discovery: ~80 lines (parse HTML, filter href by extension `.pdf/.docx/.xlsx/.pptx/.jpg/.png`, add to frontier). Document fetch: ~20 lines (http_client GET, save bytes). Metadata parse: ~100 lines (PyPDF2/pikepdf for PDF Info+XMP, zipfile+xml.etree for OOXML docProps, Pillow for EXIF). Dependencies: PyPDF2 or pikepdf (pip), Pillow (may already exist for screenshots), zipfile+xml.etree (standard library).
- Constraint: RECON_ONLY (fetch public documents = passive GET, same as any browser). Only fetch documents linked from target's own pages (no Google dorking — that's a separate capability). Skip files >10MB (metadata not worth bandwidth). Parse metadata ONLY, not document content. Do NOT store file content in graph — only extracted metadata fields.

---

## GAP-127 — SaaS vendor integration map (DNS TXT verification records)
- Status: OPEN.
- Priority: MEDIUM — reveals target's SaaS vendor stack from 1 DNS query, 0 target touch.
- Category: RM (RECON_MISS — Alpha doesn't query TXT records for SaaS verification)
- Stack: Universal
- What: SaaS vendors require domain verification via DNS TXT records. These records persist after verification and reveal the target's SaaS stack: `google-site-verification=...` (Google Workspace), `atlassian-domain-verification=...` (Atlassian/Jira/Confluence), `zendesk-verification=...` (Zendesk), `stripe-verification=...` (Stripe), `MS=ms...` (Microsoft 365), `facebook-domain-verification=...` (Facebook/Meta), `slack-verification-token=...` (Slack). Each verification record = a trust boundary that could be abused. Alpha currently queries A, MX, SPF, DMARC records (GAP-062) but does NOT query TXT records for SaaS vendor enumeration.
- Evidence: `grep "TXT|txt.*record|google-site-verification|atlassian-domain|zendesk" ` in `agent_alpha/` = 0 results for SaaS verification parsing. DNS queries focus on A/MX/SPF/DMARC, not TXT enumeration.
- Files: `agent_alpha/recon/passive_discovery.py` — DNS queries (no TXT SaaS enumeration); `agent_alpha/recon/origin_resolver.py` — A/AAAA only.
- Cross-ref: GAP-062 (TLS/MX/SPF/DMARC — TXT query should be added alongside), GAP-069 (Trust Graph — SaaS vendors = trust boundary nodes), GAP-130 (OAuth app enumeration — SaaS vendors that support OAuth = OAuth trust boundary), ADR §12.56 (supply chain recon — SaaS integrations are supply chain), ADR §12.61 axis B6 (SaaS shadow-IT).
- Impact: Missed trust boundary mapping. Knowing target uses Zendesk = Zendesk API is a potential entry vector. Knowing target uses Atlassian = Jira/Confluence may expose internal project data. Knowing target uses Google Workspace = OAuth token theft vector (GAP-114). All from 1 DNS TXT query, 0 target touch.
- Effort: LOW (~40 lines). Query DNS TXT records (dnspython, already used for A/MX). Parse known verification patterns (regex for `google-site-verification`, `atlassian-domain-verification`, `zendesk-verification`, `MS=ms`, `stripe-verification`, `facebook-domain-verification`, `slack-verification-token`). Mint SERVICE nodes for each discovered SaaS vendor.
- Constraint: RECON_ONLY (DNS query, 0 target touch). Public DNS records = public data.

---

## GAP-128 — Timezone-aware pacing (SOC-hours targeting)
- Status: OPEN.
- Priority: MEDIUM — basic APT instinct: attack when SOC is asleep.
- Category: RM (RECON_MISS — Alpha doesn't factor target timezone into pacing)
- Stack: Universal
- What: APT operators time their attacks to target's off-hours — when SOC analysts are asleep, response time is slowest, and WAF rule updates are least likely. Alpha's StealthPacer controls request rate but has no timezone awareness — it paces at the same rate regardless of whether it's 2am or 2pm target local time. Target timezone can be inferred from: HTTP `Date` header (server timezone), geo-IP lookup (target country → timezone), or document metadata (GAP-126 CreationDate timezone offset). Once known, Alpha should adjust pacing to concentrate active probes during target's off-hours (typically 11pm-6am target local).
- Evidence: `grep "timezone|tz|SOC.*hours|off.*hours|Date.*header.*timezone" ` in `agent_alpha/` = 0 results for timezone-aware pacing. StealthPacer uses fixed intervals, no timezone input.
- Files: `agent_alpha/recon/stealth_pacer.py` (or equivalent pacing module) — no timezone input; `agent_alpha/agents/alpha/scout.py` — no timezone extraction from HTTP Date header.
- Cross-ref: GAP-026 (StealthPacer gate — related: pacing control), GAP-126 (document metadata — timezone from CreationDate feeds this), ADR §12.49 (proactive evasion — timezone-aware pacing is evasion enhancement).
- Impact: Alpha runs at the same speed regardless of target SOC presence. For announced engagements, this is acceptable. For stealth assessments, attacking during SOC off-hours reduces detection risk. Basic APT instinct that costs ~20 lines to implement.
- Effort: LOW (~20 lines). Extract timezone from HTTP `Date` header (parsedatetime or manual parse). Pass to StealthPacer. Adjust pacing schedule: concentrate active probes in target off-hours (configurable, default 23:00-06:00 target local). Or simpler: just record target timezone as ASSET metadata for now, defer schedule adjustment to Phase 6.
- Constraint: RECON_ONLY (timezone extraction is passive). Schedule adjustment is config-level, not code self-modification.

---

## GAP-129 — VPN/Remote Access fingerprinting (expand GAP-081)
- Status: OPEN.
- Priority: HIGH — VPN/RA is primary APT entry vector; GAP-081 is HTTP-only top-20 ports.
- Category: RM (RECON_MISS — Alpha doesn't fingerprint non-HTTP remote access services)
- Stack: Universal (VPN endpoints, remote access tools)
- What: GAP-081 (port scanning) is scoped to "top-20 ports" with "stealth concern" framing — scanner mindset. APT operators map the FULL external perimeter including VPN endpoints (IKEv2/IPSec on UDP 500/4500, OpenVPN on UDP 1194/TCP 443, WireGuard on UDP 51820, SSTP on TCP 443, AnyConnect on TCP 443/8443) and remote access tools (TeamViewer on TCP 5938, AnyDesk on TCP 6568, Chrome Remote Desktop via HTTPS, RDP on TCP 3389, VNC on TCP 5900-5910). Many SEA targets expose TeamViewer/AnyDesk without 2FA — a payable finding. Alpha currently does not fingerprint these services. GAP-081 should be expanded beyond HTTP-only top-20 to include VPN/RA fingerprinting.
- Evidence: `grep "IKE|IPSec|OpenVPN|WireGuard|TeamViewer|AnyDesk|RDP|VNC|3389|5938" ` in `agent_alpha/` = 0 results for VPN/RA fingerprinting. GAP-081 scope is HTTP-centric.
- Files: `agent_alpha/recon/` — no VPN/RA fingerprinting module; GAP-081 detailed entry — scope is top-20 ports, HTTP-focused.
- Cross-ref: GAP-081 (port scanning — this GAP expands its scope), GAP-062 (MX/SPF — mail infrastructure is another non-HTTP surface), GAP-103 (cross-service cred reuse — VPN cred reuse if creds harvested).
- Impact: Missed primary APT entry vector. VPN compromise = initial access without touching web application. TeamViewer/AnyDesk without 2FA = direct remote access finding. Many SEA UKM expose these. Finding "TeamViewer exposed on 168.110.192.62:5938 without 2FA" = payable.
- Effort: MED (~120 lines). UDP probe for IKE (send IKE_SA_INIT, parse response). TCP connect + banner for OpenVPN/RDP/VNC/TeamViewer/AnyDesk. Service fingerprinting from response. Must be tier-gated (port scan = RECON_ONLY, but some targets may consider active port scan as intrusive — engagement config should control).
- Constraint: RECON_ONLY (fingerprinting, not exploitation). Port scanning may require engagement-level authorization beyond default RECON_ONLY — some clients consider port scanning active. Must respect engagement config `allow_port_scan` flag.

---

## GAP-130 — OAuth app enumeration (trust boundary mapping)
- Status: OPEN.
- Priority: MEDIUM — APT29 Nobelium used malicious OAuth apps; target's existing OAuth apps = trust boundary.
- Category: RM (RECON_MISS — Alpha doesn't enumerate target's OAuth app integrations)
- Stack: Universal (targets using Google Workspace, Microsoft 365, Slack, GitHub)
- What: Modern targets integrate third-party OAuth apps into their SaaS platforms (Google Workspace, Microsoft 365, Slack, GitHub). Each OAuth app has scopes (read email, read files, manage calendar) = trust boundary. APT29 Nobelium campaign used malicious OAuth application for persistent access to victim mailboxes. External red team should enumerate: which OAuth apps does the target have installed? What scopes do they have? Are any over-privileged? This is passive intelligence — querying platform APIs for installed apps (where authorized) or inferring from DNS TXT records (GAP-127) and cookie domains.
- Evidence: `grep "OAuth.*app|installed.*app|app.*permission|consent.*phishing" ` in `agent_alpha/` = 0 results for OAuth app enumeration.
- Files: No OAuth app enumeration module. `agent_alpha/recon/` — no oauth_app_probe.py.
- Cross-ref: GAP-114 (OAuth/SAML/JWT token theft — OAuth apps are the trust boundary that enables token theft), GAP-127 (SaaS vendor map — DNS TXT reveals which SaaS platforms target uses, enabling targeted OAuth app enum), GAP-069 (Trust Graph — OAuth apps = trust relationship nodes), ADR §12.56 (supply chain recon — OAuth apps are supply chain trust).
- Impact: Missed trust boundary mapping. Without knowing target's OAuth app landscape, Alpha cannot identify over-privileged apps or potential OAuth abuse vectors. APT29 pattern: enumerate OAuth apps → find over-privileged app → steal/abuse its token → persistent access.
- Effort: MED (~100 lines). For Google Workspace: Google Admin SDK API (requires domain admin token — may not be available for external red team). For Slack: Slack API `admin.apps.requests.list` (requires admin token). For GitHub: GitHub API `/orgs/{org}/installations` (public for orgs with GitHub Apps). Fallback: infer from DNS TXT (GAP-127) + cookie domain analysis (set-cookie domain reveals SaaS platform). Realistic external red team approach: infer from passive signals (DNS TXT, cookie domains, JS references to SaaS APIs), not platform admin API.
- Constraint: RECON_ONLY (passive enumeration). Do NOT install malicious OAuth apps (that's Gamma OFFENSIVE_APPROVED + destructive). Do NOT abuse OAuth tokens (that's Beta/Gamma with authorization).

---

## GAP-131 — Refresh token abuse (OAuth session persistence)
- Status: OPEN.
- Priority: MEDIUM — without refresh token handling, expired OAuth session = dead end.
- Category: SS (STRIKE-SHORT — Beta can't persist OAuth-based access)
- Stack: Universal (targets using OAuth/OIDC)
- What: OAuth/OIDC flows issue two tokens: access token (short-lived, 15min-1hr) and refresh token (long-lived, days-weeks-months). When Alpha/Beta harvests an OAuth access token (from JS leak, .env, browser storage), the token may already be expired. Without refresh token handling, Beta reports "token expired" and moves on — missing a valid persistence vector. APT operators use refresh tokens to maintain access for weeks/months without re-authentication. Beta should: (1) check if harvested token set includes refresh token, (2) if access token expired, use refresh token to get new access token, (3) report "valid refresh token with scope X, persistence duration Y" as finding.
- Evidence: `grep "refresh.*token|refresh_token|token.*refresh|OAuth.*persist" ` in `agent_alpha/` = 0 results for refresh token handling. GAP-114 mentions OAuth/JWT but does not cover refresh token flow.
- Files: No refresh token handling. `agent_alpha/tools/internal/access/` — no oauth module. GAP-114 detailed entry — covers token theft/forgery but not refresh flow.
- Cross-ref: GAP-114 (OAuth/SAML/JWT — this GAP adds refresh token persistence), GAP-102 (session cookie riding — related session persistence), GAP-101 (API key — related token-based access), GAP-116 (authenticated crawl — refresh token enables sustained crawl session).
- Impact: Missed persistence vector. Harvested OAuth token set with refresh token = weeks of access. Without refresh handling, Beta misses this and reports "expired token" = false negative. APT uses refresh tokens for silent persistence — no re-login needed, no log entry per access.
- Effort: LOW (~60 lines). Parse harvested token set for `refresh_token` field. If access token expired + refresh token present: POST to OAuth token endpoint with `grant_type=refresh_token`. Parse new access token. Report persistence duration (from refresh token expiry). Must be tier-gated: token validation = RECON_ONLY, refresh = active use of harvested credential (RECON_ONLY+ or Beta tier).
- Constraint: Refresh token use = active credential use (not pure passive). Must be authorized. Do NOT refresh tokens for accounts not in scope. Report refresh token as finding with scope + persistence duration, do NOT use refreshed token for further access without explicit authorization.

---


## GAP-153 — Engagement-scope coverage projection (generalizes §12.45; anti false-assurance)
- Status: SLICE 1 BUILT 2026-08-14 (`agent_alpha/coverage/techniques.yaml` + `coverage_ledger.py`,
  7 tests green, mypy/ruff clean). Omega report section = NEXT slice.
- Priority: HIGH — the direct fix for engagement-wide false assurance. Lowest dependency of the
  strategic layer (pure projection; independent of GAP-050 and the Conductor root-causes).
- Category: RG · Stack: Conductor/Omega
- What: §12.45 forbids "password safe" from one negative credential. The same lie exists at
  engagement scope: "no findings" on surfaces never tested. This projects `{discovered surfaces}
  × {technique catalog}` into 5 buckets (tested / not_run / blocked / capability_absent /
  out_of_scope) + an engagement `not_assessed` list, so Omega states what WAS and WAS NOT tested.
  `not_run` doubles as a runtime wiring-gate (capable-but-unfired = Lyndon #2 caught live).
- Evidence: `agents/omega/roaster.py:_build_findings` builds POSITIVE findings only — no coverage
  section. `validation_vs_scanner.py:272` already writes the honesty principle ("Nuclei has broader
  coverage") but ONLY in the dev field-prove harness, never in the client report.
- Files: `agent_alpha/coverage/techniques.yaml` (canonical denominator), `agent_alpha/coverage/
  coverage_ledger.py` (projection). NEXT: `agents/omega/` consumes CoverageReport into the report.
- Cross-ref: ADR §12.62 (Coverage-Honesty Doctrine — the decision), §12.45 (per-credential origin),
  GAP-119 (per-credential caveat — this is its engagement-scope generalization), GAP-074 (auth
  mechanism = auth-column denominator precision), GAP-073 (WAF mode = `blocked` precision),
  GAP-079 (access-level = positive-cell depth), GAP-069 (trust surfaces = new rows; ledger reports
  their absence honestly BEFORE 069 is built).
- Effort: LOW (slice 1 done). NEXT slices: Omega section (MEDIUM), per-technique run events for
  run-signal precision (MEDIUM — today recon techniques default conservatively to not_run).
- Constraint: techniques.yaml is the SINGLE technique source (anti-#7) — playbook technique_id +
  gap capability_absent derive from it. Payability stays binary (cross_verified).

---


# Enhancements to existing GAPs (2026-08-13)

## ENH-1 (GAP-113) — Automated token entropy analysis
- Parent: GAP-113 (Password Reset Abuse)
- What: GAP-113 Vector 3 (predictable reset token) currently describes manual detection. Add automated entropy analysis: request 3 reset tokens for an attacker-controlled test account, analyze randomness (Shannon entropy, sequential pattern check, timestamp correlation). If tokens are predictable (low entropy, sequential, timestamp-derived), flag as critical finding — token prediction could enable autonomous account takeover.
- Effort: LOW (~50 lines). Request 3 tokens, compute Shannon entropy, check for sequential/timestamp pattern. Compare against cryptographic randomness baseline.
- Constraint: Use attacker-controlled test account, NOT victim account. Detection only (v1) — do NOT use predicted token to change password without OFFENSIVE_APPROVED.
- Cross-ref: GAP-113 Vector 3, GAP-108 (reset user enum — related reset flow analysis).

---

## ENH-2 (GAP-108) — Response time differential for user enumeration
- Parent: GAP-108 (Password Reset Flow User Enumeration)
- What: GAP-108 currently covers message differential ("user not found" vs "reset link sent"). Add response time differential: valid users typically take longer (server generates token, sends email) than invalid users (quick rejection). Measure response time for 3+ requests per email, compare timing distributions. Valid user = 200ms, invalid = 50ms = user enumeration with higher accuracy than message differential alone.
- Effort: LOW (~30 lines). Measure HTTP response time for reset endpoint. Compare timing across valid/invalid emails. Flag significant timing differential as user enumeration vector.
- Constraint: RECON_ONLY (timing measurement, not exploitation). Use engagement-controlled test emails for baseline. Do NOT brute-force emails (that's user enumeration attack = OFFENSIVE_APPROVED).
- Cross-ref: GAP-108, GAP-113 (reset abuse — related reset flow analysis).

---

## ENH-3 (GAP-116) — TOTP secret exposure detection
- Parent: GAP-116 (Authenticated Crawl)
- What: After GAP-116 basic authenticated crawl is built, add TOTP secret exposure check: scan authenticated pages (especially profile/settings/security pages) for TOTP QR code images or TOTP secret strings. If a page displays a valid TOTP QR code (base32 secret embedded in `otpauth://totp/...` URL), this is a critical finding — anyone with access to the page can generate valid MFA codes. This is a configuration error (TOTP secret should only be shown once during setup, not on every profile view).
- Effort: LOW (~40 lines). After authenticated crawl, parse page content for `otpauth://totp/` URLs or QR code images containing TOTP secrets. Flag as critical finding.
- Constraint: RECON_ONLY (detection, not exploitation). Do NOT generate MFA codes from discovered secret (that's OFFENSIVE_APPROVED). Report as finding: "TOTP secret exposed on profile page = MFA bypass possible."
- Dependency: GAP-116 must be built first (authenticated crawl). This enhancement runs on top of crawl results.
- Cross-ref: GAP-116, GAP-099 (MFA detection — related MFA surface analysis).

---


# ADR §12.61 Cross-Reference Index (NEW)

The following GAPs are implementations of ADR §12.61 "Flank-when-CF-hard" axes. This index maps each §12.61 technique to its GAP entry for traceability.

## Axis A — Find the ORIGIN (go around CF)

| §12.61 Technique | GAP | Status | Notes |
|------------------|-----|--------|-------|
| A1: Historical DNS (SecurityTrails/DNSHistory) | **GAP-115** | OPEN | Biggest missing signal per ADR. crt.sh/VT/OTX failed on 4 field targets. |
| A2: Mail/MX/SPF → origin netblock | **GAP-062** | OPEN | MX records reveal origin infrastructure (mail servers on origin, not CF). |
| A3: Cert/favicon pivot (Shodan/Censys) | **GAP-093** + **GAP-086** | OPEN | Cert SAN reveals internal hostnames. Favicon hash matches origin via Shodan/Censys. |
| A4: Grey-cloud/forgotten subdomains | **GAP-075** | OPEN | Subdomain takeover checks dangling CNAME. Grey-cloud subdomains bypass CF. |

## Axis B — Skip the perimeter (login reachable THROUGH CF)

| §12.61 Technique | GAP | Status | Notes |
|------------------|-----|--------|-------|
| B5: Leaked credentials (breach data) | **GAP-104** | OPEN | Breach data → cred-stuff CF-fronted login. Valid creds walk through CF. #1 real-APT vector. |
| B5 prerequisite: email harvest | **GAP-054** | OPEN | WP REST user email = input for breach data query. Without email, no breach correlation. |
| B5 prerequisite: email pattern inference | **GAP-090** | OPEN | Infer email pattern from known email → generate candidates for breach query. |
| B6: Exposed secrets in public code (GitHub/GitLab) | **GAP-091** | OPEN | Developers commit .env/API keys to public repos. Passive OSINT. |
| B6 complement: JS secret extraction | **GAP-058** | OPEN | Target's own JS files may contain API keys, origin IPs. Complements B6 (external repos). |
| B7: Public cloud storage (S3/GCS/Azure) | **GAP-076** | OPEN | S3 buckets named after target, often public read. No CF protection. |
| B8: Subdomain takeover (dangling CNAME) | **GAP-075** | OPEN | Passive-discoverable, claimable. Same GAP as A4 (takeover is both origin discovery and access). |

## §12.61 flank strategy inputs

| Input | GAP | Status | Notes |
|-------|-----|--------|-------|
| CVE determines flank axis | **GAP-052** + **GAP-053** + **GAP-088** + **GAP-089** | OPEN | Unauth CVE → skip Beta (exploit entry). Auth CVE → need credential (axis B5). |
| WAF capability determines flank axis | **GAP-073** | OPEN | Aggressive WAF → skip cred-spray, flank via origin (axis A). Lenient WAF → cred-spray OK (axis B5). |
| Auth mechanism determines transport | **GAP-074** | OPEN | Must know auth mechanism to choose correct cred-stuff transport through CF. |
| DB names for cred-stuff target selection | **GAP-063** | OPEN | `erp` DB likely has different cred policy than `test` DB. |
| Origin binding (two-proof) | **GAP-042** | FIXED | Historical IP / cert pivot / favicon pivot candidates must pass two-proof binding. |

## §12.61 deferred items

| Item | GAP | Reason |
|------|-----|--------|
| Brute CF edge (challenge-solve, IP-rep evasion) | — | INFRA ceiling: residential/mobile proxy = procurement, not code. ADR §12.61 rejected. |
| Human interaction simulation | — | ADR §12.62 DEFERRED. Promotion gate: target with hCaptcha/DataDome + no origin bypass + no cred reuse. |
| HTTP Basic Auth applicator | **GAP-046** | Deferred after §12.61 slices. |
| Username harvest non-WP | **GAP-047** | Deferred after §12.61 slices. |

## §12.61 recommended order (per ADR)

ADR §12.61 recommends: "Do NOT build all of A1–B8. Recommended order by leverage:
**(1) Historical DNS origin discovery** (passive, extends the moat, most likely to open niagamas/bernofarm) → **(2) cert/favicon pivot** → **(3) leaked-cred stuffing** (axis B)."

Mapped to GAPs:
1. GAP-115 (historical DNS) — HIGHEST priority per ADR
2. GAP-093 (cert SAN) + GAP-086 (favicon hash) — cert/favicon pivot
3. GAP-104 (breach cred) + GAP-054 (email) + GAP-090 (email pattern) — leaked-cred stuffing

---

## GAP-074 — Authentication Mechanism Fingerprinting & Selection

### Problem Statement
An auth-surface label was binary (`login-form`, `spa-login-form`, `http_basic_auth`). Without understanding the underlying auth *mechanism* (form POST, JSON-RPC, HTTP Basic, JWT/SAML/OAuth), Beta would fire the wrong tool at a surface (e.g. form-POST tool at a JSON-RPC endpoint, root cause of GAP-067 failure).

### Implementation Slices
1. **Slice 1 (PR #406)**: Universal recon fingerprinting in `scout._detect_auth_surface` adding `mech_*` labels (`mech_http_basic`, `mech_json_rpc`, `mech_jwt`, `mech_saml`, `mech_oauth`, `mech_form_post`) persisted on `ASSET.tech_stack`.
2. **Slice 2a (PR #408)**: Single-source mechanism-to-applicator service mapping in `recon.auth_surface` (`_ALL_MECH_LABELS`, `MECH_TO_APPLICATOR_SERVICES`, `applicator_services_for_mechanisms`). Mechanism-aware binding in `applicator_factory._resolve_in_scope_targets()` (fail-open when unclassified, fail-closed for unmapped/unstrikable `mech_*`).
3. **Slice 2b**: Mechanism-precise coverage ledger denominator in `coverage_ledger.py` (`bare_mechanisms()`, `Surface.mechanisms`, and precision filter in `project_coverage()`).
4. **Slice 2c (Next)**: Odoo JSON-RPC fallback (`/web/session/authenticate` in `OdooAccessTool` for CF/WAF-blocked XML-RPC).

### Known Limitations (Precision vs. False-Clean Trade-off)
1. **Misclassification Omission (Recon Error)**: When a host that actually uses JSON-RPC is misclassified as `mech_form_post` (e.g. due to a static HTML post form in the shell), `coverage_ledger.project_coverage()` excludes `spa_json_login` from the applicable denominator. As a result, `spa_json_login` will NOT appear as `not_run` on that host (silent omission). This is an accepted trade-off to keep the coverage denominator free of false `not_run` noise on verified form-only targets.
2. **Shared `run_event` on Unclassified Surfaces**: On a surface with unclassified mechanism (fail-open), executing any credential applicator emits `StrikeCandidateAttempted`. Because `cred_reuse`, `spa_json_login`, and `default_creds_login` currently share `run_event: StrikeCandidateAttempted`, attempting a form strike marks all unclassified auth techniques on that host as `tested`. Future refinement may introduce technique-specific run events or payload tags.


