# Agent-Alpha — Knowledge Base
## Technical Reference for Architecture Sessions

---

## K1. Kill Chain Reference (Agent → Technique → Tool)

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

---

## K2. Attack Graph Schema

### Node Types
```python
@dataclass
class AttackNode:
    id: str                    # unique: "asset:ingco.co.id", "vuln:CVE-2019-11043"
    type: Literal[
        "asset",              # target host/domain
        "vulnerability",      # CVE or custom vuln
        "credential",         # username/password/token/key
        "service",            # running service (port+protocol)
        "data",               # harvested data type
        "access_level"        # shell, admin, db_root, domain_admin
    ]
    properties: dict          # type-specific properties
    confidence: float         # 0.0–1.0
    proof_artifacts: list     # request/response, screenshot, sample
    agent: str                # which agent found this
    timestamp_utc: str        # discovery time
    verified: bool            # passed VERIFY phase
```

### Edge Types
```python
@dataclass  
class AttackEdge:
    source_id: str
    target_id: str
    relationship: Literal[
        "exploits",           # vuln exploits asset
        "enables",            # credential enables access
        "requires",           # exploit requires precondition
        "leads_to",           # access leads to data
        "lateral_move_to",    # pivot from host A to host B
        "pivots_via",         # route used: A → tunnel → B
        "confirms"            # finding confirms hypothesis
    ]
    confidence: float
    technique_id: str         # MITRE ATT&CK ID e.g. "T1190"
```

### Key Methods
```python
class AttackGraph:
    def find_critical_paths(self) -> list[list[AttackNode]]:
        """All paths from internet-facing asset to highest-value data/access"""
    
    def calculate_blast_radius(self, from_node: str) -> BlastRadius:
        """What can attacker do from this access level?"""
        
    def to_narrative(self, style: Literal["executive","technical","remediation"]) -> str:
        """Convert graph to human-readable attack story"""
        
    def find_attack_chains(self) -> list[AttackChain]:
        """All complete chains from initial access to goal"""
        
    def highest_impact_chain(self) -> AttackChain:
        """Weighted: max(impact * probability * confidence)"""
```

---

## K3. Memory Layer Schema

```python
# Layer 1: Session (Redis, TTL=engagement duration)
class SessionMemory:
    engagement_id: str
    target_scope: Scope
    active_agent: str
    current_phase: str
    current_phase_iteration: int
    attack_graph_live: AttackGraph      # live graph during engagement
    authorization: AuthorizationState
    scratchpad: dict                    # volatile working memory

# Layer 2: Engagement (PostgreSQL, permanent)
class EngagementMemory:
    engagement_id: str
    client_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    attack_graph_final: dict            # JSON serialized
    confirmed_exploits: list
    failed_attempts: list               # for learning
    time_to_exploit_per_phase: dict     # phase → seconds
    tool_success_rates: dict            # tool → success_rate at THIS target
    proof_artifacts: list               # evidence collection
    scratchpad_snapshot: dict           # full working memory at end
    event_stream_id: str                # link to event store

# Layer 3: Intelligence (PostgreSQL + pgvector, cross-engagement)
class IntelligenceBase:
    def what_worked_for_similar_targets(
        self, tech_stack: list, target_type: str
    ) -> ScanStrategy: ...
    
    def credential_patterns(self, industry: str, region: str) -> list[CredPattern]: ...
    
    def false_positive_rate(self, tool: str, target_type: str) -> float: ...
    
    def tool_reliability(self, tool: str, conditions: dict) -> ToolMetrics: ...

# Layer 4: User (PostgreSQL)
class UserMemory:
    user_id: str
    name: str
    preferred_language: str       # "id" | "en"
    communication_style: str      # "technical" | "executive" | "mixed"
    past_engagement_ids: list
    feedback_history: list        # corrections → learning
    
    def adapt_report_style(self, findings: list, graph: AttackGraph) -> str: ...
```

---

## K4. Tool Composer Pattern

```python
class ToolComposer:
    """
    Alpha detects: Laravel 9.x + MySQL + /storage writable + no WAF
    Gamma does NOT run generic scanner.
    Gamma calls: ToolComposer.compose("laravel_debug", context)
    Result: specialized exploit for THIS target
    """
    
    def compose(
        self, 
        base_template: str,     # template name from /templates/
        context: dict           # facts from Alpha's handoff
    ) -> ComposedTool:
        """
        Inject target-specific context into template.
        Returns executable Go code or Python script (per template type).
        """
    
    # Regional category templates (client-owned systems, SOW only — not named orgs)
    # templates/regional/erp_rce.py         → ERP exploit chain
    # templates/regional/his_sqli.py        → Hospital Information System SQLi
    # templates/regional/egov_bypass.py     → E-gov portal bypass
    # templates/regional/banking_portal.py  → Banking portal misconfigs
    
    # CMS templates
    # templates/cms/wp_full_chain.py        → WordPress: enum→brute→RCE
    # templates/cms/laravel_debug.py        → Laravel debug mode exploit
    # templates/cms/joomla_chain.py         → Joomla exploit chain
    
    # Cloud templates
    # templates/cloud/aws_metadata.py       → SSRF→metadata→IAM keys
    # templates/cloud/gcs_bucket.py         → GCS misconfiguration
    
    # Bypass templates
    # templates/bypass/cf_curl_cffi.py      → curl_cffi TLS impersonation
    # templates/bypass/cf_playwright.py     → Playwright Turnstile bypass
    # templates/bypass/waf_tamper.py        → WAF bypass patterns
```

---

## K5. Event-Sourced Core

```python
# Every action = immutable event
@dataclass
class AgentEvent:
    event_id: str                 # UUID
    event_type: str               # AgentStarted, FindingDiscovered, 
                                  # HandoffCompleted, ExploitAttempted, etc.
    engagement_id: str
    agent: str                    # alpha | beta | gamma | delta | epsilon | omega
    timestamp_utc: str
    payload: dict
    sequence_number: int          # monotonic, for replay ordering

# Projections (read models derived from event stream)
class Projectors:
    def project_attack_graph(self, events: list[AgentEvent]) -> AttackGraph: ...
    def project_audit_log(self, events: list[AgentEvent]) -> list[AuditEntry]: ...
    def project_metrics(self, events: list[AgentEvent]) -> EngagementMetrics: ...
```

---

## K6. LLM Orchestration

```python
class LLMOrchestrator:
    """
    Role split:
    - Claude Sonnet/Opus: ORIENT hypothesis, PLAN action, blast radius, narrative
    - DeepSeek: payload generation, exploit template composition
    
    Consensus for critical decisions:
    - Parallel call to both LLMs
    - Agree → high confidence, proceed
    - Disagree → graph-fact tie-break or human gate
    - Every vote logged to audit (reproducibility)
    """
    
    async def reason(self, context: GraphContext) -> ReasoningResult:
        """Claude-only: hypothesis, planning, assessment"""
    
    async def generate_payload(self, spec: ExploitSpec) -> str:
        """DeepSeek: offensive payload, bypass scripts"""
    
    async def consensus(
        self, 
        context: GraphContext,
        decision_type: str
    ) -> ConsensusResult:
        """Both LLMs parallel, vote, graph-fact tie-break"""
    
    def redact_sensitive(self, content: str) -> str:
        """Strip PII/creds before sending to cloud LLM"""
```

---

## K7. Celery Task Structure

```python
# Non-blocking engagement execution
@celery_app.task(bind=True, queue="engagement_{tenant_id}")
def run_engagement(self, engagement_id: str, start_phase: str = "alpha"):
    """Runs in background worker. User can chat/query/stop while this runs."""

# Status query (non-blocking, main thread)
def get_engagement_status(engagement_id: str) -> EngagementStatus:
    """Read from Redis SessionMemory. Instant response."""

# Stop command (revokes all related tasks)
def emergency_stop(engagement_id: str) -> bool:
    """Conductor authority only. Revokes Celery tasks + marks EMERGENCY_STOP."""

# Per-tenant queue isolation
CELERY_TASK_ROUTES = {
    "run_engagement": {"queue": "engagement_{tenant_id}"},
    "alpha_scout": {"queue": "alpha_{tenant_id}"},
    # etc.
}
```

---

## K8. Outcome Taxonomy (Learning Loop Input)

```python
class OutcomeTag(Enum):
    SUCCESS_FULL    = "success_full"    # exploit proven, full access obtained
    SUCCESS_PARTIAL = "success_partial" # partial access (e.g., info leak, no RCE)
    FAILED          = "failed"          # attempt completed, did not achieve goal
    TIMEOUT         = "timeout"         # did not complete within time limit
    BLOCKED         = "blocked"         # stopped by WAF/rate-limit/protection
    INCONCLUSIVE    = "inconclusive"    # cannot determine without more access

# Accumulation in IntelligenceBase:
# Per tool × target_type × tech_stack × industry
# → success_rate, false_positive_rate, avg_duration, blocking_patterns
```

---

## K9. Authorization Flow (Code Contract)

```python
class AuthorizationStateMachine:
    """Managed ONLY by Conductor. Agents read but never write."""
    
    def create_engagement(self, client_id: str, target: str) -> Engagement:
        """Creates engagement in CREATED state."""
    
    def enable_recon(self, engagement_id: str, scope: Scope) -> bool:
        """CREATED → RECON_ONLY. Validates scope is defined."""
    
    def enable_active(self, engagement_id: str) -> bool:
        """RECON_ONLY → ACTIVE_APPROVED. Validates scope verified."""
    
    def enable_offensive(self, engagement_id: str, sow_file: bytes) -> bool:
        """ACTIVE_APPROVED → OFFENSIVE_APPROVED. 
        Requires SOW uploaded + blast radius calculated."""
    
    def emergency_stop(self, engagement_id: str, reason: str) -> bool:
        """ANY STATE → EMERGENCY_STOP. Revokes all Celery tasks. Immutable."""
    
    def can_agent_proceed(self, agent: str, engagement_id: str) -> bool:
        """Check if agent is authorized for current engagement state."""
```

---

## K10. Deployment Reference

```
Production: Oracle Cloud ARM64
            ubuntu@168.110.192.62
            Ubuntu 24.04, 24GB RAM, 4 OCPU
Services:   agent-alpha-api (FastAPI + Celery app)
            agent-alpha-worker (Celery workers)
            redis (session + broker)
            postgresql (engagement + intelligence memory)
Deploy:     git pull → build → systemd restart
Test env:   Oracle ARM64 only (Windows invalid)
Lab:        GOAD (AD testing), HTB, local Docker targets
```
