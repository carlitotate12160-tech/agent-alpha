# Agent-Alpha — Knowledge Base
## Technical Reference for Architecture Sessions

**Version:** 1.2 (K1 payload detail extracted to OPERATIONAL_REFERENCE.md — Claude-facing)
**Last updated:** 2026-06-16

---

## K1. Kill Chain Reference (Agent → Capability → Handoff Output)

> **Routing note (K21).** This is the **capability-level** summary for
> architecture discussion (Claude-facing). The payload-level tool/technique
> detail lives in `OPERATIONAL_REFERENCE.md` §O1 (DeepSeek-facing) and is
> intentionally kept out of this document.

Each agent is defined here by its **capability classes** and its **handoff
output contract** — not by specific exploit scripts. The output contract is the
part that matters for the A2A data contract (§K2, proto `HandoffPayload`).

### Alpha (SCOUT) — Reconnaissance
```
Capabilities:  subdomain enumeration, port/service scanning, tech & WAF
               detection, directory enumeration, reverse-IP lookup,
               HTTP probing, JS-asset intelligence (secret discovery)
Output:        {hosts, ports, services, tech_stack, js_secrets, api_endpoints}
```

### Beta (STRIKE) — Initial Access
```
Capabilities:  credential-spray module (browser + raw HTTP), default-credential
               check, anti-detect browser automation, proxy infrastructure,
               CAPTCHA-solving integration, multi-protocol auth checks
Output:        {valid_credentials, session_tokens, access_level, entry_point}
```

### Gamma (ANCHOR) — Exploitation
```
Capabilities:  injection assessment modules, upload-validation bypass module,
               injection-to-execution chain modules, CMS exploitation modules,
               CVE matching + exploitation modules, foothold deployment,
               db-admin exploitation module
Output:        {shell_access, webshell_path, server_context, writable_paths}
```

### Delta (HUNTER) — Post-Exploitation
```
Capabilities:  interactive encrypted shell, persistence module,
               config/credential harvest module, cross-host credential reuse,
               data-access module, pre-persistence safety scanner,
               offline hash-audit module
Output:        {harvested_creds, db_access, internal_network_map}
```

### Epsilon (SCOUT-HUNTER) — Lateral Movement
```
Capabilities:  pivot shell from foothold, internal network scanning,
               co-host pivot module, shared-hosting pivot module,
               tunneling, AD credential-audit techniques (Kerberoast/AS-REP)
Output:        {compromised_hosts, pivoted_networks, additional_findings}
```

### Omega (ROASTER) — Reporting
```
Capabilities:  findings store, evidence collection, report builder,
               verification, proof-artifact assembly
Output:        Executive + Technical + Remediation reports
Formats:       PDF, JSON, SARIF, MD — MITRE ATT&CK + PCI/NIS2 mapping
```

---

## K2. Attack Graph Schema

> **Canonical location:** `graph/schema.py` (AttackNode + AttackEdge in one file —
> one cohesive concept, mirrors this section). NOT split into `nodes.py`/`edges.py`.
> This is the single canonical definition; proto is transport-only (anti-Lyndon #6).

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
        Payload body generated by any model — see K21. Claude never
        writes the payload content, only the interface/scaffold.
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
    # templates/bypass/cf_camoufox.py      → Camoufox Turnstile bypass
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

**Phase 0 implementation status:** `events/store.py` implements append-only
in-memory store, frozen `AgentEvent` dataclass, monotonic gapless sequencing
per engagement, `replay()` with gap detection, `verify_immutability()`.
PostgreSQL-backed persistence is Phase 1 scope (§K3 EngagementMemory).

---

## K6. LLM Orchestration

```python
class LLMOrchestrator:
    """
    Role split (current testing phase, see K21 for full routing policy):
    - DeepSeek V4 Pro / MiMo V2.5 Pro: reasoning, planning, payload generation
      (testing phase — proving the system end-to-end before adding
      higher-cost/higher-risk-of-refusal models)
    - Claude Sonnet/Opus/GPT: deferred to runtime until system is proven;
      used today only for architecture/dev-time work (K21), never for
      runtime payload generation, regardless of phase.

    Consensus for critical decisions:
    - Parallel call to both LLMs
    - Agree → high confidence, proceed
    - Disagree → graph-fact tie-break or human gate
    - Every vote logged to audit (reproducibility)
    """

    async def reason(self, context: GraphContext) -> ReasoningResult:
        """Hypothesis, planning, assessment — current: DeepSeek/MiMo"""

    async def generate_payload(self, spec: ExploitSpec) -> str:
        """Offensive payload, bypass scripts — any model"""

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

**Phase 0 implementation status:** `conductor/main.py` wires a Celery app
with a placeholder no-op task (`run_engagement_task`). Real per-agent task
routing and tenant queue isolation are Phase 3 scope.

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

**Phase 0 implementation status:** Fully implemented in
`conductor/authorization.py`, 18/18 tests passing. `Scope.validate()`
enforces `MAX_SCOPE_IPS` and CIDR validity. `EmergencyStopHandler`
(`conductor/emergency.py`, 10/10 tests) wraps this with Celery-revoke
coordination and event emission — idempotent, never raises.

---

## K10. Deployment Reference

```
Production: Oracle Cloud ARM64
            ubuntu@<oracle-arm-host>   (IP in secrets vault, not in docs)
            Ubuntu 24.04, 12GB RAM, 2 OCPU  (updated 2026-07-08 — capacity
            reduced from 24GB/4 OCPU; see resource-budget note below)
Services:   agent-alpha-api (FastAPI + Celery app)
            agent-alpha-worker (Celery workers)
            redis (session + broker)
            postgresql (engagement + intelligence memory)
Deploy:     git pull → build → systemd restart
Test env:   Oracle ARM64 only (Windows invalid — Lyndon failure #9)
Lab:        GOAD (AD testing, Phase 5), HTB, GCP free tier e2-micro (K14)
```

---

## K11. Layered Architecture — Deterministic + Adaptive (ADR §12.0)

Agent-Alpha is a **2-layer hybrid**, mirroring NodeZero's deterministic
orchestration + LLM judgment over a living attack graph:

- **Deterministic layer** — tools, exploit execution, parsers, ToolComposer
  engine. Must be reliable and reproducible. No LLM involved in execution
  itself.
- **Adaptive layer** — sequencing and prioritization. `next_action =
  f(AttackGraph state)`, computed via the Cognitive Loop (K-loop: OBSERVE
  → ORIENT → PLAN → ACT → VERIFY → PERSIST, see ADR §8j).

**HARD PROHIBITION (Lyndon root-cause guard):** no static or linear step
list anywhere in agent code. Action order and selection MUST emerge from
`plan()` evaluated over current graph state + playbook. A fixed pipeline
(`scan → spray → exploit` hardcoded) is the exact "tool runner" failure
mode Lyndon exhibited. Violating this rule is treated as a regression,
not a style choice.

---

## K12. Two-Phase LLM Gate — `decide_tier(situation)` (ADR §12.1)

Three-tier router balancing cost and reproducibility (NodeZero's
"pattern-match before invoking LLM" principle):

| Tier | When | LLM calls |
|------|------|-----------|
| `RULE` | Routine, high confidence, playbook match, next step clear from graph | None |
| `SINGLE_LLM` | Ambiguous, no playbook match, low confidence, new hypothesis | 1 model |
| `CONSENSUS_LLM` | Critical: exploit-chain selection, blast-radius judgment, "Try Harder", actions changing auth tier/blast radius | 2 models in parallel |

Tier-up is a function of rule confidence, action criticality, and
novelty/playbook-miss. All numeric thresholds live in
`config/constants.py` — never inline in agent logic (Lyndon failure #7
guard).

---

## K13. Adaptivity Validation — Differential Test (ADR §12.2, Phase 2 exit criteria)

Automated proof that an agent reasons over context rather than executing
a fixed script:

- **Required (L1):** the first tool/technique chosen differs when the
  target fingerprint differs.
- **Strong (L2):** at least 2 actions differ between two different
  targets.
- **Negative control:** identical target/input → same (or consistent)
  path. Seed and temperature recorded per decision (K19/§8o-4) so this is
  reproducible, not just "looks random."
- **Test fail condition:** two targets with different fingerprints
  producing an identical action path is an automatic test failure — it
  means the adaptive layer collapsed into a static pipeline (K11
  violation).

---

## K14. Real-Target Gate (ADR §12.3, Phase 2 exit criteria)

- **Infrastructure:** targets hosted on GCP free tier (e2-micro, x86 —
  sidesteps the ARM64-only constraint for the agent itself). Targets are
  isolated from the agent host (ADR §8l). Agent and test runner remain on
  Oracle ARM64 per the Lyndon failure #9 rule.
- **Firewall (mandatory):** targets accept inbound traffic only from the
  Oracle agent IP. Vulnerable labs are never publicly exposed.
- **Mode:** labs run one at a time on e2-micro (small free-tier RAM
  budget, ~1GB).
- **Phase 2 target set — 3 distinct fingerprints:**
  1. WordPress + ModSecurity (PHP/MySQL/Apache + WAF)
  2. Laravel with `APP_DEBUG` enabled
  3. OWASP Juice Shop (Node/Express)
- **Ground truth:** each lab ships a `ground_truth.yaml` enabling precise
  false-positive/false-negative computation.
- **Gate:** Alpha→Omega end-to-end run on all three, FP rate < 20%,
  non-empty and *different* output per target (ties back to K13).
- **Prohibition:** no testing against `example.com` or any internet
  target without a signed SOW (§1).
- **GOAD/AD lab:** deferred to Phase 5 — needs Windows x86 + larger RAM,
  outside the free-tier budget.

---

## K15. RAG Timing (ADR §12.4)

- **Phase 2:** no full RAG. `PLAN` uses graph facts + a static YAML
  playbook (deterministic) as the strategy prior. This is sufficient to
  satisfy K13's adaptivity requirement (`next = f(graph + playbook)`).
- **Phase 6:** enable full RAG — internal (IntelligenceBase via pgvector,
  once engagement data actually exists) and external (knowledge
  ingestion, CVE feeds / exploit-db / MITRE ATT&CK updates, ADR §8o-3).
- **Rationale:** internal RAG needs real engagement data to be useful at
  all. Building it before that data exists is "feature before
  foundation" — Lyndon failure #1.

---

## K16. Learning Storage Format — Hybrid Event-Sourced (ADR §12.5)

- **Source of truth:** the append-only event stream (K5 / ADR §8o-1).
  Nothing else is authoritative.
- **Tool reliability metrics** → projected into a DB table for fast
  queries (K19).
- **Strategy playbooks** → projected into markdown — human-readable,
  auditable; an operator edit to a playbook is itself recorded as an
  event, not a silent file change.
- **pgvector semantic matching** → Phase 6, once enough cross-engagement
  data exists to make embeddings meaningful.
- All of the above are data/config artifacts, never code — this is what
  keeps "learning" compliant with "Learn, don't self-rewrite" (ADR
  §8o-6, K21).

---

## K17. Playbook Vetting — Hybrid by Risk (ADR §12.6)

Playbooks move through a `candidate` → `trusted` lifecycle:

- **Low-risk** (recon/scan ordering, Alpha-only tools): auto-promote to
  `trusted` once promotion criteria are met (K20).
- **Risky offensive** (Gamma+ exploit-chains, post-exploitation):
  mandatory manual operator review before promotion to `trusted` — real
  blast radius is involved (§1 / ADR §8).
- An operator can always manually vet or edit a playbook; that action is
  itself an event (auditable, never a silent overwrite).

---

## K18. "Similar Target" Fingerprint — Weighted Composite (ADR §12.7)

`what_worked_for_similar_targets()` (K3, IntelligenceBase) uses a
weighted similarity score rather than exact matching:

- **Primary (high weight):** tech_stack (CMS/framework + language + web
  server) + protection layer (WAF/CDN: Cloudflare, ModSecurity, none).
- **Secondary (medium weight):** service versions & CVE exposure,
  surface type (web / API / SSH).
- **Context (low weight):** industry + region (Indonesia/SEA) — used
  specifically for `credential_patterns()`.
- **Initial implementation:** a structured dict-based scorer. Fuzzy
  embedding via pgvector arrives in Phase 6 (consistent with K15/K16).

---

## K19. Tool Reliability Threshold — Data-Driven Score, Config Threshold (ADR §12.8)

- **Score** (`success_rate`, `fp_rate`, `avg_timeout` per tool ×
  target_type) is computed adaptively from event-stream data — this part
  changes as engagements accumulate.
- **Decision threshold** (e.g. `FP_SKIP_THRESHOLD`,
  `MIN_SAMPLES_BEFORE_SKIP`) is hardcoded in `config/constants.py`,
  version-pinned (ADR §8o-4). This part does *not* change adaptively.
- **Hard rule:** the agent must never change these thresholds itself —
  doing so would introduce unauditable drift (ADR §8o-6, K21 boundary).
- **Phase 2–5:** hardcoded defaults only. **Phase 6:** scores populated
  with real data plus a circuit-breaker for repeated timeouts (ADR §8c).

---

## K20. Playbook Promotion to 'trusted' — Diversity + Lower-Bound (ADR §12.9)

A playbook promotes from `candidate` to `trusted` only when:

- It has accumulated **≥N successes across ≥M *different* targets or
  engagements** — repeated success against the same single target does
  not count toward M.
- It meets a **minimum success rate** when applied.
- **Statistical correction:** a Wilson lower-bound is applied so a small
  N is never treated as "100% certain" — playbook confidence scales with
  sample size, not raw success count.
- All N/M/rate constants live in `config/constants.py` (single source of
  truth, no duplicated thresholds — Lyndon failure #7 guard).

---

## K21. Dev Workflow & Runtime LLM Routing — Claude (Architect) vs DeepSeek (Payload) (ADR §12.10)

This section governs **who writes what**, both at dev-time (this
chat/IDE) and at runtime (the deployed agent).

**Platform code (~95% of the codebase)** — Conductor, authorization,
event store, memory layers, AttackGraph, gRPC/proto, Celery, Cognitive
Loop, the ToolComposer *engine* (not its payload contents), report
generation: this is ordinary security-adjacent engineering, not
offensive content generation. Claude/Sonnet/Opus writes specs and
architecture; the IDE/agent implements. Zero refusal risk because no
weaponized content is being produced.

**Payload content (~5% of the codebase)**, specifically the bodies under
`templates/{bypass,cms,cloud,regional}`: this is generated either at
**runtime** by the DeepSeek provider (composed by ToolComposer against
an already-authorized target) or at **dev-time** via DeepSeek directly.
**Never via Claude, under any framing** — not as "just the interface,"
not as "fictional," not as "for testing only."

**Routing rule, stated plainly:** payload body in
`templates/{bypass,cms,cloud,regional}` → DeepSeek, never Claude.
Claude/Sonnet/Opus's role is strictly limited to: architecture,
interfaces, template scaffolding (empty function signatures + docstring
contracts, no exploit logic), safety gates, test contracts, narrative
generation, and review.

**Current runtime LLM configuration (testing phase, see K6 and
`config/constants.py`):**
- `LLM_REASONING_PROVIDER = "deepseek-v4-pro"` 
- `LLM_REASONING_CONSENSUS = "mimo-v2.5-pro"` 
- `LLM_PAYLOAD_PROVIDER = "deepseek-v4-pro"` 
- `LLM_PAYLOAD_ALLOWED = ["deepseek-v4-pro", "kimi-2.6"]` — Kimi 2.6 is a
  K21 payload fallback only (used when the primary refuses or errors),
  never a K6 reasoning-consensus partner. `LLM_REASONING_CONSENSUS` 
  stays `mimo-v2.5-pro`; the two concerns (payload routing vs. reasoning
  consensus) are independent and must not be conflated.
- `LLM_PAYLOAD_FALLBACK = "kimi-2.6"` 
- `LLM_PAYLOAD_NEVER = ["claude", "sonnet", "opus", "gpt"]` — enforced in
  both `constants.py` and `policy.yaml` (`llm_routing` block), checked at
  two independent layers per the "controls enforced at multiple layers,
  not just one" principle.

**Future state:** once the system is proven end-to-end (Phase 2 real-
target gate, K14, passed), Claude Sonnet/Opus/GPT may be introduced as
additional *reasoning* models (never payload models) per the original
role split in K6. This is an explicit "not yet" gate, not a permanent
exclusion — the team-level memory of this project tracks it as an open
item on the horizon, not a blocker on current Phase 0/1/2 work.