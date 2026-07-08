# Agent-Alpha — Architecture Decision Record & Phased Roadmap

Architecture blueprint for Agent-Alpha: autonomous red-team platform Level 1-6 (SCOUT→STRIKE→ANCHOR→HUNTER→SCOUT-HUNTER→ROASTER) with non-bypassable authorization gate, multi-agent orchestration, and memory that makes it smarter across engagements.

**Status:** Architecture-only. This document establishes design decisions + phased roadmap. Implementation details per module are drafted after this design is approved.

## 0. Design Principles (First Principles)

- **Authorization is the foundation, not a feature.** Without a solid gate, Level 6 = attack tool. With a gate = legal product that can be sold to enterprises.
- **One agent, one responsibility.** No functions override each other. Boundaries between agents are enforced via explicit handoff contracts.
- **Handoff is a data contract, not a side-effect.** Each agent only accepts defined input structures and produces defined outputs — no agent directly reads/writes another agent's state.
- **Autonomous after authorization.** Authorization is checked once in Conductor when engagement is created; after that, agents run without interrupt until hard-limit is violated.
- **Proof over claims.** Every finding must be accompanied by proof-of-exploitation (aligned with NodeZero principle: "prove exploitability", not just "vulnerability exists").
- **Reasoning over durable state, not hidden state.** Each agent reasons over AttackGraph as single source of truth — not hidden internal state. This is what makes results reproducible & auditable (core principle of agentic systems).
- **Bounded autonomy.** Autonomy is always bounded by measurable guardrails (iterations, time, cost, scope). Agent never "loops forever".
- **Event-sourced truth.** System state (graph, audit, metrics) is a projection of a single append-only event stream — not mutable state written directly. This guarantees deterministic replay & reproducibility.
- **Learn, don't self-rewrite.** Agent improves strategy/judgment via memory + reflection (stored as human-readable & auditable data/playbook), not by modifying its own source code/architecture. Self-modifying code is explicitly out of scope.
- **Safety layer untouched by agent.** Authorization, kill switch, audit, and policy enforcement can never be changed by the agent (immutable core).

## 1. Non-Negotiable — Authorization Layer

REQUIRED components in architecture, managed only by Conductor:

- **Written authorization upload** — SOW (PDF/doc) attached to engagement before Level 4+ becomes active.
- **Explicit scope definition** — IP range, domain, exclusion list; verified before agents start.
- **Tiered state authorization:**
  - RECON_ONLY → allows Level 1-3 (SCOUT)
  - ACTIVE_APPROVED → allows Level 4 (STRIKE / initial access)
  - OFFENSIVE_APPROVED + SOW → allows Level 5-6 (ANCHOR, HUNTER, SCOUT-HUNTER)
- **Emergency stop** — single authority in Conductor that truly stops ALL agents + revokes all Celery tasks.
- **Immutable audit log** — every action logged append-only (who, what, when, target, result).
- **Blast radius calculator** — run before ANCHOR & HUNTER; if exceeds threshold, requires human approval gate (manual confirm via Telegram).
- **Hard-limit enforcement** — Conductor automatically stops agent if action goes outside allowed scope.

## 2. Architecture Decision Record (Final)

| Platform     | Cybersecurity Red Team Automation, Level 1-6 |
|-------------|---------------------------------------------|
| Model        | Authorized engagement only, SOW required before Level 4+ |
| Architecture | Multi-agent, security-first, memory-persistent |
| AI Brain     | Python 3.12 (reasoning, memory, attack graph, reporting) |
| Exec Engine  | Go (agents network-heavy + custom tools deployable) |
| IPC          | gRPC internal (Python ↔ Go) |
| Orchestration| Celery + Redis broker (non-blocking, multi-tenant queues) |
| Memory       | Redis (session) + PostgreSQL + pgvector (long-term/semantic) |
| Deploy       | Oracle Cloud ARM64 (existing infrastructure) |

### Key decisions

- **Hybrid Go + Python.** Python = AI/memory/graph; Go = SCOUT/STRIKE/ANCHOR/HUNTER/SCOUT-HUNTER execution (single binary, goroutine concurrency 3-5x asyncio for port scan & credential spray, stealth—no "python script" signature, deployable to compromised host without interpreter).
- **Celery from the start.** Non-blocking tasks → user can chat "status?" / "stop scan" while task runs. Per-tenant dedicated queue, priority queue for paid tier, rate limiting per tenant.
- **Authorization = single gate in Conductor.** Agent autonomous after authorized.

### Decision points you need to decide (see §10)

- Build sequencing: Full hybrid from start vs Python MVP first then port to Go. Roadmap in §8 is structured with Python-first as default low-risk option; can be changed.

## 2b. Reference Models — Two Sources of Design

Agent-Alpha's design draws from two reference architectures:

### Reference #1 — NodeZero (Horizon3.ai): enterprise orchestration

- Hybrid 2-layer: deterministic engine orchestrating hundreds of tools + LLM for prioritization/judgment (HVT), operating over a living attack graph.
- Two-phase cost control: cheap pattern-matching filters before invoking LLM.
- Source of: proof-driven, safe-in-production, HVT prioritization, VERIFY loop.

### Reference #2 — Agentic LLM Loop (how Claude/Opus itself works): cognition

The agent scaffolding around a reasoning model is the live model for our Cognitive Loop. Mapping (already codified in our design):

| Agentic LLM mechanism | Agent-Alpha section |
|-----------------------|---------------------|
| Perceive → reason → tool → observe loop | §8j Cognitive Loop |
| Context window = working memory, no hidden state | §0 + §8j |
| Inner monologue (private reasoning) | §8j-2 |
| Scratchpad (working notes, sub-todos, dead-ends) | §8j-2 |
| Promotion rule (only verified facts persist) | §8j-2 |
| Volatile context vs durable store | §8j-2 (Redis → PostgreSQL) |
| Tool calls = deterministic execution layer | §8j ACT + §2 |
| Amnesia between sessions → cure is persistence, not self-rewrite | §8o-6 |
| Grounding to durable facts to cut hallucination | §7 |
| Plan-ahead (planner/executor, world model) | §8o-2 |

**Key lesson from Reference #2:** an agentic LLM with no persistent memory gets amnesia every session — exactly the Lyndon failure. Agent-Alpha's EngagementMemory/IntelligenceBase + event-sourcing is precisely the layer that an agentic LLM lacks by default. We add auditability/replay on top.

**Convergence of both references:** LLM decides over state; deterministic tools execute; memory is persisted; sequencing is adaptive (never a fixed linear pipeline — see §12.0).

## 3. Agent Design — Conductor + Greek Alphabet

### Final naming

| Project      | Agent-Alpha |
|--------------|-------------|
| Orchestrator | Conductor |
| SCOUT        | Alpha     (Reconnaissance) |
| STRIKE       | Beta      (Initial Access) |
| ANCHOR       | Gamma     (Exploitation) |
| HUNTER       | Delta     (Post-Exploitation) |
| SCOUT-HUNTER | Epsilon   (Lateral Movement) |
| ROASTER      | Omega     (Reporting) |

### Handoff contract (anti-override, one-way)

```
CONDUCTOR (Orchestrator)
├── Receive task from user
├── Verify authorization before Level 4+
├── Manage handoff between agents (validate data contract)
├── Emergency stop authority
├── Memory & learning coordination
│
├── Alpha / SCOUT — Goal: complete attack surface map
│   └─▶ Beta : { hosts, ports, services, tech_stack, js_secrets, api_endpoints }
│
├── Beta / STRIKE — Goal: authenticated foothold
│   Requires: ACTIVE_APPROVED + target scope verified
│   └─▶ Gamma : { valid_credentials, session_tokens, access_level, entry_point }
│
├── Gamma / ANCHOR — Goal: shell/RCE access
│   Requires: OFFENSIVE_APPROVED + written SOW
│   └─▶ Delta : { shell_access, webshell_path, server_context, writable_paths }
│
├── Delta / HUNTER — Goal: data harvest + privilege escalation
│   Requires: OFFENSIVE_APPROVED + scope includes post-exploit
│   └─▶ Epsilon : { harvested_creds, db_access, internal_network_map }
│
├── Epsilon / SCOUT-HUNTER — Goal: pivot to internal network
│   Requires: OFFENSIVE_APPROVED + internal scope defined
│   └─▶ Omega : { compromised_hosts, pivoted_networks, additional_findings }
│
└── Omega / ROASTER — Goal: actionable report + proof-of-exploitation
    Input : all findings from all agents (via Attack Graph)
    Output: Executive report + Technical report + Remediation guide
```

**Boundary rule:** agents never call other agents directly. All transitions go through Conductor which validates handoff contract + state authorization. This guarantees "no functions override each other".

## 4. Memory Architecture (4 Layer)

Key differentiator components of Agent-Alpha in the market.

- **SessionMemory (Redis)** — per-engagement, lost after completion. Contains: engagement_id, target_scope, active_agent, current_phase, findings_so_far (AttackGraph live), authorization.
- **EngagementMemory (PostgreSQL)** — permanent per-engagement: full attack graph, confirmed exploits, failed attempts (for learning), time-to-exploit per phase, tools→success-rate at this target.
- **IntelligenceBase (PostgreSQL + pgvector)** — cross-engagement learning:
  - what_worked_for_similar_targets(tech_stack, target_type) → proven strategies (e.g., WordPress+Cloudflare: skip nuclei, xmlrpc bruteforce first).
  - credential_patterns(industry) → password patterns per industry/region.
  - false_positive_rate(tool, target_type) → skip tools with high FP (e.g., nuclei on CF-protected = 89% FP), save time.
- **UserMemory (PostgreSQL)** — knows user: communication_style (technical vs executive), preferred_language (BI vs EN), past_engagements, feedback_history. adapt_report_style() adjusts output (CISO → executive first; pentester → technical first; user BI → BI report).

## 5. Custom Tools & Runtime Tool Composition

Value proposition not possessed by NodeZero / CyberStrikeAI: exploits composed specifically for the target.

```
agent_alpha/intelligence/
├── tool_composer.py            # Runtime composition from template + SCOUT context
└── templates/
    ├── regional/   (erp_rce, his_sqli, egov_bypass, banking_portal)  # category templates, client-owned + SOW only
    ├── cms/        (wp_full_chain, laravel_debug, joomla_chain)
    ├── cloud/      (aws_metadata SSRF→IAM, gcs_bucket)
    └── bypass/     (cf_curl_cffi, cf_playwright/Turnstile, waf_tamper)
```

Logic: SCOUT (Alpha) detects facts (e.g., Laravel 9.x + MySQL + /storage writable + no WAF). ANCHOR (Gamma) does not run generic scanner — ToolComposer.compose(base_template, context) generates exploit script specific to this target. Because execution is in Go, output can be a deployable single-binary. Template names denote system *categories* (banking portal, hospital information system, e-gov portal, ERP), never specific organizations; applied only to client-owned systems under signed SOW.

## 6. Attack Graph — Marketable Representation

Not a flat list, but "story of how attacker got in".

- **Node types:** asset | vulnerability | credential | service | data | access_level.
- **Edge relationships:** exploits | enables | requires | leads_to | lateral_move_to (+ confidence score).
- **find_critical_paths()** → highest impact path, e.g., Internet → /login SQLi → Admin creds → phpMyAdmin → MySQL → 50k customer records.
- **calculate_blast_radius()** → impact if attacker has same access (feed to authorization gate before ANCHOR/HUNTER).
- **to_narrative(style)** → convert graph to human language, not "CVE-XXXX found" but step-by-step story.
- Structured prompt from graph facts (see §7) is built from this graph's nodes/edges.

## 7. New Capabilities (Not Yet in Agent-Alpha)

- **Parallel attack path execution** — fork graph when one credential opens multiple paths; execute branches in parallel (like NodeZero to West + East GOAD simultaneously). Requires: Celery fan-out + thread-safe AttackGraph + Conductor scheduler that limits parallelism according to blast radius/scope.
- **"Try Harder" agent** — when stuck (e.g., RECON_EXHAUSTED), GenAI generates next-best-step hypothesis from graph facts (not web_search). Elegant resolution for dead-end.
- **Structured prompt from graph facts** — not free-form LLM call. Conductor extracts nodes/edges from attack graph → build structured prompt → inference. Results repeatable & minimal hallucination.

## 8. Additions from Horizon3.ai (NodeZero) Analysis

NodeZero operates on loop Hack → Fix → Verify → Repeat, "real attacks run safely in production", agentless, proof-driven. What is not yet explicit in your design and needs to be added:

- **VERIFY phase (re-test loop)** — new component. After client remediates, Agent-Alpha re-tests the same path to prove threat is gone ("close the loop on every fix"). Add as engagement mode: RETEST that re-executes critical_paths stored in EngagementMemory and compares results. This is a strong differentiator and not yet in your list.
- **Continuous / scheduled engagement.** Not one-shot. Engagement can be scheduled periodically because "risk changes every time environment does". Requires scheduler (Celery beat) + diffing between runs.
- **Impact-based prioritization.** ROASTER prioritizes findings that proven threaten business (proven exploitable + blast radius), not raw CVE list.
- **Safe-in-production guardrails.** Default non-destructive: rate limiting, no data destruction, snapshot/rollback awareness, opt-in for risky actions. Aligned with "run safely in production".
- **Proof-of-exploitation artifacts.** Every confirmed exploit stores proof (request/response, screenshot, redacted sample data) attached to report.

### 8a. Conversation Interaction & Caching (answer Q1)

Agent is not one-shot — can be chatted with while task runs, powered by Celery + Redis.

- **Background non-blocking.** scan example.com runs in Celery worker; main thread free to respond to chat.
- **Live commands while task runs:** status progress?, query Celery state + SessionMemory), stop scan (Conductor revoke task), additional instructions (focus subdomain admin.*) enter task context.
- **Tiered caching:**
  - Conversation cache (Redis) — conversation history per engagement (TTL per engagement), so context "connects", not reset per message.
  - Tool-result cache (Redis) — idempotent scan results (e.g., DNS/port) cached with short TTL to avoid re-run when user asks repeatedly.
  - LLM response cache — identical prompt+context not re-inferred (saves cost, deterministic).

### 8b. Finding-Level Memory — Fix Old Version Problem (answer Q2)

Previous version: each continuation = new task because no shared state. Fix:

- Every finding = node in AttackGraph, persisted in EngagementMemory (PostgreSQL), not loose text.
- Auto-linking between findings via edge (enables, leads_to, requires). Example: SCOUT finds /login → STRIKE finds creds → edge credential --enables--> admin_access connected in same graph.
- Resume without repeating. Continuing task loads same graph; agent knows what was found & doesn't re-scan.
- Continuity across tasks in engagement: findings from task 2 add nodes to engagement graph, not start from zero.

### 8c. Learning Loop — Success/Failure & Tool Reliability (answer Q3)

Mechanism that makes agent smarter with usage.

- **Outcome tagging per attempt** (explicit, partial separation exists):
  - SUCCESS_FULL — exploit proven (e.g., RCE/full access).
  - SUCCESS_PARTIAL — partial access (e.g., info leak without RCE).
  - FAILED — not successful.
  - TIMEOUT — not completed within time limit.
  - BLOCKED — stopped by WAF/rate-limit/protection.
- **Accumulation in IntelligenceBase** (cross-engagement): tool → success_rate, tool → false_positive_rate, tool → avg_timeout, per target_type/tech_stack/industry.
- **Treatment of frequently failed/timeout tools:**
  - Reliability score drops → deprioritized or skipped for similar targets (e.g., nuclei on CF-protected = 89% FP → skip, save time).
  - Circuit-breaker for repeated timeout: exponential backoff + cap retry + cooldown before trying again.
- **Strategy synthesis.** what_worked_for_similar_targets() derives scan order from success history, not from zero — core of "agent getting smarter".

### 8d. Multi-LLM Orchestration — Parallel Consensus (answer Q4)

Support 2+ LLM (DeepSeek V4 Pro + Xiaomi). Selected mode: parallel consensus.

- Critical decisions (next-best-step "Try Harder", exploit-chain selection, blast-radius judgment) → both LLMs inferred in parallel, results compared/voted.
  - Agree → high confidence, proceed.
  - Disagree → choose one most supported by graph facts (structured prompt), or escalate to human gate.
- Light tasks (classification, summary, narrative) → can use single LLM to save cost/latency.
- LLM Orchestration layer (Python) manages provider abstraction, parallel dispatch, scoring/voting, and logging each LLM vote to audit (reproducibility).
- Automatic failover exists when one provider errors/rate-limits (degrade to single-LLM with lower confidence flag).

### 8e. Specialized Test Types / Engagement Profiles (answer Q5)

Current design is generic; add engagement profiles = preset (scope template + tool set + agent path + authorization requirement). Derived from NodeZero catalog:

- **WebApp Pentest** — OWASP Top 10 + infrastructure chaining. Closest to current design → first profile.
- **Cloud Pentest** — AWS / Azure / M365 / Kubernetes. Expand templates/cloud/ (SSRF→metadata→IAM, misconfig, k8s RBAC).
- **AD Password Audit** — verify credential policy (integrate LDAP/Kerberos in Delta/Epsilon; partially read-only/non-destructive).
- **Phishing Impact Test** — simulate impact of credential theft (special path post-assumed-compromise; not sending real phishing).
- **Endpoint Security Effectiveness** — validate EDR controls (needs probe on host; overlaps with safe-in-production guardrails).

Each profile sets minimum authorization level + its own scope shape, and can be selected by user when creating engagement.

### 8f. Pivot-Chain State Tracking (answer Q3 — CORE component)

Real gap: graph already stores findings, but pivot route not yet explicitly modeled. Add so agent "remembers pivot 3 to use in pivot 8".

- Pivot node in AttackGraph = controlled host + access context (credential/session/tunnel used to reach it).
- Route edge (pivots_via, reachable_from) = records how each host was reached (host A → tunnel → host B → host C).
- Reuse & chaining. When needing to reach new host, agent traces existing route edges → reuse tunnel/credential without rebuilding from start.
- Prerequisite for parallel attack path (§7). Simultaneous branch fork requires accurate route state so branches don't collide.
- Persist in EngagementMemory, so resume/RETEST still recognizes previous pivot topology.

### 8g. OS-as-a-Tools / Living-off-the-Land (answer Q2 — CORE component)

On compromised host (Delta/Epsilon), use native OS commands instead of uploading tools — aligned with stealth target + Go single-binary.

- os_command tool abstraction = controlled shell execution on pivot host, results parsed back to graph.
- LOLBin catalog — list of native binaries (Win/Linux) for enumeration/movement without dropping suspicious files.
- Safe-in-production guardrail — default non-destructive, dangerous commands need opt-in/human gate; all commands + output audited (immutable log §1).
- Stealth — reduces footprint/signature compared to uploading external tools.

### 8h. BrowserHacker / BeEF-style (answer Q1 — OPTIONAL, not core)

Browser exploitation (hook browser via XSS, client-side pivot) is niche; NodeZero focuses on infrastructure attack-path, not BeEF-style.

- Status: optional capability, tied to Phishing Impact Test profile (§8e), not core SCOUT→ROASTER path.
- Priority: later (after core profiles & pivot/OS tools stable).
- Guardrail: simulate client-side impact, not attack real users outside scope; subject to authorization + safe-in-production.

### 8i. Additions from Horizon3 Blog/Resource (NodeZero techniques)

From NodeZero technique catalog, include following concepts:

- **Tripwires / Canary accounts** — plant decoy account/credential for detection validation (whether SOC/EDR activates when misused). Differentiator: not just attacking, but measuring defender detection capability.
- **High-Value Targeting (HVT)** — prioritize path to "crown-jewel" asset; integrate to find_critical_paths() + impact-based prioritization (§8).
- **Kerberoasting / AS-REP Roasting** — AD-specific technique for AD Password Audit profile (§8e), run by Delta/Epsilon.
- **EDR Efficiency / Endpoint Effectiveness** — measure how far endpoint controls withstand techniques; feed to Endpoint Security Effectiveness profile.

### 8j. Agent Cognitive Loop — "Brain" of Each Agent (system core)

Plan has agent + handoff, but not yet defined internal reasoning loop. This is core: each agent (and Conductor) runs loop over AttackGraph.

```
OBSERVE  → read relevant graph facts (node/edge) + outcome history
ORIENT   → classify situation, hypothesis (LLM, structured prompt §7)
PLAN     → choose next action + alternative (consensus §8d for critical decisions)
ACT      → execute via single-contract tool (gRPC to Go)
VERIFY   → confirm result + tag outcome (§8c), save proof artifact
PERSIST  → write new node/edge to graph (durable state, not hidden)
```

**Stop conditions** (Bounded autonomy): max iterations, time budget, cost budget, no-progress detection. "Try Harder" (§7) subject to these stop conditions.

Reproducible: because loop only reads/writes durable graph + structured prompt, run can be replayed & audited.

### 8j-2. Inner Monologue & Scratchpad per Task (working memory)

Volatile layer bridging Cognitive Loop (§8j) and durable AttackGraph. Selected mode: visible + persisted.

- **Inner monologue** — private reasoning trace of agent during ORIENT/PLAN: hypothesis, reason for choosing action, alternative evaluation. Streamed to user (transparency, feels "alive") and logged to audit.
- **Scratchpad** — working memory per-task: temporary notes, intermediate results, dead-ends, sub-todos. Saved to EngagementMemory for reproducibility + learning material (§8c).
- **Promotion rule** (anti-contamination): only facts passing VERIFY phase (§8j) promoted from scratchpad → AttackGraph node/edge. Speculation/hallucination stays in scratchpad, doesn't pollute graph (durable single source of truth).
- **Storage:** active scratchpad in Redis SessionMemory (live, low-latency); snapshot flushed to EngagementMemory (PostgreSQL) at checkpoint/end of task.
- **Security** (mandatory): scratchpad & monologue can contain untrusted content from target (prompt injection risk §8l) + sensitive data → redaction before stream/persist, and monologue content never executed as instruction (data, not command).
- **Consensus trace:** during critical decision (§8d), each LLM vote + reason recorded in scratchpad → supports audit & tie-break by graph facts.
- **Feed to report:** monologue/scratchpad becomes material for to_narrative() (§6) — story of "how we thought & got in", not just finding list.

### 8k. LLM Model Strategy — Role Split & Policy (Opus/Claude vs DeepSeek)

Extending parallel-consensus (§8d) with policy-based + data sensitivity separation.

- Reasoning / planning / attack-graph analysis / report narrative → strong reasoning model (e.g., Claude Opus/Sonnet). Excels here, content not raw weaponization.
- Payload / raw exploit generation → less-restricted model (e.g., DeepSeek) to avoid refusal/usage-policy block.
- **Refusal risk as design constraint:** don't depend on offensive generation from model that can refuse mid-engagement.
- **Redaction layer** — sensitive client data (creds, PII, harvested data) redacted/anonymized before sending to LLM cloud (NDA/data sovereignty compliance); self-hosted option for most sensitive data.
- **Budget cap per engagement** — token cost limited (especially Opus) + alert when approaching limit (related to stop conditions §8j).
- **Provider abstraction** — all models behind single interface; role-based routing + consensus + failover managed by LLM Orchestration layer.

### 8l. Platform Security & Data Lifecycle (securing the tool itself)

Autonomous offensive tool is high-value target; platform must be hardened.

- **Prompt injection defense** (risk #1). Content from target (web page, banner, file, tool output) can inject instruction into LLM context. Mitigation: strict separation trusted instruction vs untrusted data, content sanitization, structured prompt (§7), and never execute risky action without graph/authorization validation.
- **Secrets vault.** Harvested creds + API keys + LLM keys stored encrypted (e.g., Vault/KMS), never plaintext in log/graph.
- **Sandbox / execution isolation.** Exploits run in isolated environment (container/jail) to protect operator infra + prevent cross-engagement contamination.
- **Encryption.** At-rest (PostgreSQL, harvested data, proof artifacts) + in-transit (mTLS for gRPC Python↔Go, encrypted C2 channel).
- **Data retention & destruction.** Explicit retention policy + client data destruction post-engagement (legal/NDA obligation), with destruction proof in audit log.

### 8m. Reliability, Control & Validation

- **Loop & budget guardrail.** Per engagement: max iterations, time budget, cost cap, no-progress detection → prevent runaway autonomy (implement stop conditions §8j).
- **Checkpoint / resume.** Long engagement can be checkpointed (graph + session state) and resumed after crash without losing progress.
- **Benchmark lab.** Validate agent behavior against controlled lab: GOAD (AD), HTB, vulnerable web labs. (NodeZero validates via GOAD.)
- **Regression test agent.** Fixed scenario suite to ensure updates don't degrade agent capability/security.
- **Observability.** Metrics + tracing per agent loop (latency, cost, success rate) alongside immutable audit log.

### 8n. Reporting Standards & Advanced Rules of Engagement

- **MITRE ATT&CK mapping.** Each technique mapped to ATT&CK ID for industry-standard report.
- **Compliance mapping.** Findings mapped to relevant frameworks (PCI, NIS2, etc. — seen in Horizon3 catalog).
- **Export formats.** PDF (executive/technical), JSON, SARIF, ticketing integration (Jira).
- **Time-window enforcement.** Engagement only runs during allowed time window (work hours / off-hours).
- **Excluded techniques.** List of forbidden techniques (e.g., no DoS) enforced by Conductor as hard limit.
- **Deconfliction.** Coordination/notification mechanism for blue team to distinguish red-team activity from real incident (except agreed tripwire/black-box scenarios).
- **OPSEC / stealth profile.** "quiet" profile (rate-limited, LOLBin-first) vs "loud" (full speed), selected when creating engagement.

### 8o. Foundational Architecture (Finalization — "the spine")

Base layer that unifies all features to be consistent, reproducible, and growable. Without this, plan = feature collection; with this = system built correctly from zero.

#### 8o-1. Event-Sourced Core + CQRS (backbone)

- Single append-only event stream — every agent/Conductor action = immutable event.
- Projections (read models): AttackGraph, immutable audit log (§1), metrics/observability (§8m), scratchpad snapshot (§8j-2) — all derived from event stream, not written separately.
- Benefits: deterministic replay, "free" checkpoint/resume (§8m), truly immutable audit, legal reproducibility. Unifies §1, §6, §8j, §8m.
- Implementation: event store (PostgreSQL append-only / log), projector builds read models; Redis for live projections.

#### 8o-2. Cognition Layer — Planner/Executor + World Model + Simulation

Elevating Cognitive Loop (§8j) from reactive → think-ahead.

- **Planner/Executor split.** Planner decomposes goal → subgoal → action plan (HTN-style); Executor executes via tool. Automatic replanning on failure. "Try Harder" (§7) becomes part of planner, not patch.
- **World Model / belief state.** Model target environment with uncertainty + explicit hypotheses (not just facts). Agent acts under partial observability; hypotheses live in scratchpad (§8j-2), verified facts in graph.
- **Simulation / dry-run.** Before risky action, predict attack path against world model (think-before-act) → feed to blast-radius gate (§1) before actual execution.

#### 8o-3. Knowledge Ingestion Pipeline (learning from outside, not just self)

Closed-loop learning (§8c) quickly becomes stale. Add RAG over external feeds: CVE feeds, exploit-db, nuclei templates, MITRE ATT&CK updates.

- Embedded into pgvector; agent retrieves relevant technique/exploit during ORIENT/PLAN.
- Versioned pipeline (know which knowledge snapshot used in specific engagement → reproducibility).

#### 8o-4. Capability/Tool Registry + Versioning & Reproducibility

- **Tool registry** — tool catalog (metadata, capability, version, reliability metrics from §8c) for dynamic selection by planner.
- **Version pinning per engagement** — model + prompt + agent code + knowledge snapshot pinned → report reproducible & deterministically replayable (aligned with §8o-1).
- **Determinism controls** — seed/temperature recorded per LLM decision.

#### 8o-5. Policy-as-Code + Blackboard Coordination

- **Policy-as-Code.** RoE, scope, excluded techniques (§8n), authorization tiers (§1) as centralized declarative policy (OPA/Rego-style) enforced by Conductor — not scattered if-else. Easy to audit & change per engagement.
- **Blackboard coordination.** Shared coordination medium (above event stream) so parallel attack paths (§7) don't collide/duplicate: claim/lock resource, share discovery between branches in real-time.

#### 8o-6. Adaptive Learning (L1) — "agent that learns", NOT self-modifying code

Final decision: Agent-Alpha improves its judgment, not rewrites its source/architecture. Self-modifying code (rewriting own code/architecture, open-ended offensive tool synthesis without template) removed from scope — to avoid unauditable system that breaks reproducibility & safety.

- Old agent failure = amnesia (no memory between tasks). Cure = learn & remember, not self-rewrite. Chasing self-modifying code too early = trading one failure for worse.
- **Reflection loop.** Each engagement end, agent reads event stream (§8o-1) → extract successful/failed decisions → update playbook/heuristics/prompt (human-readable, auditable).
- **Credit assignment.** Reward propagated backward along attack-graph path → know which step determined success.
- **Growing playbook store.** Vetted strategies per target_type/tech_stack (§8c) — stored as human-readable data, not opaque weights.
- **Conductor meta-tuning.** Monitor metrics per agent → weak agents tuned at data level (prompt/strategy/playbook), without changing their code.
- **Still reproducible.** All improvements = data/config (not code) → remains version-pinned (§8o-4) & replayable.
- **Out of scope (explicit):** self-modifying source code, self-rewriting architecture, open-ended offensive tool synthesis. Only reconsider as separate & isolated research if this learning foundation proven mature across many real engagements.

## 9. Roadmap Phases (Default: Python-first, then Go)

Each phase has demoable deliverable. Go sequencing can be advanced if you choose full-hybrid in §10.

### Phase 0 — Foundation, Authorization, Event-Core & Platform Security (most critical)

Conductor skeleton, authorization state machine, SOW upload, scope verify, emergency stop. Event-sourced core + CQRS (§8o-1) as backbone (audit log immutable = event stream projection). Policy-as-Code for RoE/scope (§8o-5). Secrets vault + encryption at-rest/in-transit (mTLS) + sandbox/isolation (§8l). No offensive agent allowed to run before this is solid.

### Phase 1 — Memory + Attack Graph (as event projection)

Redis SessionMemory + conversation cache, PostgreSQL+pgvector schema, AttackGraph as read-model projection (§8o-1), finding-level auto-linking (§8b), outcome tagging skeleton (§8c).

### Phase 2 — Alpha (SCOUT) + Omega (ROASTER) end-to-end (RECON_ONLY)

Smallest demoable loop: recon → graph → report. Formal Agent Cognitive Loop (§8j) + Planner/Executor + World Model/belief state (§8o-2) + inner monologue & scratchpad visible+persisted (§8j-2) + stop conditions. Validate handoff contract & adaptive reporting style. First engagement profile: WebApp Pentest (§8e). Report: MITRE ATT&CK mapping + export PDF/JSON (§8n).

**Tool detail:** See `OPERATIONAL_REFERENCE.md` §O1 (Alpha) + §O1 (Omega) for the full kill-chain tool catalog. Per ADR §12.22 Decision 1 (wrap vs build):
- **Current (sealed):** 4 proven probes — Laravel debug, WP config, JS secret, Odoo DB manager + generic HTTP probe. Single-URL work queue, `ALPHA_RECON_NO_PROGRESS_ITERS=1`.
- **Target (WRAP, commodity):** subdomain enum (subfinder, crt.sh), port scan (nmap top-30), directory enum (feroxbuster/ffuf), reverse IP lookup (hackertarget), JS bundle crawler, tech detection (whatweb, wafw00f). Wrap behind `ToolResult` contract (§12.16).
- **BUILD INTERNAL (the moat):** credential harvest from leaked env (Laravel), credential assembly + vault, AttackGraph node/edge persistence — tools that use the graph in a way standalone tools cannot.
- **Recon breadth expansion:** handlers append discovered URLs/subdomains to `_work_queue`; raise `ALPHA_RECON_NO_PROGRESS_ITERS` from 1 to 3-5 once multi-URL discovery is wired.

### Phase 3 — Beta (STRIKE) + Celery non-blocking + LLM strategy

Initial access (ACTIVE_APPROVED), credential spray, chat-while-task-runs (§8a), multi-tenant queue, LLM Orchestration parallel consensus + role split (Claude reasoning / DeepSeek payload) + redaction + budget cap (§8d, §8k), prompt-injection defense (§8l), loop/budget guardrail + checkpoint/resume (§8m), time-window & OPSEC profile (§8n).

**Tool detail:** See `OPERATIONAL_REFERENCE.md` §O1 (Beta) for the full strike tool catalog. Per ADR §12.22:
- **Current (sealed):** CredReuseTool (vaulted credential reuse), DefaultCredsTool (6 platforms), CredentialApplicator seam (HttpFormApplicator + MySqlApplicator). Conductor auto-advance Alpha→Beta via Celery.
- **Target (WRAP):** browser automation (Playwright + stealth), proxy infrastructure (BrightData Web Unlocker), CAPTCHA bypass (2Captcha), protocol spray (SSH/FTP/IMAP).
- **BUILD INTERNAL:** credential applicator dispatch, false-success guard, scope-gated DB endpoint check — graph-aware logic standalone tools lack.
- **Note:** Consensus tier (§8d) deferred to Phase 4 per §12.23.

### Phase 4 — Gamma (ANCHOR) + ToolComposer + proof artifacts

Exploitation (OFFENSIVE_APPROVED+SOW), runtime tool composition, blast radius gate + Telegram approval.

**Tool detail:** See `OPERATIONAL_REFERENCE.md` §O1 (Gamma) for the full exploit tool catalog. Per ADR §12.22:
- **WRAP (commodity):** sqlmap, nuclei templates.
- **BUILD INTERNAL (the moat):** ToolComposer.compose(base_template, context) — runtime exploit composition from AttackGraph facts (§5). CMS-specific exploit templates, CVE matching + exploit execution, webshell deploy + persistence.
- **Safety gate (§12.22 Decision 2):** blast-radius gate before ANCHOR; co-host pivot / symlink default-DENY.

### Phase 4b — Advanced Cognition

Simulation/dry-run before risky action → feed blast-radius gate (§8o-2), capability/tool registry + version pinning & determinism controls (§8o-4).

### Phase 5 — Delta (HUNTER) + Epsilon (SCOUT-HUNTER)

Post-exploit & lateral movement, pivot-chain state tracking (§8f), OS-as-tools / LOLBin (§8g), parallel attack path execution + blackboard coordination (§8o-5), Kerberoasting/AS-REP for AD (§8i).

**Tool detail:** See `OPERATIONAL_REFERENCE.md` §O1 (Delta + Epsilon) for the full post-exploit and lateral movement tool catalog. Per ADR §12.22:
- **WRAP (commodity):** GSocket (encrypted shell), john (hash cracking).
- **BUILD INTERNAL:** pivot-chain state tracking in AttackGraph, OS-as-tools / LOLBin catalog, internal network scanning from compromised host, co-host pivot (default-DENY per §12.22 Decision 2).
- **Safety-critical:** `cohost_pivot.py` / `symlink.py` — HIGHEST RISK, default-DENY without explicit per-action SOW authorization.

### Phase 6 — Hardening, learning & differentiators

IntelligenceBase cross-engagement learning + circuit-breaker tool reliability (§8c), Adaptive Learning L1: reflection loop + credit assignment + playbook store + Conductor meta-tuning (§8o-6), knowledge ingestion pipeline (threat-intel RAG, §8o-3), VERIFY/re-test mode, continuous/scheduled engagement, "Try Harder" agent, structured-prompt-from-graph, impact-based prioritization + HVT (§8i), safe-in-production guardrails, Tripwires/canary detection-validation (§8i), additional engagement profiles (Cloud / AD Password Audit / Phishing Impact / Endpoint, §8e).

**Tool detail:** See `OPERATIONAL_REFERENCE.md` §O1 (Omega) for reporting tool targets (JSON, SARIF, compliance mapping PCI/NIS2). IntelligenceBase (pgvector embeddings) + external benchmark gate (ADR §12.21 — AutoPenBench/CyberGym/Cybench).

### Phase 6b — Optional profiles & advanced standards

BrowserHacker/BeEF-style tied to Phishing Impact Test (§8h), compliance mapping PCI/NIS2 + SARIF/Jira export + deconfliction (§8n), benchmark lab GOAD/HTB + regression test agent + observability (§8m). Priority after core stable.

### Phase 7 — Port to Go (if Python-first)

Port network-heavy agents (Alpha/Beta/Delta/Epsilon) + custom tools to Go single-binary, gRPC bridge to Python brain.

## 10. Open Decisions for You

- Build sequencing: Hybrid Go+Python from start, or Python MVP first (default roadmap §9)?
- VERIFY & continuous engagement: enter MVP or hardening phase (currently placed in Phase 6)?
- Approval channel: Telegram only, or need web dashboard for SOW upload & approval gate?
- Multi-tenancy depth: per-tenant isolation to what level (queue only vs separate DB schema vs network isolation)?
- Engagement profiles priority: besides WebApp (Phase 2), which profile prioritized (Cloud / AD / Phishing Impact / Endpoint)?

**Already decided:** Multi-LLM = parallel consensus (DeepSeek V4 Pro + Xiaomi) for critical decisions, single-LLM for light tasks (§8d).

## 11. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Legal/abuse risk | Non-bypassable authorization layer + immutable audit (Phase 0 mandatory first). |
| Uncontrolled blast radius | Calculator + human gate before Level 5-6. |
| LLM hallucination | Structured prompt from graph facts, not free-form. |
| Hybrid Go/Python complexity | Start Python-first; port to Go only for agents truly needing throughput/stealth. |
| False positive wasting time | IntelligenceBase false_positive_rate skips noisy tools per target type. |
| LLM disagreement | Voting + tie-break by graph facts; if still uncertain → human gate, each LLM vote logged for audit. |
| Context loss between tasks (old version problem) | All findings become persistent nodes in EngagementMemory; resume loads same graph (§8b). |
| Prompt injection from target (risk #1 offensive agent) | Trusted-instruction vs untrusted-data separation + sanitization + structured prompt; risky actions always via graph/authorization validation (§8l). |
| LLM refusal mid-engagement | Role split: offensive payload to less-restricted model, reasoning/report to Claude (§8k). |
| Client data leak to LLM cloud | Redaction layer before send + self-hosted option for sensitive data (§8k, §8l). |
| Runaway autonomy / cost explosion | Stop conditions (max iter, time/cost budget, no-progress) + budget cap per engagement (§8j, §8m). |
| Over-engineering self-improvement (repeating error worse way) | Self-modifying code removed from scope; improvement only at auditable + reproducible data/playbook level (§8o-6). |
| Event-sourcing complexity | Start simple (append-only log + projector), avoid over-engineering; reproducibility value justifies cost in Phase 0 (§8o-1). |

## 12. Addendum v1.1 — Adaptivity, Validation & Learning (LOCKED)

Date: 2026-06-16. Source: anti-Lyndon brainstorm + NodeZero (HVT) analysis. Status: final decisions, append-only (does not override §0–§11). All threshold numbers are initial defaults in `agent_alpha/config/constants.py` (single source of truth, version-pinned §8o-4).

### 12.0 Layered architecture principle (anti-Lyndon)

Agent-Alpha = **2-layer hybrid**, mirroring NodeZero (deterministic orchestration + LLM judgment over a living attack graph):

- **Deterministic layer** (tools, exploit, parser, ToolComposer) — must be reliable & reproducible.
- **Adaptive layer** (sequencing/prioritization) — `next_action = f(AttackGraph state)`, via Cognitive Loop §8j.

**HARD PROHIBITION (Lyndon root cause):** no static/linear step list in agent code. Action order & selection MUST emerge from `plan()` over graph state + playbook. Violating this = repeating the "tool runner" failure.

### 12.1 Two-phase LLM gate (A2) — `decide_tier(situation)`

3-tier router for cost + reproducibility (NodeZero "pattern match before LLM"):

| Tier | When | LLM |
|------|------|-----|
| `RULE` | Routine, high confidence, playbook match, next step clear from graph | None |
| `SINGLE_LLM` | Ambiguous, no playbook match, low confidence, new hypothesis | 1 model |
| `CONSENSUS_LLM` | Critical: exploit-chain, blast-radius, "Try Harder", actions changing auth tier/blast radius | 2 models (§8d) |

Tier-up trigger = f(rule confidence, action criticality, novelty/playbook-miss). Thresholds → `config/constants.py`.

### 12.2 Adaptivity validation (A1) — Differential Test (Phase 2 exit criteria)

Automatic proof the agent reads context, not a straight line:

- **Required (L1):** the FIRST tool/technique chosen differs when the fingerprint differs.
- **Strong (L2):** ≥2 actions differ between different targets.
- **Negative control:** identical target (same input) → SAME/consistent path (seed & temperature recorded §8o-4).
- 2 targets with different fingerprints producing an identical path → **TEST FAIL.**

### 12.3 Real-target gate (A3) — Phase 2 exit criteria

- **Infra:** targets on **GCP free tier** (e2-micro, x86 — solves the ARM64 constraint), **separate** from the agent (isolation §8l). Agent + test runner stay on Oracle ARM64 (Rule 10).
- **Firewall (MANDATORY):** targets accept traffic only from the Oracle agent IP (`<oracle-arm-host>`, IP in secrets vault, not in docs). Vulnerable labs must never be publicly exposed.
- **Mode:** run labs **one at a time** on e2-micro (small free tier ~1GB).
- **Phase 2 targets (WebApp), 3 different fingerprints:**
  1. WordPress + ModSecurity (PHP/MySQL/Apache + WAF)
  2. Laravel (APP_DEBUG on)
  3. OWASP Juice Shop (Node/Express)
- **Ground truth:** each lab has a `ground_truth.yaml` → precise FP/FN computation.
- **Gate:** Alpha→Omega end-to-end, **FP < 20%**, output non-empty & different per target.
- **Prohibition:** no `example.com` / internet targets without SOW (§1).
- **GOAD/AD:** deferred to Phase 5 (needs Windows x86 + large RAM, outside free tier).

### 12.4 RAG timing (A4)

- **Phase 2:** NO full RAG. PLAN uses graph facts + **static YAML playbook** (deterministic) as strategy prior. Sufficient for adaptivity (`next = f(graph + playbook)`).
- **Phase 6:** enable full RAG — internal (IntelligenceBase pgvector, after data exists) + external (knowledge ingestion §8o-3: CVE/exploit-db/ATT&CK).
- Rationale: internal RAG needs engagement data first; building earlier = "feature before foundation" (Lyndon #1).

### 12.5 Learning storage format (L1) — Hybrid event-sourced

- **Source of truth:** event stream (§8o-1).
- **Tool reliability metrics** → projection to **DB table** (fast queries).
- **Strategy playbooks** → projection to **markdown** (human-readable, auditable; operator edit = event).
- **pgvector** semantic match → Phase 6 (when enough data).
- All = data/config, not code → complies with "Learn, don't self-rewrite" (§8o-6).

### 12.6 Playbook vetting (L2) — Hybrid by risk

- Status: `candidate` → `trusted`.
- **Low-risk** (recon/scan order, Alpha tools): **auto-promote** if criteria met (§12.9).
- **Risky offensive** (Gamma+ exploit-chain, post-exploit): **mandatory manual operator review** before `trusted` (real blast radius, §1/§8).
- Operator can always manually vet/edit (= event).

### 12.7 "Similar target" fingerprint (L3) — Weighted composite

`what_worked_for_similar_targets()` uses weighted similarity (not exact-match):

- **Primary (high):** tech_stack (CMS/framework + language + web server) + protection (WAF/CDN: Cloudflare/ModSecurity/none).
- **Secondary (medium):** service versions & CVE exposure, surface type (web/api/ssh).
- **Context (low):** industry + region (Indonesia/SEA) — for `credential_patterns`.
- Initial implementation: structured dict; pgvector fuzzy embedding → Phase 6.

### 12.8 Tool reliability threshold (L4) — Data-driven score, config threshold

- **Score** (`success_rate`, `fp_rate`, `avg_timeout` per tool×target_type) = computed from event-stream data (adaptive).
- **Decision threshold** (e.g., `FP_SKIP_THRESHOLD`, `MIN_SAMPLES_BEFORE_SKIP`) = hardcoded in `config/constants.py`, version-pinned (§8o-4).
- **Agent MUST NOT change thresholds itself** (prevents unauditable drift, §8o-6).
- Phase 2–5: hardcoded defaults. Phase 6: scores filled with real data + circuit-breaker (§8c).

### 12.9 Playbook promotion to 'trusted' (L5) — Diversity + lower-bound

- **≥N successes across ≥M DIFFERENT targets/engagements** (not the same target repeated).
- **Minimum success rate** when applied.
- **Statistical correction:** Wilson lower-bound → small N is not treated as "100% certain"; playbook confidence follows N.
- All numbers in `config/constants.py`.

### 12.10 Dev workflow — Claude (architect) vs DeepSeek (payload)

Applies §8k to the build process, not just runtime:

- **Platform code (~95%)** — Conductor, auth, event store, memory, AttackGraph, gRPC, Celery, cognitive loop, ToolComposer ENGINE, report gen: ordinary engineering, NOT offensive → Claude/Sonnet writes specs, IDE implements, zero refusal risk.
- **Payload content (~5%)** in `templates/*`: generated at RUNTIME by any model (TEMPORARY testing phase, composed by ToolComposer against an authorized target), or at dev-time via any model directly — **never via Claude**.
- **Routing rule:** payload body in `templates/{bypass,cms,cloud,regional}` → any model (TEMPORARY testing phase), NEVER Claude. Claude/Sonnet/Opus only: architecture, interface, template scaffold, safety gate, test contract, narrative, review.

### 12.11 Durability & Resume (anti-Lyndon) — LOCKED

Direct answer to the Lyndon failure (restart → lose state → start over). State is
never stored only in volatile memory.

- **Runtime source of truth = durable append-only event log** (PostgreSQL, Phase 1).
  AttackGraph (NetworkX) and SessionMemory (Redis) are volatile projections, rebuilt
  via `replay()` (§8o-1).
- **Rule:** anything reconstructable from the event log MAY be volatile; only the
  event log MUST be durable. Losing the in-memory graph or Redis ≠ losing state.
- **Resume, staged:**
  - **Engagement-level (Phase 1):** PostgreSQL event backend + `Projector.rebuild()` +
    boot recovery → graph & findings restored, agent continues without re-scan (§8b).
  - **Step-level (Phase 3, §8m):** checkpoint cognitive-loop position
    (phase / iteration / active plan / scratchpad) → resume at the exact step.
- **Snapshot optimization (Phase 2):** load latest projection snapshot + replay only
  the events after it (avoids full replay). Phase 1 event log MUST be snapshot-ready.
- **Interrupted offensive action on crash = RE-VERIFY, NEVER RE-EXECUTE:** on resume,
  destructive actions are not repeated; the agent runs VERIFY (inspect target state)
  to infer the outcome of the interrupted action before proceeding. Unverifiable
  outcomes are tagged `unknown` (never assumed successful; promotion rule §8j-2).
- Phase 0 caveat: `EventStore` is in-memory by design (lost on restart); durability
  begins in Phase 1.

### 12.12 GraphStore abstraction — LOCKED

- Define a `GraphStore` interface (read-model) so the graph engine can be swapped
  without touching the Cognitive Loop. The graph is always a projection of the event
  log (§8o-1), so swapping engines is safe.
- Phase 0–3: NetworkX (in-memory, simple, sufficient). Phase 4+: evaluate Memgraph
  (Cypher, in-memory) or Neo4j if cross-engagement/large-graph queries prove necessary
  — still rebuilt from events, never the source of truth.

### 12.13 Agent scaling model — Hybrid orchestrated fan-out — LOCKED

**Decision.** The six Greek agents (Alpha…Omega) are **ROLES / capabilities, not
singleton instances**. Within a phase, work is executed by N stateless **workers**
of that role, running concurrently. This is a **hybrid** model: a centrally
orchestrated kill-chain pipeline (§3) with **intra-phase horizontal fan-out**.
It is explicitly **NOT a swarm** (no peer-to-peer agents, no self-spawning, no
emergent top-level coordination).

**Who fans out.** The **Conductor / planner** partitions a phase's work into
bounded task units and enqueues them on Celery+Redis (§2). **An agent never spawns
or commands workers itself** — that would re-introduce agent-to-agent control and
breach the non-bypassable authorization gate (§1). Workers pull pre-authorized
units; they do not talk to each other.

Example: a Reconnaissance task over 20 hosts does **not** mean "Alpha spawns 20
children." It means the Conductor partitions the scope into 20 (or fewer, capped)
RECON units and enqueues them; up to `MAX_RECON_WORKERS` execute in parallel; every
result flows back through the Conductor into the event log.

**Two valid fan-out patterns (both gated):**
- **Data-parallel** — same capability, partitioned target slice (e.g., 200 hosts split across workers).
- **Functional-parallel** — different techniques in one phase (e.g., DNS enum / port scan / JS-secret extraction concurrently).

**Invariants (non-negotiable):**
1. **Gate never dilutes.** A unit is enqueued ONLY after the Conductor validates
   the engagement's authorization state (RECON_ONLY → … per §1). Workers never read
   or write authorization state; each unit carries its pre-authorized scope.
2. **Bounded autonomy.** Per-engagement / per-tenant max concurrency is config-driven
   (single source of truth, no scattered literals — anti-Lyndon #7) and bounded by
   blast-radius + rate/quota limits. Fan-out degree is never unbounded.
3. **Deterministic aggregation.** Worker results merge into the append-only event
   stream (monotonic, gapless sequence) and project into the AttackGraph (§6, §8o-1).
   Empty/failed results are rejected, never counted as success (anti-Lyndon #3).
4. **No direct A2A dispatch.** No code path lets one agent enqueue work for another;
   only the Conductor dispatches (§3 one-way handoff).

**Role extensibility.** The role taxonomy MAY grow (e.g., a cloud-recon or
AD-specific role) under the SAME gate as engagement profiles expand (§8e). "Six" is
the current role set, not a hard ceiling — adding a role is an ADR change, not an
ad-hoc spawn.

**Phasing (anti-Lyndon #1 — foundation before scale):**
- **Phase 0–2:** single worker per role. Prove the Alpha→Omega pipeline end-to-end first.
- **Phase 3 (orchestrator):** design the Conductor↔Celery dispatch interface to be
  fan-out-aware (partition → enqueue → bounded concurrency → aggregate). Build
  multi-worker scaling incrementally AFTER the single-worker pipeline is proven.
- Multi-worker scaling is NOT built before the pipeline works (no feature-before-foundation).

**Test contract (what "done" means for the fan-out interface):**
- Conductor partitions a RECON scope of N hosts into N units; all units enqueue ONLY
  when state ∈ {RECON_ONLY, ACTIVE_APPROVED, OFFENSIVE_APPROVED} as appropriate; a
  worker executing a unit without valid auth context is rejected.
- Concurrency cap honored: with cap = K and N > K units, at most K run at once; the
  rest queue (assert never > K concurrent for an engagement).
- Aggregation: results from M workers form ONE engagement event stream with a
  monotonic, gapless sequence; duplicate or empty unit results are rejected.
- Negative: no API/code path lets agent X enqueue a task targeted at agent Y
  directly (only Conductor dispatch).

**Integration points.** Conductor (partition + gate + dispatch + aggregate) · Celery+Redis
(queue) · EventStore (append-only aggregation, §8o-1) · AttackGraph (projection, §6) ·
config constants (concurrency caps, §2). Relates to §1, §3, §8e, and the open
rate-limit/quota item.

### 12.14 Front-door 2a — Authenticated Tenant Binding — LOCKED

**Resolves** the authentication gap in P2: the Conductor API had no authentication
and `tenant_id` came from a process env var, disconnected from the (unauthenticated)
`client_id` body field. The RLS backstop (§12.13, P2) had no front door.

**Decision.** Every engagement endpoint requires a verified JWT; `tenant_id` comes
ONLY from the verified claim; engagement ownership enforced; per-request
per-tenant store routing.

**Implementation (verified in code):**
- `conductor/api_auth.py` — PyJWT, algorithm pinned (`algorithms=[JWT_ALGORITHM]`,
  no `alg=none`/confusion), `exp` checked, **fail-closed** if the secret is missing
  or < 32 bytes, `tenant_id`/`sub` claims validated.
- `conductor/main.py` — auth-by-default via `APIRouter(dependencies=[Depends(require_principal)])`;
  new engagement routes cannot ship unprotected.
- `config/stores.py` — `StoreProvider.for_tenant()` routes each tenant to its own
  RLS-scoped store (independent in-memory store per tenant when no DSN).
- `authorization.py` — `tenant_id` persisted on `EngagementRecord`; `_emit_event`
  enriches the payload so auth events route to the correct tenant store.

**Gaps found during review & closed (the audit working as intended):**
- **Unwired auth (Lyndon #2).** `require_principal` existed but was not wired into
  any route — caught immediately by the test-first 401 contract (CI red). Fixed
  via router-level dependency.
- **`/sow` + `/stop` lacked the ownership check (cross-tenant authZ hole).**
  Authenticated but not authorized — any tenant could SOW-escalate or
  emergency-stop another tenant's engagement. The original test contract
  under-specified (only `state`/`recon` were covered); tests for `sow`/`stop`
  were added, then the ownership check was applied to all four routes.
  (`test_api_auth.py` 11 green.)
- **Emergency-stop events routed to the legacy store (audit-isolation gap).**
  `EmergencyStopHandler` now resolves the engagement's tenant via `StoreProvider`;
  stop events land in the tenant's own store. (`test_emergency_tenant_routing.py` 2 green.)
- **Cosmetic (open, non-blocking):** the top-of-file docstring in `config/stores.py`
  still says "single-tenant operation for now" — contradicts `StoreProvider`; tidy
  in a follow-up commit.

**Integration points.** `conductor/api_auth.py` (Principal + JWT validation) ·
`conductor/main.py` (router-level dependency + ownership checks) ·
`config/stores.py` (StoreProvider per-tenant routing) ·
`authorization.py` (tenant_id persistence + event enrichment) ·
`tests/phase_0/test_api_auth.py` (401 + 404 contract tests). Relates to §1
(auth gate), §12.13 (P2 RLS), and the open tenant-isolation item.

### 12.15 LLM role→provider routing — roles canonical, providers configurable — LOCKED

**Resolves** the OPEN DECISION in `PHASE_2_IMPLEMENTATION_ORDER.md` (constants vs
ADR role split) and unblocks P3 (orchestrator routing).

**Decision.** Two LLM ROLES, routed separately and NEVER conflated:
- **REASONING** — ORIENT / PLAN / narrative.
- **PAYLOAD / EXECUTION** — offensive tool & exploit-body generation.

The **ROLE is the architectural invariant.** The concrete **PROVIDER behind each
role is configuration**, swappable without any code/architecture change (the
provider abstraction, §12). Neither option (a) nor (b) from the open decision is
taken literally: the role split stays canonical (ADR), and
`LLM_REASONING_PRIMARY="deepseek-v4-pro"` is reinterpreted as the *current
(testing) reasoning provider* — config, not a permanent architectural commitment.

**Provider policy per role:**

| Role | Allowed transport | Provider (config) | Notes |
|------|-------------------|-------------------|-------|
| Reasoning | Direct vendor **or** gateway/aggregator (Bedrock/Vertex in our own cloud, or a public router ONLY with zero-retention) | `LLM_REASONING_PROVIDER` — testing: `deepseek-v4-pro` / `mimo`; production target: Claude / GPT-class | Hybrid/dynamic allowed; swap = change the constant |
| Payload | **Direct provider API ONLY** | `LLM_PAYLOAD_PROVIDER` — open-weight: DeepSeek / MiMo / equivalent | **NEVER** a public aggregator/router (their ToS forbids offensive content + extra data egress); **NEVER** Claude (§12.10) |

**Data-governance invariant (non-negotiable):**
- Sensitive data — client vulns, harvested creds, target detail, payload bodies —
  MUST NOT egress to a public router/aggregator absent a zero-retention,
  no-training contractual control.
- **Strongest posture for the payload role (recommended): self-host the
  open-weight model in our own infra** (Oracle ARM64 / controlled cloud) so
  payload generation never leaves our environment at all. If a vendor-hosted
  direct API is used instead, require zero-retention/no-training terms and record
  the data-processor in the SOW/DPA.
- `llm/redaction.py` + the authorization gate + audit run IN FRONT of every
  provider call, regardless of role or transport. Payload generation is gated by
  authorization state (authorized engagements only).
- Provider API keys live in the secrets vault — never in code or plaintext env.

**Switch gate (provider maturity):** the production reasoning provider must be
Claude/GPT-class, validated against real targets, **before the first paid client
engagement**. Until then DeepSeek-v4-pro / MiMo are acceptable for testing only.
"Temporary" is bounded by this gate so it cannot become permanent by inertia
(anti-Lyndon #1/#5). [Adjust the line earlier — e.g. before Phase 4 / first demo —
if desired.]

**Constants change (config/constants.py):**
- ~~Rename `LLM_REASONING_PRIMARY` → `LLM_REASONING_PROVIDER`~~ ✅ DONE
- Add `LLM_PAYLOAD_PROVIDER` (direct open-weight provider).
- Add `LLM_PAYLOAD_TRANSPORT = "direct"` (or equivalent) so the orchestrator
  **refuses** to route payload generation through an aggregator-class transport.

**Test contract:**
- `reason()` dispatches to `LLM_REASONING_PROVIDER`; changing the constant changes
  the adapter with NO code change (assert via a mock provider registry).
- `payload()` dispatches to `LLM_PAYLOAD_PROVIDER`; assert it NEVER resolves to the
  Claude adapter AND never to an aggregator-class transport.
- Redaction runs before every provider call (both roles) — assert raw creds/PII
  never reach the outbound provider payload.
- `payload()` refuses unless the engagement's authorization state permits it
  (gated; no payload for unauthorized/recon-only engagements).

**Integration points.** `config/constants.py` (provider + transport config) →
`llm/orchestrator.py` (role-based routing + transport policy enforcement) →
`llm/providers/*` (adapters: deepseek, mimo, claude, gpt, + a gateway adapter) →
`llm/redaction.py` + authorization gate IN FRONT. The cognitive loop calls
`reason()` / `payload()` BY ROLE, never a hardcoded model name.

**Supersedes:** the ambiguous `LLM_REASONING_PRIMARY` interpretation; relates to
§12.0/§12.1 (LLM gate tiers), §12.10 (Claude never writes payloads), §1 (auth gate).

### 12.16 Tool Layer: capabilities-vs-roles, contracts, composition discipline — LOCKED

**Status:** LOCKED (2026-06-22, co-authored Opus + Natanael). Amends §12.4.
**Relates to:** §12.13 (scaling/roles), §12.8/K19 (IntelligenceBase reliability), §12.1
(tier ladder), §12.4 (RAG timing). Companion: `docs/TOOL_LAYER.md` (the contract scaffold).

#### 12.16.1 — Agents are kill-chain ROLES; payload/proxy/browser are CAPABILITIES, not agents

**Decision.** The agent taxonomy stays the six kill-chain roles (Alpha…Omega) under §12.13.
"PayloadGenerator", "Proxy Tester", and "Browser" are **capabilities/tools**, NOT new agent
roles. Rejected as agents.

**Rationale.** An agent = a PHASE of the kill chain (recon → access → exploit → post →
lateral → report). Payload generation, proxying, and browsing are *how* an agent does its
work, not *what phase* it is. Modeling a capability as an agent repeats **Lyndon #4** (generic
architecture: mixing capability with role) and pollutes the clean role taxonomy.

**Placement.**
- **PayloadGenerator** → the **LLM payload role** (DeepSeek, direct, §12.15) + **ToolComposer**.
  Invoked BY Gamma/Beta; never a standalone agent.
- **Browser (Playwright)** → a **shared capability** in the deterministic layer. Used by BOTH
  Alpha (JS/SPA recon, client-rendered targets) AND Beta (anti-detect spray + Cloudflare/
  Turnstile bypass). Built ONCE, injected into whoever needs it — never duplicated per agent.
- **Proxy** → a tool (rotation: residential/SOCKS5) PLUS an explicit **proxy-health / OPSEC
  check** (alive, not burned) that MUST run before any spray. Named as a tool, gated like one.

#### 12.16.2 — Tool layer contracts + composition discipline

**Decision.** All tools plug into one foundation (see `docs/TOOL_LAYER.md` §2): canonical
`Tool` + `Template` protocols, `ToolRegistry`, `ToolComposer`. Non-negotiable invariants:

1. **`ToolComposer.compose()` returns a PLAN, never executes.** Execution stays in the agent
   cognitive loop, where **each step is re-gated (auth state) and verified**. No autonomous
   "retrieve/compose → exploit" chain — preserves the non-bypassable gate (§1) + audit.
2. **Every `Template` MUST implement `verify()`.** A tool is "successful" only when `verify()`
   PROVES exploitability from the response and captures a proof artifact. "version matches CVE"
   or "csrf-token present" is a hypothesis, not a finding (anti-Lyndon #3). This is the line
   between Agent-Alpha and a scanner.
3. **Selection is reliability-ranked, never hardcoded.** `ToolRegistry.for_context` ranks via
   `IntelligenceBase.tool_reliability` (K19); no literal tool order in agent code (K11 / #7).
4. **Authoring split (§12.15 / K21):** Claude authors the contracts + registry/composer glue +
   test contracts (non-offensive). DeepSeek authors every offensive body (`run`/`build`/
   `verify` payload logic) in `tools/templates/*`. Claude never writes payload bodies.
5. **Bounded autonomy:** every tool runs under a `ResourceBudget` (requests/time/cost/rps),
   single-sourced from constants (§12.13 #2 / #7). `rate_limit_rps` ties to the Pre-Beta
   rate-limit control.

**Build order (does NOT pull phases forward — anti-Lyndon #1/#5):** foundation contracts now;
recon-finding tools next (first real `verify()` consumer); Access=Phase 3, Exploit + live
ToolComposer=Phase 4, Post/Lateral=Phase 5. Offensive bodies land per-phase, never up front.

#### 12.16.3 — Amends §12.4: RAG external-vs-internal split

**Decision.** Split the single "RAG = Phase 6" into two tracks:
- **Internal RAG** (pgvector over cross-engagement data) — stays **Phase 6**. Hard cold-start:
  embeddings over an empty corpus retrieve nothing; needs accumulated real engagement data.
- **External RAG** (CVE / Exploit-DB / MITRE ATT&CK feeds) — has **no cold-start** (data exists
  day 1) and **MAY precede** internal embeddings. BUT only AFTER (a) the hypothesis→verify loop
  exists and (b) recon produces precise version fingerprints — otherwise external CVE-matching
  is just a worse Nessus/nuclei (scanner-grade, the thing we beat).

**Invariant (both tracks).** RAG is **advisory + gated**: it enriches the SINGLE_LLM/CONSENSUS
reasoning tiers (§12.1) and feeds `hypothesis.py` → `verifier.py`; it is NEVER an autonomous
retrieve→exploit path. RULE tier (deterministic playbook) stays first for reproducibility/
anti-injection/cost. External feed content crosses a trust boundary → redaction before any LLM
(§8l); payload bodies still DeepSeek-direct; feed freshness is a correctness requirement (a
stale CVE DB = false confidence, worse than none).

**Consequences**
- No new agent classes; capability work routes into the deterministic tool layer.
- The differentiator is now concretely located: ToolComposer + `verify()`-gated templates +
  reliability ranking + (Phase 6) RAG — NOT breadth of external-tool wrappers.
- A clear DeepSeek/Claude contract boundary for every future tool.

### 12.17 Secrets Vault — Postgres backend + lazy per-tenant provider — LOCKED

**Status:** LOCKED (2026-06-28). **Relates to:** §8l (platform security), §12.14
(tenant binding), §12.13 (RLS isolation), §1 (auth gate).

**Decision.** Harvested credentials and API keys are stored in a Postgres-backed,
tenant-isolated, Fernet-encrypted vault — NOT plaintext in log/graph. The vault
mirrors the event store's laziness: import-safe, Postgres/key touched only at
`for_tenant()` during a real tenant task.

**Components:**
- `SecretsVault` Protocol (`security/secrets.py`) — `store`, `retrieve`, `delete`,
  `delete_engagement`, `list_labels`. Multi-backend contract.
- `SecretsManager` — in-memory default (single-process, no key needed).
- `PostgresSecretsVault` (`security/postgres_secrets_vault.py`) — Fernet encryption
  at rest, RLS-scoped per tenant, shared key from `AGENT_ALPHA_VAULT_KEY` env.
- `SecretsVaultProvider` (`config/stores.py`) — lazy per-tenant provider mirroring
  `StoreProvider`. Key loaded on FIRST `for_tenant()` call, never at import.
- `load_vault_key()` — fail-closed: raises if `AGENT_ALPHA_VAULT_KEY` not set.

**Key fix (eager→lazy):** Initial wiring called `secrets_vault_from_env()` eagerly
at `main.py:44`. On Oracle (DSN set), this called `load_vault_key()` at import time
→ 7 collection errors. Replaced with `SecretsVaultProvider` (lazy, per-tenant),
matching `StoreProvider`'s proven pattern.

**Test contract:** `tests/phase_3/test_postgres_secrets_vault.py` — 4 integration
tests (skip if no DSN): cross-instance retrieval, encryption at rest, tenant
isolation, engagement-based purge. 9 unit tests for the Protocol + manager.

### 12.18 Scope.db_endpoints + Applicator Factory — Gate-enforced DB access — LOCKED

**Status:** LOCKED (2026-06-29). **Relates to:** §1 (auth gate), §12.14 (tenant
binding), §12.16 (tool layer), §8l (platform security).

**Problem.** Direct-DB credential application is the most invasive action. Three
flaws needed convergence:

| Flaw | Risk | Root cause |
|------|------|------------|
| **FLAW 1** (auth-gate softening) | `cred_reuse` holds `auth` handle → can bypass tier | No separation between gate logic and tool |
| **FLAW 2** (out-of-scope DB host trap) | Leaked `DB_HOST` from .env (localhost/internal) used as target | No scope check on DB endpoints |
| **FLAW 3** (ServiceProperties has no host) | DB port assumed co-located with asset host | No host⊕port join via `open_ports` |

**Decision.**

1. **`Scope.db_endpoints`** (`conductor/models.py`) — explicit `host:port` list in
   the signed SOW scope. Validated at scope creation. Gate enforces exact match.

2. **`is_db_endpoint_in_scope()`** (`conductor/authorization.py`) — gate method that
   checks `host:port` against `scope.db_endpoints`. Never raises (fail-closed
   return `False`). Read-only query on the event-sourced state.

3. **`applicator_factory.py`** (`conductor/`) — the ONLY place where authorization
   state and scope are read to decide WHICH credential applicators `cred_reuse` may
   use, and AGAINST WHICH in-scope target each is bound.

   - **Tier gate (FLAW 1):** `required_auth` vs engagement state. `cred_reuse`
     receives `BoundApplicator` list and iterates — it holds NO `auth`/`scope`
     handle. Stop-signal guard test enforces this.
   - **Scope gate (FLAW 2):** DB applicators bind ONLY to ASSET `host:port`
     validated by `is_db_endpoint_in_scope()`. Leaked `DB_HOST` rejected.
   - **Host⊕port join (FLAW 3):** host from `AssetProperties.host`, port from
     `open_ports`. ServiceProperties has no host — port joined via asset, never
     assumed.
   - **`BoundApplicator(applicator, target)`** — cred_reuse calls
     `apply(target=...)` verbatim, never chooses a target.
   - **`AuthScopeView` Protocol** — read-only slice of AuthorizationStateMachine;
     no transition methods exposed to the factory.

**Single source of truth (#7):** the `required_auth → state` ladder is defined once
in the factory, mirroring `AuthorizationStateMachine.can_agent_proceed`.

**Test contract:** `tests/phase_3/test_applicator_factory.py` — 9 tests covering
all three flaws + cred_reuse blindness guard. `tests/phase_0/test_db_endpoint_scope.py`
— gate-level scope validation tests.

### 12.19 External Benchmark Gate — Proof of value-add before GA — PROPOSED

**Status:** PROPOSED → LOCK on merge. Adds a NEW exit gate; does not change any
existing phase. **Relates to:** §12.2 (differential test), §12.3 (real-target gate),
§8m (reliability/validation), §8o-6 (adaptive learning).

#### Context

Agent-Alpha's success bar is internal ("find what a scanner missed, prove it, produce
a payable report"), proven once on lab container 9201. Competitors publish **external,
comparable numbers**: XBOW (#1 HackerOne US), CAI (HTB CTFs, bug bounties). We have
zero external numbers → "value-add vs competitors" is currently an architectural claim,
not a measured fact. This gate makes the claim falsifiable.

#### Flaw considered first (why a naive benchmark gate is a trap)

- **CTF benchmarks are saturating and flatter.** Frontier models hit ~93% on Cybench;
  InterCode-CTF is effectively solved. A high Cybench score would prove we're *not
  behind*, not that we're *differentiated*. CTFs lack the noise, state, and validation
  gap of real engagements.
- **Benchmark-chasing risks Lyndon #1/#5** — optimizing for a leaderboard instead of
  the payable-report bar. The gate must therefore be *secondary* to the internal bar,
  and must weight **autonomy + real-world** benchmarks above saturated CTF.
- The literature is explicit that fully-autonomous pentest "remains distant" and all
  serious players keep a human in the loop. So the gate measures **autonomous
  capability as a yardstick**, not as a claim that the product runs unsupervised.

#### Decision

Adopt a **three-tier external benchmark gate**, run on **Oracle ARM64** (anti-#9), as
part of **Phase 6 / pre-GA** exit criteria. Targets are CALIBRATION targets — set the
floor from a first baseline run, then ratchet. Do not invent a pass number before the
baseline.

```
Tier A — AUTONOMY (primary, weighted highest):
  AutoPenBench, fully-autonomous mode (NO human hints).
  Why: directly measures the scripted-vs-autonomous gap (chain_runner → Conductor).
  Gate: Agent-Alpha autonomous score ≥ the published autonomous baseline (~21% solved
        at publication) AND beats our own previous run (monotonic ratchet).

Tier B — REAL-WORLD CHAINING (primary):
  CyberGym (real CVE-derived, multi-step) and/or a multi-step-scenario benchmark
  (arXiv 2603.11214 family).
  Why: measures state tracking + error recovery + the validation gap — our thesis.
  Gate: report solved-rate + a VALIDATION metric (fraction of claimed successes that
        are VERIFIED true, i.e. no false-success #3). Target: false-success rate <
        internal Phase-2 bar (<20% FP) on the benchmark too.

Tier C — COMPARABILITY (secondary, sanity floor):
  Cybench (40 pro CTF) — for an apples-to-apples public number only.
  Gate: report the score; NOT a blocker (saturated). Used to detect regressions.
```

#### The internal bar still dominates

A passing external score does **not** by itself clear Phase 6. The payable-report bar
(§success condition) remains the primary gate; benchmarks are the *external
corroboration*. If they ever conflict, the payable-report bar wins.

#### Test contract

```
T1  Benchmark harness runs Agent-Alpha through the REAL autonomous live path (Conductor
    auto-advance + Celery), NOT chain_runner. (If it can only run via chain_runner, the
    autonomy gap from §autonomy-audit is unresolved — gate cannot be claimed.)
T2  Each run emits: solved-rate, VERIFIED-success rate (false-success guard), wall-clock,
    LLM cost. All four logged to the event store (auditable, reproducible).
T3  Scores recorded per ADR version + git SHA → ratchet enforced (a release may not ship
    a LOWER Tier-A/B score than the previous release without a written waiver).
T4  Baseline run completed and its numbers written back into THIS ADR as the initial
    floor before the gate is declared active.
```

#### Integration point

The benchmark harness is an **external driver** that creates an engagement via the
normal Conductor API (SOW/auth gated like any engagement — benchmarks run as
authorized self-owned targets), then reads results from the event store + Omega
report. It adds **no** new code path inside the agents — it exercises the existing
autonomous path. This is also a forcing function: the gate is unrunnable until the
autonomy wiring (§autonomy-audit, Tier 2) exists, so it pulls that work forward
honestly.

#### Sequencing

- **Now:** record the gate (this ADR). Do NOT build the harness yet (Phase 6 —
  building it before the autonomous path exists = dead code #2).
- **Trigger to build the harness:** the autonomy grep/trace audit is green (Conductor
  auto-advance + bounded Beta loop + fallback) AND the cred-reuse moat is on the
  Celery path. Until then the gate is a recorded target, not active work.

**Confidence ~75%** — benchmark landscape moves fast; specific published baselines
(AutoPenBench ~21% autonomous, Cybench ~93% frontier) should be re-confirmed at
baseline time, not trusted from this doc.

### 12.20 Conductor Handoff-Consumer — Autonomous spine on Celery path — LOCKED

**Status:** LOCKED (2026-06-29). **Relates to:** §12.13 (agent scaling, Celery), §12.14
(tenant binding), §12.18 (applicator factory), §1 (auth gate), §8o-1 (event-sourcing).

**Closes audit gap A1.** Conductor previously never consumed handoffs; the payable chain
only ran via `live_fire/chain_runner.py` (single-process script). This module makes the
Conductor advance Alpha→Beta on the Celery path, gate-validated, and is the call-site
where the applicator factory (§12.18) feeds Beta's cred_reuse task.

**Components:**
- `conductor/advance.py` — handoff-consumer with pure decision logic (`decide_advance`)
  and effectful orchestration (`advance_engagement`). Proto enum semantics (PhaseStatus,
  AgentRole) with CONDUCTOR/0 = unset guard (anti false-default #3).
- `tests/phase_3/test_conductor_advance.py` — RED tests: pure decision (forward transition,
  tier gate, emergency stop, idempotency) + effectful (dispatch with factory applicators,
  park across tier, idempotent under retry).
- `docs/conductor_advance_handoff.md` — integration spec: wiring to `main.py`, new event
  types (HANDOFF_READY, AGENT_DISPATCHED, AWAITING_APPROVAL, CHAIN_COMPLETE), Celery
  dispatcher injection, Step 3c cred_reuse applicator injection.

**Key invariants:**
- **Agent never calls agent.** Agent task signals Conductor to advance via
  `advance_engagement_task.delay()`. Conductor's `advance_engagement()` is the SINGLE
  place that reads handoff, validates contract, checks auth gate, and dispatches next
  agent.
- **Auth gate not softened.** Alpha (RECON_ONLY) → Beta (ACTIVE_APPROVED) is a tier
  boundary. Conductor auto-advances ONLY to an agent whose required tier is ALREADY
  granted. If next agent needs higher tier → engagement PARKS (AWAITING_APPROVAL),
  requires human approval. Autonomy WITHIN a tier, human gate BETWEEN tiers.
- **Idempotent under Celery retry.** `AGENT_DISPATCHED` event with `after_handoff_seq`
  prevents double-dispatch.
- **Applicator factory call-site.** `advance_engagement()` calls `applicator_builder`
  for credential-consuming agents (Beta) only; passes `BoundApplicator` list to
  dispatcher → cred_reuse receives injected applicators, no auth/scope handle
  (stop-signal guard).

**Sequencing (anti-#10):**
1. Mount `advance.py` + `test_conductor_advance.py` to Oracle #61 → run tests → must
   GREEN (pure + effectful with fakes).
2. Wiring per `conductor_advance_handoff.md`: add event types, `advance_engagement_task`
   Celery task, `Dispatcher` impl, `ApplicatorBuilder` wrapper, agent task tail.
3. Integration test: create engagement → enable_active → run recon → assert Beta task
   enqueued, NO agent-to-agent dispatch.

**Decommission script path.** Once Celery path runs green, `chain_runner.py` becomes
dev/live-fire harness only — NOT a second production orchestrator (anti-#6).

### 12.21 External Benchmark Gate — Proof of value-add before GA — PROPOSED

**Status:** PROPOSED → LOCK on merge. Adds a NEW exit gate; does not change any existing
phase. **Relates to:** §12.2 (differential test), §12.3 (real-target gate), §8m
(reliability/validation), §8o-6 (adaptive learning).

Three-tier external benchmark as Phase 6 / pre-GA exit criteria, run on Oracle ARM64.
Tier A = AutoPenBench autonomous (primary, measures scripted-vs-autonomous gap).
Tier B = CyberGym real-world chaining (primary, false-success guard). Tier C = Cybench
(secondary, regression only). Internal payable-report bar still dominates. Harness
exercises real Conductor autonomous path, NOT chain_runner. Build trigger: autonomy
audit green + cred-reuse on Celery path. Full detail in `ADR.md` §12.21.

### 12.22 Tool strategy: wrap commodity, build the moat, gate the dangerous — PROPOSED

**Status:** PROPOSED → LOCK on merge. Extends §12.16 (tool layer) and §5–§7 differentiators.

**Decision 1 — litmus rule:** build internal ONLY if uses attack graph / cross-engagement
memory / proof-composition; otherwise WRAP behind `ToolResult` contract. WRAP = nmap,
nuclei, sqlmap, feroxbuster/ffuf, proxy, captcha, GSocket, john. BUILD = ToolComposer,
IntelligenceBase, AttackGraph narrative, regional verified templates.

**Decision 2 — safety revisions:** cohost_pivot/symlink default-DENY (co-host = different
owner, almost always out of SOW). Credential spray lockout governor. Persistence/exfil
require explicit SOW clause + guaranteed teardown/restore.

**Decision 3 — new internal tools:** scope/blast-radius governor (compliance moat),
TransportResilience (WAF/CF discriminator — classify CF-RAY/challenge as WAF-BLOCKED,
never "not vulnerable"), engagement teardown/restore tool. Full detail in `ADR.md` §12.22.

### 12.23 Consensus-LLM tier — deferral from Phase 3 to Phase 4 (Gamma) — LOCKED

**Status:** LOCKED (2026-07-02). Supersedes "multi-LLM consensus" in Phase 3 exit criteria.
Aligns ADR with `docs/PHASE_3_TEST_CONTRACT.md`. Doc-integrity sweep COMPLETE: §8-era
citations repointed to §12.23.

`CONSENSUS_LLM` tier + `MiMoProvider` + parallel-consensus moved to Phase 4 (Gamma).
Phase 3 runs single reasoning provider only. Consensus is for exploit-chain selection,
blast-radius assessment, "Try Harder" — none occur in Phase 3 (ACTIVE_APPROVED, bounded,
reversible). The irreversible high-blast-radius decisions land in Gamma (OFFENSIVE_APPROVED
+ SOW). Full detail in `ADR.md` §12.23.
