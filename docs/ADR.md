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
- **Implementation (Phase 2, 2026-06-19 — amends framing):** the monologue is **loop-driven** — one `ThoughtFrame` emitted per cognitive-loop phase (OBSERVE/ORIENT/ACT/PERSIST), NOT `reasoning_content`-only. Rationale: under Opsi-B playbook-first the RULE tier makes zero LLM calls, so `reasoning_content` is empty on the headline path. Reasoning is sourced per tier — **RULE → playbook `rationale`**, **SINGLE_LLM → DeepSeek `reasoning_content`** (captured in `CompletionResult.reasoning`). The monologue is a **USER channel via an injected `MonologueSink`**, strictly separate from A2A (A2A stays structured JSON). Emission core implemented + tested (`agent_alpha/agents/monologue.py`, `tests/phase_2/test_monologue.py`); real-time **user-delivery transport (Redis pub/sub → WebSocket) is deferred to Phase 3**, since a connected user requires the Celery non-blocking execution path built there.

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

### Phase 3 — Beta (STRIKE) + Celery non-blocking + LLM strategy

Initial access (ACTIVE_APPROVED), credential spray, chat-while-task-runs (§8a), multi-tenant queue, LLM Orchestration parallel consensus + role split (Claude reasoning / DeepSeek payload) + redaction + budget cap (§8d, §8k), prompt-injection defense (§8l), loop/budget guardrail + checkpoint/resume (§8m), time-window & OPSEC profile (§8n).

### Phase 4 — Gamma (ANCHOR) + ToolComposer + proof artifacts

Exploitation (OFFENSIVE_APPROVED+SOW), runtime tool composition, blast radius gate + Telegram approval.

### Phase 4b — Advanced Cognition

Simulation/dry-run before risky action → feed blast-radius gate (§8o-2), capability/tool registry + version pinning & determinism controls (§8o-4).

### Phase 5 — Delta (HUNTER) + Epsilon (SCOUT-HUNTER)

Post-exploit & lateral movement, pivot-chain state tracking (§8f), OS-as-tools / LOLBin (§8g), parallel attack path execution + blackboard coordination (§8o-5), Kerberoasting/AS-REP for AD (§8i).

### Phase 6 — Hardening, learning & differentiators

IntelligenceBase cross-engagement learning + circuit-breaker tool reliability (§8c), Adaptive Learning L1: reflection loop + credit assignment + playbook store + Conductor meta-tuning (§8o-6), knowledge ingestion pipeline (threat-intel RAG, §8o-3), VERIFY/re-test mode, continuous/scheduled engagement, "Try Harder" agent, structured-prompt-from-graph, impact-based prioritization + HVT (§8i), safe-in-production guardrails, Tripwires/canary detection-validation (§8i), additional engagement profiles (Cloud / AD Password Audit / Phishing Impact / Endpoint, §8e).

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

### 12.22 Tool strategy: wrap commodity, build the moat, gate the dangerous — PROPOSED

**Status:** PROPOSED → LOCK on merge. Extends §12.16 (tool layer) and the §5–§7 differentiators.

Decides what Agent-Alpha builds internally vs wraps, the safety-critical revisions to
OPERATIONAL_REFERENCE.md tools, and Cloudflare/WAF handling.

#### Context

OPERATIONAL_REFERENCE.md lists ~40 tools across the kill chain. A review found: most are
COMMODITY (nmap/nuclei/sqlmap/feroxbuster/proxy/captcha/GSocket) — rebuilding them internally
is Lyndon #1/#4 at scale (breadth-chasing). Competitors (XBOW web-app autonomy; CAI generic
multi-agent + 300+ LLM) already out-breadth us on commodity tooling. We cannot win on
breadth. We win on the graph × cross-engagement-memory × proof triad they structurally lack.

Separately, the review found four tools that are not "build vs wrap" questions but
LEGAL/SAFETY landmines that must be gated before any further offensive work.

#### Decision 1 — The litmus rule (wrap vs build)

> Build a tool INTERNALLY only if it uses the attack graph, cross-engagement memory, or
> proof-composition in a way a standalone tool cannot. Otherwise WRAP the external tool
> behind the `ToolResult` contract (§12.16).

- **WRAP (commodity):** recon (nmap, httpx, subfinder, nuclei, feroxbuster/ffuf, whatweb,
  wafw00f), sqlmap, proxy infra (BrightData/residential/SOCKS5), captcha (2Captcha),
  GSocket, john. No unique value in reimplementing these.
- **BUILD INTERNAL (the moat — these are the "Agent-Alpha-only" tools):**
  1. **ToolComposer** (§5, §12.16) — runtime exploit-chain composition from graph context;
     `compose()` = plan-not-execute; `Template.verify()` mandatory (proof, not assumption).
  2. **IntelligenceBase** (§4, pgvector) — cross-engagement learning: rank the chain most
     likely to work on THIS fingerprint from what worked on similar past engagements.
  3. **Attack-graph narrative + payable report** (Omega) — the deliverable clients pay for;
     MITRE + PCI/NIS2 + SARIF. The report is the product.
  4. **Regional verified templates** (banking_portal, his_sqli, egov, ERP/Laravel) — proof-
     carrying, SE-Asia stacks global tools de-prioritize.
  The triad (1×2×proof) is the durable moat — no competitor has graph+memory+proof together.

#### Decision 2 — Safety/scope revisions (NON-NEGOTIABLE, gate before more offense)

These OPERATIONAL_REFERENCE.md tools are revised to default-DENY without explicit, per-action
SOW authorization, enforced by the Conductor scope gate:

1. **`cohost_pivot.py` / `symlink.py` (Epsilon) — HIGHEST RISK.** Co-hosted domains have
   DIFFERENT owners = almost always OUT of SOW. Each co-host target MUST pass a per-target
   scope check; default DENY. Touching a co-host not in SOW is an unauthorized-access
   offense against a third party. This gate is non-bypassable.
2. **Credential spray (Beta)** — add a lockout-safety governor: spraying real accounts can
   lock out the client's users (a DoS). Bounded attempts/account, SOW-scoped account lists,
   honor lockout thresholds. Rate-limit alone is insufficient.
3. **Persistence + `cleanup_scan` + anti-forensics (Delta)** — require an explicit SOW
   clause per action, a GUARANTEED teardown/restore at engagement end, and full audit for
   client handback. Never leave real persistence; never destroy client evidence.
4. **`db_dump` exfil (Delta)** — proof-of-access, not bulk theft: minimize + redact +
   encrypt; the report proves access with a bounded sample, not a full dump.

These four are also a SELLING POINT when surfaced as the **scope-aware blast-radius governor
tool** (see Decision 3) — "provably stays in scope" is a compliance differentiator.

#### Decision 3 — New internal tools (born from the safety review = nilai jual)

1. **Scope/blast-radius governor (tool, not just gate):** pre-execution, every action's
   target is checked against SOW; co-host/out-of-scope flagged and DENIED. Compliance moat.
2. **TransportResilience capability (§12.16 capability, NOT an agent) — Cloudflare/WAF:**
   - Reaching origin (if origin IP in SOW) is scoping, not evasion.
   - Passing anti-bot to TEST the authorized app: wrap `curl_cffi` (TLS/JA3 impersonation) +
     Playwright (Turnstile) — commodity, gated to in-scope targets only.
   - **The unique value = the WAF/CF-block DISCRIMINATOR:** classify a CF-RAY/challenge/403
     as WAF-BLOCKED — NOT a vulnerability verdict. This kills false-negatives ("blocked" ≠
     "safe") and false-success, feeding the proof/verify moat. On block: adapt transport /
     lower rate / hand to the payload lane, OR honestly report "unverifiable behind WAF".
   - Payload-level evasion bodies remain the DeepSeek lane (K21); Claude owns the
     discriminator interface + the gate, never the evasion payload.
   - Respects existing OPSEC profiles (§8n) + RateLimiter — never trip CF rate limits and
     burn the engagement.
3. **Engagement teardown/restore tool:** proves the platform leaves the client system clean
   (reverses uploads/persistence). Trust/selling point for a compliance-focused SaaS.

#### Build order (per-phase, not up front — §12.16)

Registry + Composer (the moat enabler, audit gap A4) → scope/blast-radius governor →
external-tool wrap adapters (recon trio) → TransportResilience discriminator →
IntelligenceBase (Phase 6) → teardown/restore. Each independently testable; offensive
bodies (templates/*) are DeepSeek's, behind `Template.verify()`.

#### Test contract (gates these decisions)

```
- Litmus: any NEW tool PR states wrap-or-build + the graph/memory/proof justification.
- cohost/symlink: a co-host target NOT in SOW → DENIED (RED test, default-deny).
- spray: attempts/account bounded; a lockout-threshold breach → halt that account.
- persistence/exfil: blocked without the explicit SOW clause; teardown verified at end.
- WAF discriminator: a CF-RAY/challenge response is classified WAF-BLOCKED, never
  "not vulnerable" and never COMPLETE/success (anti false-negative + anti-#3).
```

**Confidence ~85%** — the wrap-vs-build litmus + the safety revisions are well-grounded
(competitor research + the OPERATIONAL_REFERENCE review). Residual: the exact scope-gate
API on #61 (reuse `is_in_scope` / `is_db_endpoint_in_scope` patterns) and where the
TransportResilience capability plugs into the HttpClient — confirm on #61 before building.

### 12.20 Conductor Handoff-Consumer — Autonomous spine on Celery path — LOCKED

**Status:** LOCKED (implemented + merged as PR #69 on Oracle #61, 2026-06-29). This is the
written ADR body for the decision that shipped. **Relates to:** §12.13 (agent scaling,
Celery), §12.14 (tenant binding), §12.18 (applicator factory), §1 (auth gate), §8o-1
(event-sourcing).

#### Context

Through Phase 2 the kill chain was driven by a single-process script
(`live_fire/chain_runner.py`): a human ran it, and it orchestrated Alpha→Beta→Omega in one
process. The autonomy audit (A1) confirmed the Conductor did NOT consume agent handoffs —
the payable cred-reuse chain only existed on the script path, not on the Celery path. That
is not an autonomous platform; it is a script with agents. The handoff-consumer makes the
**Conductor** advance the chain itself, on the durable Celery path, without ever letting one
agent call another.

#### Decision

The Conductor owns a handoff-consumer (`conductor/advance.py::advance_engagement`) that,
triggered as the tail of each agent's Conductor-owned Celery task, advances the chain by ONE
validated step:

1. **Event-sourced trigger.** An agent task, on completion, appends a `HANDOFF_READY` event
   (carrying the `HandoffPayload` per `proto/a2a.proto`: `status` PhaseStatus, `from_agent`
   AgentRole, `next_recommended` AgentRole) and signals the Conductor to advance. An agent
   **never** enqueues the next agent. `advance_engagement` reads the latest handoff from the
   event stream (replay-safe).
2. **Pure decision** (`decide_advance`): `dispatch | park_awaiting_approval | halt_complete |
   noop`, computed from the handoff status, a forward-only transition check
   (`KILL_CHAIN_ORDER`, single source #7), the auth verdict (passed as a value), and an
   idempotency flag. proto3 zero-value traps are guarded: advance only on `COMPLETE`
   (`PENDING`=0 default never mistaken for done); `next_recommended`==`CONDUCTOR`(0)=unset →
   no auto-dispatch to the Conductor.
3. **Auth gate RESPECTED, never softened.** Alpha (RECON_ONLY) → Beta (ACTIVE_APPROVED) is a
   tier boundary. The Conductor does NOT auto-promote authorization state. It auto-advances
   ONLY to an agent whose required tier is already granted (a human ran
   `enable_active`/`enable_offensive`). If the next agent needs a higher tier → the
   engagement PARKS (`AWAITING_APPROVAL`, `requires_human_approval=True`). Autonomy WITHIN a
   tier; human gate BETWEEN tiers.
4. **Idempotent under Celery retries.** An `AGENT_DISPATCHED` event keyed by the handoff
   sequence makes re-dispatch a no-op. Separately, the agent-execution helper
   (`execute_agent`) is idempotent on the agent BODY: it will not re-run an OFFENSIVE agent
   on retry if a terminal handoff for (engagement, agent_role) already exists (re-running
   Beta = repeated attack).
5. **No agent-to-agent dispatch (non-negotiable §12.13).** Only the Conductor dispatches,
   via an injected `Dispatcher` carrying serializable args only (`engagement_id`,
   `tenant_id`, `agent`). Live applicators are NOT Celery-serializable; the applicator
   factory is therefore called in `run_agent_task` (the worker), the single §3c call-site.
6. **Shared, safe execution** (`execute_agent`): both `run_engagement_task` (Alpha) and
   `run_agent_task` (Beta/Omega) route through one helper that does, in order — tenant
   ownership, auth re-check at execution (TOCTOU), graph replay from events (never a fresh
   empty graph), run under timeout, **status from the REAL agent outcome** (never hardcoded
   COMPLETE — anti-Lyndon #3), failure event, then `emit_handoff_and_advance` (persist
   handoff BEFORE enqueue; never swallow a dispatch failure).

#### Why (non-negotiables it encodes)

- Auth gate single + non-bypassable (§5) — re-asserted at execution, not just dispatch.
- Event-sourced state (§8o-1) — handoffs are events; the graph is a replay projection.
- No agent-to-agent (§12.13) — Conductor is the only dispatcher.
- No false-success (#3) — status comes from the verified outcome; WAF/empty/exception ≠ done.

#### Test contract (shipped green on Oracle ARM64)

```
tests/phase_3/test_conductor_advance.py  — decide_advance: dispatch/park/backward/emergency/
   non-complete/idempotent/halt/omega; advance_engagement dispatch + park + idempotency.
tests/phase_3/test_execute_agent.py      — false-success (FAILED→FAILED), auth re-check
   (blocked→not run), graph replay (Beta sees Alpha CREDENTIAL), tenant ownership, body
   idempotency on retry.
tests/phase_3/test_emit_handoff_and_advance.py — dispatch failure not swallowed; handoff
   persisted before advance.
```

#### Integration point

`Conductor → run_engagement_task (Alpha) → HANDOFF_READY → advance_engagement_task →
advance_engagement → (dispatch) run_agent_task(Beta) → factory builds applicators →
CredReuseTool → HANDOFF_READY(next=OMEGA) → advance → run_agent_task(Omega/ROASTER) →
CHAIN_COMPLETE`. `chain_runner.py` is demoted to a dev/live-fire harness — NOT a second
production orchestrator (#6).

#### Follow-ups (tracked, not blockers)

- `run_engagement_task` (Alpha) fully unified onto `execute_agent` — its gates must MATCH,
  no second gate semantics (#6/#7).
- `CHAIN_COMPLETE` idempotency on the OMEGA terminal (advance re-emits on re-run; minor).
