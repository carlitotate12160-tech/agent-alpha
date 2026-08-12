> CANONICAL SOURCE: architecture decisions (locked). History → ADR_HISTORY.md; summary → ADR_SUMMARY.md (derived).

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

### Related/Supplemental ADRs

- **Bounded-Autonomy Stall Semantics** — `docs/adr_bounded_autonomy_stall_semantics.md`.
  Defines how `NO_PROGRESS` is interpreted: it is suppressed while the frontier still has un-probed work, so a noisy discovery surface (e.g. real crt.sh returning many dead sibling subdomains) does not starve a reachable target that merely sorts later in the queue. Hard ceilings still bound the loop.

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

### Reference #N — Strix (usestrix/strix): active-first open-source pentest agent

**Date:** 2026-07-20. **Source:** field scan (~36K★, GPT-5 / Claude Sonnet 4.5 backed).

What it is: autonomous AI pentest agents, ACTIVE-first ("run your code, hack it";
dev/CI/PR-scan positioning). Toolkit: HTTP Interception Proxy, Browser Exploitation,
Shell/Command Execution, Custom Exploit Runtime, Recon/OSINT. Graph-of-agents,
parallel. Ships a reproducible PoC per finding ("won't report until exploited").

CRIB (later, Phase-C active vuln classes + Gamma):
  - HTTP Interception Proxy   → G12 (traffic manipulation; IDOR / business-logic)
  - Browser Exploitation      → G10 (stateful/browser tool; IDOR / auth-flow)
  - Custom Exploit Runtime + Shell → G9 / Gamma ANCHOR (exploitation primitive)
  All land BEHIND our gates (OFFENSIVE_APPROVED + blast-radius; payloads = DeepSeek lane).
  Strix has NO such gating — do not copy its ungated execution model.

DO NOT CRIB:
  - Targeting philosophy. Strix = active-first. Ours = passive-first (R2) + NodeZero HVT.
    For LEGAL red-team (SEA/Indonesia), passive-first + minimal-RoE is the edge.
  - Governance. Strix = ungated dev tool. Ours = event-sourced + auth-gated +
    signed consent (§12.36) + blast-radius + auditable.

NOT a differentiator: "prove exploitability via PoC" — Strix shares it (both
NodeZero-aligned). Do not claim it as moat vs Strix.

Moat delta (what actually separates us): governance + cross-engagement memory
(GAP-003) + regional templates. NOT toolkit breadth.

Competitive signal: pentest-agent toolkits are commoditizing (open-source, 36K★,
LLM-backed). Reinforces §12.22 "wrap commodity, build the moat" — do NOT compete
on toolkit breadth; win on governance + memory + passive-first + regional.

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
    └── bypass/     (cf_curl_cffi, cf_camoufox/Turnstile [PLANNED], waf_tamper)
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

Support 2+ LLM (DeepSeek V4 Pro + Xiaomi). Selected mode: parallel consensus. (§12.23: consensus tier deferred to Gamma/Phase 4)

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
PLAN     → choose next action + alternative (critical-decision consensus DEFERRED to Gamma/Phase 4 — see §12.23)
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
- **Consensus trace:** during critical decision (§8d), each LLM vote + reason recorded in scratchpad → supports audit & tie-break by graph facts. (§12.23: consensus tier deferred to Gamma/Phase 4)
- **Feed to report:** monologue/scratchpad becomes material for to_narrative() (§6) — story of "how we thought & got in", not just finding list.
- **Implementation (Phase 2, 2026-06-19 — amends framing):** the monologue is **loop-driven** — one `ThoughtFrame` emitted per cognitive-loop phase (OBSERVE/ORIENT/ACT/PERSIST), NOT `reasoning_content`-only. Rationale: under Opsi-B playbook-first the RULE tier makes zero LLM calls, so `reasoning_content` is empty on the headline path. Reasoning is sourced per tier — **RULE → playbook `rationale`**, **SINGLE_LLM → DeepSeek `reasoning_content`** (captured in `CompletionResult.reasoning`). The monologue is a **USER channel via an injected `MonologueSink`**, strictly separate from A2A (A2A stays structured JSON). Emission core implemented + tested (`agent_alpha/agents/monologue.py`, `tests/phase_2/test_monologue.py`); real-time **user-delivery transport (Redis pub/sub → WebSocket) is deferred to Phase 3**, since a connected user requires the Celery non-blocking execution path built there.

### 8k. LLM Model Strategy — Role Split & Policy (Opus/Claude vs DeepSeek)

Extending parallel-consensus (§8d) with policy-based + data sensitivity separation. (§12.23: consensus tier deferred to Gamma/Phase 4)

- Reasoning / planning / attack-graph analysis / report narrative → strong reasoning model (e.g., Claude Opus/Sonnet). Excels here, content not raw weaponization.
- Payload / raw exploit generation → less-restricted model (e.g., DeepSeek) to avoid refusal/usage-policy block.
- **Refusal risk as design constraint:** don't depend on offensive generation from model that can refuse mid-engagement.
- **Redaction layer** — sensitive client data (creds, PII, harvested data) redacted/anonymized before sending to LLM cloud (NDA/data sovereignty compliance); self-hosted option for most sensitive data.
- **Budget cap per engagement** — token cost limited (especially Opus) + alert when approaching limit (related to stop conditions §8j).
- **Provider abstraction** — all models behind single interface; role-based routing + consensus + failover managed by LLM Orchestration layer. (§12.23: consensus tier deferred to Gamma/Phase 4)

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

Initial access (ACTIVE_APPROVED), credential spray, chat-while-task-runs (§8a), multi-tenant queue, LLM Orchestration parallel consensus (§12.23: Gamma/P4, not Phase 3) + role split (Claude reasoning / DeepSeek payload) + redaction + budget cap (§8d, §8k), prompt-injection defense (§8l), loop/budget guardrail + checkpoint/resume (§8m), time-window & OPSEC profile (§8n).

### Phase 2.5 — REACH (Autonomous Surface Expansion)

**Status:** ACCEPTED (Natanael + Opus 4.8, 2026-07-10)
**Amends:** `docs/ADR.md` §9 Roadmap Phases — inserts **Phase 2.5** between Phase 2
and Phase 4. Governs the retired `docs/OPERATIONAL_REFERENCE.md` "Priority 1 (Phase 2 Completion)" snapshot (now at `docs/archive/OPERATIONAL_REFERENCE_v3_PR147.md` — frozen, not a living doc).
**Verified against:** repo `a9dcab7` (main).

> **Legal & Authorization Notice.** All REACH behavior runs ONLY after the Conductor
> authorization gate (RECON_ONLY minimum) and inside SOW scope. Surface expansion is
> scope-bounded by Policy-as-Code (RoE); out-of-scope hosts are never enqueued.

#### 1. Context — why this phase exists

Phase 2 was sealed as the *"smallest demoable loop: recon → graph → report"* — a
deliberate single-URL MVP. The autonomous **surface-expansion** capability
(seed → grow attack surface → pivot → re-discover) was never given an explicit phase
home: it is scattered across §8j (cognitive loop), §8o-2 (world model), the ops-doc
"Phase 2 Completion", and Phase 5 (pivot). An orphaned capability with no owning phase
is exactly how a silent foundation gap forms (the Lyndon pattern: everything on paper,
nobody owns the wiring).

**Verified gap (code trace @ `a9dcab7`):**
- `scout.py:112` seeds `_work_queue = [target_url]`; **no code anywhere calls
  `_work_queue.append/extend`** — the exploration frontier never grows.
- `constants.py:146` `ALPHA_RECON_NO_PROGRESS_ITERS = 1` — recon ends after one idle
  cycle when the seed drains.
- **No WAF/CF/403/challenge branch** exists in `agents/` or `tools/` — a blocked root
  dead-ends instead of pivoting.
- Recon breadth (subdomain / port / dir / reverse-IP / JS) = NOT IMPLEMENTED
  (per the retired `OPERATIONAL_REFERENCE.md` snapshot, now at
  `docs/archive/OPERATIONAL_REFERENCE_v3_PR147.md`).

Consequence: every field-proven chain (Odoo/WP/db) works **only because the live_fire
runner hand-feeds the exact vulnerable entry_point**. Given a real CF-fronted root
domain, the product dead-ends. The charter success bar ("find what a scanner missed,
*autonomously*") is currently met only when a human supplies the target.

#### 2. Reference model — NodeZero (loop, not breadth)

NodeZero (Horizon3.ai) is a seed-driven autonomous expansion engine:
discover/enumerate → chain-without-script → pivot → re-enumerate, over a knowledge
graph with a cross-run learning loop. Agent-Alpha's ADR already describes this same
loop-shape (§8j + AttackGraph + IntelligenceBase). Phase 2.5 realizes the **inner
(recon) loop** of it.

**Governing principle — "loop like NodeZero, moat unlike NodeZero":**
Adopt the *expansion loop shape*. Do NOT chase NodeZero's enumeration/CVE breadth —
that is unwinnable against a funded incumbent and regresses to Lyndon #4 (generic
scanner). Agent-Alpha's moat stays: context-aware exploit composition, regional
(Indonesia/SE-Asia) templates, proof-based payable narrative, cross-engagement memory
(§12.22). The loop is the legs that deliver targets to the moat; the moat is the punch.

#### 3. Decision

1. Insert **Phase 2.5 — REACH** into §9, between Phase 2 and Phase 4.
2. **FREEZE all Phase-4 breadth** (new STRIKE vectors, Gamma prep beyond what is sealed)
   until Phase 2.5 **and** its Layer-V seal pass. One layer open at a time.
3. Build the **inner loop first** (Alpha expansion). The **cross-agent loop**
   (pivot → re-discover across hosts) remains Phase 5 and must NOT start before 2.5 seals.

**Meta-rule (the anti-Lyndon seal definition — applies to ALL phases henceforth):**

> A capability is **"done"** only when proven on a **real target** through the **full
> live path** (Conductor → agent → AttackGraph → Omega), fed **only a root domain /
> in-scope seed**. A field-prove via a `live_fire/*` script that hand-feeds the
> entry_point counts as a **unit test**, NOT a phase seal.

#### 4. Sub-layers, exit criteria & differential test contracts

Each sub-layer is RED-first (test contract written and failing before implementation),
sealed on Oracle ARM64 only, with zero regression to prior phases.

**R1 — Frontier expansion wiring**
- Recon handlers return in-scope URLs discovered on the page; `scout.step` enqueues them
  into `_work_queue` (dedup against `_probed`). Raise `ALPHA_RECON_NO_PROGRESS_ITERS`
  1 → 3 (single source of truth in `constants.py`, anti-#7).
- Scope guard: only Policy-as-Code in-scope hosts are enqueued (RoE); out-of-scope
  links are dropped and audited.
- **Exit / differential test:** seed page with N in-scope links → N+1 probes and graph
  grows; page with 0 links → drains as today; an out-of-scope link → NOT enqueued.
  A finding on iteration k must be able to add frontier for iteration k+1.

**R2 — Passive surface discovery (WRAP)**
- New recon Tool(s) conforming to the Tool protocol, ranked by ToolRegistry, gated
  RECON_ONLY: crt.sh + subfinder(passive) + reverse-IP → returns subdomains/hosts.
- Discovered hosts scope-filtered, then enqueued to the frontier (reuses R1).
- **Exit / test:** given an in-scope root with a known-subdomain fixture → subdomains
  enqueued and probed; out-of-scope subdomains filtered; zero active packets to target
  (passive sources only) — no RoE/rate-limit exposure.

**R3 — Obstacle-aware re-plan (WAF/CF pivot)**
- OBSERVE classifies each probe outcome into an explicit set:
  `{ok, empty, transport_fail, BLOCKED(waf|cf|403|challenge)}`.
- On BLOCKED: emit a distinct event and ORIENT selects a **PIVOT** action (probe a
  discovered alternate host / origin-IP candidate from the frontier) instead of
  treating the block as a non-analyzable dead-end.
- **Exit / differential test:** CF-blocked root **with** an alternate host in frontier →
  agent probes the alternate (pivot); `stop_reason ≠ NO_PROGRESS` at iteration 1.
  Clean root → no pivot path taken. Blocked with **no** alternatives → honest BLOCKED
  result surfaced (NOT silent success, anti-#3).

**R4 — Active recon (optional, deferrable within 2.5)**
- nmap top-30 + directory enum, behind scope + the sealed RateLimiter. Only after
  R1–R3. May slip to Phase 4 without blocking the Layer-V seal.

**Layer V — Validate the moat through REACH (the Phase 2.5 SEAL)**
- Re-run **one** existing chain (Odoo or WP) fed **only the root domain**, over the full
  live path, on a self-owned lab that models a multi-host, CF-fronted client.
- **Exit (this is the real charter success bar):** `CHAIN PROVEN: True` starting from a
  root domain with **no hand-fed entry_point**; true-negative on the hardened host.
  Until Layer V passes, breadth stays frozen.

#### 5. Anti-Lyndon mapping

- **#1 feature-before-foundation:** freezing breadth until REACH+V seals is the whole
  point — no more depth on a foundation that can't reach targets.
- **#2 dead code:** every sub-layer wired + differential-tested on the live path.
- **#3 false success:** R3 blocked-with-no-alternatives returns honest BLOCKED; Layer V
  requires a real root-only proof.
- **#11 hardcoded sequence:** each sub-layer ships a differential test (behavior changes
  with graph state) — frontier growth and pivot are state-driven, never a static list.

#### 6. Integration points

- **Calls into:** `scout.step` (frontier), `orchestrator.decide` (ORIENT branch for
  BLOCKED), ToolRegistry (R2 tools ranked), Policy-as-Code (scope gate), RateLimiter
  (R4). No change to Conductor auth gate, event store, or Omega.
- **Called by:** `run_recon` inner loop; downstream Beta/Omega unchanged — they simply
  receive a richer graph.
- **Does NOT touch:** authorization state machine, A2A contract, Gamma+ (still gated).

---

*This amendment wins over any prior session that reopens Phase-4 breadth before
Phase 2.5 + Layer V are sealed.*

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

**Already decided:** Multi-LLM = parallel consensus (DeepSeek V4 Pro + Xiaomi) for critical decisions, single-LLM for light tasks (§8d). SUPERSEDED by §12.23 — consensus tier + MiMoProvider move to Gamma (Phase 4); Phase 3 runs single reasoning provider. No consensus on any Phase-3 live path.

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
| `CONSENSUS_LLM` | Critical: exploit-chain, blast-radius, "Try Harder", actions changing auth tier/blast radius | 2 models (§8d) (§12.23: deferred to Gamma/Phase 4) |

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
- **Browser (Camoufox)** → a **shared capability** in the deterministic layer [PLANNED —
  not yet implemented]. Used by BOTH Alpha (JS/SPA recon, client-rendered targets) AND Beta
  (anti-detect spray + Cloudflare/Turnstile bypass). Built ONCE, **leased through the
  Conductor authorization gate** — never injected directly agent-to-agent (consistent with
  the non-negotiable single auth gate, §1). Camoufox (anti-fingerprint Firefox fork)
  replaces Playwright — engine-level fingerprint evasion (canvas, WebGL, font, screen) vs
  JS-layer patches; harder for CF/Turnstile to detect.
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

### 12.21 External Benchmark Gate — Proof of value-add before GA — PROPOSED

**Status:** PROPOSED → LOCK on merge. Adds a NEW exit gate; does not change any existing
phase. **Relates to:** §12.2 (differential test), §12.3 (real-target gate), §8m
(reliability/validation), §8o-6 (adaptive learning).

#### Context

Agent-Alpha's success bar is internal ("find what a scanner missed, prove it, produce a
payable report"), proven once on lab container 9201. Competitors publish **external,
comparable numbers**: XBOW (#1 HackerOne US), CAI (HTB CTFs, bug bounties). We have zero
external numbers → "value-add vs competitors" is currently an architectural claim, not a
measured fact. This gate makes the claim falsifiable.

#### Flaw considered first (why a naive benchmark gate is a trap)

- **CTF benchmarks are saturating and flatter.** Frontier models hit ~93% on Cybench;
  InterCode-CTF is effectively solved. A high Cybench score would prove we're *not behind*,
  not that we're *differentiated*. CTFs lack the noise, state, and validation gap of real
  engagements.
- **Benchmark-chasing risks Lyndon #1/#5** — optimizing for a leaderboard instead of the
  payable-report bar. The gate must therefore be *secondary* to the internal bar, and must
  weight **autonomy + real-world** benchmarks above saturated CTF.
- The literature is explicit that fully-autonomous pentest "remains distant" and all
  serious players keep a human in the loop. So the gate measures **autonomous capability
  as a yardstick**, not as a claim that the product runs unsupervised.

#### Decision

Adopt a **three-tier external benchmark gate**, run on **Oracle ARM64** (anti-#9), as part
of **Phase 6 / pre-GA** exit criteria. Targets are CALIBRATION targets — set the floor from
a first baseline run, then ratchet. Do not invent a pass number before the baseline.

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
  Gate: report solved-rate + a VALIDATION metric (fraction of claimed successes that are
        VERIFIED true, i.e. no false-success #3). Target: false-success rate < internal
        Phase-2 bar (<20% FP) on the benchmark too.

Tier C — COMPARABILITY (secondary, sanity floor):
  Cybench (40 pro CTF) — for an apples-to-apples public number only.
  Gate: report the score; NOT a blocker (saturated). Used to detect regressions.
```

##### The internal bar still dominates

A passing external score does **not** by itself clear Phase 6. The payable-report bar
(§success condition) remains the primary gate; benchmarks are the *external corroboration*.
If they ever conflict, the payable-report bar wins.

#### Test contract

```
T1  Benchmark harness runs Agent-Alpha through the REAL autonomous live path (Conductor
    auto-advance + Celery), NOT chain_runner. (If it can only run via chain_runner, the
    autonomy gap from §autonomy-audit is unresolved — gate cannot be claimed.)
T2  Each run emits: solved-rate, VERIFIED-success rate (false-success guard), wall-clock,
    LLM cost. All four logged to the event store (auditable, reproducible).
T3  Scores recorded per ADR version + git SHA → ratchet enforced (a release may not ship a
    LOWER Tier-A/B score than the previous release without a written waiver).
T4  Baseline run completed and its numbers written back into THIS ADR as the initial floor
    before the gate is declared active.
```

#### Integration point

The benchmark harness is an **external driver** that creates an engagement via the normal
Conductor API (SOW/auth gated like any engagement — benchmarks run as authorized
self-owned targets), then reads results from the event store + Omega report. It adds **no**
new code path inside the agents — it exercises the existing autonomous path. This is also a
forcing function: the gate is unrunnable until the autonomy wiring (§autonomy-audit, Tier
2) exists, so it pulls that work forward honestly.

#### Sequencing

- **Now:** record the gate (this ADR). Do NOT build the harness yet (Phase 6 — building it
  before the autonomous path exists = dead code #2).
- **Trigger to build the harness:** the autonomy grep/trace audit is green (Conductor
  auto-advance + bounded Beta loop + fallback) AND the cred-reuse moat is on the Celery
  path. Until then the gate is a recorded target, not active work.

**Confidence ~75%** — benchmark landscape moves fast; specific published baselines
(AutoPenBench ~21% autonomous, Cybench ~93% frontier) should be re-confirmed at baseline
time, not trusted from this doc.

### 12.22 Tool strategy: wrap commodity, build the moat, gate the dangerous — PROPOSED

**Status:** PROPOSED → LOCK on merge. Extends §12.16 (tool layer) and the §5–§7 differentiators.

Decides what Agent-Alpha builds internally vs wraps, the safety-critical revisions to
the kill-chain tool catalog (formerly in `OPERATIONAL_REFERENCE.md`, now archived at
`docs/archive/OPERATIONAL_REFERENCE_v3_PR147.md`), and Cloudflare/WAF handling.

#### Context

The retired `OPERATIONAL_REFERENCE.md` snapshot (now at
`docs/archive/OPERATIONAL_REFERENCE_v3_PR147.md`) lists ~40 tools across the kill chain. A review found: most are
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

These tools (cataloged in the retired `OPERATIONAL_REFERENCE.md` snapshot, now at
`docs/archive/OPERATIONAL_REFERENCE_v3_PR147.md`) are revised to default-DENY without explicit, per-action
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
     Camoufox (Turnstile) — commodity, gated to in-scope targets only.
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
(competitor research + the retired `OPERATIONAL_REFERENCE.md` review, snapshot at
`docs/archive/OPERATIONAL_REFERENCE_v3_PR147.md`). Residual: the exact scope-gate
API on #61 (reuse `is_in_scope` / `is_db_endpoint_in_scope` patterns) and where the
TransportResilience capability plugs into the HttpClient — confirm on #61 before building.

### 12.23 Consensus-LLM tier — deferral from Phase 3 to Phase 4 (Gamma) — LOCKED

**Status:** LOCKED (2026-07-02). Appended after §12.22. Supersedes the "multi-LLM
consensus" item in the canonical **Phase 3 exit criteria** and aligns the ADR with
`docs/PHASE_3_TEST_CONTRACT.md`. The doc-integrity sweep this decision requires
(repoint §12.20→§12.23 citations; supersede the stale consensus prose at §8-era lines)
is COMPLETE.

#### Context

The old Phase-3 exit criteria listed four gates: Beta (STRIKE) + Celery non-blocking +
**multi-LLM consensus** + prompt-injection defense. But:

1. `PHASE_3_TEST_CONTRACT.md` already defers the `CONSENSUS_LLM` tier + `MiMoProvider`
   to Phase 4 ("do NOT build now = avoid dead code #2"). The ADR and the test contract
   therefore disagreed — a doc-integrity defect, not a settled decision.
2. Consensus (§8d) was designed for one class of decision: *exploit-chain selection,
   blast-radius assessment, "Try Harder", and any action that changes auth tier or blast
   radius* (§12.1 routing table, `CONSENSUS_LLM` row). **None of those occur in Phase 3.**
   Phase 3 = Beta/STRIKE: default-creds, credential spray, credential reuse — all
   `ACTIVE_APPROVED`-tier, bounded, verifiable, reversible. The irreversible
   high-blast-radius decisions land in **Gamma (Phase 4, `OFFENSIVE_APPROVED` +
   blast-radius gate).**
3. Building the consensus tier in Phase 3 would wire `MiMoProvider` onto a path that
   never triggers `CONSENSUS_LLM` = **dead code (Lyndon #2)** — the exact failure this
   project exists to avoid.

#### Flaw considered first (the real risk of deferring)

The objection: *"an autonomous agent making critical calls with a single LLM is less
safe."* Addressed explicitly, not buried:

- The only Phase-3 action that changes authorization tier is the **CREATED → … →
  OFFENSIVE_APPROVED** transition, which is **human-gated** (`enable_offensive` requires
  a human-uploaded SOW). Consensus is not the guard there — the **gate** is. Deferring
  consensus removes **zero** Phase-3 tier-change safety.
- Beta's autonomous decisions are bounded (Bounded Autonomy stop conditions), verified
  (no false-success, #3), and reversible. A wrong single-LLM PLAN in Phase 3 wastes
  budget; it does not cross an irreversible blast-radius line.

Therefore the deferral does **not** reduce Phase-3 safety. It moves consensus to where
its triggering decisions actually live.

#### Decision

1. **Remove "multi-LLM consensus" from Phase 3 exit criteria.** Phase 3 runs the single
   reasoning provider (§12.15 — DeepSeek-v4-pro reasoning PRIMARY) for ORIENT/PLAN.
2. **Move the `CONSENSUS_LLM` tier + `MiMoProvider` + parallel-consensus tie-break (§8d)
   into Phase 4 (Gamma) exit criteria**, where exploit-chain selection and blast-radius
   assessment occur under `OFFENSIVE_APPROVED`.
3. **Consensus has NO code representation today — verified on #61:** no `decide_tier`, no
   `CONSENSUS_LLM` enum, no `MiMoProvider` on any live path (grep-clean). The deferral is
   therefore **doc-only**. When Phase 4 builds Gamma it ADDS the consensus tier + its
   routing as greenfield work (no existing enum to preserve).

#### Revised Phase 3 exit criteria (the clean hard-stop)

```
Phase 3 is "done" only when ALL pass on Oracle ARM64 CI:
[ ] Beta (STRIKE) — default_creds + cred_reuse, verified non-empty findings (#3)
[ ] Celery non-blocking execution + tenant propagation through Celery
[ ] Real emergency revoker (≤5s) under Celery
[ ] Conductor fan-out interface (§12.13) + auto-advance on the Celery path
[ ] Prompt-injection defense (redaction + structured A2A)
[ ] Service-aware cred-reuse moat (DB path) wired on the Conductor/Celery path
    — NOT chain_runner single-process
[ ] NO consensus / MiMoProvider on any Phase-3 live path  ← deferred, asserted absent
```

(Struck from the prior list: "multi-LLM consensus".)

#### Phase 4 (Gamma) gains

```
[ ] CONSENSUS_LLM tier built: 2 providers in parallel, votes + reasons audited
[ ] MiMoProvider wired as the consensus second seat
[ ] Tie-break by graph facts; disagreement → human gate (§8d)
[ ] Consensus REQUIRED for: exploit-chain selection, blast-radius assessment,
    any action changing auth tier or blast radius
```

#### Test contract for this amendment

```
T1 doc-integrity: no Phase-3 exit-criteria checklist (ADR, skill, PROGRESS_TRACKER,
   PHASE_3_TEST_CONTRACT) still lists consensus as a Phase-3 gate.        [DONE — sweep]
T2 anti-dead-code guard: no live path imports/constructs MiMoProvider or runs a vote
   (grep-clean at #61). When Phase 4 adds consensus it must be reachable on a Gamma
   critical-decision path, else dead code.
T3 Phase-4 exit-criteria doc lists consensus as a Gamma gate (the deferral has a
   destination, not a void).
```

#### Integration point

At #61 the orchestrator has NO tier-routing enum and consensus has no representation
(consensus is grep-clean on all live paths). There is no Phase-3 interface to preserve —
the "consensus-ready interface" is a **Phase-4 greenfield design task**, not a Phase-3
invariant. Phase 4 introduces both the consensus tier and the routing that reaches it, on
Gamma's exploit-chain / blast-radius decisions.

**Confidence ~95%** — verified against #61: consensus is grep-clean on all live paths.
The deferral is doc-only; the residual is the sweep landing on every checklist (done).

### 12.25 Well-known-path recon baseline — LOCKED

`run_recon` seeds a fixed, target-INDEPENDENT set of sensitive paths
(`constants.WELL_KNOWN_LEAK_PATHS` — `/.git/config`, later `/.env` + backup files)
into the frontier for every in-scope host — the seed of the path_probe catalog.

Universal by design (standard recon hygiene); NOT a per-target static attack
sequence (Lyndon #11 governs the ATTACK chain, not recon breadth). Stealth
control, if ever needed, is a first-class `recon_policy` toggle (default on),
never per-target hand-feeding.

**Confidence ~85%** — two assumptions to confirm at apply time:
(a) call order = `[seed, /.git/config]` (seed popped first, well-known appended
after in `run_recon`); if impl appends before seed, reverse `expected`.
(b) monologue fixture 404s `/.git/config` so cycle 2 is OBSERVE-only; if fixture
raises, that is a fixture issue, not an invariant.

---

### 12.26 Recon vector strategy: rubric, class taxonomy, and the recon/Gamma boundary — LOCKED

**Status:** LOCKED (2026-07-12). **Relates to:** §12.22 (wrap/build/gate), §12.25
(well-known-path baseline), §1 (auth gate), Lyndon #4 (generic-scanner).

**Problem.** Recurring pressure to "add more playbooks/vectors" (audit lists of
Swagger, GraphQL, Drupal, Joomla, Rails, Tomcat, Jenkins, K8s, Redis, …). Taken
literally this rebuilds a generic scanner (Lyndon #4) — an unwinnable race against
nuclei's template count — and, worse, blurs recon with exploitation.

**Decision 1 — vector-inclusion rubric.** A new payable vector is added ONLY if it
passes all three: (1) a real/paying client stack needs it (data-driven, never for
completeness — speculative stacks = data-starvation); (2) it CHAINS to a payable
outcome (yields a reusable credential → access), not a dead-end fingerprint;
(3) it leverages the moat (graph / cross-engagement intelligence / proof). Fail any
→ WRAP a commodity or drop it. The current payable-content set (git_exposure,
backup_file, actuator, wp_config, laravel_debug, odoo_dbmanager, js_secret) already
covers the known client base (WP / Laravel / Odoo / Spring); it is ~saturated.

**Decision 2 — four-class taxonomy (class determines code path AND auth gate).**
Every candidate maps to exactly one class; do NOT lump them into one "playbook" list:
- **Payable content-probe** (leak → creds): fits the `path_probe` catalog (DIRECT/DUMP).
  e.g. live `/.env`, `web.config`. RECON_ONLY.
- **Surface-discovery** (frontier/graph feeder, NOT a finding): expands autonomous
  reach like crt.sh in Layer V. e.g. Swagger/OpenAPI, GraphQL introspection,
  `.DS_Store`, directory listing, exposed admin panels. Build as ONE data-driven
  surface catalog, separate from payable path_probe. RECON_ONLY.
- **Exploitation** (STOP-gated, Gamma): DETECTING an exposed panel is recon; ACTING on
  it is exploitation. e.g. Tomcat Manager WAR deploy, Jenkins `/script` RCE, S3 write,
  etcd. Requires OFFENSIVE_APPROVED + SOW + blast radius. NEVER on the recon path.
- **Non-HTTP service** (not a playbook): Redis/Mongo/Elasticsearch/CouchDB no-auth =
  a `db_service_probe` (TCP handshake) extension, not an HTTP-observation playbook.

**Decision 3 — header-matching is an ENGINE capability, not a vector.** `observation` 
already carries `headers` (scout builds `{"body", "headers"}`) but `PlaybookRule.matches` 
reads only `body`. Adding `header_contains` / `header_regex` indicators (backward-
compatible; body-only rules unchanged) unblocks a whole class at once (Tomcat realm,
`WWW-Authenticate` Basic/NTLM, `Server:` fingerprint, S3 XML, CORS). This is the
highest-leverage recon addition and is prioritised above any individual template.

**Non-negotiable reaffirmed.** The recon/Gamma boundary in Decision 2 is a hard auth-gate
rule: an "RCE"/write capability must never be built into a RECON_ONLY vector to make a
demo look impressive. Detection is recon; execution is Gamma-gated.

**Confidence ~80%** — strategic call; the header-matcher claim is code-verified
(headers present, ignored). Client-base assumption per cross-engagement notes; if a new
market segment appears (e.g. API-heavy fintech), the rubric — not preference — governs.

---

### 12.27 REACH R3 exit-gate hardening: body/header-aware obstacle classification — LOCKED

**Status:** LOCKED (2026-07-14). **Relates to:** §12.22 (TransportResilience WAF/CF discriminator), §12.2/§12.3 (differential + real-target FP<20% gate), §12 REACH amendment R3 (obstacle-aware re-plan), Lyndon #3 (false success) / #5 (scope creep).

**Problem.** Phase-4 breadth was treated as "progress" on lab-green alone, but real targets expose the gap. bernofarm.com served a Cloudflare JS challenge (HTTP 200, ~11.8KB "One moment, please") on 55+ URLs — all classified OK → 55 LLM calls, 0 findings (Bug #18). `classify_response()` is status-only (Bug #19): it cannot see a 200-status challenge/interstitial body. dnr.id exploded into 64 mod_autoindex sort-variant URLs of identical content (Bug #17/#20). Greedy page-wide rules select `default_creds`/`odoo` on nav-bar "Login" and even on 404 pages (Bug #2/#14). Each is a distinct false-success / token-burn vector a clean lab never reproduces.

**Decision 1 — CHALLENGE verdict, body+header aware.** `classify_response()` gains a `CHALLENGE` verdict for CDN/WAF interstitials (Cloudflare "Just a moment"/"cf-browser-verification"/challenge-platform, Sucuri, Imperva/Incapsula, Akamai reference-ID) detected from body AND response headers (`Server: cloudflare`, `CF-Ray`). Contract widens to accept headers (backward compatible; status-only paths unchanged). `CHALLENGE`, like `UNSUPPORTED_MEDIA_TYPE`, skips BOTH rule and LLM tiers, no frontier expansion, no asset-node persist — but still records a WAF/CF-blocked audit event.

**Decision 2 — identical-body dedup.** Scout hashes each OK body (SHA-256) per engagement; a repeat hash short-circuits before any tier (skip LLM/RULE, still audit-persist). Kills "same CDN page analyzed N times" (Bug #20); with mod_autoindex sort-param stripping (Bug #17), the sort-variant explosion. **Note:** event-source body hash (per-run idempotency state) is deferred to step-resume (GAP-002/§12.29) and must then cover ALL per-run idempotency state uniformly.

**Decision 3 — greedy-rule false-positive guard.** Page-wide markers ("Login"/"Sign in"/Odoo asset links) may no longer, alone, select a payable probe. A rule fires only on a specific surface (login form + `type=password`, or URL/status precondition) and NEVER on 404 (Bug #2/#14).

**Decision 4 — exit gate = fixtures, not lab-green.** A capability is REACH-sealed / Phase-4-eligible only when these verdicts are proven on RECORDED real-condition fixtures (§12.28) with `sum(cost_usd)==0` on junk bodies. Lab-green alone never advances a phase (anti-Lyndon #3/#5). A live real-target run is a manual, authorized-only smoke check — NEVER a hard CI gate, because CF challenge is intermittent.

**Confidence ~85%** — bugs field-proven on bernofarm.com/dnr.id/ibudanbalita.com; classifier header-availability is code-verified (headers already in `observation`). Detection patterns are heuristic and versioned in `RECON_CONDITION_CATALOG.md`, not hardcoded lore.

---

### 12.28 Record/replay condition harness: real conditions as regression fixtures — LOCKED

**Status:** LOCKED (2026-07-14). **Relates to:** §12.27 (exit-gate proof source), §12.3 (real-target gate), §8l (data redaction), `live_fire/lab_guard` (self-owned allowlist).

**Problem.** The lab does not represent the real internet (no CF challenge, 415, mod_autoindex, interstitials). Real-engagement logs (`*_output.txt`) are summarized ALPHA lines — some UTF-16 with null bytes — NOT raw bodies/headers, so they cannot be replayed. Heuristics for "what is not target content / when to skip the LLM" lived in human memory, not code.

**Decision 1 — capture reality, do not hand-author.** A transparent `RecordingHttpClient` wraps `HttpClientProtocol` and writes raw `status+headers+body` exchanges (JSON, per engagement, call-ordered to preserve CF intermittency) to `recordings/<id>.json`. `ReplayHttpClient` replays deterministically with zero network. Recorder is opt-in (env flag), default OFF → production/CI path byte-for-byte unchanged.

**Decision 2 — record raw, gitignore; curate archetypes manually.** Raw cassettes are NEVER committed (gitignored, local/Oracle only) — they may carry secrets/PII and no auto-scrub runs. CI regression fixtures are curated + scrubbed by hand into `tests/fixtures/cassettes/`. Capture only on `lab_guard`-allowlisted self-owned targets; client engagements stay on the Conductor+SOW path, never this harness.

**Decision 3 — catalog is the single source of truth.** `docs/RECON_CONDITION_CATALOG.md` maps each condition archetype → observed signature → expected verdict → fixture → guarding test. Every new real engagement adds a row: the taxonomy becomes code, not lore, and feeds the §12.27 exit gate.

**Confidence ~85%** — seam is code-verified (all `live_fire/*` + `recon_runner` build `HttpClient` and inject `http_client=`); `FakeHttpClient` already proves the replay shape.

---

### 12.29 Goal-directed cognition: Objective + Planner/World-Model + goal-completion — LOCKED

**Status:** LOCKED (2026-07-15). **Relates to:** §8o-2 (Planner/Executor + World Model + Simulation), §8j (cognitive loop), §7 ("Try Harder"), §12.0 (no hardcoded sequence), §12.24 (stall semantics), §12.27 (clean-graph prereq). **Absorbs GAP-004 + GAP-010.**

**Problem.** Today's loop is reactive 1-step: `run_cognitive_loop` calls `agent.step({})` with EMPTY context (`agents/base.py:112`), there is no Planner/World-Model (grep 0 results), and `BoundedAutonomy.should_stop()` only has 4 conditions (`MAX_ITERATIONS/TIME/COST/NO_PROGRESS`, `base.py:80-88`) — no `GOAL_COMPLETED`. As a result the agent is a breadth-first prober, unaware of its goal and unaware of when it is done; it runs until budget is exhausted even when the chain is already proven.

**Decision 1 — Objective as first-class entity.** `EngagementObjective` (target impact / HVT) becomes a runtime entity that flows into `step(context)` (context is no longer `{}`). Action and crawl priority are derived from the objective + graph, not FIFO (naturally closes Bug #11).

**Decision 2 — Planner/Executor split.** `planner.plan(world_model, objective)` produces a multi-step plan (HTN-style); the Executor runs it via the tool contract; automatic replanning occurs when a tool fails or beliefs change. "Try Harder" (§7) becomes part of the planner, not a patch.

**Decision 3 — World-Model / belief-state.** Hypotheses under uncertainty live in the scratchpad (GAP-002); only facts that pass VERIFY are promoted to the graph (§8j-2). The planner reads a CLEAN graph (§12.27 hard prerequisite).

**Decision 4 — Goal-completion stop.** Add `GOAL_COMPLETED` to `StopReason`. Example criteria: `CREDENTIAL —ENABLES→ ACCESS_LEVEL` with `verified=True`. Checked every step; multi-objective (after A completes → B if budget remains); per-objective budget (not only a global cap).

**Decision 5 — anti-Lyndon.** Plans MUST emerge from `f(graph, objective)` (§12.0), never a hardcoded step list; every planner capability ships with a differential test (behavior changes with graph state).

**Confidence ~80%** — seam `step(context)` + `StopReason` code-verified; full value requires GAP-002 (scratchpad) + §12.27 (clean graph) first.

---

### 12.30 Bounded curiosity-driven exploration — LOCKED

**Status:** LOCKED (2026-07-15). **Relates to:** §8j (OBSERVE/ORIENT), §8j-2 (promotion rule), §8l (untrusted data/prompt-injection), §12.26 (engine-capability > new vector), §12.27 (clean-graph prereq), §12.29 (planner upgrade path).

**Problem.** The loop is reactive-tool-ranked: ORIENT only selects from `RECON_TOOL_CATALOG` and the frontier only absorbs hrefs (`scout.py:296-313`). The agent cannot pursue anomalies like a human red-teamer would ("this header is odd / endpoint `/api/v2/internal` is interesting — dig in").

**Decision 1 — curiosity = deterministic signal, not improvisation.** ORIENT computes `curiosity_score(observation)` from structured signals over `{status, headers, body, url}` that ALREADY exist (header anomalies, non-standard endpoints, reflected input, version/tech disclosure). No LLM → reproducible.

**Decision 2 — STRICT effect when score is high.** (a) re-prioritize frontier; (b) exactly ONE hypothesis-probe using an EXISTING capability/tool (may escalate to `SINGLE_LLM` with structured-prompt); (c) hypothesis recorded to scratchpad. Curiosity NEVER synthesizes probes outside the catalog (anti-generative — target content is untrusted, generative = handing the steering wheel to the attacker).

**Decision 3 — security envelope (non-negotiable).** Stays in scope (`is_in_scope`), stays RECON_ONLY (does not trigger offensive), `MAX_CURIOSITY_PROBES` in `constants.py` counts against the same budget (anti-#7), target content treated as DATA (§8l), findings remain hypotheses in scratchpad until they pass VERIFY (§8j-2, anti graph-pollution).

**Decision 4 — upgrade path.** The curiosity signal is designed as input to the Planner (§12.29): once the planner exists, curiosity promotes "explore hypothesis X" to a sub-objective. Bounded now, goal-directed later — not a fork.

**Confidence ~80%** — envelope code-verified against the OBSERVE/ORIENT seam; value depends on §12.27 (clean graph) as a hard prerequisite.

---

### 12.31 Cross-tool verification tiers — LOCKED

**Status:** LOCKED (2026-07-15). **Relates to:** §8j (VERIFY), §8j-2 (promotion rule), GAP-003 (IntelligenceBase FP rate), Bug #2/#14 (greedy false-positive).

**Problem.** VERIFY exists but is **per-tool self-verification**: `strike.py:335-337` verifies from the same tool; `scout.py:330-331` template self-verify; `AttackNode.verified=True` is set by the discovering tool. `ToolResult.__post_init__` (`contracts.py:56-65`) is only a structural check. As a result, a single tool's false positive enters the graph as verified (Bug #2).

**Decision 1 — two verification tiers.** `AttackNode.verified` is tiered: `self_verified` (discovering tool) vs `cross_verified` (independent signal/tool confirms) before a finding is considered confirmed.

**Decision 2 — cross-validation gate.** High-FP-risk findings require cross-validation before `cross_verified`. Risk weight comes from IntelligenceBase (GAP-003): tools with high historical FP rates cannot auto-confirm.

**Decision 3 — transparent reporting.** Reports distinguish `self_verified` vs `cross_verified`; only `cross_verified` enters payable "proven" claims.

**Confidence ~75%** — seam `verified` + `ToolResult` code-verified; effectiveness depends on GAP-003 (FP rate) which requires EngagementMemory persist (Bug #7) first.

---

### 12.32 Post-access authenticated re-recon — LOCKED

**Status:** LOCKED (2026-07-15). **Relates to:** §8f (pivot-chain = post-exploit lateral, BUKAN auth re-recon), §8j, §12.26 (DETECT=recon, ACT=Gamma boundary), §12.29 (post-access sub-objective).

**Problem.** After Beta obtains `valid_credentials` there is no active-session re-discovery (`strike.py:335-337`); `http_client` has a `cookies` kwarg but no authenticated-crawl mode (grep 0 results). The most valuable vulnerabilities (OWASP A01: IDOR/Broken-Access-Control/priv-esc) are not covered.

**Decision 1 — AuthenticatedCrawlMode (RECON).** After access is obtained, re-crawl with an active session to discover new surfaces; diff unauth vs auth (new endpoints/menus/APIs). This remains **recon** (DETECT).

**Decision 2 — boundary auth-gate maintained.** DISCOVERING authenticated surfaces = recon. EXPLOITING (testing actual IDOR, horizontal/vertical priv-esc that changes state) = offensive, **Gamma-gated** (OFFENSIVE_APPROVED + SOW + blast-radius), never on the recon path (§12.26).

**Decision 3 — wiring.** Becomes a post-access sub-objective in the Planner (§12.29); "access obtained" is not a final goal (§12.29 Decision 4) → triggers the next re-recon objective.

**Confidence ~75%** — `cookies` primitive exists; full value requires §12.29 (planner) + a stable Beta chain.

---

### 12.33 Adaptive evasion — LOCKED

**Status:** LOCKED (2026-07-15). **Relates to:** R3 (obstacle-aware = pivot host, BUKAN adapt evasion), §12.22 Decision 2 (TransportResilience discriminator + lockout governor), §8n (OPSEC statis), GAP-005 (dynamic OPSEC), §12.29 (re-plan).

**Problem.** When `Verdict.BLOCKED` (403/429/503) the agent only records and continues the same way (`scout.py`); `opsec_profile` = static preset (`policy.yaml`); `cf_curl_cffi`/`cf_camoufox` are mentioned in §12.22 but 0 files exist. Every subsequent request with the same fingerprint = more noise → lockout/SIEM risk.

**Decision 1 — REFINED (2026-07-20, field-proven vs alpha-ai.web.id).** Evasion technique selection is CLASS-SCOPED (see `transport_resilience.py`), not universal:

  Viability matrix (IP reputation doctrine):
  - CHALLENGE + IP residential/clean  → browser_solve viable (9c)
  - CHALLENGE + IP datacenter         → browser_solve NOT viable (ASN reputation dominates)
                                         → origin-direct (if authorized) OR residential egress
  - FINGERPRINT (403/JA3, no challenge marker) → tls_impersonate (9b, curl_cffi)
  - RULE_DENY   (signature on .bak/.git/.env)  → NOT transport-evadable.
     Lever = origin-direct (scoping, if origin IP in SOW) OR alternate recon vector.

  Rationale: Cloudflare managed challenge for datacenter ASN is background JS
  fingerprinting with NO interactive widget (no Turnstile checkbox). Browser
  automation cannot solve it regardless of fingerprint quality — rejection is
  IP-reputation-driven, not fingerprint-driven. Verified empirically on Oracle
  ARM64 (datacenter ASN): geoip=True + humanize=True + headless="virtual" +
  Camoufox Firefox — CF still blocks with managed challenge (all selectors
  "not found", no iframe, title="Just a moment..."). Interactive Turnstile
  (checkbox widget) IS solvable — appears on residential/clean IPs where CF
  deems the IP borderline. Industry confirmation: Strix, RedAmon, NodeZero —
  none solve CF managed challenge from datacenter IP; they pivot to internal,
  origin-direct, or ACME path bypass.

Roadmap's "evasion = gating blocker upstream of Gamma" holds ONLY for CHALLENGE/FINGERPRINT.
Field evidence (alpha-ai.web.id, real CF): /wp-config.php.bak=RULE_DENY(ABORT);
/web, /web/login, /web/assets/*.js = CHALLENGE(browser_solve). 9b deferred — no
FINGERPRINT vector present in the A1 lab (feature-before-need = Lyndon #1).

A1 validation with challenge_solved=false from datacenter IP is EXPECTED (C7
fail-loud), not a bug. Service mechanism (detect, attempt, report honestly) is
proven. For real client engagements: client whitelists scanner IP OR provide
residential proxy OR set CF to lower protection during pentest window.

**Decision 1 — EXTENDED (2026-07-20, field-proven: datacenter egress).**
browser_solve is network-position-dependent: CHALLENGE is solvable from residential
egress, NOT from a datacenter IP (ASN reputation dominates; no fingerprint beats it —
field: Oracle IP → CF managed challenge, challenge_solved=False after 3 attempts).
Reach strategy (scoping, NOT evasion — see reach_strategy.py):
  RULE_DENY, or CHALLENGE-without-viable-solve → ORIGIN_DIRECT, gated by SIGNED
  authorized_origins (§12.36). Hitting a client origin bypasses their WAF → requires
  explicit front-loaded consent, event-sourced, fail-closed. Commercial CAPTCHA
  solvers are FORBIDDEN: sending a client target to a 3rd party breaches engagement
  confidentiality. Origin candidates come from discovery (CT/Shodan/DNS-history),
  never hand-fed; candidate ≠ authorization.

**Decision 2 — implement `cf_curl_cffi` template.** TLS impersonation for CF (fulfilling §12.22 reference). Stays RECON_ONLY + scope-bounded; **evasion ≠ exploitation**.

**Decision 3 — dynamic OPSEC & tracking.** Wire to PolicyEnforcer (GAP-005): "5x failed → switch before lockout" (subject to lockout governor §12.22 Decision 2). Technique effectiveness tracked in scratchpad (GAP-002); alternative re-planning via Planner (§12.29).

**Confidence ~70%** — seam classifier/OPSEC code-verified; requires GAP-005 (PolicyEnforcer wired) + new template.

**Decision 1 — EXTENDED (2026-07-21, origin-direct scoping refinement — SLICE C).**
Origin-direct is CLASS-SCOPED + datacenter-egress aware, wired into the A1
validation runner (`a1_validation_runner.py`). Invariants:

  - **Front-door probe (C7 gate) preserved**: the front-door MUST show
    CHALLENGE/blocked — origin-direct is never an alternative to a passing
    front door. `challenge_encountered` is computed from the front-door probe,
    not from the origin-direct result.
  - **`challenge_solved` stays False on origin-direct (anti-#3)**: origin-direct
    BYPASSES the challenge — it does NOT solve it. `"reached" ≠ "solved"`.
    The honest story for Omega: "CF challenge NOT solved; bypassed via exposed
    origin" — that IS the payable finding. Locked by test
    `test_origin_direct_challenge_solved_stays_false`.
  - **`choose_reach(mitigation, browser_solve_viable, authorized_origin)`**
    selects ORIGIN_DIRECT only when browser_solve is not viable (datacenter ASN,
    kwarg — not hardcoded) AND an authorized origin exists.
  - **`assert_origin_authorized(origin, host, profile)` is fail-closed (C8)**:
    raises `OriginNotAuthorizedError` if origin ∉ signed `authorized_origins`.
  - **Discovery candidate ≠ authorization (C9)**: a candidate from
    `OriginDiscovery.candidates()` is filtered against `authorized_origins`
    BEFORE reaching `choose_reach`. Unauthorized candidates yield `origin=None`
    → strategy stays DIRECT. Locked by `test_c9_unauthorized_candidate_no_origin_direct`.
  - **`origin_direct_fetch`**: httpx GET to `https://<origin_ip>/<path>` with
    `Host: <domain>` header. Origin IP is NEVER added to `_LAB_HOSTS`. No
    commercial CAPTCHA solver.
  - **Typed event**: `ORIGIN_DIRECT_ATTEMPT` (EventType) carries
    `{host, origin_ip, authorized, discovered_via}` — audit-sensitive because
    hitting a client origin bypasses their WAF.

  TLS verify posture doctrine:
  - **Lab slice**: `verify=False` — origin cert matches *domain*, not *IP*.
    Naive `verify=True` always fails. Self-owned target, zero risk.
  - **Production (client origin-direct)**: MUST use SNI-override domain-cert
    verification (connect to IP, verify cert against domain via SNI/hostname
    pin). httpx supports this via `httpx.Client(verify=ctx)` with a custom
    SSLContext that sets `check_hostname=True, server_hostname=<domain>`.
    Without this, origin-direct is a MITM gap (transparent proxy between agent
    and origin). This is a product-hardening item, not a Slice C blocker.

---

### 12.34 Within-engagement credential mutation — LOCKED

**Status:** LOCKED (2026-07-15). **Relates to:** §8c (`credential_patterns(industry)` = cross-engagement/Phase 6, BUKAN within-engagement), §12.22 Decision 2 (credential-spray lockout governor), GAP-002 (pattern tracking), GAP-003 (cross-engagement feed).

**Problem.** `cred_reuse.py` only does literal reuse; `default_creds.py` uses a static list; there is no mutation (grep 0 results). If `Company2025!` works on service A but B uses `Company2026!`, the agent will not find it — a human would automatically try pattern variants.

**Decision 1 — CredentialPatternMutator.** Analyze harvested credentials → extract patterns (company+year+suffix). Generate variants (increment year, swap separator, case, common suffix).

**Decision 2 — bounded & gated.** Trying variants = credential spray (ACTIVE action) → subject to auth tier (ACTIVE_APPROVED+) + lockout governor §12.22 (limit attempts, cooldown). Used only after literal reuse fails.

**Decision 3 — learning.** Successful patterns tracked in scratchpad (GAP-002) for reuse within the same engagement; proven patterns fed to IntelligenceBase (GAP-003) for cross-engagement (bridge to §8c).

**Confidence ~75%** — within-engagement is cheaper than §8c (does not require cross-engagement data); requires an active lockout governor to be safe.

---

### 12.35 pgvector image digest pinning — CVE-2025-68121 + Go stdlib CVEs

**Status:** ACCEPTED (2026-07-18). **Relates to:** infra/docker-compose.yml, .github/workflows/ci.yml, .github/workflows/security-audit.yml.

**Problem.** The `pgvector/pgvector:pg16` image contains 15 CVEs in its Go stdlib components (crypto/tls, crypto/x509, net/url, net/mail, mime, os-symlink). The CRITICAL CVE-2025-68121 (incorrect certificate validation in crypto/tls during session resumption) is exploitable when Config.Clone mutates ClientCAs/RootCAs between handshakes. Our app is Python-only, but the image's Go components are still present and could be reachable if the DB is exposed.

**Decision 1 — digest-pin to patched image.** Pin to `pgvector/pgvector:pg16-trixie@sha256:d0b40f6862437359b69f0ed790ce620d0226e220994c0e7349702d04dc1eb548` (ARM64) in both `infra/docker-compose.yml` and `.github/workflows/ci.yml`. The `pg16-trixie` variant is newer than `pg16` and includes Go 1.25.12+ (released 2026-07-07), which fixes CVE-2025-68121 and 14 HIGH-severity Go stdlib DoS CVEs.

**Decision 2 — compensating control for residual CVEs.** The following CVEs have NO upstream patch yet (marked "Fixed in —" in NVD):
- CVE-2026-32281 (crypto/x509)
- CVE-2026-32283 (net/url)
- CVE-2026-33814 (net/mail)
- CVE-2026-39820 (mime)
- CVE-2026-42499 (os-symlink)

**Compensating control:** The PostgreSQL database is NOT internet-exposed — only the Python application connects on the private network (127.0.0.1 binding in docker-compose.yml). The Go stdlib DoS surface is not reachable by an external attacker. This is documented as a residual risk with a tracking note to re-bump when upstream patches land.

**Decision 3 — CI gate tightening.** In `.github/workflows/security-audit.yml`, drop `|| true` from the pgvector Trivy scan so that FIXED CVEs (those with available patches) actually block CI. Keep `--ignore-unfixed` so the residual CVEs do not red the gate. This ensures future fixable CVEs are caught early.

**Decision 3b — .trivyignore for gosu Go stdlib CVEs (2026-07-21).** The pinned `pg16-trixie` image still bundles `gosu` built with Go 1.24.6. 16 CVEs in Go stdlib (1 CRITICAL + 15 HIGH) now have upstream fixes (Go 1.25.x / 1.26.x), but the pgvector maintainer has not rebuilt the image with a newer Go toolchain. Since `gosu` is a startup-only privilege-dropping helper (not a network service), and the DB is bound to 127.0.0.1, these CVEs are suppressed via `.trivyignore` with explicit CVE IDs. `--exit-code 1` remains active so any NEW fixable CVE (in PostgreSQL itself, not gosu) still blocks CI. Remove `.trivyignore` entries when pgvector publishes an image with Go >= 1.25.9.

**Decision 3c — Redis upgrade 7→8 (2026-07-21).** Upgraded from `redis:7-alpine` to `redis:8-alpine` (8.8.0) in `infra/docker-compose.yml`, `.github/workflows/ci.yml`, and `.github/workflows/security-audit.yml`. Redis 8 is backward compatible for all commands used by the application (GET, SET, HGETALL, HSET, DELETE). Not yet digest-pinned (intentional — allows Trivy to scan latest image).

**Decision 4 — verification requirement.** Verification MUST be done on Oracle ARM64 only (arch match). Commands:
```bash
docker pull pgvector/pgvector:pg16-trixie@sha256:d0b40f6862437359b69f0ed790ce620d0226e220994c0e7349702d04dc1eb548
trivy image --severity CRITICAL,HIGH pgvector/pgvector:pg16-trixie@sha256:d0b40f6862437359b69f0ed790ce620d0226e220994c0e7349702d04dc1eb548
make check  # verify test suite still green against pinned image
```

**Confidence ~90%** — digest pin is a minimal, targeted fix; compensating control is sound (DB not internet-exposed); verification on Oracle ARM64 is required before this is considered complete.

---

### 12.36 Front-loaded signed EngagementProfile — PROPOSED (lock on confirm)

**Status:** PROPOSED (2026-07-18). Renumber if §12.36 is taken.
**Relates to:** §12.20–22 (Policy-as-Code / PolicyEnforcer), auth state machine
(CREATED→RECON_ONLY→ACTIVE_APPROVED→OFFENSIVE_APPROVED), §1 (blast-radius gate),
GAP-005 (PolicyEnforcer production wiring), Lyndon #4 (security-first) / #6 (one canonical type)
/ #7 (single config source). **Non-negotiable preserved:** single auth gate in Conductor;
event-sourced append-only state; agents autonomous AFTER authorized.

**Problem.** Consent/authorization is fragmented: `policy.yaml` is GLOBAL/static, `Scope` is
per-engagement, and per-engagement OPSEC/evasion/technique opt-ins have no signed capture. The
product trend is toward many RUNTIME approval gates — bad UX AND legally weak (a mid-run "confirm"
is ambiguous: what exactly was authorized?). Consent should be ONE signed act BEFORE Run, and the
agent should then run autonomously within that envelope.

**Decision 1 — EngagementProfile is the signed consent artifact.** At engagement creation the
client selects, OVER THE EXISTING `policy.yaml` vocabulary, a per-engagement profile:
- scope (domains / ip_ranges / exclusions / db_endpoints) — the `Scope` already captured;
- opsec/stealth profile (quiet | normal | loud | announced | blend — already in `opsec_profiles`);
- CF/WAF evasion (yes/no → drives `resolve_opsec_profile`'s existing evasion gate);
- subdomain expansion (yes/no → gates passive_discovery/crt.sh);
- technique opt-ins (from `excluded_techniques.require_explicit_opt_in`, e.g. T1003/T1055);
- blast_threshold (Decision 4);
- service selection.
This IS the Rules of Engagement. It is attached to the engagement record (EXTENDS it — it does
NOT create a second Scope, anti-#6).

**Decision 2 — one signature, autonomous within the envelope.** Confirming the profile = the auth
state transition (→ACTIVE_APPROVED / OFFENSIVE_APPROVED) WITH the RoE attached. The agent then runs
autonomously inside the signed envelope with ZERO further human gates, except the single carve-out
(Decision 4). "Non-bypassable auth gate" means the agent cannot act OUTSIDE the envelope — it does
NOT mean repeated human clicks. This REDUCES gates; it does not add them.

**Decision 3 — signature = tamper-evident, event-sourced, immutable.** Confirm produces
`sha256(canonical_profile_json)` + principal/client identity + UTC timestamp, appended to the event
store (append-only audit = existing non-negotiable). The signed profile is IMMUTABLE post-sign; any
change is a NEW signed version + a NEW event that SUPERSEDES (never an in-place edit). A mutable DB
boolean is NOT acceptable consent. This is the "strong digital-sign proof".

**Decision 4 — the ONLY runtime human pause: blast-radius > signed threshold.**
- Severity scale (grounded, `graph.narrative`): `low | medium | high | critical`, driven by reaching
  high-value access (`root` / `domain_admin` / `db_root`).
- **Default threshold = "high"** (current `constants.BLAST_GATE_SEVERITY_THRESHOLD`): proceed
  autonomously for low/medium blast; PARK for human opt-in only when worst-case blast severity ≥ high
  (the agent is about to reach / has reached crown-jewel access). This is the sweet spot for
  "minimize gates" — routine offensive work is autonomous; only the genuinely high-impact moment (the
  one a client wants to sign off on) pauses.
- Client MAY set it in the signed profile: `medium` (more cautious) | `high` (default) |
  `critical` (pause only on catastrophic) | `off` (log-only, full autonomy).
- ELEVATING autonomy (`critical` / `off`) REQUIRES an explicit extra acknowledgment line captured in
  the signed profile ("I authorize the agent to reach {high-value access} without pausing"). Higher
  autonomy ⇒ stronger, explicitly-recorded consent.

**Decision 5 — hard floor the profile can NEVER sign away.**
- `excluded_techniques.always_forbidden` (T1485 Data Destruction, T1561 Disk Wipe, T1498/T1499 DoS)
  stay forbidden regardless of blast setting — the `off` toggle NEVER re-enables irreversible actions.
- Out-of-signed-scope target = hard DENY (not a pause, no interruption — the agent simply does not
  touch it). `assert_pivot_target` / cohost default-DENY stays.
- The auth-tier gate (OFFENSIVE_APPROVED + SOW + scope-verified) is unchanged. Profile autonomy is
  bounded BELOW by these; it can only grant WITHIN what the tier + SOW already permit.

**Decision 6 — fail-safe default.** No valid signed profile → engagement never reaches
OFFENSIVE_APPROVED → offensive agents cannot run (structural, via the auth gate). Within an authorized
engagement whose threshold is unset/unparseable → default to `high` (conservative), never `off`. A
missing PolicyEnforcer builds the default (gate ON, never silently off — existing `advance.py`
invariant).

**Decision 7 — anti-Lyndon.** EngagementProfile = ONE canonical type on the engagement record (no
duplicate Scope, #6). OPSEC / technique / scope / blast ALL resolve FROM this single signed source (no
second config path, #7). Nothing here relaxes the auth gate or the event-sourced non-negotiable.
Runtime gates go from "several" to "exactly one, client-calibrated" — this is a SIMPLIFICATION.

**Confidence ~85%.** Vocabulary + seams are code-verified and already present: `policy.yaml`
`opsec_profiles`, `PolicyEnforcer.resolve_opsec_profile` (evasion gate), `HttpClient(opsec=)`, `Scope`,
`blast_gate.assess_blast_gate` (threshold=high), append-only event store. This UNIFIES them behind one
signed profile — mostly wiring + one new canonical type, not a rewrite. Open: the profile schema field
set + signature/versioning mechanics (slice-2a onward) and the "explicit acknowledgment for elevated
autonomy" UX (product decision).

**Slice order (implementation):**
- 2a: EngagementProfile schema (selections over policy.yaml vocab) + capture at create_engagement +
  sha256+identity+timestamp signature event (immutable) — the signed-consent FOUNDATION.
- 2b: resolve OPSEC from the signed profile → HttpClient(opsec=) on the production recon path.
- 2c: resolve technique opt-ins + per-tool scope (defense-in-depth) from the profile.
- Blast threshold already wired (slice-1); 2a only makes it a PROFILE FIELD (default high preserved).

---

### 12.38 Origin-Scope by Ownership — PROPOSED

**Status:** PROPOSED (Natanael greenlit the model 2026-07-25).
**Lane:** Security-critical auth → Claude Opus (per model-routing table).
**Lyndon check:** touches `engagement_profile` + `domain_verification` + `authorization`
+ `agents/alpha/scout` (reach) + `recon/origin_discovery` = **>2 files → interface
redesign, NOT a patch (Step-5 rule).** Single canonical "origin authorization"
concept — no second copy (anti-#6). Token format + TTL single-source (anti-#7).

**Phase:** Phase-0/§12.36 auth foundation. Precedes every WAF-fronted engagement
(ibudanbalita/CloudFront, cimbniaga/Imperva). Does NOT precede the niagamas WP spine
(no CDN → no reach). Build order: **niagamas spine first, THIS second.**

---

#### Penjelasan sederhana (untuk klien / non-teknis)

Klien memberikan URL saja (contoh: `https://ibudanbalita.com`). Sistem tidak butuh
klien menyerahkan IP origin. Yang terjadi:

1. **Klien kasih URL** → sistem buat challenge token unik untuk engagement ini.
2. **Sistem tampilkan instruksi DNS-TXT** → klien tambah 1 record DNS di domain mereka
   (bukti mereka punya domain itu — sama seperti Google Search Console / Let's Encrypt).
3. **Klien confirm** → sistem cek DNS → cocok → domain terbukti milik klien.
4. **Sistem auto-discover origin IP** (via CT logs, DNS history, dll) — klien TIDAK perlu
   kasih IP.
5. **Sistem verify origin** → cek apakah IP itu benar-benar serve domain klien (cert SAN
   match) → kalau ya, origin-direct diizinkan.
6. **Agen menembak origin** → bypass WAF/CDN → temukan vulnerability.

Intinya: **klien cukup kasih URL + bukti kepemilikan DNS. Sisanya sistem yang kerjakan.**

DNS-TXT dipilih karena ini standar industri (Google, Microsoft, Let's Encrypt) dan
tidak memerlukan akses ke server klien — cukup akses ke DNS panel.

---

#### Problem

Indonesian clients buy "prove our WAF/CDN is penetrable" and **refuse to hand over the
origin IP** — the tool must discover it. Current gate `assert_origin_authorized` requires
`origin_ip ∈ signed authorized_origins` (a hand-fed IP list). Client won't provide it →
`authorized_origins` empty → ORIGIN_DIRECT can never fire → **core product ask is
structurally blocked.** Fix is not a probe; it is the origin-authorization model.

#### Decision

Replace the hand-fed IP allowlist with a **two-proof runtime binding**. The client
supplies only a URL. Authorization to hit a *discovered* origin IP is derived, never
typed in.

##### Proof-1 — Domain ownership (server-minted DNS-TXT)
```text
1. Client: "test https://ibudanbalita.com; origin withheld."
2. Conductor MINTS token  t = hmac(engagement_key, engagement_id || domain || nonce)
   — server-side, bound to THIS engagement. (Caller never supplies the token — that
   was deferred-#2; now mandatory. Caller-supplied token = client forges ownership of
   a domain they don't control.)
3. Conductor displays:  _agentalpha.<domain>  TXT  "agent-alpha=<t>"
4. Client places the record, confirms.
5. verify_domain_ownership(domain, "agent-alpha=<t>", resolver) is True
   → domain enters signed scope_targets. Token t is logged (event-sourced).
```
`verify_domain_ownership` already exists (#252); the only change is the token is
**minted+stored server-side and bound to engagement_id**, not passed in by the caller.

##### Proof-2 — Origin binding (anti-collateral)
New injectable seam `OriginBinder` (mirrors the `OriginDiscovery` seam pattern):
```python
class OriginBinder(Protocol):
    def serves(self, origin_ip: str, fronted_host: str) -> bool:
        """True IFF origin_ip demonstrably serves fronted_host:
        fetch https://{origin_ip} with Host+SNI = fronted_host, verify=off, and
        require cert SAN CONTAINS fronted_host  (strong — authorizing)   OR
        cryptographic origin marker placed by the client  (strong — authorizing).
        Body-identity match is DIAGNOSTIC ONLY — it MUST NOT authorize hitting
        a discovered IP (a cache/CDN/shared-host can echo the owned site's body
        without being the client's origin → authorizing collateral).
        Fail-closed: default _FailLoudBinder.serves() raises."""
```
A discovered neighbor domain `E` on the same shared IP fails `serves(ip, D)` because
the cert/identity is for `E`, not `D`. Body-identity match alone is insufficient — a
CDN, cache, or shared host can echo the owned site's body without being the client's
origin. Body-identity is retained as a **diagnostic signal** in the engagement report
but MUST NOT appear in the authorization predicate.

##### Revised gate
```python
def assert_origin_authorized(origin_ip, fronted_host, profile, binder):
    assert_not_guardrailed(fronted_host)                 # bank/gov TLD overrides all
    if fronted_host not in profile.scope_targets:        # Proof-1 result (owned)
        raise OriginNotAuthorizedError("fronted host not a proven-owned target")
    if not profile.allow_evasion:                        # signed capability + consent
        raise OriginNotAuthorizedError("evasion capability not consented (§12.36)")
    if not binder.serves(origin_ip, fronted_host):       # Proof-2 (binding)
        raise OriginNotAuthorizedError(
            f"origin {origin_ip!r} not proven-bound to owned host {fronted_host!r} "
            f"(cert SAN / identity mismatch) — refusing collateral hit")
    # only now: origin-direct is authorized for this IP, this run
```

##### Schema change
- `EngagementProfile.authorized_origins` (hand-fed signed IP set) → **removed as client
  input.** Per-IP authorization is a RUNTIME decision (signed capability × live binding),
  not a signed static list. The signed profile authorizes the *capability* (`allow_evasion`
  + consent) and the *owned domains* (`scope_targets` + ownership token); the specific IP
  is bound at run time.
- `ownership_tokens: Mapping[str,str]` (domain → server-minted token) added, embedded in
  the signed canonical JSON (mutation invalidates HMAC).

#### Test contract (RED before the change)

| # | Test | Asserts |
|---|------|---------|
| 1 CARDINAL | discovered IP serving a DIFFERENT domain (cohost neighbor) on shared host → `assert_origin_authorized` RAISES | Proof-2 closes collateral (fails today: no binding) |
| 2 | caller-supplied token for a domain the client does NOT control → ownership False | server-minted, engagement-bound token |
| 3 | token minted for engagement A, replayed in engagement B → rejected | token bound to engagement_id |
| 4 happy | owned domain D + IP whose cert SAN ⊇ D → authorized; origin-direct fires | two-proof pass |
| 5 | `allow_evasion=False` + both proofs → RAISES | capability gate independent of binding |
| 6 | guarded TLD (bank) + both proofs → GuardrailError | guardrail overrides consent |

#### Integration points
- **Who calls it:** `scout._attempt_reach` step-5 (ORIGIN_DIRECT dispatch) calls
  `assert_origin_authorized(..., binder)` — the Conductor-owned authorization gate
  performs the binder evaluation internally before `origin_direct_fetch`. Scout
  does NOT call `binder.serves(...)` separately (single gate, not two).
  Conductor authorize-flow mints token + `verify_domain_ownership` before signing.
- **What it calls:** `verify_domain_ownership` (Proof-1), `OriginBinder.serves` (Proof-2,
  new), `origin_discovery.candidates` (already wired-as-seam, currently injected None).
- **SSRF gate:** `OriginBinder` rejects any `origin_ip` failing the shared
  internal-destination guard (reused from `resolve_targets` — loopback, private,
  link-local, multicast, metadata `169.254.169.254`, `::1`, `fd00::`, etc.)
  BEFORE any connection. Redirect targets are validated the same way. Egress
  allowlist enforced before binding and fetching.
- **Autonomous-wiring debt this closes:** `origin_discovery` + `binder` must be injected
  into scout on the live path (both None/island today). Register in
  `test_wiring_gate.py` until wired.

#### Honest limits (do NOT oversell to clients)
- This sells **origin-exposure bypass** ("your WAF is bypassable — origin reachable and
  serving your domain"). It does **NOT** defeat a properly-configured interactive challenge
  (browser_solve PARKED — datacenter-IP egress; needs residential/mobile proxy = INFRA, not
  code). If cimbniaga's Imperva origin is not exposed, the honest verdict is "could not
  bypass" (anti-#3, never fake success).

---

### 12.39 Alpha → Gamma (skip Beta): when direct exploitation routing is valid — ACCEPTED design-intent

**Status:** ACCEPTED as design-intent (Natanael + architect, 2026-07-25). NOT implemented
in slice-1a. The ALPHA→GAMMA routing branch is built WITH Gamma (roadmap #8) AND its
verifying oracle (roadmap #5), never before.
**Scope:** Conductor routing × verification-oracle layer × Gamma phase. Cross-cutting →
recorded as an ADR (durable decision-data), NOT as a code comment in router.py (a comment
referencing an unbuilt oracle tier is a half-scaffold, Lyndon #2).

#### Context

The kill chain is linear Alpha→Beta→Gamma. Beta/STRIKE = **initial access** — it converts
a discovered credential / auth-surface into an authenticated session. For vulnerability
classes that are exploitable **without any authentication** (Laravel/Ignition debug RCE,
SQLi in a public form, Odoo `/web/database/manager` exposure, unauth deserialization,
unauth file-upload→webshell, unauth public-CVE), Beta has no credential to reuse — it is
dead weight, and forcing the chain through it delays or blocks the payable proof. For these
classes, the exploitation IS the proof of the finding, so Alpha→Gamma direct is not an
optimization — it is the value-producing path.

#### Decision — Alpha may route directly to Gamma IFF ALL FOUR hold

1. **No-auth exploitation.** The exploit primitive requires no credential/session. (If
   auth is required → Beta first, then Gamma from the authenticated position.)
2. **Confirmed primitive, not a fingerprint.** The vulnerable behaviour is
   `cross_verified` (independent oracle confirmed the sink is reachable and behaves
   vulnerable), NOT a version/banner match. A CVE version-match alone is a HYPOTHESIS →
   stays a candidate finding, never an exploit dispatch. This is the hard gate.
3. **Reach solved.** The vulnerable endpoint is actually reachable (not WAF/CDN-blocked, or
   origin-direct authorized per the origin-scope-by-ownership ADR). Otherwise Gamma fires
   into a WAF.
4. **Auth + blast gate still enforced.** Skipping Beta skips ROUTING, never AUTHORIZATION.
   Alpha→Gamma still requires OFFENSIVE_APPROVED + blast-radius gate pass + SOW. Routing
   proposes; the auth/blast gates dispose. Never auto-promote tier.

Router shape (built later, WITH Gamma + oracle):
```
route_next(from ALPHA):
  confirmed unauth-exploitable vuln (requires_auth=False, verification==CROSS_VERIFIED)
      and gamma_authorized                                  -> GAMMA   # skip Beta
  confirmed unauth-exploitable vuln, gamma NOT authorized   -> OMEGA   # report "exploitable, pending offensive tier"
  harvested credential + login surface                      -> BETA    # cred-mediated
  fingerprint / version-match only (hypothesis)             -> OMEGA   # candidate, NOT an exploit dispatch
  nothing                                                    -> OMEGA
```

#### The verification dependency (this is the anti-dead-code binding)

Condition #2 requires a `cross_verified` stamp. Ground truth on main (HEAD 6da5512):

| Verifier | Verifies | Status |
|----------|----------|--------|
| `CredReuseOracle` (oracle/verifier.py) | ACCESS_LEVEL nodes reached via credential reuse | **CLOSED by slice-1c** — `run_verification_pass` wired into `conductor/verification.verify_access_nodes` post-Beta on the autonomous path. test_wiring_gate xfail REMOVED. |
| exploit-reachability oracle (for unauth SQLi/RCE/DB-manager) | that an unauth exploit primitive is real, not a fingerprint | **DOES NOT EXIST.** CredReuseOracle cannot do this (wrong finding type). |
| `ChainOracle` | chain cross_verified iff EVERY edge cross_verified | **NOT BUILT** — roadmap #5 ("finishes the verification moat"). Deferred, NOT island. |

**Consequence, explicit:** the ALPHA→GAMMA branch cannot be built until an
**independent exploit-reachability oracle** exists to produce condition #2's
`cross_verified` for unauth primitives. Building the routing branch before that oracle =
a branch gated on a stamp nobody sets = dead branch, AND it invites the real disaster:
dispatching Gamma off a fingerprint (condition #2 unmet) → honeypot / false-positive /
outage / burned technique. So: **the routing skip is bound to the verification moat, not
to the vuln class.**

#### Constraint carried forward (so ChainOracle is not built as a fake verifier)

When ChainOracle / the exploit-reachability oracle is built (roadmap #5), it MUST be a
**COMPOSITION of independent per-edge oracles** — each re-checks ground truth with a
failure mode DIFFERENT from the finder's. It must NEVER be a graph traversal over what the
tools already asserted (that is an internal-consistency check with the same failure mode =
Lyndon #3, false success at the oracle level). "Proven" in a payable report = cross_verified
= an independent signal confirmed it, not the graph agreeing with itself.

#### Tracked debt (enforce, do not rely on memory)

- ~~`run_verification_pass` island → wire into execute_agent post-Beta (slice-1c).~~
  **CLOSED by slice-1c** — wired into `conductor/verification.verify_access_nodes`; xfail
  removed from `tests/governance/test_wiring_gate.py`.
- exploit-reachability oracle + ChainOracle → NOT in the wiring-gate (not built = not an
  island). Tracked here + roadmap #5 as the prerequisite for the ALPHA→GAMMA routing branch.
- ALPHA→GAMMA router branch → built in the Gamma phase (roadmap #8) ONLY after: sellable
  Alpha→Beta→Omega loop proven + exploit-reachability oracle + ToolComposer + blast gate.

#### Slice-1a stays clean

`router.py` (slice-1a) implements ALPHA→{BETA, OMEGA} and BETA→{GAMMA, OMEGA} only. No
ALPHA→GAMMA branch, no speculative comment referencing an unbuilt oracle. This ADR is the
memory; the code carries only what is wired today.

---

### 12.40 Content-Analysis Lane — oracle-gated LLM hypothesis over already-fetched bodies — PROPOSED (lock on confirm)

**Status:** PROPOSED. Phase 4 (recon recall). One vertical slice follows immediately (plugin→CVE).

---

#### Context (grounded in bernofarm.com, 2026-07-27)

Field rematch vs Strix: bernofarm 0 (Agent-Alpha) vs 7 (Strix). Raw-response analysis proved
the dominant gap is NOT reach and NOT the classifier. Three of Strix's seven findings sit inside
the **195 KB homepage Agent-Alpha already fetched at HTTP 200** and did nothing with (the body
matched no RULE playbook → escalated to the LLM tier → coerced to `generic_http_probe` → token
burn, zero findings):

- #1 SEO-spam hidden-link injection (HIGH) — hidden `<a>` via `left:-9999px` CSS in the homepage.
- #4 WP File Manager Pro plugin (HIGH 8.8, CVE-2020-25213, RCE) — plugin asset path in the homepage HTML.
- #7 exposed AJAX handler + nonce (MEDIUM) — nonce in inline `<script>` on the homepage.

Root cause = a **recall ceiling**: Agent-Alpha only finds what a path-keyed RULE playbook can
pattern. It has no capability to analyse rich content it has already retrieved. Strix mines the
same HTML with LLM-over-DOM — but **ungated** (it over-reports, e.g. its #3 wp-login.php at
severity NONE, and its findings' exploitability is not independently confirmed). Copying Strix's
ungated model = a false-positive firehose = Lyndon #3. The task is to gain Strix-like recall
WITHOUT its FP profile, using the verification discipline Agent-Alpha already has.

Reach is explicitly OUT of scope here: bernofarm's `/wp-json/` root, `/wp-json/wp/v2/users`, and
all backup paths returned **403 openresty (origin block)** to BOTH tools (Strix's browser was 403
too). CF-edge soft-200 challenge (`/wp-json/wp/v2/posts` → "One moment, please…") and
session-carrying replay are a separate reach decision (see Related, §12.4x).

---

#### Decision

Add a **ContentAnalyzer** lane: an LLM pass over a body Agent-Alpha has ALREADY fetched, whose
output is never a finding by itself — every LLM claim must pass a **deterministic per-class
verifier** before it becomes a graph node. This is the existing `VerificationTier` discipline
applied to a new finding source.

**Reach-independent by construction:** the lane issues NO new HTTP request for detection. It runs
on `resp.text` already in hand (starting with the homepage). Optional independent confirmation
(one extra fetch) is what escalates a finding from SELF_VERIFIED → CROSS_VERIFIED — and may be
blocked by the same origin/CF obstacle, in which case the finding stays SELF_VERIFIED, reported
honestly as "detected, not independently confirmed".

---

#### The gate contract (the whole point of this ADR)

```
LLM proposes (over already-fetched body):
  Hypothesis {
    finding_class : "seo_spam_hidden_link" | "plugin_cve" | "exposed_nonce"   # closed enum
    locator       : str    # CSS selector / asset URL / regex span the claim rests on
    raw_evidence  : str    # exact substring from the body (must be present verbatim)
    llm_confidence: float
  }

Deterministic per-class VERIFIER runs (pure function of the body + hypothesis):
  - confirms raw_evidence is present verbatim (anti-LLM-hallucination guard)
  - applies the class-specific deterministic check (below)
  - returns Confirmed{proof, severity, cwe} | Rejected{reason}

Only Confirmed → a VULNERABILITY node at VerificationTier.SELF_VERIFIED.
Rejected → NOT a finding, NOT a node (anti-#3). Logged as a rejected hypothesis (audit).
CROSS_VERIFIED remains oracle-exclusive (run_verification_pass, one independent fetch) — never
minted by this lane directly. A payable "proven" claim still requires CROSS_VERIFIED per §12.31.
```

The verifier's failure mode differs from the finder's (LLM proposes / regex+DOM confirms), so
SELF_VERIFIED here is a genuine self-check, not internal-consistency theatre (Independent
Verification Axiom).

---

#### Three initial verifier classes (SSOT — one class, one verifier, anti-#6/#7)

| Class | LLM proposes | Deterministic verifier | Severity |
|---|---|---|---|
| `plugin_cve` | plugin name+version from asset path | parse `/wp-content/plugins/<slug>/…?ver=X`; map (slug,version)→CVE via a static, versioned catalog; confirm slug present verbatim | from CVE (e.g. 8.8) |
| `seo_spam_hidden_link` | injected hidden anchor | confirm an `<a href>` whose computed style is off-screen (`left:-9999px`/`display:none`/`text-indent`) AND host is off-site | HIGH (compromise indicator) |
| `exposed_nonce` | AJAX endpoint + nonce in inline JS | regex-confirm a `nonce`/`_wpnonce` token adjacent to an `admin-ajax.php` action in the body | MEDIUM |

`plugin_cve` ships FIRST (payable 8.8, the bernofarm #4).

---

#### What this lane is NOT (anti-Strix / anti-Lyndon boundaries)

- NOT ungated LLM findings — no Confirmed verifier, no node. Ever.
- NOT a new reach mechanism — zero detection-time HTTP; no browser; no proxy. Reach = separate ADR.
- NOT a replacement for RULE playbooks — deterministic RULE tier still runs first; the LLM lane
  only handles OK bodies that no RULE matched (what currently wastes tokens on `generic_http_probe`).
- NOT a second finding catalogue — verifiers live one-per-class; the CVE map is a single static SSOT.
- NOT open-ended "analyse anything" — `finding_class` is a CLOSED enum; adding a class = a new
  verifier + RED test, never a free-form LLM output.

---

#### Integration point

`scout._step_once`, on `Verdict.OK` where the RULE tier (`_decide`/`rule_only`) returned no match:
invoke `ContentAnalyzer.analyze(resp.text, url)` INSTEAD of falling through to the
`generic_http_probe` LLM default. Confirmed hypotheses persist VULNERABILITY nodes via the
existing `persist_node` path (auth/scope-gated as every discovery). Register `ContentAnalyzer` in
`RECON_TOOL_CATALOG` and as tracked wiring-debt in `tests/governance/test_wiring_gate.py` until the
autonomous `run_recon` path invokes it (RUNNER-SEAL ≠ WIRED).

---

#### Test contract (RED-first; cardinal must fail before the lane exists)

- `test_content_analyzer_confirms_plugin_cve`: homepage HTML containing
  `/wp-content/plugins/wp-file-manager/…?ver=6.0` → `plugin_cve` node, SELF_VERIFIED, CVE mapped.
- `test_unbacked_hypothesis_is_rejected` (CARDINAL): LLM proposes a `plugin_cve` whose `raw_evidence`
  is NOT present verbatim in the body → 0 nodes (anti-hallucination gate holds).
- `test_seo_spam_requires_offscreen_style`: a normal visible link → rejected; an `left:-9999px`
  off-site anchor → confirmed.
- `test_rule_tier_still_wins`: a body that matches a RULE playbook never reaches the LLM lane.
- Cost bound: one analyzer pass per UNIQUE OK body (dedup by body hash), not per path.

---

#### Consequences / risks

- Token cost rises on OK-but-unmatched bodies (previously a wasted `generic_http_probe` call
  anyway). Bounded by body-hash dedup + a per-engagement analyzer-call cap.
- FP risk is carried entirely by the verifier layer — if a class can't be deterministically
  verified, it does not ship as a class. That is the acceptance bar.
- The CVE catalogue is static data (playbook-tier), refreshed as data, never self-modifying code.

---

#### Related / explicitly out-of-scope (separate ADRs)

- **§12.4x Session-carrying reach (Strix/Caido pattern) — PROPOSED-NEXT, not here.** Solve the CF
  edge challenge once (headless browser), capture the `cf_clearance` session, replay subsequent
  requests through a local proxy carrying that cookie so CF-edge-challenged paths (soft-200
  `/wp-json/wp/v2/posts`) return real content. This is a REACH capability, orthogonal to content
  analysis; it does NOT bypass origin-level 403 (openresty), which no cookie defeats. Free,
  self-hosted (Caido guest token / sidecar) per the observed Strix architecture. Decide separately;
  do NOT fold into §12.40.
- Classifier soft-200 gap ("One moment, please…" interstitial mis-classed OK): a small precision
  fix in `response_classifier` — structural JS-reload-interstitial signature or WEAK-marker+header
  hint, NOT a natural-language STRONG marker (violates the #188 principle). Track as a bug, not an ADR.

---

#### Lyndon check

- #1 feature-before-foundation: NO — closes a measured real-target recall gap, one slice, build follows.
- #2 dead code: guarded — wiring-debt gate until `run_recon` calls it.
- #3 false success: this ADR EXISTS to prevent it — unverified LLM claim is never a finding.
- #5 scope creep: closed enum of 3 classes; reach + classifier explicitly carved out.
- #6/#7 duplication: one verifier per class; single static CVE catalogue.

---

### 12.41 Reach-class per host — entry-point differential + tiered transport — PROPOSED (lock on confirm)

**Status:** PROPOSED. Phase 4 (reach). Supersedes the fragile body-shape classifier heuristic in
PR #278. One build slice follows immediately (classifier demotion + host reach-class memo).

---

#### Context (grounded in bernofarm.com, Oracle run eng_9b865c17, 2026-07-28)

From an Oracle (datacenter) IP, Cloudflare served a soft-200 JS interstitial ("One moment,
please…", ~11.8 KB, `setTimeout`+`location.reload()`) on EVERY path. Observed failures:

- `classify_response` returned OK on the soft-200 → the entire existing reach ladder
  (`_attempt_reach` → `choose_reach` → `origin_direct_fetch` / `browser_solve`) NEVER triggered.
  The camoufox reach capability already exists and is injected on the autonomous path
  (`recon_runner.py:178,260`) — it was starved, not missing (Verdict.CHALLENGE is its only trigger).
- Alpha sprayed ~21 paths, each httpx-fetched into the same challenge shell, each escalated to the
  LLM tier → `generic_http_probe` → 21 wasted calls + 21 meaningless nodes (false-OK, token burn).
- The PR #278 attempt to detect the soft-200 by BODY SHAPE (anchor/heading/reload-script counting)
  is a heuristic in the classifier's anti-FP core; CodeRabbit found 3 Major defects (DoS via
  `int()` on attacker-controlled digits, order-dependent meta-refresh regex, and — the important
  one — a legitimate short redirect page mis-flagged as CHALLENGE). Perfect body-shape
  classification of "challenge vs legit" is not achievable and does not belong in the classifier.

Code facts that shape this decision (verified in `agents/alpha/scout.py`, `recon/reach_strategy.py`):
- `_attempt_reach` already holds BOTH the httpx `resp` and the reach `_ReachResponse` → the
  DIFFERENTIAL (httpx body vs reach body) is computable there for free.
- `browser_solve.solve_and_fetch()` returns `.status_code/.body/.headers/.challenge_solved` — the
  browser SELF-REPORTS whether it defeated a challenge. It does NOT expose cookies (`cf_clearance`).
- `_ReachResponse` carries no cookies; `http_client` has no cookie injection → cf_clearance
  session-replay is NOT supported without new plumbing (and CF increasingly binds cf_clearance to
  the browser TLS fingerprint, so httpx replay is unreliable anyway).
- Reach is consent-gated: `browser_solve` requires signed `allow_evasion`; `ORIGIN_DIRECT` requires
  an authorized origin (`origin_discovery` ∩ `profile.authorized_origins`).
- `_reach_attempted` is per-URL — there is NO per-host reach memo today.

---

#### Decision

Reach-class is a per-host property, decided ONCE at first contact with the host, then applied to
every path on that host. The classifier no longer VONIS challenge; it only supplies a cheap
COST-GATE signal for whether to spend one browser probe.

```
On first _step_once for a NEW host (entry URL, e.g. the target root or a discovered subdomain):
  1. httpx-fetch the entry.
  2. COST-GATE (cheap, low-stakes): entry looks blocked / thin / reload-shell?  (loose signal)
       NO  → reach_class[host] = CLEAR  (use httpx for all paths; no browser cost)
       YES → ONE browser probe of the entry, then DIFFERENTIAL-VERIFY (below).
  3. DIFFERENTIAL-VERIFY (empirical, FP-safe — the whole point):
       confirmed challenge  iff  browser.challenge_solved AND browser body gained substantive
                                  content the httpx body lacked.
         → reach_class[host] = CHALLENGED_BROWSER  (route this host's paths via browser reach,
            OR via ORIGIN_DIRECT if an authorized origin is known — origin-direct preferred).
       not confirmed (browser body ≈ httpx body)  → reach_class[host] = CLEAR  (the cost-gate
            false-fired; use the httpx content; ZERO false-positive harm).
       browser could not solve (hard block / datacenter-IP reputation) → reach_class[host] =
            HARD_BLOCKED → honest INCONCLUSIVE for that host (anti-#3).
  4. Cache reach_class[host] (Alpha per-run, in-memory, reset each run_recon — like _reach_attempted).
     All subsequent paths on the host use the cached transport; no re-classification, no re-spray.
```

**Cost-gate precision note:** the cost-gate fires only when the httpx response is NOT `Verdict.OK`
OR the body is thin (< N KB) with a reload-signal present (`settimeout` / `location.reload` /
short `<meta http-equiv="refresh">`). A clean HTTP 200 with substantive content never triggers
browser cost — the host is CLEAR immediately. This prevents browser probes on the majority of
subdomains discovered via crt.sh (most return clean 200s or simple 404s).

FP is eliminated empirically, not heuristically: a legitimate reload/thin page that trips the loose
cost-gate costs at most ONE browser probe to disconfirm, after which the host is CLEAR and never
re-suspected. A false cost-gate never discards real content and never mints a false finding.

Priority within CHALLENGED: **ORIGIN_DIRECT first** (if an authorized origin is discovered — cheap,
skips CF's front door entirely, no challenge to solve), browser reach second, honest block third.
`choose_reach` already encodes ORIGIN_DIRECT > EVASION; this ADR makes the decision host-level and
cached rather than per-URL and repeated.

---

#### Explicitly NOT in scope (anti-over-engineering / anti-Lyndon)

- **No cf_clearance session-replay.** Uncertain payoff (CF fingerprint-binding), needs new
  browser_solve + http_client cookie plumbing. A CHALLENGED_BROWSER host routes its paths through
  the browser directly. Revisit only if browser-per-path cost proves prohibitive AND origin-direct
  coverage is low.
- **No perfect body-shape challenge classifier.** The reload-shape signal is demoted to a loose
  cost-gate, never a content verdict. PR #278's shape heuristic is reverted to that role (its DoS +
  regex defects disappear with it; keep only a bounded, cheap "thin/reload-ish" hint).
- **No cross-engagement reach persistence.** reach_class is Alpha per-run. Persisting it (so the
  next engagement to the same host skips re-classification) is a Phase-6 refinement, not now.

---

#### Consent gate (SOW prerequisite — operational, not code)

Browser reach fires only with signed `allow_evasion`; origin-direct only with an authorized origin.
On a real engagement (e.g. bernofarm), reach stays dormant — correctly — until the SOW consents to
evasion. The ADR does not soften this gate.

---

#### Integration point

`scout._step_once`: on the first pop of a URL for a host not in `self._reach_class`, run
`_classify_host_reach(entry_resp)` and cache the result; route the current and subsequent paths per
the cached class. The reload/thin cost-gate replaces the PR #278 `_is_reload_interstitial` verdict
path in `response_classifier` — the classifier returns a cheap boolean hint, not Verdict.CHALLENGE.
`_attempt_reach` is reused unchanged for the browser/origin dispatch; the differential compare is
added where it already holds both bodies. Register the host-reach path as wiring-debt in
`tests/governance/test_wiring_gate.py` until `run_recon` exercises it end-to-end.

---

#### Test contract (RED-first; cardinal must fail before the change)

- `test_legit_reload_page_classified_clear_no_false_challenge` (CARDINAL): entry is a legit short
  page (heading + text + one link + a same-site reload) → cost-gate may fire → browser probe returns
  ≈ same content → reach_class = CLEAR, content USED, 0 findings-from-misclassification. (FP-safe.)
- `test_cf_soft200_entry_classified_challenged_and_reached`: entry is a CF soft-200 shell; browser
  probe returns substantive real content + challenge_solved → reach_class = CHALLENGED, reach body
  used for subsequent paths.
- `test_challenged_host_probes_browser_once_not_per_path`: N paths on a challenged host → exactly
  ONE browser probe (memo holds), not N. (Kills the 21-spray token burn.)
- `test_origin_direct_preferred_when_authorized_origin_known`: CHALLENGED + authorized origin →
  ORIGIN_DIRECT, browser not invoked.
- `test_hard_block_is_inconclusive_not_ok`: browser cannot solve → INCONCLUSIVE, never false-OK.

---

#### Consequences / risks

- Browser cost bounded to ~one probe per suspected host (not per path). Non-CF hosts pay zero
  browser cost (cost-gate stays NO). Preserves the httpx cost moat.
- Datacenter-IP reputation hard-blocks remain unsolved by any code — residential/mobile proxy =
  infra. This ADR closes the JS-challenge + fingerprint-common case, not IP-reputation hard-blocks.
- "Substantive content gained" is a threshold, but the two cases are bimodal (challenge shell of
  spinner/script vs a real page) — plus `challenge_solved` is the primary signal, the differential
  only guards against a browser that reports solved yet returns nothing new.

---

#### Build slice order

1. **slice-1** (this ADR's core): demote `response_classifier` reload-shape to a cheap cost-gate
   hint (revert PR #278 verdict path + its 3 defects) + `_classify_host_reach` (entry differential)
   + per-run `reach_class` memo in `_step_once`. RED-first per the cardinal above.
2. **slice-2**: ORIGIN_DIRECT-first preference within CHALLENGED (depends on origin discovery /
   subdomain wiring, §12.38) + wiring-gate promotion.

---

#### Lyndon check

- #1 feature-before-foundation: NO — closes a proven real-target reach failure; reuses the existing
  reach ladder; one slice, build follows.
- #2 dead code / runner-seal: the reach ladder is wired but starved; this slice makes it fire on the
  autonomous path; wiring-debt gate enforces it.
- #3 false success: the whole design replaces a heuristic verdict with an empirical (browser-proven)
  one; a false cost-gate never fabricates a finding.
- #5 scope creep: cookie-replay, perfect classifier, cross-engagement persist all explicitly carved out.
- #6/#7 duplication: reuses `_attempt_reach` / `choose_reach` (no second reach path); reach_class is
  a single per-host memo, single source.

---

### 12.42 Attacker Vantage + Footprint + Doctrine — EXTERNAL, agentless, exhaustive-surface — PROPOSED (lock on confirm)

**Context / gap.** Agent-Alpha's vantage was never a first-class ADR item. Implied by the reach
arc, origin discovery (§12.38), adaptive evasion (§12.33), Epsilon "pivot to internal network",
PRD internet→crown-jewel — never stated. The design references occupy DIFFERENT vantages;
copying their mechanics without pinning ours invites scope drift (#4 generic, #5 creep).
NodeZero (Ref #1) = assumed-internal / agentless (foothold already inside; no perimeter to
breach). Strix (Ref #N) = dev/CI / source-available.

**Decision — two axes, both pinned.**
- **Vantage = EXTERNAL, unauthenticated adversary.** Engagement begins from the public internet
  with only a client-owned domain — no implant, VPN, source, or inside foothold at t0 (black-box).
  Breaching the perimeter (reach: TLS-fingerprint bypass, origin discovery, CDN/WAF
  discrimination) is IN-SCOPE and is the FIRST kill-chain segment, not an afterthought.
- **Footprint = AGENTLESS.** No persistent implant installed on client targets — ever. Post-
  exploitation stays agentless (LOLBin / in-memory / existing-protocol reuse, §8g). "No software
  installed on client targets" is a first-class selling property, claimable today. Zero-residue
  (cleanup verification) is a future target requirement pending implementation.
- Internal / assumed-breach vantage (NodeZero-style AD/GOAD from a foothold) = LATER, SECONDARY
  profile (Phase 5, Epsilon onward), reached only by pivot AFTER external foothold proven — never
  the default entry.

**Attacker Doctrine (how the agent must THINK).** Buyer question = "how strongly can our
perimeter be breached." The agent reasons like a real attacker: "where can I get in — I don't
care how." A guarded front door does not end the engagement; the attacker tries side windows,
the roof, the tunnel. Operationalised — NOT as an ever-growing hardcoded vector list, but as:
1. **Exhaustive surface map.** The platform's job is to enumerate the ENTIRE attack surface
   (apex, www, subdomains, origin IPs behind CDN, alternate ports/protocols/services, API and
   mobile backends, auth portals, third-party integrations) into the AttackGraph — not 3 doors.
   A door the agent cannot SEE (e.g. frameset links, BUG 3) is a hole left open. Discovery does
   NOT grant authorization to test — every discovered asset must pass Conductor + Policy-as-Code
   scope/authorization before probing (§12.36 signed EngagementProfile).
2. **Stop only when surface is exhausted, not when N paths fail.** Surface exhaustion = empty
   deduplicated in-scope frontier. A BLOCKED path must not collapse the engagement while un-probed
   surface remains (§12.24 bounded-autonomy stall). `next_action = f(graph)` (§12.0), never a
   static pipeline. Iteration, time, or cost ceilings may terminate a run with a non-success
   incomplete result when the frontier remains unresolved or continues expanding.
3. **Vuln-classes are added as GATED, oracle-verified lanes over that surface** (pattern §12.40),
   one at a time — never a parallel build-out. This is the guard against #1/#5.
4. **Post-pivot business-logic / "black-swan" flaws = DEFERRED to Phase 5/6** (require Gamma +
   an outcome-oracle, §12.32 Gamma-gated). The true long-term differentiator, explicitly NOT built
   now (recon must be proven on a real target first — feature-before-foundation).

**Consequences.** Reach is on the critical path BECAUSE we are external — de-prioritising it
abandons the vantage. Recon is black-box (fingerprint-driven, passive-first R2, no source
shortcuts). Competitive story = "external attacker simulation"; overlap with NodeZero/Strix is
MECHANISM (proof, graph), never vantage. Any proposal assuming inside foothold / source / implant
at START is OUT unless an explicit post-pivot secondary profile.

**Anti-Lyndon.** Pins entry vantage + footprint + the exhaustive-vs-creep boundary so every
feature is judged against them — closes #4 and gives #5 a written test.

**Integration.** No code change — matches the built path (recon_lab, origin_resolver,
transport_resilience). PRD §2 gains a positioning pointer. Epsilon "internal network" = post-pivot
secondary, consistent with Phase 5 gating.

---

### 12.43 Proof Standard — zero-FP via independent oracle + human-legible artifact — PROPOSED (lock on confirm)

**Extends** §12.31 (verification tiers) and §12.32 (auth-vs-unauth diff). Does NOT redefine them
(anti-#6).

**Principle.** A finding is payable ONLY when BOTH hold: (1) an INDEPENDENT oracle confirms it —
failure mode DIFFERENT from the finder (re-authenticate, re-fetch ground truth), reaching
`cross_verified` per §12.31; AND (2) a human-legible ProofArtifact is attached (screenshot + raw
request/response HAR), stored in the vault, referenced by `storage_ref`. Raw HAR is vault-only;
client-visible reports and dashboards use a redacted artifact with secrets/credentials stripped.
Access controls for raw vs redacted artifacts are defined separately in the vault layer.

**Critical distinction (anti-#3).** The screenshot is the EXHIBIT, not the oracle. A screenshot
can render a login page, a cached page, or a soft-200 — pixels prove nothing alone. The zero-FP
GATE for an access/login-class finding = with the harvested credential, an INDEPENDENT fresh
session obtains an authenticated-only ground-truth marker the unauthenticated session did NOT
(auth-vs-unauth diff §12.32): e.g. the logged-in user's own account id, an admin-only DOM element,
a session/CSRF token bound to the account. Only AFTER that oracle passes is the screenshot taken.

**ProofArtifact tiers (single canonical enum, extends §12.31).**
- `asserted` (L0) — tool/LLM said so. NOT a finding.
- `self_verified` (L1) — finder re-checked (same failure mode). Weak; not payable alone.
- `cross_verified` (L2) — independent oracle confirmed (different failure mode). PAYABLE floor.

Every L2 finding MUST carry `{oracle_evidence (the independent request/response), visual_artifact
(screenshot), storage_ref}`. Missing OR invalid oracle evidence, visual artifact, or storage_ref →
downgrade to L1, excluded from KPI (PRD §5 "no silent success").

**Consequence.** Raises Omega report quality (client sees the dashboard, not a claim) AND enforces
the zero-FP bar mechanically (unverified never counts toward a KPI). Screenshot capture = Camoufox
(§12.16 shared browser capability), gated exactly like browser_solve (lab / authorized only).

**Integration.** ProofArtifact is already minted by the dbmanager / WP handlers; this mandates the
oracle+visual PAIR for ALL L2 (cross_verified) payable findings. The auth-vs-unauth ground-truth
diff (§12.32 AuthenticatedCrawlMode) is the specific oracle for the ACCESS/login class; other
finding classes use their class-appropriate independent oracle. No new agent, no new canonical type.

**Lyndon check.** #3 false success — this IS the fix (screenshot-as-claim would BE #3; the oracle
gate prevents it). #6 duplication — extends the §12.31 enum, never redefines it.

---

### 12.44 Evasion technique catalog — datacenter-viable vs infra-bound — PROPOSED (lock on confirm)

**Extends** §12.33 (adaptive evasion, class-scoped) and §12.42 (external vantage). Does NOT
re-decide §12.33's class→technique mapping; it widens the technique space and classifies each by
network-position dependency, and defines the home for executors (the empty `evasion/` package).

**Context / gap.** §12.33 locked THREE techniques (rate_throttle, browser_solve, tls_impersonate)
+ the reach-strategy origin-direct, and proved the residential-IP ceiling. But the technique space
is wider, and the current map conflates "we can't beat this" (infra) with "we haven't built this
yet" (code). An EXTERNAL agent (§12.42) needs the full catalog, honestly split, so investment goes
to the datacenter-viable, high-ROI techniques — not to chasing an infra-bound ceiling.

**Positioning note (why this arc is external-specific).** Agent-Alpha is external-first (§12.42).
The entire evasion arc exists BECAUSE the agent starts on the public internet behind the edge.
A future internal / assumed-breach product (NodeZero-style, separate name) makes most of this
irrelevant — from inside, there is no CDN/WAF edge to bypass. So evasion is an EXTERNAL-vantage
investment and is correctly prioritised now; it is NOT carried into the internal product later.

**Decision — reframe: evasion ROI is a ladder, not "beat the challenge".** For an external
datacenter-egress agent the value order is:

1. **BYPASS THE EDGE (origin-direct)** — datacenter-viable, defeats ALL classes at once. If the
   real origin IP is discovered and hit with the owned `Host`, CF/Imperva/Akamai is bypassed
   entirely (no challenge, no fingerprint check). Gated by §12.38 (two-proof origin ownership).
   The investment here is ORIGIN DISCOVERY BREADTH — DNS history, cert-SAN correlation, favicon-hash
   pivot (Shodan/Censys), MX/mail infra sharing, non-fronted subdomains, mis-scoped DNS. Highest ROI;
   this is also the sellable proposition (origin-exposure bypass), not challenge-defeat.
2. **FINGERPRINT PARITY** — datacenter-viable, defeats MitigationClass.FINGERPRINT (passive bot
   block, e.g. bernofarm 403). tls_impersonate/JA3 is the START. Extend: JA4/JA4+, HTTP/2 fingerprint
   (Akamai h2 SETTINGS/window/priority/pseudo-header order), header order+casing fidelity, client
   hints (`sec-ch-ua`). INVARIANT: the UA ↔ TLS ↔ HTTP/2 triad must be CONSISTENT — a mismatch is an
   instant bot flag, worse than no impersonation.
3. **BEHAVIORAL / RATE REALISM** — datacenter-viable, defeats RATE_LIMIT + soft behavioral scoring.
   rate_throttle executor + jitter/backoff; session-warming (visit benign paths to earn a
   `cf_clearance` cookie, then reuse it across the httpx transport — amortise the expensive step).
4. **IP REPUTATION + INTERACTIVE CHALLENGE** — INFRA-bound, NOT a code problem. Levers:
   (a) residential/mobile proxy egress (infra); (b) client-side, the professional path for authorized
   red team — SOW clause: client whitelists the scanner IP OR lowers edge protection during the
   pentest window. CF managed challenge from a datacenter ASN is IP-reputation-driven; no fingerprint
   beats it (§12.33, field-proven). Commercial CAPTCHA solvers = FORBIDDEN (§12.33, confidentiality).
5. **WAF SIGNATURE (RULE_DENY)** — mostly WEAPONISED-PAYLOAD evasion (encoding/mutation, request
   smuggling, parameter pollution) = DeepSeek lane, Gamma phase — NOT recon reach. For reach,
   RULE_DENY is not transport-evadable; lever = origin-direct or an alternate recon vector (§12.33).

**Viability matrix (the honest split).**

| Technique | Mitigation class | Datacenter-viable? | Lane / home |
|-----------|------------------|--------------------|-------------|
| origin-direct (+ origin discovery breadth) | ALL (bypass) | YES | reach strategy + §12.38 |
| tls_impersonate (JA3) | FINGERPRINT | YES (built) | evasion/ executor |
| JA4/JA4+, HTTP/2 fp, header-order, client-hints | FINGERPRINT | YES | evasion/ executor (extend) |
| rate_throttle + jitter | RATE_LIMIT | YES | evasion/ executor |
| session-warming / cf_clearance reuse | CHALLENGE (compute) | YES (if IP not blocked) | evasion/ executor |
| browser_solve (JS-compute challenge) | CHALLENGE | YES only if IP not reputation-gated | browser capability |
| residential/mobile egress | CHALLENGE (managed) / IP rep | NO — infra | engagement setup, not code |
| client whitelist / lower-protection window | IP rep / managed | N/A — client-side | SOW clause |
| commercial CAPTCHA solver | interactive CAPTCHA | FORBIDDEN | — (never) |
| payload mutation / smuggling | RULE_DENY | (Gamma) | DeepSeek lane, later |

**`evasion/` package structure (the empty folder's purpose).** Home for an `EvasionTechnique`
registry + EXECUTORS (today the 3 executors live inside `recon/transport_resilience.py`; migrate
incrementally). Each technique declares: (a) the `MitigationClass` it defeats, (b) `viability`
(`datacenter` | `infra` | `client_side` | `forbidden`), (c) its executor. The §12.33 planner
selects by observed obstacle class AND viability — it must NEVER propose an `infra`/`forbidden`
technique as if it were code-solvable (that is the honesty the current 3-technique map lacks).

**Clarification (2026-08-05): `evasion/` EXTENDS `transport_resilience.EvasionTechnique`, does
not redefine it.** The existing `EvasionTechnique` enum (`recon/transport_resilience.py:49`) with
members `RATE_THROTTLE`, `BROWSER_SOLVE`, `TLS_IMPERSONATE`, `NONE` is the canonical type. The
`evasion/` package must EXTEND this type (add members, add a `viability` field via a wrapper
dataclass or a separate descriptor registry keyed by the enum value) — it must NOT create a
second parallel `EvasionTechnique` type (anti-Lyndon #6). If extension of the `StrEnum` proves
infeasible (e.g., because `viability` requires a per-member data field that `StrEnum` cannot
carry), the new descriptor type MUST be renamed (e.g., `EvasionCatalogEntry`,
`EvasionTechniqueDescriptor`) to avoid naming collision with the existing enum. The
`TECHNIQUE_FOR_MITIGATION_CLASS` mapping in `constants.py` stays single-source (anti-#7).

**Phase discipline (build order — NOT part of this lock).** Do NOT build the catalog up front.
§12.33 itself defers by need ("9b deferred — no FINGERPRINT vector in the A1 lab"). Build slice by
slice, each driven by a REAL obstacle hit on a real target (anti Lyndon #1/#5). Current milestone is
GAP-015 field-prove, not evasion breadth.

**Current lab reality (alpha-ai.web.id, full CF, datacenter egress).** The obstacle this lab
presents is CHALLENGE = CF managed challenge, which is IP-reputation-gated → browser_solve NOT
viable from Oracle (§12.33, empirically). So on THIS lab the only datacenter-viable code lever is
ORIGIN-DIRECT (discover the origin IP + §12.38 ownership proof); fingerprint parity would not help
(the block is not fingerprint-class). This directly shapes GAP-015 field-prove: reaching the WP
login behind full CF requires origin-direct first, or the challenge is unsolvable from datacenter —
honest, and it tells us WHICH evasion slice (origin discovery) has real pull, not fingerprint.

**Anti-Lyndon.** #1/#5: this is a MENU + honesty classification, not a build order — the guard
against building evasion breadth speculatively. #3: forbids the planner from presenting an
infra-bound technique as code-solvable (false capability). #7: technique→class mapping stays single
-source in constants/§12.33; this ADR widens the menu, does not fork the mapping.

---

### 12.45 Credential-result semantics + password recall ladder — PROPOSED (lock on confirm)

**Extends** §12.43 (proof standard) and the cred_finding_catalog (§3a). Governs what a credential
RESULT means in a report — especially a NEGATIVE one.

**Context / gap.** GAP-015 predictable-credential is a HIGH-precision, LOW-recall, safe-online
vector: it derives ≤4 bounded candidates (username / username+123 / domain_stem / domain_stem+123)
per enumerated user. A POSITIVE is a proven finding. But a NEGATIVE (no derived candidate worked)
means ONLY "not trivially derivable from the username/domain by a handful of bounded guesses" — it
says NOTHING about the password's real strength. If a report phrases that negative as
"password is safe / not predictable / secure", and a real attacker later cracks it, the report was
falsely reassuring — a credibility-destroying false assurance.

**Decision — a red team NEVER certifies "safe". Absence of a finding ≠ absence of vulnerability.**
1. **Positive only is a finding.** A credential finding is minted ONLY on a proven positive
   (finding_class=predictable_credential, §3a). There is NO "credential_safe" / "password_strong"
   node, event, or report claim — ever.
2. **Negatives carry a methodology caveat, never a verdict.** Where a report must mention a
   credential test that found nothing, it states the METHOD and its LIMIT, not a strength verdict:
   e.g. "bounded online derivation (≤4 candidates/user, lockout-safe) found no reusable credential
   for user X — this is NOT a password-strength assessment; offline cracking, credential stuffing,
   and large wordlists were out of engagement scope." Omega is FORBIDDEN from emitting
   "safe/secure/strong/not predictable" from a negative credential result.
3. **Methodology transparency.** Every credential section states what WAS and WAS NOT tested (the
   vectors + their recall). This is how a red team avoids over-claiming absence.

**Password recall ladder (how findings scale to match a real attacker — roadmap, NOT built now).**
Online guessing is inherently low-recall (lockout caps it at ~4-5). A real attacker cracks
strong-looking passwords via, in order of value:
1. **Offline hash crack** — the strong one. When Alpha HARVESTS password hashes (DB dump / backup /
   wp-config→DB access), crack them OFFLINE with hashcat + rockyou + rules (billions of guesses, NO
   lockout, safe). This matches how real attackers crack "safe-looking" passwords. Gamma-adjacent
   (needs the hash-harvest chain). A negative here (uncracked with a stated wordlist+ruleset+budget)
   is a MUCH stronger — though still not absolute — signal than a negative online guess.
2. **Credential stuffing** — check enumerated identities against known breach corpuses (reuse across
   services is rife). Needs an ethical/legal breach-data source (paid). Roadmap.
3. **OSINT-targeted wordlist + rules** — company/year/season/local terms → hashcat rules. Broader
   than the 4 derived candidates but still online-lockout-bounded.

Recall is scaled by offline-crack + credential-stuffing, NEVER by unsafe online spray (which stays
low-recall AND risks locking out real accounts, §12.22 D2).

**Anti-Lyndon.** #3 false success — a negative reported as "safe" is a false NEGATIVE-success
(over-claiming absence); this doctrine forbids it. One concept: findings assert only what was
PROVEN; methodology transparency covers the rest.

**Integration.** No code now. Enforcement hooks (later): Omega report builder must have no
"safe/strong" credential phrasing path; the offline-hash-crack + credential-stuffing vectors are
tracked roadmap (register in docs/BUGS_AND_GAPS.md), built as gated slices when the hash-harvest
chain (Gamma-adjacent) lands.

---

### 12.46 Origin-binding runtime authorization — external-vantage origin-direct without pre-signed IPs — PROPOSED (lock on confirm)

**Status:** PROPOSED → LOCK on confirm. **Extends** §12.36 (signed EngagementProfile), §12.38
(two-proof origin ownership), §12.42 (external vantage), §12.44 (evasion catalog — origin-direct =
highest-ROI, the sellable proposition). Does NOT re-decide the auth gate; it adds a SECOND, runtime
authorization path that is strictly proof-gated.

#### Positioning (why this is the product's spine)

Agent-Alpha is EXTERNAL red team: input is a URL/domain, nothing else. The client will NOT hand over
the origin IP or lower their WAF — if they did, this would be an INTERNAL / assumed-breach product
(NodeZero-class, different name). The job is to MAP every path an APT would use to get in — origin
discovery included — so the client can close them. Therefore origin-direct MUST work from the domain
alone. This ADR makes that possible without softening the gate.

#### Context / the chicken-and-egg gap

Today `assert_origin_authorized` (engagement_profile.py:329) authorizes an origin hit ONLY when the
origin IP is in the HMAC-signed `authorized_origins` (immutable — embedded in the signature, §12.36).
But a CF/Akamai-fronted origin IP is HIDDEN at signing time — that is the whole point of the
engagement. The client cannot pre-list what the CDN conceals. So the signed-list path can NEVER
authorize a discovered origin, and `discover_origin_ips` (origin_resolver.py — the built
subdomain→IP pivot) is a permanent island: even if called, its candidates are rejected. Result:
external origin-direct is impossible today.

#### Decision — the signed profile grants a CAPABILITY, not an IP; per-IP authorization is DERIVED at runtime from proof

Add `allow_origin_discovery: bool` to the signed EngagementProfile (mirrors `allow_evasion` /
`allow_subdomain_enum`; §12.36 consent-gated: requires consent_items + signed_by/at). When
consented, the agent MAY discover candidate origins and authorize a hit on any candidate that
passes TWO proofs, event-sourced and audited. The invariant is UNCHANGED and in fact STRENGTHENED:
*never hit an IP we cannot prove is the client's* — the proof simply moves from a human-typed list
to a runtime cryptographic/identity binding (stronger than a person typing an IP into a form).

#### The two proofs (§12.38 made concrete)

- **P1 — Domain ownership (already built).** `fronted_host` ∈ signed `scope_targets` AND DNS-TXT
  ownership (conductor/domain_verification.py, `dns-txt:token=value`). Establishes the client owns
  the DOMAIN. Reused as-is (anti-#6).
- **P2 — Origin-binding (NEW — the thing to build).** The candidate IP demonstrably serves the OWNED
  domain. Evaluated by `verify_origin_binding(candidate_ip, fronted_host, profile, http_client)`,
  which reuses `origin_direct_fetch` (hit IP:443 with `Host: fronted_host`) then checks, in order:
  1. **TLS cert SAN match** — the cert the origin presents for that Host includes `fronted_host` in
     its SubjectAltName. Cheap, strong. *Caveat:* a wildcard / shared / CF-Universal-SSL cert can
     match without proving single-tenancy → cert-SAN ALONE is insufficient when the cert is
     wildcard/shared.
  2. **Ownership canary (PRIMARY — reuses the P1 token, anti-#6).** The client places ONE token file
     at `/.well-known/agent-alpha-<token>.txt`. P1 = fetch it through the fronted domain (via CF) →
     the user controls the site. P2 = fetch the SAME path via `IP:443` + `Host: fronted_host` → the
     origin serves the token → proven to be the client's origin. One artifact, two fetches, no new
     mechanism. A co-tenant cannot reproduce the token → this is the anti-cohost-collateral teeth.
     DNS-TXT remains an ALTERNATIVE P1 method for users who prefer DNS / don't control the web root.
  3. **Content-identity corroboration** — the IP+Host response matches the CF-fronted response on a
     unique fingerprint (title + a per-engagement body marker + favicon hash). Corroborating, never
     sole.
  **Authorize iff P1 AND P2**, where P2 = (exact-SAN, non-wildcard) OR (canary) — corroborated by
  content-identity. Wildcard/shared cert without canary or content-identity ⇒ REJECT (fail-closed).

#### State model (event-sourced, signature-integrity preserved)

Never mutate the signed profile.
- New event `OriginBindingProven { engagement_id, fronted_host, origin_ip, proof_type, evidence_ref }`
  emitted only when P1∧P2 hold; carries the binding artifact for audit.
- `assert_origin_authorized` extended: authorized iff
  `origin_ip ∈ signed authorized_origins`  **OR**
  `profile.allow_origin_discovery AND an OriginBindingProven event exists for (engagement, origin_ip, fronted_host)`.
- Nothing else changes; the fronted-host scope check (scope_targets/lab) stays as the outer gate.

#### Executor + integration (wires the island)

`discover_origin_ips` → drop `is_cloudflare_ip` candidates → `verify_origin_binding` per candidate
(bounded by the reach LockoutGovernor, §12.33) → on proof emit `OriginBindingProven` →
`origin_direct_fetch`. Wire into the autonomous recon origin path so `_attempt_reach`'s
authorized-origin set is populated by PROVEN-bound origins, not only the static signed list. The
`StaticOriginDiscovery` lab stand-in remains for field-prove harnesses.

#### Viability

Datacenter-viable, no infra: cert read + canary/content checks are free. This is the §12.44 Level-1
lever (origin-direct) finally reachable from a domain-only external engagement.

#### Fail-closed matrix

| Situation | Result |
|-----------|--------|
| `allow_origin_discovery` not consented | runtime path OFF — signed-list only |
| candidate is a CF/Akamai edge IP | rejected pre-binding (`is_cloudflare_ip`) |
| cert SAN ≠ owned domain, no canary | REJECT (co-tenant) — no event, no hit |
| wildcard/shared cert, no canary/content match | REJECT (cannot prove single-tenancy) |
| P1 fails (domain not owned / not in scope) | REJECT (outer gate) |
| P1 ∧ P2 hold | `OriginBindingProven` → origin-direct authorized + audited |

#### Anti-Lyndon

Anti-Lyndon #2 — wires the `discover_origin_ips` island into the live path with real teeth.
Anti-Lyndon #3 — `OriginBindingProven` is the anti-false-authorization — a "we reached the origin" claim requires
the binding artifact, never inferred. Auth gate NOT softened — proof is REQUIRED, only
runtime-derived and consent-gated. Anti-Lyndon #6 — reuses `origin_direct_fetch` + `domain_verification`
DNS-TXT + `is_cloudflare_ip`, no duplicate checker.

#### Phase discipline (build order — NOT part of this lock)

FIRST slice = `verify_origin_binding` + `allow_origin_discovery` consent + `OriginBindingProven`
event + wire the EXISTING subdomain→IP pivot through it (bernofarm: 94 CT subdomains → real test).
Discovery-source BREADTH — DNS-history (#1), Shodan/Censys favicon+cert (#3), MX/SPF (#5),
SSRF-callback (#7) — are LATER slices, each a commodity-wrap that FEEDS this authorizer (never the
moat itself, anti-#6). Do NOT build the source catalog up front (anti #1/#5); add one source per
real obstacle.

#### Design-level test contract (must hold before "done")

- Co-tenant IP (serves a different domain's cert, no canary) ⇒ REJECTED; no `OriginBindingProven`;
  no origin-direct fetch. (The cardinal safety test — must be able to FAIL. )
- Proven origin (exact SAN = owned domain, or canary echoed) ⇒ `OriginBindingProven` emitted ⇒
  origin-direct authorized.
- `allow_origin_discovery=False` ⇒ `verify_origin_binding` never authorizes (capability off).
- Signature integrity: authorizing a runtime origin does NOT mutate or re-sign the profile.

#### Resolved decisions (2026-08-03)

1. **Friction model — HYBRID, scaled by action tier (invite-only ≠ domain ownership).** The platform
   is invite-only: sign-in proves the USER is a vetted customer — it does NOT prove the typed domain
   is theirs (a logged-in user can still type a domain they don't own = CFAA + collateral risk). So:
   - **Passive recon** (DNS/CT/OSINT, fingerprint through the front): URL only, runs immediately.
   - **Origin-direct / active / offensive**: require a ONE-TIME per-domain ownership verification
     (well-known-HTTP token file OR DNS-TXT — user's choice), CACHED per account (verify once per
     domain, not per engagement).
   - **IP is optional** — provided = cooperative shortcut; absent = discover + bind. (IP-optional is
     what keeps this EXTERNAL; requiring it would make it internal / NodeZero-class.)
   Invite-only lowers friction elsewhere (no per-engagement user re-vetting); it never replaces P1.

2. **Canary = reuse the ownership token at a well-known HTTP path** (see P2.2 above). No separate
   marker. Cert-SAN is corroborating, not primary. Wildcard/shared cert without the token ⇒ REJECT.

3. **Candidate budget = 3 probes per host, backoff 5s → 15s → 60s with ±20% jitter, PER-HOST**
   (reuse the reach LockoutGovernor, §12.33). Cap at 3 for opsec (quiet); jitter avoids bot-like
   periodicity (§12.44 behavioral realism).

#### Staging (product-reputation first, per Natanael 2026-08-03)

Early on, keep USER-FACING friction low to land real proofs and build the name; tighten UX rules
later. The LINE: relax friction, NEVER the two safety proofs (P1 for intrusive actions, P2 for
every origin hit). A single wrong-target / collateral incident destroys the reputation faster than
any friction — and the proofs are cheap (P2 automatic, P1 once-per-domain), so they PROTECT the name,
they don't slow it.

### 12.47 Recon-phase tool unification — Tool/ToolRegistry as the SINGLE home for stack-specific capability — PROPOSED (lock on confirm)

**Extends** §12.16 (Template/Tool contracts), §12.22 (tool strategy: wrap commodity, build the moat,
gate the dangerous), §12.26 (DETECT=recon / ACT=Gamma). Does NOT re-decide the `Tool`/`Template`
shapes themselves (§12.16 locked those); it decides WHERE new stack-specific recon capability is
allowed to live going forward, and freezes growth of the pattern that produced the gap below.

**Context / gap (measured, not estimated).** `agent_alpha/agents/alpha/scout.py`'s WordPress
"recon-depth battery" (fingerprint-keyed handlers: REST-route escalation, WooCommerce, version
disclosure, plugin danger-list, dedicated credential maps, WP-specific crawl-budget gating) spans
**551 of the file's 2084 lines (~26%)**. 5 of the 9 `CapabilitySpec` entries in `capability_probe.py`
are WP-labeled. By contrast: Laravel has exactly ONE handler (`_handle_laravel_debug`, a single
`APP_DEBUG` leak check) and no `CapabilitySpec` of its own; Spring/Tomcat has only Actuator
disclosure; every other stack (Node, .NET, generic PHP, …) gets universal git/env checks only. Odoo
is the one exception with its own dedicated module (`odoo_dbmanager_probe.py`, Phase 4) — smaller
than WP's battery but at least separated from `scout.py`'s dispatch registry.

**Root cause.** WP was Phase 3's field-proving reference target (project-status: "WP + JS-secret
recon vectors field-proven"). Its battery grew organically through `Alpha._dispatch_registry` — a
hardcoded `dict[str, handler_method]` in `scout.py`. That pattern does not scale: every new stack
means another hand-written ~500-line section with the same shape. Left alone this is a slow-motion
version of Lyndon #8 (god object), distributed across handler methods instead of one function.

**What already exists and was never finished.** `tools/contracts.py` (§12.16) already defines the
right shape: `Tool.phase: str  # recon | access | exploit | post | lateral` and
`Tool.applies_to(ctx) -> float` (relevance-scored selection, not an if-ladder — K11), ranked by the
already-built `ToolRegistry.ranked`. Today `ToolRegistry` is wired ONLY for access-phase capability
(`tools/internal/access/*` — Odoo access, default creds, cred-reuse). The one recon-adjacent seam,
`tools/templates/cms/laravel_finding.py`, is a `Template` (narrower: `build()`/`verify()` only, no
`phase`/`applies_to`/`run`) whose body deliberately `raise NotImplementedError` — a RED skeleton
never picked back up. WP was never ported to either shape. The two systems have not converged.

**Decision.**

1. **`Tool` (phase="recon") is the ONLY sanctioned home for new stack-specific recon capability,
   effective immediately.** No new entries are added to `Alpha._dispatch_registry` /
   `CAPABILITY_CATALOG` for a stack that isn't already there. A new stack (Laravel-complete, Spring,
   Node, .NET, …) is added as a `Tool` implementation registered in `ToolRegistry`, ranked by
   `applies_to(ctx)` against `TargetContext.tech_stack` — the same mechanism access-phase tools
   already use, not a second parallel pattern (anti-#6).
2. **`Alpha.run_recon` gains a second dispatch path, additive.** It keeps calling its existing
   `_dispatch_registry` for everything already wired (WP, Odoo, Tomcat, git/backup/js-secret/
   db-service probes — untouched, not a rewrite) AND separately calls
   `ToolRegistry.ranked(ctx)` filtered to `phase="recon"` for anything registered there. Two
   sources feeding the same frontier queue / graph, not two competing engines.
3. **Existing scout.py batteries are frozen, not ripped out.** WP's 551 lines keep running exactly
   as-is. Migrating it into a `Tool` is a SEPARATE future decision (a real behavior-preserving
   refactor, its own slice) — not authorized by this entry. This entry only stops the gap from
   growing wider today.
4. **Recon-phase `Tool`s inherit the same non-negotiables as everything else Alpha does**
   (§12.26): DETECT only, read-only, never mutate, never mint a finding without a proof artifact
   (`ToolResult.__post_init__` already enforces this structurally — anti-#3). A `Tool` with
   `phase="recon"` that reaches into access/exploit behavior is a contract violation, not a
   recon capability.

**Phase discipline (build order — NOT part of this lock).** This entry decides the MECHANISM, not
which stack gets built next or whether/when WP migrates. Per §12.44's own precedent: do not build
speculatively. The next slice (Laravel-as-first-real-Tool, or WP-migration-as-reference-Tool) is a
separate decision, made when there is a real driving need (anti-#1/#5) — tracked as an open
follow-up to this entry, not decided here.

**Anti-Lyndon.** #1/#5: this locks the model, not a build-it-all-now plan — no stack gets built
speculatively off this entry alone. #6: ONE canonical way to add stack-specific recon capability
going forward, not two (`_dispatch_registry` growth is frozen, `Tool`/`ToolRegistry` is canonical).
#7: `applies_to`/tech_stack matching stays single-source in `TargetContext`/`ToolRegistry` — this
does not fork a second relevance-scoring scheme alongside `capability_probe.py`'s label matching.
#8: this is the direct fix for scout.py's slow drift toward a god object — growth stops here, it
does not get undone in one shot.

### 12.48 Passive-First Recon Doctrine — OSINT-before-touch as mandatory Phase 0 — ACCEPTED (2026-08-04)

**Extends** §12.25 (well-known paths), §12.26 (recon vector strategy), §12.42 (vantage = external),
§12.44 (evasion technique catalog), §12.46 (origin-binding). **Supersedes** the implicit
"probe-first" assumption throughout the existing recon flow.

**Problem (field-observed, not theoretical).** Agent Alpha is deployed on Oracle Cloud ARM64
(datacenter IP, §2). Every HTTP request from this vantage carries an ASN reputation that
WAF/CDN providers (Cloudflare, Akamai, Sucuri, Imperva) score as high-risk by default.
The current `run_recon` flow immediately fires active HTTP probes — `WELL_KNOWN_LEAK_PATHS`,
`SURFACE_DISCOVERY_PATHS`, capability fingerprint seeds — before gathering ANY intelligence
about the target. Even at 2 rps (`DEFAULT_RATE_LIMIT_RPS`), this produces a burst of 15–30
requests to distinct paths from a datacenter IP with a Python TLS fingerprint and
`Agent-Alpha-Recon/{id}` User-Agent. Result: WAF blocks the agent within the first few seconds
(403/503), and the engagement produces zero usable findings. This has been reproduced on multiple
real SOW-authorized client targets.

**Root cause.** The agent lacks INTELLIGENCE before first touch. A professional red team operator
(or APT) NEVER touches a target blind — they build a complete surface map from passive sources
first. Agent Alpha currently behaves like a vulnerability scanner, not an intelligent agent.

**Decision.**

1. **Mandatory Phase 0: Passive Intelligence Gathering (zero target contact).**
   `Alpha.run_recon()` gains a new first stage BEFORE the cognitive loop and BEFORE any HTTP
   request to the target. This stage queries external OSINT sources to build a `PassiveIntelMap`
   (surface map + tech stack hints + protection posture + origin IP candidates). NO HTTP request
   to ANY in-scope target is made during Phase 0.

2. **OSINT sources (tiered, graceful degradation).**
   Three OSINT sources integrated in build order:

   | Source | Data Provided | API Key Required | Tier |
   |--------|---------------|------------------|------|
   | **crt.sh** | Subdomain map via Certificate Transparency logs | No | 1 (mandatory) |
   | **VirusTotal** | Historical DNS, passive DNS, subdomain list, URL scan history | Yes | 2 (recommended) |
   | **DNSDumpster / HackerTarget** | Passive DNS map, MX/TXT records, reverse DNS | No (free tier) | 2 (recommended) |

   Module: `recon/passive_intel.py` — single orchestrator that calls each source, merges results
   into a unified `PassiveIntelMap`. Each source is a separate function, independently testable.
   Missing API keys → source silently skipped (graceful degradation, not failure). crt.sh reuses
   the existing `passive_discovery.py` parser (§ existing code, anti-#6).

3. **Intel-driven active recon (Phase 1 replaces blind probing).**
   After Phase 0 completes, `run_recon` uses the `PassiveIntelMap` to:
   - **Prioritize targets**: subdomain without CF proxy > origin IP > CF-fronted domain.
   - **Select relevant paths**: only probe paths matching the tech stack HINTED by passive intel
     (e.g., only probe WP paths if VirusTotal or crt.sh subdomains suggest WordPress).
   - **Route reach strategy**: if passive intel reveals origin IP candidates, route via
     origin-direct (§12.33/§12.46) BEFORE attempting the CF front-door.
   - **Detect protection posture**: if passive DNS shows CF nameservers, agent KNOWS WAF is present
     and applies evasion from the FIRST request (see §12.49).

4. **`PassiveIntelMap` shape (data contract).**

   ```python
   @dataclass(frozen=True)
   class PassiveIntelMap:
       domain: str
       subdomains: tuple[str, ...]           # All discovered subdomains
       in_scope_subdomains: tuple[str, ...]   # Filtered through is_in_scope
       origin_ip_candidates: tuple[str, ...]  # Potential origin IPs (from DNS history)
       mx_records: tuple[str, ...]            # Mail servers (can reveal origin)
       txt_records: tuple[str, ...]           # SPF/DKIM/DMARC records
       tech_stack_hints: tuple[str, ...]      # Technology hints from passive sources
       protection_detected: str | None        # "cloudflare" | "akamai" | "sucuri" | None
       nameservers: tuple[str, ...]           # NS records (CF NS = CF-proxied)
       historical_paths: tuple[str, ...]      # From Wayback/VT URL scans
   ```

5. **API key management (hybrid model).**
   API keys stored in `.env` (system-level, same pattern as existing secrets).
   Per-engagement toggle in `EngagementProfile` (§12.36) determines which sources are
   ENABLED for a given engagement (default: all available sources ON). Keys = infrastructure,
   config = per-engagement. New `.env` entries: `VIRUSTOTAL_API_KEY`, `HACKERTARGET_API_KEY`.

6. **Existing §12.25 (well-known paths) amendment.**
   `WELL_KNOWN_LEAK_PATHS` seeding is now GATED by Phase 0 output. When passive intel provides
   tech stack hints, only stack-relevant paths are seeded (reuses `Planner.select_leak_paths(labels)`
   with labels from `PassiveIntelMap.tech_stack_hints`). When no hints available (all OSINT
   sources failed/empty), falls back to current behavior (universal + DEFAULT_LEAK_PATHS) —
   no regression on air-gapped or OSINT-unreachable targets.

7. **Exhaustive surface strategy (§12.42 amendment).**
   The agent must NOT give up after front-door blocking. After Phase 0 passive intel:
   - Priority 1: Origin IP direct (if found from passive intel)
   - Priority 2: Subdomains without CF/WAF protection
   - Priority 3: MX/Mail server infrastructure (often reveals origin)
   - Priority 4: TLS impersonation to front-door (curl_cffi, §12.33)
   - Priority 5: Non-HTTP services discovered via passive intel (deferred to §8g)
   - Priority 6: Associated domains / related infrastructure
   - LAST RESORT: report honest result + suggest client whitelist agent IP in WAF
   Only after ALL viable paths are attempted does the agent report "target unreachable from
   datacenter vantage" — and even then, the passive intel surface map IS a deliverable.

8. **Client whitelist fallback.**
   When ALL reach strategies fail from datacenter vantage, the agent MAY include in its handoff
   payload a structured recommendation for the client to whitelist the agent's egress IP(s) in
   their WAF. This is standard pentest practice. The recommendation is informational only — never
   automated, never presumptuous. Format: `ReachRecommendation` in the handoff message.

**Event-sourced**: `PASSIVE_INTEL_GATHERED` event type with the full `PassiveIntelMap` payload,
appended BEFORE any active recon event.

**Anti-Lyndon.** #1/#5: build slice-by-slice (crt.sh first since parser exists, VT second,
DNSDumpster third) — not all-at-once. #3: if all OSINT sources fail, fall back to existing
behavior — never silently produce zero intel. #6: crt.sh parser reused from existing
`passive_discovery.py`, not re-implemented. #7: `PassiveIntelMap` is the single shape consumed
by all downstream logic (active recon, reach strategy, planner). #11: Phase 0 output DRIVES
Phase 1 target selection — not a static/linear step list (§12.0 compliance).

### 12.49 Proactive Evasion Posture — evasion-by-default, not evasion-after-block — ACCEPTED (2026-08-04)

**Extends** §12.33 (adaptive evasion), §12.44 (evasion technique catalog), §12.48 (passive-first).
**Supersedes** the reactive evasion trigger in `transport_resilience.py`'s `EvasionPlanner` which
only proposes evasion AFTER N consecutive BLOCKED verdicts.

**Problem.** The current evasion model is REACTIVE: Agent sends a request with Python's default
TLS fingerprint and `Agent-Alpha-Recon/{id}` User-Agent → WAF blocks it → `classify_mitigation()`
identifies the block class → `EvasionPlanner.evaluate()` proposes a technique → agent retries
with evasion. This is fundamentally broken for datacenter deployment because:

1. **First-request blocking.** CF/Akamai/Sucuri can block on the FIRST request based on IP
   reputation (ASN) + TLS fingerprint (JA3/JA4). There is no "N consecutive blocks" — block is
   immediate. The existing `EVASION_CONSECUTIVE_BLOCKED_N` threshold means the agent wastes N
   requests getting blocked before even TRYING evasion.
2. **Fingerprint exposure.** The first request with Python httpx TLS fingerprint and
   `Agent-Alpha-Recon` UA has already IDENTIFIED the agent to the WAF. Even if subsequent requests
   use evasion, the WAF has already logged the suspicious source IP. Some WAFs escalate blocking
   after seeing a scanner-like first impression.
3. **APT doctrine mismatch.** No professional red team operator sends a "naked" request as their
   first touch. Evasion is the DEFAULT posture from the first request — not a fallback.

**Decision.**

1. **curl_cffi as DEFAULT transport for all active target requests.**
   `HttpClient` gains a `transport_mode` parameter: `"stealth"` (curl_cffi, default for
   production) | `"raw"` (httpx, for lab/unit tests only). When `transport_mode="stealth"`:
   - TLS fingerprint = Chrome 131 (via curl_cffi `impersonate="chrome131"`)
   - This is already implemented in `reach_transport.py` as `tls_impersonate_fetch()` but
     currently used ONLY as a fallback after FINGERPRINT block. Now it becomes the DEFAULT
     transport for EVERY active request to a target.
   - Lab/test environments keep `"raw"` (httpx) for determinism and speed.

2. **Realistic browser headers as DEFAULT.**
   `HttpClient` default headers change from:
   ```
   BEFORE: User-Agent: Agent-Alpha-Recon/{engagement_id}
   AFTER:  User-Agent: <random real browser UA from a curated rotation pool>
           Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
           Accept-Language: en-US,en;q=0.9
           Accept-Encoding: gzip, deflate, br
           Connection: keep-alive
           Sec-Fetch-Dest: document
           Sec-Fetch-Mode: navigate
           Sec-Fetch-Site: none
           Sec-Fetch-User: ?1
           Upgrade-Insecure-Requests: 1
   ```
   UA rotation pool: 5-10 current Chrome/Firefox/Safari UAs on Windows/Mac, refreshed
   quarterly. Pool stored in `constants.py` (`BROWSER_UA_POOL`), selected per-engagement
   (not per-request — same browser identity throughout engagement for session consistency).

3. **Protection-aware first request (§12.48 integration).**
   When Phase 0 passive intel detects CF/Akamai/Sucuri (e.g., CF nameservers in DNS), the agent
   applies MAXIMUM evasion from the first request:
   - Origin-direct if origin IP candidates are available (§12.46)
   - curl_cffi with TLS impersonation if no origin available
   - NEVER raw httpx to a known-protected target
   When no protection is detected, curl_cffi stealth is still the default (defense in depth —
   absence of evidence ≠ evidence of absence).

4. **Reactive evasion RETAINED as escalation layer.**
   `EvasionPlanner` and `LockoutGovernor` (§12.33) are NOT removed. They become the SECOND layer:
   - Layer 1 (proactive, §12.49): stealth transport + realistic headers from first request.
   - Layer 2 (reactive, §12.33): if stealth still gets blocked → classify_mitigation →
     escalate to browser_solve/origin-direct/client-whitelist-recommendation.
   The reactive layer now has a LOWER threshold (`EVASION_CONSECUTIVE_BLOCKED_N` reduced from
   current value) since the agent is already using stealth transport — if stealth + TLS
   impersonation still triggers blocks, the mitigation class is likely CHALLENGE or RULE_DENY,
   not FINGERPRINT.

5. **OPSEC profile integration.**
   `DEFAULT_OPSEC_PROFILE` changes from `"announced"` to `"stealth"`. The `"announced"` profile
   (honest identifying UA) remains available for engagements where the client explicitly requests
   identified scanning (common in compliance/audit engagements). Profile selection via
   `EngagementProfile.opsec_profile` (§12.36).

   | Profile | UA | Transport | Pacing | Use Case |
   |---------|-----|-----------|--------|----------|
   | `stealth` | Browser rotation | curl_cffi | Human-like (§12.50) | Default, red team |
   | `announced` | `Agent-Alpha/{ver}` | httpx | Rate-limited | Compliance scan, client request |

**Clarification (2026-08-05): "stealth" default sits INSIDE the existing front-loaded consent
envelope (§12.36). "default" ≠ "authorized".** The existing `policy.yaml` defines an
`announced`/`blend` authorization pair where `blend` has `evasion: true` and
`resolve_opsec_profile()` (`conductor/policy.py:109`) already fail-closes to `announced` when
`evasion_authorized=False`. The `"stealth"` profile MUST follow the same gate — it is NOT a
third ungated path. Two options:

- **(a) Map `stealth` == `blend` semantics (PREFERRED).** `"stealth"` is the renamed/evolved
  `"blend"` profile. `policy.yaml` entry for `stealth` carries `evasion: true`. The existing
  `resolve_opsec_profile(requested, evasion_authorized=)` gate applies unchanged: `stealth`
  without `evasion_authorized=True` (i.e., `allow_evasion=False` or `opsec_stealth=False` in the
  signed EngagementProfile) → fail-closed to `announced`. The `opsec_stealth` consent flag in
  `EngagementProfile` (already wired in `authorization.py:562-573` with `ConsentRequiredError`)
  is the signed capability that authorizes the `stealth` profile. `test_opsec_profile.py` /
  `test_policy_yaml.py` expectations MUST assert: default `stealth` + no consent → `announced`
  (fail-closed), never silent authorization.

- **(b) Rename if semantics differ.** If `"stealth"` is intentionally different from `"blend"`
  (e.g., stealth = curl_cffi transport only without UA spoofing, blend = full UA+header
  spoofing), then `"stealth"` MUST be renamed to avoid conflating with the existing
  `announced`/`blend` authorization pair. A profile name that implies evasion-like behavior but
  bypasses the `evasion_authorized` gate is a silent authorization path = anti-Lyndon #3.

**The invariant:** `DEFAULT_OPSEC_PROFILE = "stealth"` means stealth is the *requested* profile,
not the *authorized* one. Without signed consent (`opsec_stealth=True` or `allow_evasion=True`
in the EngagementProfile), `resolve_opsec_profile` must fall back to `announced`. The agent never
silently operates in stealth mode without front-loaded consent.

**Event-sourced**: `EVASION_POSTURE_SELECTED` event at engagement start, recording which transport
mode, UA, and OPSEC profile are active — audit trail for "how did the agent present itself."

**Anti-Lyndon.** #3: default stealth is HONEST (a red team that looks like a scanner is
dysfunctional, not honest) — BUT "default" never means "authorized without consent" (this
clarification). #6: curl_cffi reuses existing `reach_transport.py` implementation,
not a second TLS transport. #7: UA pool is single-source in `constants.py`. #11: evasion posture
is driven by passive intel (§12.48 protection_detected), not a static flag.

### 12.50 Human-Like Behavioral Fingerprint — pacing, jitter, burst patterns — ACCEPTED (2026-08-04)

**Extends** §12.49 (proactive evasion), §12.33 (adaptive evasion). Refines the existing
`rate_limiter.py` which enforces a fixed `1/rps` interval.

**Problem.** The current `RateLimiter` guarantees `>= 1/rps` seconds between successive requests.
At `DEFAULT_RATE_LIMIT_RPS = 2.0`, this produces requests at exactly 0.5-second intervals — a
PERFECTLY PERIODIC signal that is trivially distinguishable from human browsing behavior by any
modern WAF behavioral analysis. Real browsers exhibit:
- **Burst patterns**: page load fetches 3-8 resources in rapid succession (< 100ms apart)
- **Read pauses**: 2-15 seconds between page navigations (user reading content)
- **Think pauses**: occasional 15-60 second gaps (user thinking, typing, switching tabs)
- **Session shape**: activity concentrated in bursts with long idle periods

The fixed-interval rate limiter produces a signature that correlates with automated scanning,
not human browsing.

**Decision.**

1. **Replace fixed-interval with burst-and-pause pacing.**
   New `StealthPacer` (replaces `RateLimiter` for stealth OPSEC profile):

   ```
   Pattern: [BURST] → [READ PAUSE] → [BURST] → [THINK PAUSE] → ...

   BURST:       3-5 requests with 50-200ms intervals (page + assets)
   READ PAUSE:  2-8 seconds (±20% jitter) — user reading the page
   THINK PAUSE: 10-30 seconds (±20% jitter) — occasional, every 3-5 bursts
   IDLE:        60-120 seconds — rare (every 10-15 bursts), simulates tab switch
   ```

   Each interval has ±20% random jitter (uniform distribution). Jitter is cryptographically
   seeded per-engagement (deterministic replay in tests, unpredictable in production).

2. **Burst size adapts to page context.**
   - Homepage / new host: single request (browser navigating to new site)
   - Same-host follow-up: burst of 3-5 (browser loading page + fetching linked assets)
   - This is not a cosmetic detail — WAFs correlate request count per navigation event

3. **RateLimiter retained as FLOOR.**
   `StealthPacer` wraps `RateLimiter` — the min-interval guarantee is preserved as a safety
   floor (never exceed `rps` sustained over any 10-second window). The pacer adds variability
   ON TOP of the floor, never below it. `"announced"` OPSEC profile keeps using plain
   `RateLimiter` (fixed interval is appropriate for identified scanning).

4. **Implementation location.**
   `agents/stealth_pacer.py` — new module. `HttpClient` accepts either `RateLimiter` or
   `StealthPacer` via the existing `rate_limiter` constructor parameter (duck typing: both
   expose `acquire()`). Production runner injects `StealthPacer` for stealth profile,
   `RateLimiter` for announced profile.

5. **Constants (single source, `constants.py`).**
   ```python
   STEALTH_BURST_MIN = 3
   STEALTH_BURST_MAX = 5
   STEALTH_BURST_INTERVAL_MS = (50, 200)    # min, max ms between burst requests
   STEALTH_READ_PAUSE_S = (2.0, 8.0)        # min, max seconds
   STEALTH_THINK_PAUSE_S = (10.0, 30.0)     # min, max seconds
   STEALTH_IDLE_PAUSE_S = (60.0, 120.0)     # min, max seconds
   STEALTH_THINK_EVERY_N_BURSTS = (3, 5)    # think pause frequency
   STEALTH_IDLE_EVERY_N_BURSTS = (10, 15)   # idle pause frequency
   STEALTH_JITTER_FACTOR = 0.20             # ±20%
   ```

**Anti-Lyndon.** #3: variable pacing is HONEST behavioral realism, not deception — a red team
agent that produces scanner-like traffic is a bug, not a feature. #7: all timing constants are
single-source in `constants.py`. #11: pacing is not a static pattern — burst size adapts to
navigation context (new host vs same-host follow-up).

**Amendment (2026-08-10): Target-aware pacing profile.** `StealthPacer` accepts an optional
`business_hours_profile` derived from the engagement target's timezone and industry. Recon
traffic blends with target peak hours (more bursts during active period, longer pauses
outside). Credential stuffing shifts to off-hours (SOC understaffed, alert fatigue peak).
NOT hardcoded 09:00–17:00 — the profile is target-industry-aware:
- E-commerce: weekend-active, extended evening hours
- Government/corporate: weekday 09–17, sleep weekend
- 24/7 services (hosting, fintech): always-active, blend with baseline

This is a parameter on the existing `StealthPacer`, not a new module. The default (no
`business_hours_profile` set) preserves current behavior — burst-and-pause without
time-of-day awareness. Anti-Lyndon #7: single source — the profile is defined in
`engagement.yaml` and consumed by `StealthPacer`; no second pacing module.

### 12.51 Gamma Exploit Generation — 3-Layer Hybrid Dual-Engine (PROPOSED)

**Date:** 2026-08-04
**Context:** Agent-Alpha's current architecture (Alpha/Beta) operates at the web-layer with known paths and deterministic responses. Phase Gamma (ANCHOR - Exploitation) introduces significant risk: hallucinated payloads, EDR/AV triggers, and production collateral damage. We need a safe, reliable way to synthesize novel exploits that cannot be predefined in a static playbook.

**Decisions:**
1. **Hybrid Dual-Engine Architecture:**
   - **Curated Tool Library:** For known vulnerability patterns (SQLi, SSRF, File Upload, Default Creds), use deterministic, engineered `Tool` implementations.
   - **LLM ExploitSynthesizer:** For novel/creative attacks (business logic, complex chains), use LLM-driven generation.

2. **3-Layer Exploit Synthesis (LLM Lane):**
   - **Layer 1: Constraint-Guided Generation.** The LLM is NOT given a free-form coding task. It receives a rigid constraint template containing the target context, CVE, method, and safety/EDR constraints (e.g., "NO base64, NO eval, cleanup required").
   - **Layer 2: Sandbox Verification.** Before execution, the generated payload is validated structurally (HTTP well-formed) and behaviorally (blast-radius < threshold, AV pattern check, scope bounds). Fails result in bounded LLM regeneration (max 3 cycles).
   - **Layer 3: Graduated Execution.** The payload is executed via a Dry Run (logging) -> Proof Attempt (send to target) -> Mandatory Cleanup (revert changes) -> Proof Recording (CROSS_VERIFIED).

**Anti-Lyndon:** #3 (false success): The 3-layer synthesis ensures that an exploit is structural and safe before transmission; a failure in outcome is a failed run, never a hallucinated "success". #1 (no speculative build): Gamma remains STOP-gated behind ToolComposer and blast-radius gates; this doctrine locks the design, not the code.

### 12.52 Governance Simplification & Friction Reduction (ACCEPTED)

**Date:** 2026-08-04
**Context:** Agent-Alpha's governance architecture (Celery queues, LLM Consensus, Reactive Evasion) was designed with an "enterprise scale" mindset. However, for a targeted red team agent, these layers introduce severe latency, token cost overhead, and operational friction. A nimble APT operator executes basic recon and initial access instantly, without bureaucratic "committee" decisions or excessive queue overhead.

**Decisions:**
1. **Restrict LLM Consensus (§12.1 Amendment):**
   - The `CONSENSUS_LLM` gate is now STRICTLY RESTRICTED to Phase Gamma (ANCHOR) or any action with a high blast radius (destructive/mutative actions).
   - Phase Alpha (SCOUT) and Beta (STRIKE) MUST use `RULE` (static deterministic logic) or `SINGLE_LLM` (DeepSeek V4) to eliminate latency and token overhead.

2. **Restrict Celery Fan-Out Overhead (§12.13 Amendment):**
   - Dispatching individual HTTP GET requests as separate Celery tasks is PROHIBITED due to Redis/queue round-trip latency.
   - Targeted web application recon and active probing must be executed in-process using native concurrency (`asyncio` in Python, or goroutines in Go).
   - Celery is reserved ONLY for massive-scale horizontal operations (e.g., scanning 50,000 IPs, offline hash cracking, or massive subdomain enumeration) and long-running isolated jobs.

3. **Reactive Evasion Relegation:**
   - Formalizes the decision in §12.49: The bureaucratic "wait for 5 blocks before evading" is eliminated. Stealth is the default physical reality of the agent's transport layer. The EvasionPlanner only handles high-level tactical blocks (JS Challenges, Origin Bypass).

**Anti-Lyndon:** #8 (Complexity for complexity's sake): Removing Celery overhead for simple HTTP requests and dropping LLM consensus for read-only actions makes the agent dramatically faster, cheaper, and closer to actual red team tradecraft.

### 12.53 Deep Evasion Stack (Layer 2 Evasion) (ACCEPTED)

**Date:** 2026-08-04
**Context:** While §12.49 (Proactive Evasion via `curl_cffi`) defeats basic commercial WAFs, advanced NG-WAFs and SOC analysts inspect traffic deeper: header ordering, session continuity, and IP reputation (datacenter vs residential). To mimic a legitimate user journey, the agent requires a "Deep Evasion" layer.

**Decisions:**
1. **Session Persistence (Stateful Agent):** The agent must maintain state (`http.cookiejar`, CSRF tokens) throughout a session. Humans do not drop cookies between requests; the agent must mirror this to avoid stateless bot detection.
2. **Strict Header Ordering & HTTP/2 ALPN:** HTTP headers must be sorted in the exact sequence expected by the specific browser claimed in the `BROWSER_UA_POOL` (e.g., Firefox and Chrome have different `Accept-Language` / `Accept-Encoding` orders). 
3. **Residential Proxy Hook:** The network layer must support routing configurations to exit through residential proxy pools or clean exit nodes, mitigating the inherent IP reputation penalty of attacking from Oracle/AWS datacenter IPs.

### 12.54 Deep Recon Quick Wins (Phase 0 Expansion) (ACCEPTED)

**Date:** 2026-08-04
**Context:** Standard OSINT (crt.sh, VirusTotal) maps the perimeter, but leaves high-ROI ("cheat code") vectors untouched. APT operators prioritize asymmetric intelligence gathering before touching the target.
**Decisions:**
Extend Phase 0 (Passive Recon) with two high-value, low-noise OSINT sources:
1. **Wayback Machine (Historical Endpoints):** Query `web.archive.org` to find forgotten APIs or legacy endpoints (e.g., `/api/v1/old_login.php`) that might bypass modern WAF rules or lack authentication. Zero touch to the target.
2. **Credential Breach OSINT (Dehashed/HIBP):** Query breach databases for the target's domain. Gaining valid or historical credentials bypasses all WAF complexities. If credentials are found, the agent transitions to Phase Beta (STRIKE) for credential validation.
**Constraint:** Cloud storage enumeration (S3/Azure) is deferred to a future slice. GitHub/Source Code OSINT is explicitly rejected for this phase due to high noise (false positives) and compute overhead.

### 12.55 Doctrine of Realistic Exploitation (The 1-Day Standard) (ACCEPTED)

**Date:** 2026-08-04
**Context:** Can the agent find 0-days? Autonomous 0-day hunting in a blackbox web environment is an over-engineered hallucination trap. LLMs struggle to find novel 0-days without whitebox access (source code/fuzzer logs) and burn massive token budgets.
**Decisions:**
1. **No Blackbox 0-Day Hunting:** Agent-Alpha is explicitly prohibited from attempting to "discover" novel 0-day vulnerabilities via blind blackbox guessing.
2. **1-Day & Misconfiguration Focus:** The agent operates strictly as an ultimate weaponizer of known patterns. It focuses on 1-day exploits (unpatched known CVEs) and configuration flaws (exposed `.bak` files, default credentials).
3. **Real-time Threat Intelligence:** To execute 1-days effectively, the agent's `IntelligenceBase` must integrate or query real-time vulnerability databases (NVD/CVE/VulnCheck/ExploitDB) to map detected tech stack versions to known exploits.
4. **ToolComposer Constraint:** The ExploitSynthesizer (Gamma) does not invent exploits from scratch. It takes a known CVE PoC or template and *adapts* it to the target's specific context (adjusting payload encoding, evading WAF signatures).

### 12.56 Passive Supply Chain Recon & Assume Breach (ACCEPTED)

**Date:** 2026-08-05
**Context:** APTs like Cozy Bear frequently use supply chain attacks (compromising 3rd-party vendors) rather than attacking hardened targets directly.
**Decisions:**
Agent-Alpha is strictly forbidden from actively hacking 3rd-party vendors, as this is illegal and outside commercial SOWs. However, Agent-Alpha MUST simulate supply chain threats ethically through three approved vectors (to be built in future Phase 0 slices):
1. **Passive Dependency & Asset Hijacking:** Detect client negligence in managing vendor assets. This includes *Subdomain Takeovers* (e.g., forgotten Zendesk CNAMEs) and *Poisoned CDNs* (detecting HTML/JS loading deprecated/compromised 3rd-party scripts like `polyfill.io`).
2. **Dependency OSINT (Software Composition Analysis):** Parse exposed `package.json`, `pom.xml`, or HTTP headers to identify vulnerable 3rd-party libraries (e.g., outdated jQuery or Log4j) without touching the vendor's servers.
3. **Assume Breach Mode (Future Phase):** For internal or authorized scenarios, Agent-Alpha will support starting from an artificially compromised state (low-level credentials) to simulate a vendor breach and attempt lateral movement/privilege escalation.
**Constraint:** These vectors are officially part of the Phase 0 (Recon) and Epsilon (Lateral) doctrines, but their code implementation is queued *after* the core foundation (Slices 1-6) is complete.


### 12.57 Alpha as a Gate-Respecting Operator — Closed Feedback Loop (ACCEPTED)

**Date:** 2026-08-08
**Context:** Field-prove on alpha-ai (T4 MOAT PASS) + an APT-operator behaviour audit
(8 log-grounded "teguran") showed Alpha behaves closer to a *scanner with APT techniques*
than an *operator*: it probes, persists, and continues — findings accumulate but do not steer
subsequent behaviour. Verified against code, this is an **INCOMPLETE feedback loop, NOT an absent
one**: Alpha already has fingerprint→`frontier_seeds` (`_handle_capability_fingerprint`),
dead-end `try_harder`, `EvasionPlanner` consecutive-BLOCKED exhaustion, a deterministic rule-tier
(runs when the LLM declines), and the Bug #26 `protection_detected` spray-suppressor. What is
missing is the rest of the loop.

**Decision — Alpha becomes an operator by CLOSING the feedback loop, gate-respecting.**
The four operator behaviours are adopted, each mapped so it NEVER crosses the Conductor auth gate:

1. **Finding → action (recon-side, gated hand-off).** A jackpot finding triggers *immediate
   RECON follow-through IN Alpha* — deterministic secret extraction (regex, not LLM) → CREDENTIAL
   node → correlation with other findings — producing a HOT, prioritised hand-off. The
   recon→ACCESS pivot (e.g. cred-reuse to Odoo) is dispatched to **Beta at the gated Alpha→Beta
   hand-off**, never by Alpha. Alpha is `RECON_ONLY`; initial access is Beta + `ACTIVE_APPROVED`
   (see non-negotiable "Auth gate in Conductor only"). Autonomous end-to-end proof is tracked as
   the OdooAccessTool autonomous-win debt.
2. **Mid-engagement pattern learning.** N consecutive 404 on a path pattern-group (`.env*`) →
   skip the rest of the group, on this host and (if the stack differs) other hosts. Deterministic
   counter, extends the `EvasionPlanner` consecutive pattern (anti-#6). Cross-engagement learning
   (IntelligenceBase) stays deferred. → GAP-020.
3. **Fingerprint drives path selection (hard-filter, not just add).** A confirmed stack must
   REMOVE irrelevant generic paths, not only add stack-specific ones. Static list filtered by
   fingerprint — simple, deterministic, no dynamic path generation. → GAP-021.
4. **Strategy pivot on failure (bounded, playbook-driven).** Recon-side already = `try_harder`;
   access-side pivots are playbook-defined alternatives in a deterministic order, **bounded (≤3),
   never infinite retry, never LLM "what next"**. → Beta concern, tracked.

**Rejected alternative — event-driven parallel pivot (DEFERRED to Phase 5+).** The proposal
"Conductor dispatches Beta the instant a finding lands, mid-recon, in parallel with Alpha" is NOT
adopted for Phase 4 because: (a) mid-recon the engagement is `RECON_ONLY` — Beta needs
`ACTIVE_APPROVED`, an elevation that is a consent/human step (cannot be "immediate"); (b)
Alpha-still-running + Beta-acting on one engagement = agent concurrency that brushes the
"no mutable shared state between agents" non-negotiable; (c) premature — the field run completes in
~6.5 min, recon is not the bottleneck; the real gap is the autonomous chain being unproven, not
hand-off timing. Phase 4 uses the **phase-level gated hand-off** (Alpha completes recon →
Conductor advances → Beta). Revisit event-driven pivot only when parallel agents / fan-out land.

**Rejected — an LLM "judgment layer".** Risk/honeypot/target-priority hooks are premature and
hallucination-prone. The LLM stays in ORIENT (hypothesis about a response), never in DECIDE
("what should I do next"); DECIDE is deterministic + playbook-driven.

**Constraint:** All four are recon-quality / hand-off-quality improvements within the existing
phase + auth model — zero new offensive capability, zero gate change, zero new recon *vector*
(they reduce waste, they do not add breadth). Concrete slices: GAP-020 → GAP-021 → GAP-022.

### 12.58 Strategic Situation Reasoning ("operator instinct") (PROPOSED / SEED)

> Status: **PROPOSED — seed for a dedicated session.** Number §12.58 provisional
> (confirm next-free on commit). Do NOT implement until this ADR is ACCEPTED and a
> single first-slice scope is agreed. Captured 2026-08-09.

**Context (the problem, first-principles).**

Field runs (niagamas, bernofarm) show Agent-Alpha behaving mechanically: it grinds a
per-target work queue and never "reads the board." Concretely:
- The cognitive loop is per-target (OBSERVE→ORIENT→PLAN→ACT→VERIFY→PERSIST); routing is
  a pure function of graph predicates (`route_next`).
- The only global-state awareness is stall/no_progress detection (BoundedAutonomy /
  `work_remaining`). There is **no strategic reprioritization**.
- Result: when all primary targets are unreachable/hardened, the agent does NOT pivot to
  a reachable/softer target; it does not skip dead hosts; it does not act on identities it
  already harvested. A human operator continuously reassesses ("front is hard → flank").

This is the through-line of every gap this session: no soft-door pivot, dropped usernames,
Beta targeting the dead apex instead of the reachable surface.

**Reframe (important):** what is missing is NOT "awareness/consciousness/instinct". It is a
concrete, buildable capability: a **deterministic strategic control-loop + heuristic
reprioritization of the work queue**. "APT instinct" = experience-encoded pattern
heuristics (dead host → skip; hard front → find flank; have creds → reuse). These are
deterministic rules, NOT reasoning that requires an LLM.

**Decision (proposed shape).**

1. **Deterministic, not LLM.** Strategic DECIDE stays deterministic. ADR §12.57 already
   REJECTED an "LLM judgment layer" (hallucination-prone; LLM stays in ORIENT). A
   SituationAssessor that "reasons strategically" via LLM is out of scope by prior decision.

2. **Incremental instincts, not a framework up-front.** Do NOT build SituationAssessor +
   StrategyAdjustment type + periodic hook + queue-wire + tests in one go — that is
   feature-before-foundation (#1) + premature abstraction (#4) + a god-component risk.
   Build ONE concrete deterministic heuristic first; extract the `SituationAssessor`
   container only when 2–3 instincts exist (promotion-on-repeat — same discipline used for
   the reach wrapper and the path_probe catalog).

3. **First instinct = entry-selection / dead-target pivot.** Reprioritize the strike/recon
   frontier by (reachability + softness + value); skip WAF-confirmed-dead targets in favour
   of reachable ones. This is exactly the niagamas failure AND the already-queued
   entry-selection slice (Beta strikes the reachable auth surface, not the dead apex).

4. **Trigger-driven, not heavy periodic (initially).** Reassess on concrete triggers
   (target unreachable / WAF_BLOCKED / stall / new auth-surface found), not a costly
   periodic strategic pass. Cadence/cost of any true "periodic" assessment is an open
   question for the ADR.

**Component sketch (for WHEN it is promoted — NOT a build order).**

- `InstinctRules` — deterministic meta-heuristics (pure functions over graph + frontier +
  reach evidence). One rule per instinct. No LLM.
- `StrategyAdjustment` — canonical output type (e.g. reprioritize(target, delta),
  skip(target), pivot(from,to)). Do NOT create until ≥2 adjustments exist.
- Hook into `run_cognitive_loop` — trigger-based assessment; deterministic; testable.
- Hook into the work queue / frontier — apply adjustments (reprioritize/skip). This is the
  highest-value concrete piece.

**Rejected / guarded.**

- **LLM strategic brain** — rejected (§12.57).
- **Big-bang SituationAssessor framework before a proven instinct** — rejected
  (feature-before-foundation, premature abstraction).
- **Per-target hardcoded behaviour** (e.g. niagamas-specific) — rejected (#11); every rule
  must be universal across clients.

**Open questions (resolve in the dedicated session before building).**

1. Trigger set vs periodic cadence (cost, determinism, replay-stability).
2. How reprioritization composes with BoundedAutonomy stall semantics + the frontier order
   (must not starve the live target — cf. the §ADR bounded-autonomy stall fix).
3. Reprioritization signal: reachability (WAF_BLOCKED evidence) + softness
   (protection_detected — currently producer-only, would need consumption) + value
   (auth-surface / harvested-cred proximity).
4. Determinism + seeded replay for tests.

**Cardinal test contract (first slice).**

- GIVEN a graph where every primary target is WAF-confirmed unreachable AND one in-scope
  subdomain is reachable (auth surface),
- WHEN the strategic reprioritization runs,
- THEN the reachable subdomain is selected/struck and the dead apex is skipped
  (deterministic, no LLM). Universal — synthetic hosts, no per-client logic.

**Field evidence backing this ADR.**

- niagamas: apex CF-hard + unreachable; `hub` (401 basic-auth) + `pos` (Laravel login)
  reachable — agent did not pivot to them; Beta targeted the dead apex.
- bernofarm: same mechanical, non-pivoting behaviour.

### 12.59 Hybrid Cognition Roadmap — deterministic-first, LLM-in-DECIDE as Phase-6 OPEN (ACCEPTED, Phase-6 OPEN)

**Date:** 2026-08-09
**Supersedes/extends:** operationalises §12.58 (operator instinct) into a phased build
order; re-affirms §12.57 (LLM stays in ORIENT, never DECIDE) for Phases 4–5.

**Context (the first-principles question).**

The operator asked, correctly, whether *pure deterministic rules can ever behave like a
human APT operator* — "even adding 6 steps, deterministic rules won't feel human." The claim
is HALF right, and the precision decides the architecture. Two layers were being conflated:

- **CONTROL layer (DECIDE)** — read the board, flank when the front is hard, reuse creds,
  skip dead hosts, pivot to a live surface. This is exactly what makes an agent feel like it
  "has a way of thinking" — and it is **fully deterministic-expressible** (the §12.58 thesis).
  Today's robot-feel is NOT the absence of an LLM here; it is the **absence of the
  deterministic control loop** (now being built, one instinct at a time). Putting an LLM in
  DECIDE is precisely what §12.57 rejected (hallucination on offensive targeting).
- **HYPOTHESIS layer (ORIENT)** — inventing a hypothesis outside the playbook ("this odd
  response smells like misconfig X, try Y"). This is where determinism genuinely has a
  ceiling — and where the LLM **already lives** per §12.57.

Conclusion: the layer that needs more-than-deterministic is already LLM-backed (ORIENT); the
layer the operator wanted to add an LLM to (DECIDE) is where determinism is a STRENGTH
(reproducible, gate-safe, Oracle seeded-replay) and an LLM is a LIABILITY. A great APT
operator is not random in execution — the discipline is deterministic; the creativity is in
hypothesis, not in gate execution.

**Decision — a three-phase hybrid, deterministic-first.**

1. **Phase 4 — deterministic instincts, one at a time (ACCEPTED).** Build & FIELD-PROVE each
   instinct as a plain deterministic rule before the next: entry-selection (Beta strikes the
   reachable auth-surface, not the dead apex — instinct #1, ADR §12.58 cardinal test), then
   dead-target pivot, then cred-reuse. No container, no framework, no LLM in DECIDE. Each
   instinct is a pure function, seeded-replay stable, Oracle-sealed.
2. **Phase 5 — promote to `SituationAssessor` (ACCEPTED, still deterministic).** Only when
   3–5 instincts exist, extract the container (promotion-on-repeat, the discipline used for
   the reach wrapper and path_probe catalog). Still deterministic; still no LLM in DECIDE.
3. **Phase 6 — LLM advisor in DECIDE (OPEN QUESTION, NOT a locked decision).** Candidate
   only. Banked with an **empirical trigger**: after `SituationAssessor` is stable, if the
   agent STILL feels robotic ON THE CONTROL LAYER, that is the evidence to reconsider an
   LLM-propose / deterministic-validate structure — with data, not a hunch. If the residual
   ceiling is in ORIENT (the likely case), strengthen the existing ORIENT LLM instead of
   moving the LLM into DECIDE.

**Why Phase 6 is OPEN, not ACCEPTED (the flaw in "LLM propose, validator approve").**

"LLM proposes, a deterministic validator approves/rejects" is defensible in principle
(final authority stays deterministic) BUT is not a free lunch relabel of §12.57:

- The validator only ADDS value if the LLM proposes something OUTSIDE the deterministic menu.
  If the validator has a deterministic preference ordering strong enough to rank proposals,
  the LLM was unnecessary (the ranker already decides). If the validator only checks
  "legal / passes gates", then across all legal-but-wasteful options the **LLM effectively
  steers** — which re-enters the §12.57 hallucination risk. This circularity must be resolved
  before Phase 6 is accepted.
- Any LLM in the live loop breaks seeded-replay unless decisions are recorded and replayed
  (real engineering debt for Oracle seals).

**Two hard conditions IF Phase 6 is ever opened.**

1. The LLM only earns its place by proposing outside the deterministic menu; the validator
   must then have an **independent oracle** to judge that proposal's quality, not merely its
   legality (else = §12.57 by the back door).
2. Full **record-and-replay** of every LLM proposal + validator verdict, so Oracle seals stay
   reproducible (anti-#3/#9).

**Rejected / guarded.**

- **LLM in DECIDE during Phase 4–5** — rejected (§12.57; determinism is the strength there).
- **Locking the Phase-6 LLM architecture now** — rejected (#1/#5: deciding a 2-phase-out
  architecture before a single instinct is field-proven; §12.58 forbids designing the
  container before the instincts exist — this is one step further out).
- **Periodic strategic assessment** — NOT rejected; deferred (§12.58 open question #1).
  Trigger-driven first; cadence/cost of any true periodic pass revisited at Phase 5.

**Open questions (resolve before Phase 6, not now).**

1. Does the LLM ever propose a CONTROL action the deterministic layer wouldn't — with a
   measurable win — after 3–5 instincts exist? (The empirical trigger.)
2. Independent-oracle design for validating out-of-menu proposals.
3. Record-and-replay mechanics for LLM-in-loop under Oracle seals.

**Cardinal discipline (carried from §12.58).** One vertical slice at a time; instinct proven
in the field before the next; container by promotion, not up-front; the auth gate
(§12.57 non-negotiable) is never softened by any cognition layer.

### 12.60 Two-Tier Proof + Field-Feedback Ratchet — lab-green is not field-ready (ACCEPTED)

**Date:** 2026-08-09
**Extends:** the Independent Verification Axiom + Lyndon #9 (wrong test environment) to their
deeper reading: **lab vs field**, not merely Windows vs Oracle.

**Context (the observed failure).**

Across the entry-selection arc, EVERY gap (GAP-029 dead-host, GAP-030 Vue login regex,
GAP-036 LLM tool-pick, GAP-037 no basic-auth applicator, GAP-038 WP-only username harvest,
soft-404 false positives) was found by the FIELD (niagamas, bernofarm, ingco.co.id), never by
the lab. The lab stayed green throughout. Root cause: **a lab is built to MATCH the capability,
so it omits exactly what the capability omits.** Passing it proves "the code does what the code
was written to do" — internal consistency, same failure mode as the finder — which the
Independent Verification Axiom says is NOT verification. Lab-green ≠ field-ready. This is also
the mechanism behind Natanael's frustration #5 (endless bug-fixing, no milestone): the field
keeps surfacing the next omission forever, because nothing turns a field failure into a
permanent guard.

**Decision — proof is two-tier, and every field failure ratchets into the lab.**

1. **Tier-1 (lab-seal) = reproducibility. NECESSARY, NOT SUFFICIENT.** Deterministic,
   seeded-replay, Oracle ARM64. NEW RULE: a capability's Tier-1 fixture MUST include the
   adversarial shapes the field has already shown for that capability class — not only the
   happy path. (Login detection → fixture carries Vue-bound + basic-auth + static together.)
   Tier-1 alone may NOT back a "done"/"field-ready" claim.

2. **Tier-2 (field-prove) = THE BAR.** A capability is "field-proven + payable" only after it
   runs on a real / self-owned hostile target. Self-owned full-CF (alpha-ai) for capabilities
   needing full attack; real clients for recon/auth-gated. Registered per-capability.
   Self-owned lab targets (wp_lab, alpha-ai) are Tier-1.5 — closer than a unit fixture, still
   not the uncontrolled field.

3. **Field-Feedback Ratchet (the enforced mechanism).** Every field failure is captured as a
   PERMANENT synthetic adversarial fixture in Tier-1 — promotion-on-repeat at the TEST layer.
   ingco dead-subdomain topology, niagamas dead-apex, pos Vue-login, hub basic-auth-only,
   bernofarm full-CF → each becomes a named fixture. Enforced like the wiring-gate: a
   `tests/governance/test_field_regression.py` (or per-phase field-fixture corpus) so a fixed
   field bug can NEVER silently regress AND the lab corpus grows toward field realism. Over
   time, Tier-1 green starts to MEAN field-ready — because the lab now contains the field's
   nastiness. Milestone = "survives the hostile corpus", not "unit tests pass".

**Consequences.**

- "Sealed" now has a tier: `lab-sealed` < `field-proven`. Session_Handoff and the ledger state
  which tier a capability is at (mirrors verified tri-state unverified<self_verified<cross_verified).
- Every NEW slice this session forward carries BOTH: a Tier-1 fixture that includes the field
  shape that motivated it, AND a Tier-2 field-prove note (which target, expected observable).
- The field-regression corpus is the anti-#5 milestone: it only grows, never silently shrinks.

**Rejected / guarded.**

- **Lab-green = done** — rejected (the failure this ADR names).
- **Skip Tier-1, only field-test** — rejected (field runs are not seeded-replay reproducible;
  Oracle determinism still required; a field win with no fixture regresses next refactor).
- **A giant field-simulation framework up-front** — rejected (#1/#4). The corpus grows ONE
  fixture per real field failure (promotion-on-repeat), never speculatively.

**Open questions.**

1. Fixture fidelity: how much of a hostile field topology (CF challenge, LiteSpeed 403,
   reflected soft-404) can be synthesised deterministically vs needs a live target?
2. Tier-2 cadence for real clients under the auth gate (recon-only vs authorized attack).
3. Where the field-regression corpus lives (one governance file vs per-phase) and its ratchet
   test shape.


### 12.61 Flank-when-CF-hard — origin-discovery breadth (ACCEPTED, menu)

**Date:** 2026-08-09
**Extends:** §12.58 (operator instinct: "front hard → flank") + §12.60 (two-tier proof) +
the banked doctrine "stop beating full-CF apex from datacenter IP; the moat = origin-exposure
bypass; bernofarm success = find a REACHABLE non-CF surface."

**Context (field pattern).** Four recent field targets — niagamas (apex full-CF), bernofarm
(full-CF), ibudanbalita (full-CF + CloudFront), busonlineticket (Sucuri) — were all logged as
"CF ceiling." Verified: on ibudanbalita, origin discovery yielded 0 candidates (crt.sh failed +
CF hides origin) → Beta correctly declined (fail-closed). The proven wins (alpha-ai origin-direct,
solusibersama Cloudways) were on targets with an EXPOSED origin/surface.

**Reframe (first-principles APT).** The CF "ceiling" is NARROWER than assumed. The true ceiling
is only **bruteing the CF edge itself** (interactive challenge-solve + IP-reputation from a
datacenter IP = residential/mobile proxy = INFRA, correctly deferred). An operator never gedors
the hardened front door — they FLANK. Two axes, mostly PASSIVE / datacenter-friendly:

- **A. Find the ORIGIN (go around CF, not through it):**
  1. **Historical DNS** (SecurityTrails/DNSHistory) — the A-record BEFORE CF was fronted; origin
     IP often unchanged. HIGHEST leverage, passive. (Agent today: only crt.sh/VT/OTX — which
     FAILED on these targets. This is the biggest missing signal.)
  2. **Mail/MX/SPF** — mail servers usually on origin infra, not CF → origin netblock. Passive.
  3. **Cert / favicon / title pivot** (Shodan/Censys) — search IPv4 for a host serving the
     target's exact favicon-hash / cert / title → the origin directly. Passive (API).
  4. **Grey-cloud / DNS-only records + forgotten subdomains** (dev/staging/cpanel/legacy) —
     often not proxied → direct origin. (Enum exists; the filter "which is non-CF/origin" is the value.)
- **B. Skip the perimeter (don't need the origin) — the login is reachable THROUGH CF:**
  5. **Leaked credentials** (breach data for the org email domain) → credential-stuff the
     CF-fronted login. Valid creds walk through CF. The #1 real-APT initial-access vector.
  6. **Exposed secrets in public code** (org + devs' GitHub/GitLab) — API keys, DB creds, .env,
     hardcoded origin IPs. Passive OSINT.
  7. **Public cloud storage** (S3/GCS/Azure from org name) — often public, no CF.
  8. **Subdomain takeover** (dangling CNAME) — passive-discoverable, claimable.

**Decision.** Adopt origin-discovery/perimeter-skip breadth as the next **deterministic instinct
territory** ("front CF-hard → flank"), built as a MENU under §12.58/§12.59 discipline:

1. **One slice at a time, promotion-on-repeat.** Do NOT build all of A1–B8. Recommended order by
   leverage: **(1) Historical DNS origin discovery** (passive, extends the moat, most likely to
   open niagamas/bernofarm) → **(2) cert/favicon pivot** → **(3) leaked-cred stuffing** (axis B).
2. **The moat is COMPOSITION + PROOF, not API-wrapping** (anti frustration #6). Value = orchestrate
   the signals into a PROVEN origin-exposure chain, then hit the origin via the existing two-proof
   binding — NOT another lookup wrapper.
3. **Auth model unchanged (non-negotiable).** A discovered origin still requires the two proofs
   (domain-ownership + origin-binding). Credential-stuffing requires an in-scope login + the
   existing lockout-governor + consent. No gate softened.
4. **§12.60 two-tier.** Each technique carries a field-shaped Tier-1 fixture + a Tier-2 field-prove
   (re-run niagamas/bernofarm) — a technique is "done" only when it opens a real target, not a lab.

**Product framing (SEA market).** For a full-CF target with NO exposed origin, the honest outcome
is NOT "failure" — it is a **defensive-validation deliverable**: "your edge/WAF held N techniques
from a datacenter-IP attacker; here is what WOULD expose you." Payable without a breach; answers the
SEA market's actual question ("seberapa kuat proteksi kami"). (See the CF-ceiling honest-outcome gap.)

**Rejected / guarded.**
- **Brute the CF edge (challenge-solve, IP-rep evasion) from a datacenter IP** — deferred (INFRA
  ceiling: residential/mobile proxy = procurement, not a code slice).
- **Build-all origin-discovery framework up-front** — rejected (#1/#5; menu + promotion-on-repeat).
- **Per-target hardcoded discovery** — rejected (#11; every technique universal, signals-driven).
- **API-wrapper-as-value** — rejected (frustration #6; the moat is composition + proof).

**Open questions.** (1) External-API dependency/cost policy for SecurityTrails/Shodan/Censys
(keyless fallbacks + budget). (2) How the flank instinct composes with entry-selection + §12.58
reprioritization (a fronted-apex host with a discovered origin should re-enter the strike frontier).
(3) Breach-data source legality/scope for axis-B leaked-cred stuffing.

**Cardinal (first slice — historical DNS).** GIVEN a full-CF apex whose crt.sh yields nothing but
whose historical A-record points at a still-live origin IP, WHEN origin discovery runs, THEN the
historical IP is surfaced as a candidate and (two-proof-bound) becomes strike-reachable — proven on
a real full-CF target (Tier-2), not a lab.


### 12.62 Human Interaction Simulation for browser_solve path (PROPOSED — DEFERRED)

**Date:** 2026-08-10
**Extends:** §12.49 (proactive evasion), §12.53 (deep evasion stack).
**Related:** GAP-049 (header contradiction fix — PR #396).

**Context.** Advanced bot detection systems (hCaptcha, Turnstile, DataDome,
Akamai Bot Manager with interaction analysis) inspect not only TLS fingerprints
and headers but also behavioral signals: mouse movement patterns, scroll
behavior, click timing, and focus/blur events. curl_cffi defeats fingerprint-
level detection (JA4/Akamai match), but cannot produce interaction signals
because it does not execute JavaScript or render a page.

**Decision.** DEFERRED. Human interaction simulation (random mouse paths, scroll
patterns, click jitter) is a valid technique but is scoped to the `browser_solve`
path ONLY — never the recon path. Building it now is premature:

1. **Recon via browser destroys §12.49 stealth.** A real browser executes JS,
   exposing canvas/WebGL/font fingerprints that curl_cffi does not. For recon
   (the majority of requests), curl_cffi is STEALTHIER than a browser.
2. **Browser path is exception, not default.** `browser_solve_viable` is a
   fallback for CHALLENGE-class mitigation only. Most engagements never reach it.
3. **Cost is disproportionate.** Browser automation with interaction simulation
   is 100x slower than HTTP GET. Engagements that do not need it would pay the
   cost for no benefit.
4. **No target has required it yet.** Agent-Alpha's field targets (niagamas,
   bernofarm, ibudanbalita, alpha-ai) were all handled by curl_cffi stealth or
   origin-direct bypass. Building interaction simulation speculatively is
   Lyndon #1 (feature before foundation).

**Promotion gate.** This ADR becomes ACTIVE when a field engagement hits a target
that:
- Uses hCaptcha/Turnstile/DataDome with interaction analysis, AND
- Cannot be bypassed via origin-direct (§12.46) or credential reuse (§12.61 axis B)

Until then, it is recorded here to preserve the design intent without building
dead code.

**Scope when activated.**
- `browser_solve` path only: Camoufox/Playwright with mouse movement simulation
- Random bezier-curve mouse paths (not straight-line — straight lines are a bot signal)
- Scroll patterns with variable speed and direction changes
- Click timing with human-like jitter (200-800ms between action and click)
- Never applied to recon probes — recon stays curl_cffi

**Anti-Lyndon.** #1 (feature before foundation — deferred until a target requires
it). #4 (generic architecture — scoped to browser_solve, not recon). #5 (scope
creep — not built until promotion gate triggers). #7 (single source — interaction
patterns defined in one module, not scattered).


