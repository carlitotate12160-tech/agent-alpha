# Agent-Alpha — ADR Summary (Decision Map)

> **Purpose.** Token-cheap map of every architectural decision for Claude project
> context. Full rationale + detail lives in `ADR_ROADMAP.md` (repo only). When a
> section is needed in depth, paste that specific §N from the full ADR into chat.
> This file is the index; it is intentionally NOT the source of truth.

**Mirrors:** `ADR_ROADMAP.md` v1.1 (LOCKED, append-only). If conflict → full ADR wins.

---

## §0 Design Principles (First Principles)

- Authorization is the foundation, not a feature.
- One agent, one responsibility; handoff is a data contract, not a side-effect.
- Autonomous after authorization (checked once in Conductor).
- Proof over claims (proof-of-exploitation required).
- Reasoning over durable state (AttackGraph = single source of truth), not hidden state.
- Bounded autonomy (iterations/time/cost/scope guardrails).
- Event-sourced truth (state = projection of append-only event stream).
- Learn, don't self-rewrite (improve via data/playbook, never modify own code).
- Safety layer immutable to the agent (auth, kill switch, audit, policy).

## §1 Authorization Layer (non-negotiable, Conductor-only)

Written-auth/SOW upload, explicit scope, tiered states
(RECON_ONLY → ACTIVE_APPROVED → OFFENSIVE_APPROVED), emergency stop, immutable
audit log, blast-radius calculator + human gate, hard-limit enforcement.

## §2 Final Decisions

| Item | Value |
|------|-------|
| Domain | Security-only, Level 1-6, authorized engagement (SOW for Level 4+) |
| AI Brain | Python 3.12 (reasoning, memory, graph, reporting) |
| Exec Engine | Go (network-heavy agents + deployable tools) |
| IPC | gRPC (Python ↔ Go); A2A = structured English JSON |
| Orchestration | Celery + Redis (non-blocking, multi-tenant queues) |
| Memory | Redis (session) + PostgreSQL + pgvector (long-term/semantic) |
| Deploy | Oracle Cloud ARM64 (only valid test env) |
| Multi-LLM | Parallel consensus (DeepSeek + secondary) critical; single-LLM light |

## §3 Agents

Conductor (orchestrator) → Alpha SCOUT → Beta STRIKE → Gamma ANCHOR →
Delta HUNTER → Epsilon SCOUT-HUNTER → Omega ROASTER. Agents never call each
other directly; all transitions via Conductor (validates contract + auth state).

## §4 Memory (4-layer)

SessionMemory (Redis, volatile) · EngagementMemory (PostgreSQL, permanent) ·
IntelligenceBase (pgvector, cross-engagement learning) · UserMemory (style/lang).

## §5–§7 Differentiators

ToolComposer (runtime exploit composition from template + SCOUT context) ·
AttackGraph (node/edge story, find_critical_paths, blast_radius, to_narrative) ·
Parallel attack paths · "Try Harder" agent · structured prompt from graph facts.

## §8 NodeZero-derived additions (titles)

VERIFY/re-test mode · continuous engagement · impact-based prioritization ·
safe-in-production guardrails · proof artifacts · conversation caching (8a) ·
finding-level memory (8b) · learning loop/outcome tagging (8c) ·
multi-LLM consensus (8d) · engagement profiles (8e) · pivot-chain tracking (8f) ·
OS-as-tools/LOLBin (8g) · cognitive loop OBSERVE→PERSIST (8j) ·
inner monologue + scratchpad (8j-2) · LLM role split (8k) ·
platform security/prompt-injection defense (8l) · reliability/checkpoint (8m) ·
reporting standards/RoE (8n).

## §8o Foundational Spine

- 8o-1 Event-sourced core + CQRS (backbone; projections = graph/audit/metrics).
- 8o-2 Cognition layer (planner/executor + world model + simulation/dry-run).
- 8o-3 Knowledge ingestion pipeline (RAG over CVE/exploit-db/ATT&CK; Phase 6).
- 8o-4 Tool registry + version pinning + determinism (seed/temp recorded).
- 8o-5 Policy-as-Code + blackboard coordination.
- 8o-6 Adaptive learning L1 = judgment, NOT self-modifying code (explicit out-of-scope).

## §9 Roadmap (phase one-liners)

- **P0** Foundation: Conductor, auth state machine, SOW, emergency stop, event core, policy-as-code, secrets vault. *(complete)*
- **P1** Memory + AttackGraph as event projection; finding auto-linking; durable PostgreSQL event backend + engagement-level resume.
- **P2** Alpha→Omega end-to-end (RECON_ONLY); cognitive loop; differential test; real-target gate; static YAML playbook.
- **P3** Beta STRIKE; Celery non-blocking; LLM consensus + role split; step-level checkpoint/resume.
- **P4 / 4b** Gamma ANCHOR + ToolComposer + proof artifacts; advanced cognition (simulation, registry).
- **P5** Delta + Epsilon; pivot-chain; LOLBin; parallel paths; AD (GOAD).
- **P6 / 6b** IntelligenceBase learning; reflection/playbook; RAG; VERIFY mode; extra profiles; benchmark/observability.
- **P7** Port network-heavy agents to Go.

## §11 Key Risks → Mitigations (one-liners)

Legal/abuse → auth + immutable audit · blast radius → calculator + human gate ·
hallucination → structured prompt from graph · prompt injection → trusted/untrusted
separation · LLM refusal → role split (payload→DeepSeek/Kimi/SWE-1.6/XAI/Gemini/Sonnet/GPT, all models allowed) · data leak → redaction +
self-host · runaway cost → stop conditions + budget cap · over-engineering learning
→ no self-modifying code.

## §12 Addendum v1.1 — LOCKED (append-only)

All threshold numbers live in `config/constants.py` (single source of truth, §8o-4).

- **12.0** 2-layer hybrid (deterministic + adaptive). HARD PROHIBITION: no static/linear step list in agent code; `next_action = f(graph + playbook)`.
- **12.1** Two-phase LLM gate: `RULE` / `SINGLE_LLM` / `CONSENSUS_LLM`.
- **12.2** Differential test (Phase 2 exit): different fingerprint → different path, else TEST FAIL.
- **12.3** Real-target gate: GCP free-tier isolated labs, firewall to agent IP only, 3 fingerprints, FP < 20%.
- **12.4** RAG timing: Phase 2 = static YAML playbook; full RAG = Phase 6.
- **12.5** Learning storage: event-sourced; metrics→DB table, playbooks→markdown; all data/config not code.
- **12.6** Playbook vetting: low-risk auto-promote; risky offensive needs manual review.
- **12.7** "Similar target" = weighted composite (tech_stack + protection primary).
- **12.8** Tool reliability: score data-driven, threshold hardcoded; agent never edits thresholds.
- **12.9** Playbook promotion: ≥N successes across ≥M different targets + Wilson lower-bound.
- **12.10** Dev workflow: platform code → Claude; payload bodies in `templates/*` → DeepSeek/Kimi/SWE-1.6/XAI/Gemini/Sonnet/GPT, NEVER Claude.
- **12.11** Durability/resume: durable append-only event log = source of truth; graph/Redis volatile (rebuilt via replay). Staged resume (engagement-level P1, step-level P3). Interrupted offensive action = RE-VERIFY, never re-execute.
- **12.12** GraphStore abstraction: swappable graph engine (NetworkX P0-3, Memgraph/Neo4j P4+), always a projection of the event log.
