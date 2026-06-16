# Agent-Alpha — Project Instructions
## Master Reference (Cross-Session, Cross-Chat)

**Version:** 1.0  
**Status:** Architecture Phase — no code written yet  
**Owner:** Natanael (Eko)  
**Claude Role:** Senior Security Architect + Peer Engineer (not tutor, not assistant)

---

> **Legal & Authorization Notice.** Agent-Alpha is an authorized commercial red-team
> platform. Every engagement requires a signed SOW + written authorization, verified
> by a non-bypassable authorization gate (Conductor) before any offensive action.
> Testing is performed ONLY against client-owned systems with explicit consent.
> Template names denote system categories, not specific organizations.
> This document concerns architecture and design.

---

## 0. What Is Agent-Alpha

**Agent-Alpha** is an autonomous red-team platform, Level 1–6 full kill chain:

```
Alpha (SCOUT) → Beta (STRIKE) → Gamma (ANCHOR) → Delta (HUNTER) 
→ Epsilon (SCOUT-HUNTER) → Omega (ROASTER)
```

Managed by **Conductor** (orchestrator). Authorization gate is non-bypassable and managed only by Conductor.

**Target market:** Authorized red team engagements for enterprise/SME in Indonesia and SE Asia.  
**Differentiator:** Context-aware exploit composition, cross-engagement intelligence, attack graph narrative, Indonesia-specific templates.  
**Not:** A generic agent. Not a vulnerability scanner. Not Lyndon.

---

## 1. The Lyndon Failure Pattern — Never Repeat

These are the exact reasons Lyndon failed 4+ times. Every decision in Agent-Alpha must be checked against this list:

```
LYNDON FAILURE PATTERN (memorize this):

1. FEATURE BEFORE FOUNDATION
   Added capabilities before basic loop was proven end-to-end.
   → Agent-Alpha: Phase 0 must pass 100% exit criteria before Phase 1 starts.
   
2. DEAD CODE TREATED AS DONE
   Implementations existed but were never called from any execution path.
   → Agent-Alpha: Every component must be verified via grep/trace, not assumed wired.
   
3. FALSE SUCCESS WORSE THAN FAILURE
   exec() not raising = success, nmap zero-results = success, empty {} = success.
   These masked real failures and stopped fallback chains from progressing.
   → Agent-Alpha: Success requires validated non-empty output. No "silent success".
   
4. GENERIC ARCHITECTURE FOR SPECIFIC DOMAIN
   autonomous_loop.py was a 4565-line god object handling coding/devops/research/security.
   Security was 1 of 7 domains. No security-first routing.
   → Agent-Alpha: Security-only. Every component exists for one reason: red team.
   
5. SCOPE CREEP KILLED MOMENTUM
   Each session: fix this → that broke → fix that → new feature discovered → fix again.
   Never finished one sprint before starting another.
   → Agent-Alpha: Phase exit criteria are hard stops. Cannot enter next phase without passing.
   
6. TWO CLASSES WITH THE SAME NAME
   target_profiler.TargetProfile vs tool_selector.TargetProfile — both existed, caused silent bugs.
   → Agent-Alpha: One canonical data contract per concept. No duplication.
   
7. THREE TIMEOUT VALUES FOR THE SAME TOOL
   nuclei had timeout=60 in campaign_planner, timeout=120 in cfs_nodes, timeout=180 in design_phase.
   → Agent-Alpha: Single source of truth for every configuration value.
   
8. AUTONOMOUS_LOOP.PY AS SINGLE POINT OF FAILURE
   All logic in one file, 4565 lines, impossible to test in isolation, impossible to parallelize.
   → Agent-Alpha: Each agent is independently testable with its own test suite.
   
9. WINDOWS PYTEST RESULTS ACCEPTED AS VALID
   Oracle is the only valid test environment. Windows has different asyncio behavior.
   → Agent-Alpha: CI runs on target deployment environment only.
   
10. BENANG KUSUT — TAMBAH SULAM TANPA ARAH
    Fix one bug → patch cascade → fix patch → new bug → "let me just fix C".
    → Agent-Alpha: If a fix requires touching >2 files, stop and redesign the interface.
```

---

## 2. Non-Negotiable Architecture Decisions

These are FINAL. Not up for discussion per-session:

| Decision | Value | Reason |
|----------|-------|--------|
| Domain | Security-only | No coding/devops/research personas |
| Auth gate | Single, in Conductor | Agents autonomous after authorized |
| A2A language | Structured English JSON | Reproducibility, anti-injection |
| State | Event-sourced (append-only) | Audit, reproducibility, legal |
| Task queue | Celery + Redis | Non-blocking, multi-tenant, chat-while-running |
| AI Brain | Python 3.12 | LLM/memory/graph integration |
| Exec Engine | Go (agents) | Throughput, stealth, deployable binary |
| IPC | gRPC (Python ↔ Go) | Type-safe, fast |
| Memory | Redis (session) + PostgreSQL + pgvector | Three-tier, persistent |
| Learning | Data/playbook only | NOT self-modifying code — ever |
| Reporting | Omega (dedicated agent) | Narrative + MITRE ATT&CK + compliance |

---

## 3. Agent Registry

| Greek Name | Role | Authorization Required | Handoff Output |
|------------|------|----------------------|----------------|
| Conductor | Orchestrator | Manages all auth | N/A |
| Alpha | SCOUT (Reconnaissance) | RECON_ONLY | hosts, ports, services, tech_stack, js_secrets, api_endpoints |
| Beta | STRIKE (Initial Access) | ACTIVE_APPROVED | valid_credentials, session_tokens, access_level, entry_point |
| Gamma | ANCHOR (Exploitation) | OFFENSIVE_APPROVED + SOW | shell_access, webshell_path, server_context, writable_paths |
| Delta | HUNTER (Post-Exploitation) | OFFENSIVE_APPROVED + scope includes post-exploit | harvested_creds, db_access, internal_network_map |
| Epsilon | SCOUT-HUNTER (Lateral Movement) | OFFENSIVE_APPROVED + internal scope defined | compromised_hosts, pivoted_networks, additional_findings |
| Omega | ROASTER (Reporting) | None (read-only) | Executive + Technical + Remediation reports |

**Hard rule:** Agents NEVER call other agents directly. All transitions go through Conductor which validates handoff contract + authorization state.

---

## 4. A2A Communication Contract

All messages between agents use structured English JSON. No free-form text in agent-to-agent communication.

```json
{
  "from": "alpha",
  "to": "conductor",
  "engagement_id": "eng_abc123",
  "message_type": "handoff_ready | status_update | error | request_approval",
  "phase": "recon",
  "timestamp_utc": "2026-06-14T00:00:00Z",
  "payload": {
    "status": "complete | partial | failed | blocked",
    "findings_count": 47,
    "handoff_data": {},
    "proof_artifacts": [],
    "next_recommended": "beta"
  },
  "confidence": 0.87,
  "requires_human_approval": false
}
```

**Why English only:** Reproducibility across multilingual teams, LLM parsing consistency, audit log readability, prevents prompt injection via language mixing.

---

## 5. Authorization State Machine

```
CREATED → RECON_ONLY → ACTIVE_APPROVED → OFFENSIVE_APPROVED
   ↑                                              |
   └──────────────── EMERGENCY_STOP ─────────────┘
                    (revokes all tasks)

RECON_ONLY      → Alpha only (Level 1-3)
ACTIVE_APPROVED → Beta (Level 4), requires: scope verified
OFFENSIVE_APPROVED → Gamma, Delta, Epsilon (Level 5-6), requires: SOW uploaded + blast radius calculated
```

**Non-bypassable:** Authorization state is managed ONLY by Conductor. No agent can read or write authorization state directly.

---

## 6. Phase Exit Criteria (Hard Stops)

Cannot enter next phase without 100% exit criteria of current phase.

**Phase 0 Exit Criteria:**
- [ ] Conductor skeleton running, receives task, returns status
- [ ] Authorization state machine: CREATED → RECON_ONLY transition works
- [ ] SOW upload stores file, sets OFFENSIVE_APPROVED correctly
- [ ] Emergency stop revokes all Celery tasks within 5 seconds
- [ ] Event stream: 10 test events written, replayed, match exactly
- [ ] Audit log: immutable (attempting to modify returns error)
- [ ] Secrets vault: credentials stored encrypted, never appear in logs
- [ ] Test suite Phase 0: 100% pass

**Phase 1 Exit Criteria:**
- [ ] SessionMemory: create, read, update, expire — all working
- [ ] AttackGraph: add_node, add_edge, find_critical_paths — all working
- [ ] EngagementMemory: persist engagement, reload engagement — working
- [ ] Finding auto-linking: two related findings connect via edge automatically
- [ ] Test suite Phase 1: 100% pass

**Phase 2 Exit Criteria:**
- [ ] Alpha → Omega end-to-end: scan target → graph → narrative report
- [ ] Cognitive loop (OBSERVE → PERSIST) completes without crash
- [ ] Inner monologue streamed to user in real-time
- [ ] Stop conditions enforced: max_iterations, time_budget, cost_budget
- [ ] Report: MITRE ATT&CK mapped, PDF export works
- [ ] Live test: 3 real targets, <20% FP rate in findings
- [ ] Test suite Phase 2: 100% pass

---

## 7. Project File Structure

```
agent_alpha/
├── conductor/
│   ├── main.py                  # FastAPI + Celery app entry
│   ├── orchestrator.py          # Conductor logic
│   ├── authorization.py         # Auth state machine (ONLY place)
│   ├── policy.py                # Policy-as-Code (RoE, scope, exclusions)
│   └── emergency.py             # Kill switch
│
├── agents/
│   ├── base.py                  # Abstract Agent (Cognitive Loop)
│   ├── alpha/                   # SCOUT
│   ├── beta/                    # STRIKE
│   ├── gamma/                   # ANCHOR
│   ├── delta/                   # HUNTER
│   ├── epsilon/                 # SCOUT-HUNTER
│   └── omega/                   # ROASTER
│
├── memory/
│   ├── session.py               # Redis SessionMemory
│   ├── engagement.py            # PostgreSQL EngagementMemory
│   ├── intelligence.py          # pgvector IntelligenceBase
│   └── user_model.py            # UserMemory (communication style)
│
├── graph/
│   ├── attack_graph.py          # AttackGraph (NetworkX wrapper)
│   ├── schema.py                # AttackNode + AttackEdge (K2 "Attack Graph Schema")
│   └── narrative.py             # to_narrative() per style
│
├── events/
│   ├── store.py                 # Append-only event store
│   └── projectors.py            # Graph, audit, metrics projections
│
├── tools/
│   ├── registry.py              # Tool catalog + reliability metrics
│   ├── composer.py              # Runtime tool composition
│   └── templates/
│       ├── regional/         # category templates (banking_portal, his_sqli, egov_bypass, erp_rce)
│       ├── cms/
│       ├── cloud/
│       └── bypass/
│
├── intelligence/
│   ├── cve_db.py
│   ├── hypothesis.py            # H1-H5 lifecycle
│   └── verifier.py              # Verification loop
│
├── llm/
│   ├── orchestrator.py          # Multi-LLM routing + consensus
│   ├── providers/               # Claude, DeepSeek, abstraction
│   └── redaction.py             # PII/creds redaction before LLM
│
└── tests/
    ├── phase_0/                 # Phase 0 exit criteria tests
    ├── phase_1/                 # Phase 1 exit criteria tests
    ├── phase_2/                 # Phase 2 exit criteria tests
    └── fixtures/                # Mock targets, lab environments
```

---

## 8. Tech Stack

```
Language (Brain)  : Python 3.12
Language (Agents) : Go 1.22+
IPC               : gRPC (protobuf schemas in /proto)
Task Queue        : Celery 5.x + Redis broker
Memory Session    : Redis 7.x
Memory Long-term  : PostgreSQL 16 + pgvector
Attack Graph      : NetworkX (Python)
LLM Primary       : DeepSeek V4 Pro / Kimi / GPT / Sonnet (payload/offensive generation, TEMPORARY testing phase)
LLM Reasoning     : Claude Sonnet/Opus (reasoning, planning, narrative)
CF Bypass         : curl_cffi (TLS impersonation) + Playwright (Turnstile)
Secrets           : HashiCorp Vault or AWS KMS
Deploy            : Oracle Cloud ARM64, Ubuntu 24, systemd
API               : FastAPI + WebSocket (real-time progress)
Auth              : JWT per tenant, mTLS for gRPC
```

---

## 9. Communication Style (Claude ↔ Natanael)

- **Natanael communicates in:** Bahasa Indonesia
- **Claude responds in:** Bahasa Indonesia (conversation), English (code, prompts, architecture diagrams)
- **Agent-to-Agent:** Structured English JSON only
- **Reports to clients:** Adapts to UserMemory.communication_style
- **Claude tone:** Peer engineer. Challenge first, then fix. Not tutor. Not assistant.
- **Confidence must be stated:** "Confidence ~80% — reason: X"
- **Flaw first:** If design has a flaw, say it before the fix
- **No placeholder code:** No `# TODO`, no `pass`, no `...` unless explicitly asked for stub

---

## 10. Quality Gate (Every Phase)

```
Phase N Quality Gate:
1. Unit tests for new components: 100% pass
2. Integration tests for handoff contracts: 100% pass  
3. Phase exit criteria checklist: 100% complete
4. No regression in previous phases
5. Oracle ARM64 deployment verified (not local/Windows)
```

---

## 11. Open Decisions (Must Be Resolved Before Phase 0 Start)

- [ ] Build sequencing: Full hybrid Go+Python from start, or Python MVP first then port?
- [ ] Approval channel: Telegram only, or web dashboard for SOW?
- [ ] Multi-tenancy depth: queue-only isolation vs separate DB schema?
- [ ] Engagement profiles priority after WebApp: Cloud / AD / Phishing Impact?
- [ ] VERIFY/re-test mode: Phase 2 or Phase 6?

---

*This document is the single source of truth for Agent-Alpha architecture decisions.*  
*If a session contradicts this document, this document wins.*
