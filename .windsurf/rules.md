# Agent-Alpha — Windsurf Rules
## Applied to all IDE sessions for Agent-Alpha project

---

## Project Identity

You are working on **Agent-Alpha** — autonomous red-team platform, Level 1-6.
This is a **security-only** project. No coding assistants, devops tools, 
or general-purpose features.

**Agent registry:**
- Conductor (Orchestrator)
- Alpha (SCOUT) | Beta (STRIKE) | Gamma (ANCHOR)
- Delta (HUNTER) | Epsilon (SCOUT-HUNTER) | Omega (ROASTER)

---

## Non-Negotiable Rules for Every Task

```
1. SECURITY DOMAIN ONLY
   If a task is not directly related to red team capabilities, refuse it.
   
2. NO PLACEHOLDER CODE
   No # TODO, no pass, no ... unless explicitly asked for stub.
   Every function must be fully implemented or not written at all.
   
3. PHASE GATE RESPECTED
   Do not implement Phase N+1 components if Phase N is not complete.
   If asked to build something out of order, flag it.
   
4. ONE CANONICAL TYPE PER CONCEPT
   Before creating a new class/struct, check if it already exists.
   Never create duplicate types (Lyndon failure: two TargetProfile classes).
   
5. SINGLE SOURCE OF TRUTH FOR CONFIGURATION
   No hardcoded values that duplicate a constant elsewhere.
   All timeouts, limits, thresholds → single constants file.
   
6. VERIFY WIRING BEFORE MARKING DONE
   After implementing a function, grep for callers.
   "Written" ≠ "wired". Dead code is the primary failure mode.
   
7. TEST CONTRACT REQUIRED
   Every new component must have a test contract before implementation.
   Test first (at least as skeleton), then implement.
   
8. A2A MESSAGES: STRUCTURED ENGLISH JSON ONLY
   No free-form text between agents.
   All agent messages use the defined JSON schema.
   
9. AUTHORIZATION GATE: CONDUCTOR ONLY
   No agent checks or modifies authorization state directly.
   Only Conductor reads/writes AuthorizationStateMachine.
   
10. ORACLE ARM64 IS THE ONLY VALID TEST ENVIRONMENT
    Do not run tests locally and claim they pass.
    All test results must come from Oracle ARM64.
```

---

## Model Assignment Matrix

All models available in Windsurf. Choose based on task type:

| Task Type | Primary Model | Fallback |
|-----------|--------------|---------|
| **New component architecture** (new agent, new layer) | Claude Opus 4.5/4.6 Thinking | Gemini 2.5 Pro |
| **Security-critical logic** (auth, event store, audit) | Claude Opus 4.5/4.6 Thinking | GPT-4.1 |
| **Multi-file cross-dependency** (3+ files touch) | Claude Sonnet 4.5/4.6 | Gemini 2.5 Pro |
| **Single-file logic** (medium complexity) | Claude Sonnet 4.5/4.6 | GPT-4.1 mini |
| **Mechanical string/config fix** (single location) | Claude Haiku / GPT-4.1 mini | Gemini 2.5 Flash |
| **Go agent implementation** | Gemini 2.5 Pro | Claude Sonnet |
| **Test contract design** | Claude Sonnet 4.5/4.6 | GPT-4.1 |
| **gRPC/protobuf schema** | Gemini 2.5 Pro | Claude Sonnet |
| **SQL/PostgreSQL schema** | Claude Sonnet | GPT-4.1 |
| **Attack graph algorithms** | Claude Opus Thinking | Gemini 2.5 Pro |
| **Celery/Redis integration** | GPT-4.1 | Claude Sonnet |

**Rule:** Never use the same model for both architecture decision AND implementation 
of the same component. Separation of concerns applies to AI models too.

---

## Prompt Format (Every Task)

```
PROJECT: Agent-Alpha
PHASE: [0 | 1 | 2 | 3 | 4 | 5 | 6]
FILE: <exact relative path from project root>
TASK: <1 sentence, English>

CONTEXT:
- What this file is for
- What calls this file
- What this file calls
- Which agent owns this component

LYNDON PATTERN CHECK:
- Is this repeating any of the 10 failure patterns? [Yes/No + which]

REQUIRED:
1. [Specific requirement 1]
2. [Specific requirement 2]
3. [etc.]

CONSTRAINTS:
- Do NOT touch: [specific files/functions]
- Do NOT add: [non-security features, generic capabilities]
- Authorization changes: Conductor only
- A2A messages: structured English JSON schema (see KNOWLEDGE.md §K1 A2A Contract)

TEST CONTRACT:
- Test 1: [happy path] → [expected output]
- Test 2: [edge case] → [expected behavior]  
- Test 3: [failure case] → [expected handling]

VERIFY WIRING:
- After implementing, run: grep -rn "<function_name>" agent_alpha/
- Confirm function is called from: [expected caller]

ENVIRONMENT: Oracle ARM64 only
Expected test result: [N] tests pass, 0 fail
```

---

## File Structure Reference

```
agent_alpha/
├── conductor/          # Auth gate lives HERE ONLY
├── agents/             # Alpha, Beta, Gamma, Delta, Epsilon, Omega
├── memory/             # Session, Engagement, Intelligence, UserModel
├── graph/              # AttackGraph, nodes, narrative
├── events/             # Append-only event store, projectors
├── tools/              # Registry, composer, templates
├── intelligence/       # CVE db, hypothesis, verifier
├── llm/                # Multi-LLM orchestrator, providers, redaction
└── tests/              # phase_0/, phase_1/, phase_2/, fixtures/
```

---

## What to Refuse

```
❌ Adding coding/debugging/devops/research functionality
❌ Agent calling another agent directly (must go through Conductor)
❌ Free-form text in A2A messages
❌ Modifying authorization state outside Conductor
❌ Self-modifying code or dynamic architecture changes
❌ Mutable shared state between agents
❌ Implementing Phase N+1 before Phase N exit criteria pass
❌ Accepting test results from Windows/local environment
❌ Creating a second class for a concept that already has a canonical class
❌ Placeholder implementations ("I'll implement this later")
```

---

## Phase 0 Checklist (Current Phase)

Must be 100% complete before Phase 1 starts:

- [ ] Conductor skeleton (FastAPI + Celery app) running
- [ ] AuthorizationStateMachine: CREATED→RECON_ONLY transition
- [ ] SOW upload endpoint storing file correctly
- [ ] Emergency stop: revokes all Celery tasks within 5 seconds
- [ ] Event store: append-only, 10 events written+replayed matching exactly
- [ ] Audit log: immutable (modify attempt returns error)
- [ ] Secrets vault: credentials encrypted, never in logs
- [ ] All Phase 0 tests: 100% pass on Oracle ARM64
