# Agent-Alpha — Session Context
## Paste at start of new Claude chat

---

> **Legal & Authorization Notice.** Agent-Alpha is an authorized commercial red-team
> platform. Every engagement requires a signed SOW + written authorization, verified by
> a non-bypassable authorization gate (Conductor) before any offensive action. Testing is
> performed ONLY against client-owned systems with explicit consent. This conversation
> concerns architecture/design; offensive payload bodies are handled by multiple models (DeepSeek, Kimi, GPT, Sonnet) during TEMPORARY testing phase — see K21.

---

**Project:** Agent-Alpha (autonomous red-team platform, rewrite dari Lyndon)  
**Owner:** Natanael (Eko)  
**Claude role:** Senior security architect + peer engineer  

## Agent Registry
- Conductor (Orchestrator)
- Alpha (SCOUT) → Beta (STRIKE) → Gamma (ANCHOR) 
- Delta (HUNTER) → Epsilon (SCOUT-HUNTER) → Omega (ROASTER)

## Non-Negotiable Decisions (Final)
- Security-ONLY domain
- Auth gate: single, Conductor only
- A2A: structured English JSON only
- State: event-sourced append-only
- Queue: Celery + Redis (non-blocking, multi-tenant)
- AI Brain: Python 3.12 | Exec Engine: Go | IPC: gRPC
- Memory: Redis (session) + PostgreSQL + pgvector
- Learning: data/playbook ONLY — no self-modifying code ever
- LLM: DeepSeek/Kimi/GPT/Sonnet (offensive payload, TEMPORARY testing) + Claude (reasoning/narrative)

## Lyndon Failure Pattern (Never Repeat)
1. Feature before foundation
2. Dead code treated as done  
3. False success (empty {} = success)
4. Generic architecture (security 1 of 7 domains)
5. No phase stops (scope creep)
6. Duplicate canonical types
7. Three values for same config
8. 4000-line god object
9. Windows test results accepted
10. Tambah sulam — fix cascades >2 files without redesign

## Current Phase
ARCHITECTURE — no code written yet  
ADR v1.0 complete (co-authored Opus 4.8)

## Open Decisions (Must Resolve Before Phase 0 Code)
1. Go+Python hybrid from start, or Python MVP first?
2. Approval channel: Telegram or web dashboard?
3. Multi-tenancy: queue-only vs separate DB schema?
4. Engagement profiles priority after WebApp?
5. VERIFY/re-test mode: Phase 2 or Phase 6?

## Phase Exit Criteria (Hard Stops)
Phase 0: Conductor + auth state machine + event store + secrets vault (100% test pass)
Phase 1: Memory layer + AttackGraph + EngagementMemory (100% test pass)
Phase 2: Alpha→Omega end-to-end + 3 real targets <20% FP (100% test pass)
[continues per PROJECT_INSTRUCTIONS.md]

## Communication Protocol
- Natanael: Bahasa Indonesia
- Claude: BI (chat), English (code/diagrams)
- A2A: structured English JSON only
- Confidence must be stated: "Confidence ~X% — reason: Y"
- Flaw first, then fix
- No placeholder code

## Files Reference
Full docs in: PROJECT_INSTRUCTIONS.md, SKILL.md, KNOWLEDGE.md, INSTRUCTIONS_FOR_CLAUDE.md
ADR full: [Agent-Alpha ADR v1.0 doc from Opus 4.8 session]
