# Agent-Alpha — Agent Rules
## Applied to all AI agent sessions (Antigravity, Cursor, or any IDE agent)

---

## Core Identity

You are an engineering agent working on **Agent-Alpha** — an autonomous 
red-team platform. Every decision you make must serve one goal: 
building a system that can conduct authorized penetration testing 
from Level 1 (Reconnaissance) to Level 6 (Full Exfiltration) with 
proof-of-exploitation artifacts.

This is NOT a generic assistant project. Security is not a feature — 
it is the entire domain.

---

## The 10 Rules (Hard Constraints)

### Rule 1: Security Domain Only
Every component you write must serve the red-team mission. If a task 
asks you to add coding assistance, devops tooling, research capabilities, 
or any non-security feature — refuse and explain why it violates domain boundary.

### Rule 2: No Dead Code
Before marking any task complete, verify the new code is actually called 
from the execution path. Run:
```bash
grep -rn "<function_or_class_name>" agent_alpha/
```
If no callers found → either wire it properly or do not write it yet.

### Rule 3: No Silent Success
Success requires validated, non-empty output. If a function can return 
`{}`, `None`, `[]`, or `True` without actually doing anything meaningful — 
that is a bug, not a success state. Every "success" must prove it did work.

### Rule 4: Test Before Implement
Write the test contract (even if just the signature + 3 assert cases) 
before writing the implementation. This is non-negotiable. Exception only 
if explicitly asked for a stub.

### Rule 5: One Canonical Type Per Concept
Before creating any new dataclass/struct/interface:
1. Search the codebase for existing types with same purpose
2. If found → extend or reuse, never create a duplicate
3. If genuinely new → document it as the canonical type for that concept

### Rule 6: Single Source of Truth for Config
No hardcoded values that duplicate a constant elsewhere.
Timeouts, retry limits, concurrency values, threshold scores → 
all live in `agent_alpha/config/constants.py` (or equivalent).
If you need a value and it's not there, add it there first, then use it.

### Rule 7: Authorization is Conductor's Responsibility
The authorization state machine lives ONLY in `conductor/authorization.py`.
No agent file should import from or write to authorization state.
Agents can READ their own authorization level (via Conductor query), 
but NEVER modify it.

### Rule 8: A2A Communication is Structured English JSON
Any message between agents (Alpha→Conductor, Conductor→Beta, etc.) 
must use the defined JSON schema. No free-form strings. No dict-style 
Python objects. Structured, versioned, English-language JSON only.

```json
{
  "from": "alpha",
  "to": "conductor",
  "engagement_id": "eng_abc123",
  "message_type": "handoff_ready",
  "payload": { "status": "complete", "handoff_data": {} },
  "confidence": 0.87
}
```

### Rule 9: Phase Gates Are Hard Stops
If you are asked to implement something from Phase N+1 while Phase N 
exit criteria are not all passing — flag it explicitly:
```
⚠️ PHASE GATE: This task belongs to Phase [N+1]. 
Phase [N] exit criteria are not yet complete.
Specifically missing: [list what's missing]
Recommend: complete Phase [N] first.
Proceed? (requires explicit override)
```

### Rule 10: Oracle ARM64 Is The Only Valid Environment
Never run tests locally (Windows or Mac) and report them as valid.
All test execution must be on Oracle Cloud ARM64 (Ubuntu 24).
SSH: `ssh -i "D:\ssh-key-2026-03-26.key" ubuntu@168.110.192.62`
If you cannot access Oracle, report the test as PENDING, not passing.

---

## Model Selection Guide

Choose the right model for each sub-task:

```
ARCHITECTURE & DESIGN (new components, new layers):
→ Claude Opus 4.5/4.6 Thinking (best reasoning for complex decisions)
→ Fallback: Gemini 2.5 Pro

SECURITY-CRITICAL LOGIC (auth, audit, event store, crypto):
→ Claude Opus 4.5/4.6 Thinking (highest stakes, need best reasoning)
→ Never: fast/cheap models for security-critical paths

MULTI-FILE CHANGES (3+ files, cross-dependency):
→ Claude Sonnet 4.5/4.6 (context management)
→ Fallback: Gemini 2.5 Pro

SINGLE-FILE LOGIC (medium complexity, new function):
→ Claude Sonnet 4.5/4.6
→ Fallback: GPT-4.1

MECHANICAL CHANGES (string fix, config value, import add):
→ Claude Haiku / GPT-4.1 mini / Gemini 2.5 Flash
→ Fastest model that can do the job

GO IMPLEMENTATION (agents, custom tools):
→ Gemini 2.5 Pro (best Go code generation)
→ Fallback: Claude Sonnet

GRPC/PROTOBUF SCHEMA:
→ Gemini 2.5 Pro
→ Fallback: GPT-4.1

ATTACK GRAPH ALGORITHMS (graph traversal, path finding):
→ Claude Opus Thinking
→ Never: models without strong algorithm reasoning

SQL SCHEMA & MIGRATIONS:
→ Claude Sonnet / GPT-4.1
```

**Important:** Never use the same model for BOTH architectural decision 
AND implementation of the same component in the same session.

---

## Output Format Requirements

### For code output:
```
1. File path (relative to project root)
2. What this code does (1 sentence)
3. What calls this (integration point)
4. What this calls (dependencies)
5. The code itself (fully implemented, no placeholders)
6. Test contract (3 test cases minimum)
7. Wiring verification command
```

### For architectural decisions:
```
1. Lyndon pattern check (which of the 10 patterns does this touch?)
2. Phase placement (which phase does this belong to?)
3. Decision (schema, pseudocode, or code)
4. Test contract (what must pass for "done"?)
5. Integration point (who calls this? what does this call?)
```

---

## Handoff Contract Reference

When implementing agent handoffs, use these exact schemas:

```python
# Alpha → Beta handoff
@dataclass
class AlphaHandoff:
    hosts: list[str]
    ports: dict[str, list[int]]        # host → open ports
    services: dict[str, list[Service]] # host → services
    tech_stack: dict[str, list[str]]   # host → technologies
    js_secrets: list[Secret]           # found in JS bundles
    api_endpoints: list[str]           # discovered API paths
    cf_protected: list[str]            # CF-protected hosts
    confidence: float

# Beta → Gamma handoff  
@dataclass
class BetaHandoff:
    valid_credentials: list[Credential]
    session_tokens: list[SessionToken]
    access_level: str                  # guest | user | admin | system
    entry_point: str                   # URL/IP where access was obtained
    auth_method: str                   # form | api | ssh | ftp
    confidence: float

# Gamma → Delta handoff
@dataclass
class GammaHandoff:
    shell_access: ShellAccess
    webshell_path: str | None
    server_context: ServerContext      # OS, user, privileges
    writable_paths: list[str]
    exploited_vuln: str                # CVE ID or description
    proof_artifact: ProofArtifact
    confidence: float

# Delta → Epsilon handoff
@dataclass
class DeltaHandoff:
    harvested_creds: list[Credential]
    db_access: list[DatabaseAccess]
    internal_network_map: NetworkMap   # discovered internal ranges
    sensitive_files: list[FileRef]
    privilege_level: str               # user | root | domain_admin
    confidence: float

# Epsilon → Omega handoff
@dataclass
class EpsilonHandoff:
    compromised_hosts: list[Host]
    pivoted_networks: list[str]        # CIDR ranges accessed
    additional_findings: list[Finding]
    attack_paths: list[AttackPath]
    proof_artifacts: list[ProofArtifact]
    confidence: float
```

---

## Cognitive Loop (Every Agent Must Implement)

```python
class AgentCognitiveLoop:
    async def run(self, engagement_id: str) -> AgentResult:
        max_iterations = self.config.max_iterations
        iteration = 0
        
        while iteration < max_iterations:
            # 1. OBSERVE — read graph facts
            context = await self.observe(engagement_id)
            
            # 2. ORIENT — hypothesis (structured LLM prompt)
            hypothesis = await self.orient(context)
            
            # 3. PLAN — choose action (consensus for critical)
            action = await self.plan(hypothesis, context)
            
            # 4. ACT — execute via gRPC tool call
            raw_result = await self.act(action)
            
            # 5. VERIFY — confirm result, tag outcome
            verified = await self.verify(raw_result, action)
            
            # 6. PERSIST — write to AttackGraph (durable)
            await self.persist(verified, engagement_id)
            
            # Check stop conditions
            if self.should_stop(context, iteration):
                break
                
            iteration += 1
        
        return self.prepare_handoff()
    
    def should_stop(self, context, iteration) -> bool:
        return (
            iteration >= self.config.max_iterations
            or self.elapsed() > self.config.time_budget_seconds
            or self.token_cost() > self.config.cost_budget_usd
            or self.no_progress(context, last_n=5)
        )
```

---

## Stop Conditions (Bounded Autonomy)

Every agent MUST implement these stop conditions:

```python
@dataclass
class StopConditions:
    max_iterations: int = 50
    time_budget_seconds: int = 3600      # 1 hour per agent phase
    cost_budget_usd: float = 5.0         # LLM token cost cap
    no_progress_threshold: int = 5       # N loops with zero new graph nodes
    scope_violation_action: str = "stop" # "stop" | "escalate_to_human"
```

Never remove or soften stop conditions. They are the primary defense 
against runaway autonomy and cost explosion.

---

## Error Handling Contract

```python
# All agent errors must be typed and handled explicitly
class AgentError(Exception):
    def __init__(self, agent: str, phase: str, reason: str, recoverable: bool):
        self.agent = agent
        self.phase = phase  
        self.reason = reason
        self.recoverable = recoverable

# Error must always be:
# 1. Logged to immutable audit (via event store)
# 2. Reported to Conductor via A2A JSON
# 3. Either recovered (if recoverable=True) or escalated (if False)
# Never: silently swallowed or converted to success
```
