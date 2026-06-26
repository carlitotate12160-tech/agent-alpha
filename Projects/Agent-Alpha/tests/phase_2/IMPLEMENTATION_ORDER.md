# Phase 2 — Implementation Order (derived from the test contract)

Build strictly bottom-up. Each component is "done" only when the named tests
go green **on Oracle ARM64** (anti-Lyndon #9). Do not start a component until
the one above it passes. No component is merged unless it is wired into a live
path (anti-Lyndon #2) — the e2e test is the wiring proof.

| # | Component | File | Tests that must pass | Calls → / ← Called by |
|---|-----------|------|----------------------|------------------------|
| 1 | DeepSeekProvider | `llm/providers/deepseek.py` | `test_deepseek_provider.py` | → api.deepseek.com / ← LLMOrchestrator |
| 2 | PlaybookEngine | `tools/playbook.py` | `test_playbook_engine.py` | → YAML files / ← LLMOrchestrator |
| 3 | LLMOrchestrator | `llm/orchestrator.py` | `test_llm_orchestrator.py` | → Playbook, then Provider / ← Alpha |
| ~~4~~ | ~~ToolRegistry~~ DEFERRED | ~~`tools/registry.py`~~ | none — not injected by the Alpha test | would be dead code now (anti-Lyndon #2). Build with multi-tool + reliability scoring in a later phase (K19). Alpha dispatches its single tool internally. |
| 4 | base: BoundedAutonomy + run_cognitive_loop | `agents/base.py` | `test_cognitive_loop.py` | → graph/event store / ← Alpha (via run_recon) |
| 5 | Alpha (SCOUT) | `agents/alpha/scout.py` | `test_alpha_recon.py` | → auth, orchestrator, http, graph / ← Conductor. run_recon MUST drive recon via run_cognitive_loop (wires the loop — anti-Lyndon #2) |
| 6 | Omega (ROASTER) | `agents/omega/roaster.py` | `test_alpha_to_omega_e2e.py` | → graph.to_narrative (read-only) / ← Conductor |

## Reused canonical types (do NOT re-declare — anti-Lyndon #6)
`AuthorizationStateMachine`, `Scope`, `a2a_pb2.A2AMessage`/`HandoffPayload`,
`AttackNode`/`AttackEdge`/`NodeType`, `NetworkXGraphStore`, `EventStore`,
`SessionRecord`, `to_narrative`, and every threshold in `config/constants.py`.

## New interfaces the tests imply (signatures, bodies filled by impl)
```
DeepSeekProvider(api_key: str, model: str = constants.LLM_REASONING_PRIMARY)
  .list_models() -> list[str]
  .complete(messages: list[dict], max_tokens: int) -> CompletionResult
      # CompletionResult: .text:str  .usage_cost_usd:float  .model:str
  # __init__ raises ValueError if model in constants.LLM_PAYLOAD_NEVER

PlaybookEngine.from_directory(path) -> PlaybookEngine
  .match(observation: dict) -> PlaybookDecision | None   # None => escalate
      # PlaybookDecision: .tool:str .tier=constants.LLM_TIER_RULE .technique_id:str
  # MUST NOT hold/call any LLM.

LLMOrchestrator(playbook: PlaybookEngine, provider)
  .decide(observation: dict) -> Decision   # RULE hit => no provider call

BoundedAutonomy(max_iterations=..., time_budget_s=..., cost_budget_usd=...,
                no_progress_threshold=...)   # all default from constants
  .should_stop(iteration, elapsed_s, cost_usd, iters_without_progress)
      -> StopReason | None
run_cognitive_loop(agent, policy) -> LoopOutcome
      # LoopOutcome: .stop_reason:StopReason .iterations_run:int .nodes_discovered:int

Alpha(authorization, graph_store, event_store, orchestrator, http_client)
  .run_recon(engagement_id: str, target_url: str) -> a2a_pb2.A2AMessage
      # refuses (status BLOCKED) if authorization.can_agent_proceed(ALPHA,..) is False
      # empty/unreachable target => status FAILED (never silent success)

Omega(graph_store)            # read-only
  .generate_report(style) -> Report
      # Report: .narrative:str .mitre_techniques:list[str]
      #         .mitre_attack_version:str  .export_pdf(path)->Path
```

## OPEN DECISION — resolve before building component #3
`config/constants.py` sets `LLM_REASONING_PRIMARY = "deepseek-v4-pro"`, but the
master ADR's LLM role split says **Claude = reasoning/planning/narrative,
DeepSeek = payload only**. ORIENT/PLAN in the cognitive loop are *reasoning*.
These two cannot both be canonical. Pick one and make the other follow:
  - (a) constants win: DeepSeek does reasoning too → update the ADR role split.
  - (b) ADR wins: add a `LLM_REASONING_CLAUDE` constant and route ORIENT/PLAN
        there; keep DeepSeek for payload/SINGLE_LLM tool selection.
Tests reference `constants.LLM_REASONING_PRIMARY` symbolically, so they stay
valid either way — but the orchestrator's routing depends on the answer.
