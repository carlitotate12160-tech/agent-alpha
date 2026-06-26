## Summary

Implements C2: LLM role -> provider routing (ADR §12.15).

## C2 - Role-Based Provider Routing

**ADR §12.15:** ROLE is the architectural invariant; the PROVIDER behind each role is config.

### Reasoning Role
- Provider: `LLM_REASONING_PROVIDER` (config-only)
- Policy: MAY egress via gateway/aggregator *iff* zero-retention contract
- NEVER-guard: REMOVED (reasoning may legitimately be Claude/GPT-class in production)
- Usage: ORIENT / PLAN / narrative

### Payload Role
- Provider: `LLM_PAYLOAD_PROVIDER` (config-only)
- Policy: MUST egress via DIRECT vendor API only (LLM_PAYLOAD_TRANSPORT == "direct")
- NEVER-guard: ENFORCED (no reasoning-class models: claude, sonnet, opus, gpt)
- Allowlist: `LLM_PAYLOAD_ALLOWED` (deepseek-v4-pro, kimi-2.6)
- Usage: Offensive tool & exploit-body generation (Gamma / Phase 4)

## Implementation

- `agent_alpha/llm/routing.py` — Single chokepoint for role -> provider resolution
  - `resolve_reasoning_provider()` — reasoning role, config-only
  - `resolve_payload_provider()` — payload role, gated by `assert_payload_policy()`
  - `assert_payload_policy()` — enforces transport + allowlist + NEVER policy
  - `ProviderPolicyError`, `PayloadTransportError`, `PayloadProviderError` — domain errors

- `tests/phase_2/test_routing.py` — 13 hermetic policy tests
  - Reasoning role: resolves to configured provider, NOT NEVER-guarded, config-only swap
  - Payload role: accepts allowlisted direct, rejects gateway transport, rejects forbidden models
  - Transport gate precedes model gate (egress risk dominates)
  - Policy errors share base class (anti-Lyndon #3)

- `agent_alpha/live_fire/runner.py` — patch to use `resolve_reasoning_provider()`
  - Replaces direct `DeepSeekProvider` instantiation
  - Reasoning provider is now config-only (ADR §12.15)

## Tests

- 13/13 tests passing
- All hermetic (no network, no real provider construction)
- Tests pin the invariants: config-only swap, transport gate, allowlist, NEVER-guard

## ADR §12.15 Compliance

- Provider swap = config-only (zero code change)
- Role split enforced: reasoning ≠ payload
- Transport policy enforced: payload = direct only
- NEVER-list enforced: payload ≠ reasoning-class models
