# Add Tool-Layer Foundation Contracts (ADR §12.16)

## Summary

Implements the canonical tool-layer contracts from ADR §12.16. Claude authors these protocols + types (non-offensive glue). DeepSeek will author the offensive BODIES — `Tool.run`, `Template.build`, `Template.verify` — in tools/templates/* per-phase.

## Changes

### Added Files

- **agent_alpha/tools/contracts.py**
  - `TargetContext` - everything a tool needs to decide + act, projected from AttackGraph
  - `ResourceBudget` - bounded autonomy for every tool (max_requests, max_seconds, max_cost_usd, rate_limit_rps)
  - `ToolResult` - outcome of a tool/template with anti-Lyndon #3 enforcement (success requires findings)
  - `Template` Protocol - exploit/finding payload unit (DeepSeek's lane)
  - `Tool` Protocol - capability the Conductor/agent may run (DeepSeek's lane)

- **tests/phase_2/test_tool_contracts.py**
  - Tests for ToolResult anti-false-success contract
  - Tests for ResourceBudget single-source rps
  - Tests for protocol conformance (what DeepSeek must implement)
  - Tests for applies_to relevance scoring (not hardcoded ladder)
  - Tests for template verify proof-not-assumption

## Design Decisions

### Anti-Lyndon #3: No Silent Success
- `ToolResult` enforces at construction: success requires >= 1 finding
- Failed ToolResult must not carry findings
- Confidence must be bounded [0,1]
- Structurally prevents fake success from offensive bodies

### Protocol-Based Design
- `Template` and `Tool` are Protocols (runtime_checkable)
- DeepSeek implements these protocols in tools/templates/*
- Claude owns the contract + registry/composer (non-offensive glue)
- Clear separation: Claude = contracts, DeepSeek = offensive bodies

### Single Source of Truth
- `ResourceBudget.rate_limit_rps` ties to `constants.DEFAULT_RATE_LIMIT_RPS`
- No hardcoded rate limits in tool code (anti-Lyndon #7)

### Relevance Scoring
- `Tool.applies_to()` returns relevance 0..1 from tech_stack/context
- NOT a hardcoded if-ladder (K11)
- Lets registry/composer rank, not agent guess

## Testing

Run on Oracle ARM64:
```bash
.venv/bin/pytest tests/phase_2/test_tool_contracts.py -v
```

## Checklist

- [x] Tool/Template protocols
- [x] TargetContext, ResourceBudget, ToolResult dataclasses
- [x] Anti-Lyndon #3 enforcement in ToolResult
- [x] Contract tests
- [x] Single source constant integration
- [x] Protocol conformance tests

## Next Steps

- DeepSeek to implement first real template (laravel_finding.py)
- Registry + composer to land once >= 2 real tools exist (dead code otherwise)
