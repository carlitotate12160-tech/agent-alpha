# Phase 2 — Test Contract

**Status:** RED (tests written before implementation — TDD).
Every test in this directory is expected to FAIL on collection or assertion
until the Phase 2 components are implemented. That is by design.

**Decision (Opsi B — confirmed 2026-06-19):** Alpha is adaptive via a
*playbook-first* tier ladder, NOT free-form LLM reasoning.
`RULE (playbook)` → `SINGLE_LLM` → `CONSENSUS`. The LLM is only consulted
when the playbook has no precedent for the observation. RAG / full adaptive
reasoning is Phase 6, not here. (ADR §12.1, §12.4)

**First target (confirmed):** Laravel with `APP_DEBUG=true`. Chosen for the
fastest verifiable feedback loop — a single HTTP GET exposes the Whoops
debug page (stack trace + environment variables) detectable without WAF logic.

---

## What "done" means (maps to ADR Phase 2 exit criteria)

| Exit criterion | Test file |
|----------------|-----------|
| DeepSeek reachable from Oracle + inference round-trip | `test_deepseek_provider.py` |
| Playbook RULE tier deterministic; LLM only for novel cases | `test_playbook_engine.py` |
| Cognitive loop OBSERVE→PERSIST completes without crash | `test_cognitive_loop.py` |
| Stop conditions enforced (iterations/time/cost/no-progress) | `test_cognitive_loop.py` |
| Alpha *reads* HTTP response and reaches a distinct conclusion | `test_alpha_recon.py` |
| No silent success (empty result = `failed`, never `complete{}`) | `test_alpha_recon.py` |
| Alpha → Omega end-to-end: scan → graph → narrative report | `test_alpha_to_omega_e2e.py` |
| Report MITRE ATT&CK mapped + PDF export | `test_alpha_to_omega_e2e.py` |

> Live target <20% FP rate and inner-monologue streaming are validated by a
> separate live-fire run (3 real authorized targets), not by this unit/contract
> suite. They are tracked in `docs/PROGRESS_TRACKER.md`, not asserted here.

---

## Components this contract forces into existence (currently MISSING)

```
agent_alpha/llm/providers/deepseek.py   DeepSeekProvider (reachability + completion)
agent_alpha/llm/orchestrator.py         tier router: RULE → SINGLE_LLM → CONSENSUS
agent_alpha/tools/registry.py           ToolRegistry (catalog + reliability read)
agent_alpha/tools/playbook.py           PlaybookEngine (YAML, RULE tier, deterministic)
agent_alpha/agents/base.py              Agent ABC + CognitiveLoop + BoundedAutonomy
agent_alpha/agents/alpha/scout.py       Alpha (SCOUT)
agent_alpha/agents/omega/roaster.py     Omega (ROASTER, read-only)
```

All reuse the canonical Phase 0/1 types — no duplicate concepts (anti-Lyndon #6):
`AuthorizationStateMachine`, `AttackNode`/`AttackEdge`, `NetworkXGraphStore`,
`EventStore`, `SessionRecord`, `to_narrative`, and every threshold from
`config/constants.py`.

---

## Running (Oracle ARM64 ONLY — anti-Lyndon #9)

```bash
# pure-unit contract (no network), runnable anywhere but AUTHORITATIVE only on Oracle:
pytest tests/phase_2 -m "not live" -q

# live DeepSeek reachability + inference (requires env var, Oracle egress):
export DEEPSEEK_API_KEY=sk-...        # rotated key, never committed
pytest tests/phase_2 -m live -q
```

`-m live` tests `skipif` when `DEEPSEEK_API_KEY` is unset, so CI on a box
without egress stays green for the unit tier and explicitly SKIPS (not passes)
the live tier. A skipped live test is NOT a passing exit criterion.
