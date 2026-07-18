# Agent-Alpha — Session Handoff (2026-07-18)

Resume with: "lanjut Agent-Alpha — Bug #21 sealed; next = GAP-005 slice-2 (PolicyEnforcer
wire) or Tier C GAP-004 D3/D2 (world-model → HTN planner)."

## Landed this arc (all merged, Oracle-green)
- Bug #2 Odoo two-rule split + no-refetch core (#186).
- CF CHALLENGE verdict + identical-body dedup (#188), CWE-693 header coercion +
  natural-language CF markers demoted to WEAK (#189).
- Security hardening: secret redaction (allowlist), pgvector CVE bump (#190/#191),
  verify=False -> default-True opt-out, engagement_id boundary validation.
- GAP-002 scratchpad wired into the cognitive loop (#192) — event-sourced,
  tenant-scoped, non-island.
- Planner v1 (#193 + review fixes #194): objective-aware deterministic scoring
  (no CRC), GOAL_COMPLETED verified via is_met() (self-report removed +
  regression-guarded), pre-step resume completion. Bug #11 closed.
- Bug #21 LLM-tier tool starvation SEALED (#196): exclude_tools forwarded to
  SINGLE_LLM tier — prompt-level instruction + post-filter coercion + contract
  guard (CodeRabbit). Single-file fix (orchestrator.py), zero caller change.

## Key doctrine reinforced (do not regress)
- Green != proven. Every fix ships a test that FAILS if the bug returns
  (differential must pass on semantics not hash; is_met on verified graph;
  self-report ignored).
- Allowlist > denylist for secrets. Reuse the canonical redactor (llm/redaction),
  don't build a second.
- One canonical typed contract (objective, profile) — no dict/typed drift (#6/#7).
- Front-loaded signed consent (ADR §12.36), not many runtime gates: one signed
  EngagementProfile = the RoE; only blast>threshold (client-set) pauses at runtime.

## Next (choose one)
1. Planner v2 — HTN Planner/Executor + World-Model (§12.29 D2/D3). Keep it thin,
   differential-tested; do NOT big-bang.
2. Sellability — LOCK ADR §12.36, build slice-2a signed EngagementProfile
   (schema + capture at create_engagement + sha256+identity+timestamp signature,
   immutable, event-sourced), then resolve OPSEC/objective FROM it.
3. GAP-005/006 slice-2 — PolicyEnforcer OPSEC (2a) then technique+scope (2b) into
   recon_runner/execute_agent.

## Still open (tracked, non-blocking)
- Verify S2: pgvector:pg16 digest actually pinned in docker-compose.yml + ci.yml;
  document "Fixed in —" residual CVEs + network-isolation compensating control.
- Bug #17 (mod_autoindex sort), #19 (body-content classifier). GAP-003
  IntelligenceBase (needs Bug #7 engagement-memory persist).
- Planner objective is lab-injected; production objective must come from the signed
  EngagementProfile (§12.36).

## Test env
Oracle ARM64, Python 3.12.13, .venv312. Always `make check` (never bare pytest —
system python 3.10 fails StrEnum). Gamma/ANCHOR STILL STOP-gated.
