> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-07-21)

Resume with: "lanjut Agent-Alpha — A1-REACH SEALED (field-proven on Oracle: origin-direct CF bypass, chain_proven=True, nuclei=0, scanner_missed=True). NEXT = FORK: Omega payable report first (recommended), then Moat GAP-003, then Gamma. 578 green on the a1 suite."

## Current Project Status

```
Project Phase  : A1-REACH SEALED — field-proven on Oracle against real Cloudflare
                 (self-owned lab alpha-ai.web.id). Success-condition HIT: nuclei=0 →
                 chain proven via HARVESTED cred → verified admin, via origin-direct CF
                 bypass. 9c browser_solve PARKED (datacenter IP). Gamma STILL STOP-gated.
Last Decision  : A1-reach chain closed end-to-end through five honest live-path gaps the
                 unit tests had masked (green != proven; each surfaced only by the field-prove):
                 (1) probe decoupled from browser_solve — OBSERVE via http_client, not solver
                     (#238); (2) no-follow redirect seam on HttpClient — resolves CR CWE-918
                     SSRF on the probe (#240); (3) consent-decouple — signed --profile +
                     EngagementProfile.verify(), resolves CR CWE-862, C9 now a real filter
                     (sign_profile writer added); (4) CLI deps wiring — main() constructs
                     SecretsManager + NetworkXGraphStore + InMemoryEventStore; (5) origin-direct
                     login TLS — per-call verify override, wrapper injects verify=False for the
                     IP-literal origin (lab only; prod = SNI-override domain-cert, ADR §12.33).
                 Field-prove result: valid_run=True, challenge_encountered=True,
                 challenge_solved=False, chain_proven=True, edge_from_harvested_cred=True,
                 nuclei_findings=0, scanner_missed_exploitability=True,
                 technique_used=origin_direct, origin_authorized=True.
                 GOVERNANCE: sealed via field-prove harness on self-owned infra, NOT the
                 Conductor SOW path — REACH MECHANISM proven; production auth-gate
                 (SOW->OFFENSIVE_APPROVED) = Phase-6 VERIFY.
Next Action    : FORK opened (REACH sealed). Order chosen: Omega -> Moat GAP-003 -> Gamma,
                 with commodity-wrap as continuous background (NOT a phase).
                 1. OMEGA (payable client report) — turn the proven A1 chain into a client-
                    facing deliverable: narrative + attack-flow (entry -> bypass -> harvest ->
                    login -> admin) + reproducible proof artifacts. Lowest risk, converts the
                    seal into revenue-demonstrable output. See Omega design notes (this arc).
                 2. Moat GAP-003 IntelligenceBase (needs Bug #7 EngagementMemory persist).
                    Includes the AI-native minimal-FP verifier: wrapped-tool breadth ->
                    Claude context-triage -> DETERMINISTIC prove-or-kill -> attack graph
                    (VERIFY tier / GAP-009). LLM never the final arbiter (anti-#3).
                 3. Gamma (ToolComposer + blast-gate -> ANCHOR) — deepest, most dangerous;
                    open only after a sellable loop exists.
                 See docs/strategic_gaps_roadmap.md for the full G1–G17 + phased roadmap.
Test env       : Oracle ARM64, Python 3.12.13, .venv312 — ALWAYS `.venv312/bin/python3 -m pytest`
                 or `make check`. Full suite 1246+ green.
Phase status (verified on Oracle):
  Phase 0-3 : DONE.
  Phase 4   : breadth CONSOLIDATED — 14 playbooks (git/backup/actuator via path_probe catalog;
              tomcat/basic_auth/s3/graphql/odoo via capability catalog; wp/laravel/js/etc).
  Cognitive : GAP-002 WIRED; GAP-004 complete (D1/D2-a/D2-b/D3/D4/D5 all LANDED);
              GAP-003 IntelligenceBase OPEN; GAP-005/006 slice-2a WIRED, 2b/2c OPEN.
  A1-reach  : SEALED — field-proven on Oracle end-to-end (origin-direct CF bypass, cred
              harvest -> login -> verified admin; nuclei=0, scanner_missed=True). 9c
              browser_solve PARKED (datacenter IP -> CF managed challenge, no widget).
  Security  : Trivy .trivyignore for pgvector gosu CVEs + Redis 8 upgrade (PR #234).
              CodeQL: 6 low/medium alerts (log-injection + clear-text FP), all assessed.
Bug ledger  : FIXED #2/#6/#14 (greedy rules + starvation), #10 (415), #18 (CF CHALLENGE),
              #20 (identical-body dedup), #11 (crawl discrimination via planner), #21 (LLM-tier
              exclude_tools not passed). OPEN: #17 (mod_autoindex sort explosion), #19
              (body-content classifier generalization), #7 (engagement memory persist —
              Moat/GAP-003 prereq; canonical def = docs/BUGS_AND_GAPS.md). NOTE: "CF-pin"
              is a repro/infra task (Cloudflare dashboard), NOT Bug #7 — do not merge.
              RESOLVED this arc: CR CWE-918 (probe SSRF/no-follow), CR CWE-862 (consent
              tautology -> signed --profile + verify), origin-direct TLS split-brain,
              CLI dep under-wiring.
META (durable): status docs rot FAST. Before building anything, grep/trace the live path first —
              this session caught backup_file already-done, CRC theater, is_met dead-code, and
              self-report theater by verifying, not trusting the doc.
```

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
- 9c browser_solve service: Camoufox FastAPI service for CF Turnstile. Field evidence:
  Oracle ARM64 (datacenter ASN) → CF managed challenge, no widget → PARKED.
  WSL/residential IP → challenge_solved=true, cf_clearance obtained.
- ADR §12.33 EXTENDED: IP-reputation doctrine + origin-direct reach strategy.
  Origin-authorization gate (signed authorized_origins, fail-closed).
- A1-reach Slice A/B/C SEALED: origin-direct gate + reach_strategy + 9d.
- Trivy pgvector .trivyignore (16 gosu CVEs) + Redis 7→8 upgrade (#234).

## Key doctrine reinforced (do not regress)
- Green != proven. Every fix ships a test that FAILS if the bug returns
  (differential must pass on semantics not hash; is_met on verified graph;
  self-report ignored).
- Allowlist > denylist for secrets. Reuse the canonical redactor (llm/redaction),
  don't build a second.
- One canonical typed contract (objective, profile) — no dict/typed drift (#6/#7).
- Front-loaded signed consent (ADR §12.36), not many runtime gates: one signed
  EngagementProfile = the RoE; only blast>threshold (client-set) pauses at runtime.
- IP reputation doctrine: browser_solve NOT viable from datacenter ASN (CF managed
  challenge has no widget). Residential/clean IP required for CF challenge solve.

## Next (choose one)
1. Gamma prereq — ToolComposer + blast-gate → ANCHOR: depth of "prove exploitable".
2. Sellability — LOCK ADR §12.36, build slice-2a signed EngagementProfile
   (schema + capture at create_engagement + sha256+identity+timestamp signature,
   immutable, event-sourced), then resolve OPSEC/objective FROM it.
3. GAP-005/006 slice-2 — PolicyEnforcer OPSEC (2a) then technique+scope (2b) into
   recon_runner/execute_agent.
4. Moat — Bug#7 EngagementMemory persist → GAP-003 IntelligenceBase.

## Still open (tracked, non-blocking)
- Bug #17 (mod_autoindex sort), #19 (body-content classifier). GAP-003
  IntelligenceBase (needs Bug #7 engagement-memory persist).
- Planner objective is lab-injected; production objective must come from the signed
  EngagementProfile (§12.36).
- CodeQL: 6 low/medium alerts (5× log-injection, 1× clear-text FP) — assessed, not
  blocking. Dismiss as FPs or sanitize later.

## Test env
Oracle ARM64, Python 3.12.13, .venv312. Always `make check` (never bare pytest —
system python 3.10 fails StrEnum). Gamma/ANCHOR STILL STOP-gated. 1246 tests green.
