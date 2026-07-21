> DERIVED from ADR.md — regenerated, DO NOT hand-edit.

# Agent-Alpha — ADR Summary (Decision Map)

> **Purpose.** Token-cheap map of every architectural decision for Claude project
> context. Full rationale + detail lives in `ADR.md` (repo only). When a
> section is needed in depth, paste that specific §N from the full ADR into chat.
> This file is the index; it is intentionally NOT the source of truth.

**Mirrors:** `ADR.md` v1.1 (LOCKED, append-only). If conflict → `ADR.md` wins.
`ADR_HISTORY.md` (formerly `ADR_ROADMAP.md`) is deprecated — do not cite.

---

## §0 Design Principles (First Principles)

- Authorization is the foundation, not a feature.
- One agent, one responsibility; handoff is a data contract, not a side-effect.
- Autonomous after authorization (checked once in Conductor).
- Proof over claims (proof-of-exploitation required).
- Reasoning over durable state (AttackGraph = single source of truth), not hidden state.
- Bounded autonomy (iterations/time/cost/scope guardrails).
- Event-sourced truth (state = projection of append-only event stream).
- Learn, don't self-rewrite (improve via data/playbook, never modify own code).
- Safety layer immutable to the agent (auth, kill switch, audit, policy).

## §1 Authorization Layer (non-negotiable, Conductor-only)

Written-auth/SOW upload, explicit scope, tiered states
(RECON_ONLY → ACTIVE_APPROVED → OFFENSIVE_APPROVED), emergency stop, immutable
audit log, blast-radius calculator + human gate, hard-limit enforcement.

## §2 Final Decisions

| Item | Value |
|------|-------|
| Domain | Security-only, Level 1-6, authorized engagement (SOW for Level 4+) |
| AI Brain | Python 3.12 (reasoning, memory, graph, reporting) |
| Exec Engine | Go (network-heavy agents + deployable tools) |
| IPC | gRPC (Python ↔ Go); A2A = structured English JSON |
| Orchestration | Celery + Redis (non-blocking, multi-tenant queues) |
| Memory | Redis (session) + PostgreSQL + pgvector (long-term/semantic) |
| Deploy | Oracle Cloud ARM64 (only valid test env) |
| Multi-LLM | Parallel consensus (DeepSeek + secondary) critical; single-LLM light |

## §3 Agents

Conductor (orchestrator) → Alpha SCOUT → Beta STRIKE → Gamma ANCHOR →
Delta HUNTER → Epsilon SCOUT-HUNTER → Omega ROASTER. Agents never call each
other directly; all transitions via Conductor (validates contract + auth state).

## §4 Memory (4-layer)

SessionMemory (Redis, volatile) · EngagementMemory (PostgreSQL, permanent) ·
IntelligenceBase (pgvector, cross-engagement learning) · UserMemory (style/lang).

## §5–§7 Differentiators

ToolComposer (runtime exploit composition from template + SCOUT context) ·
AttackGraph (node/edge story, find_critical_paths, blast_radius, to_narrative) ·
Parallel attack paths · "Try Harder" agent · structured prompt from graph facts.

## §8 NodeZero-derived additions (titles)

VERIFY/re-test mode · continuous engagement · impact-based prioritization ·
safe-in-production guardrails · proof artifacts · conversation caching (8a) ·
finding-level memory (8b) · learning loop/outcome tagging (8c) ·
multi-LLM consensus (8d) · engagement profiles (8e) · pivot-chain tracking (8f) ·
OS-as-tools/LOLBin (8g) · cognitive loop OBSERVE→PERSIST (8j) ·
inner monologue + scratchpad (8j-2) · LLM role split (8k) ·
platform security/prompt-injection defense (8l) · reliability/checkpoint (8m) ·
reporting standards/RoE (8n).

## §8o Foundational Spine

- 8o-1 Event-sourced core + CQRS (backbone; projections = graph/audit/metrics).
- 8o-2 Cognition layer (planner/executor + world model + simulation/dry-run).
- 8o-3 Knowledge ingestion pipeline (RAG over CVE/exploit-db/ATT&CK; Phase 6).
- 8o-4 Tool registry + version pinning + determinism (seed/temp recorded).
- 8o-5 Policy-as-Code + blackboard coordination.
- 8o-6 Adaptive learning L1 = judgment, NOT self-modifying code (explicit out-of-scope).

## §9 Roadmap (phase one-liners)

- **P0** Foundation: Conductor, auth state machine, SOW, emergency stop, event core, policy-as-code, secrets vault. *(complete)*
- **P1** Memory + AttackGraph as event projection; finding auto-linking; durable PostgreSQL event backend + engagement-level resume.
- **P2** Alpha→Omega end-to-end (RECON_ONLY); cognitive loop; differential test; real-target gate; static YAML playbook.
- **P3** Beta STRIKE; Celery non-blocking; LLM consensus + role split; step-level checkpoint/resume.
- **P4 / 4b** Gamma ANCHOR + ToolComposer + proof artifacts; advanced cognition (simulation, registry).
- **P5** Delta + Epsilon; pivot-chain; LOLBin; parallel paths; AD (GOAD).
- **P6 / 6b** IntelligenceBase learning; reflection/playbook; RAG; VERIFY mode; extra profiles; benchmark/observability.
- **P7** Port network-heavy agents to Go.

## §11 Key Risks → Mitigations (one-liners)

Legal/abuse → auth + immutable audit · blast radius → calculator + human gate ·
hallucination → structured prompt from graph · prompt injection → trusted/untrusted
separation · LLM refusal → role split (payload→any model, TEMPORARY testing phase) · data leak → redaction +
self-host · runaway cost → stop conditions + budget cap · over-engineering learning
→ no self-modifying code.

## §12 Addendum v1.1 — LOCKED (append-only)

All threshold numbers live in `config/constants.py` (single source of truth, §8o-4).

- **12.0** 2-layer hybrid (deterministic + adaptive). HARD PROHIBITION: no static/linear step list in agent code; `next_action = f(graph + playbook)`.
- **12.1** Two-phase LLM gate: `RULE` / `SINGLE_LLM` / `CONSENSUS_LLM`.
- **12.2** Differential test (Phase 2 exit): different fingerprint → different path, else TEST FAIL.
- **12.3** Real-target gate: GCP free-tier isolated labs, firewall to agent IP only, 3 fingerprints, FP < 20%.
- **12.4** RAG timing: Phase 2 = static YAML playbook; full RAG = Phase 6.
- **12.5** Learning storage: event-sourced; metrics→DB table, playbooks→markdown; all data/config not code.
- **12.6** Playbook vetting: low-risk auto-promote; risky offensive needs manual review.
- **12.7** "Similar target" = weighted composite (tech_stack + protection primary).
- **12.8** Tool reliability: score data-driven, threshold hardcoded; agent never edits thresholds.
- **12.9** Playbook promotion: ≥N successes across ≥M different targets + Wilson lower-bound.
- **12.10** Dev workflow: platform code → Claude; payload bodies in `templates/*` → any model (TEMPORARY testing phase), NEVER Claude.
- **12.11** Durability/resume: durable append-only event log = source of truth; graph/Redis volatile (rebuilt via replay). Staged resume (engagement-level P1, step-level P3). Interrupted offensive action = RE-VERIFY, never re-execute.
- **12.12** GraphStore abstraction: swappable graph engine (NetworkX P0-3, Memgraph/Neo4j P4+), always a projection of the event log.
- **12.13** Agent scaling model: hybrid orchestrated fan-out. Agents = ROLES (not singletons); Conductor partitions work into bounded units for N stateless workers via Celery+Redis. No agent-to-agent dispatch; only Conductor dispatches. Two patterns: data-parallel (partitioned target) and functional-parallel (different techniques). Invariants: gate never dilutes, bounded autonomy, deterministic aggregation, no direct A2A dispatch. Phase 0-2 = single worker; Phase 3 = fan-out-aware interface.
- **12.14** Front-door 2a: authenticated tenant binding. JWT authN, tenant from verified claim only, ownership 404 on all engagement routes, per-tenant store routing. Resolves P2 auth gap.
- **12.15** LLM role→provider routing: roles canonical (REASONING vs PAYLOAD), providers configurable. Reasoning = direct or gateway (zero-retention public router OK); Payload = direct provider ONLY (never aggregator, never Claude). Data-governance invariant: sensitive data never egresses to public router without zero-retention contract.
- **12.16** Tool layer: agents=kill-chain roles; payload/proxy/browser=capabilities not agents (browser=Camoufox, shared Alpha+Beta; proxy needs health check). Tool/Template/Registry/Composer contracts: compose()=plan-not-execute, Template.verify() mandatory (proof not assumption), reliability-ranked not hardcoded, offensive bodies=DeepSeek. Build per-phase, not up front.
- **12.4 (amended)** RAG split: internal pgvector RAG=Phase 6 (cold-start); external CVE/Exploit-DB/ATT&CK feed may precede internal IF hypothesis→verify loop + recon fingerprinting exist. Both advisory+gated, feed hypothesis/verifier, never autonomous retrieve→exploit.
- **12.17** Secrets vault: Postgres-backed, Fernet-encrypted, RLS-scoped per tenant. `SecretsVault` Protocol + `SecretsManager` (in-memory) + `PostgresSecretsVault` + `SecretsVaultProvider` (lazy per-tenant, mirrors `StoreProvider`). Import-safe; key loaded on first `for_tenant()`.
- **12.18** Scope.db_endpoints + Applicator Factory: `Scope.db_endpoints` (explicit `host:port` in SOW) + `is_db_endpoint_in_scope()` gate method + `applicator_factory.py` (Conductor-side, the ONLY place auth state + scope read to select/bind applicators). Three flaws converged: FLAW 1 (tier gate, cred_reuse auth-blind), FLAW 2 (in-scope DB endpoint, not leaked DB_HOST), FLAW 3 (host⊕port join via `open_ports`). `BoundApplicator(applicator, target)` — cred_reuse iterates, never chooses target.
- **12.19** External benchmark gate (PROPOSED): three-tier external benchmark as Phase 6 / pre-GA exit criteria. Tier A = AutoPenBench autonomous (primary), Tier B = CyberGym real-world chaining (primary, false-success guard), Tier C = Cybench (secondary, regression only). Internal payable-report bar still dominates. Harness exercises real Conductor autonomous path, NOT chain_runner. Build trigger: autonomy audit green + cred-reuse on Celery path.
- **12.20** Conductor handoff-consumer: autonomous spine on Celery path. `advance.py` (pure decision + effectful orchestration) + `test_conductor_advance.py` (RED tests). Proto enum semantics with CONDUCTOR/0 = unset guard. Agent never calls agent; Conductor's `advance_engagement()` is SINGLE place for handoff consumption, validation, auth gate check, and dispatch. Auto-advance respects tier gate (parks across ungranted tier, human gate between tiers). Idempotent under Celery retry. Applicator factory call-site for Beta. Integration spec in `conductor_advance_handoff.md`.
- **12.21** External benchmark gate (PROPOSED): three-tier external benchmark as Phase 6 / pre-GA exit criteria. Tier A = AutoPenBench autonomous (primary), Tier B = CyberGym real-world chaining (primary, false-success guard), Tier C = Cybench (secondary, regression only). Internal payable-report bar still dominates. Harness exercises real Conductor autonomous path, NOT chain_runner. Build trigger: autonomy audit green + cred-reuse on Celery path.
- **12.22** Tool strategy: wrap commodity, build the moat, gate the dangerous. Decision 1 — litmus rule: build internal ONLY if uses attack graph / cross-engagement memory / proof-composition; otherwise WRAP behind `ToolResult` contract. WRAP = nmap/nuclei/sqlmap/ffuf/proxy/captcha/GSocket/john. BUILD = ToolComposer, IntelligenceBase, AttackGraph narrative, regional verified templates. Decision 2 — safety revisions: cohost_pivot/symlink default-DENY, credential spray lockout governor, persistence/exfil require explicit SOW clause + teardown. Decision 3 — new internal tools: scope/blast-radius governor, TransportResilience (WAF/CF discriminator), engagement teardown/restore.
- **12.23** Consensus-LLM tier deferral: `CONSENSUS_LLM` tier + `MiMoProvider` + parallel-consensus moved from Phase 3 to Phase 4 (Gamma). Phase 3 runs single reasoning provider only. Consensus is for exploit-chain selection / blast-radius / "Try Harder" — none occur in Phase 3 (ACTIVE_APPROVED, bounded, reversible). Doc-integrity sweep complete: §8-era citations repointed to §12.23.
- **12.24** Bounded-autonomy stall semantics (full: `docs/adr_bounded_autonomy_stall_semantics.md`): NO_PROGRESS is suppressed while the frontier still has un-probed work — `step()` reports `work_remaining`; `run_cognitive_loop` ignores NO_PROGRESS when `work_remaining>0`; hard ceilings (max_iter/time/cost) still bound a dud queue. Fixes a noisy real-crt.sh surface starving a live target that sorts after dead siblings (Layer V-B). REJECTED the YAML-exclusions band-aid (hand-feeding + masks the product bug). Refines §0 "bounded autonomy".
- **12.25** Well-known-path recon baseline: `run_recon` seeds a fixed, target-INDEPENDENT set of sensitive paths (`constants.WELL_KNOWN_LEAK_PATHS` — `/.git/config`, later `/.env` + backup files) into the frontier for every in-scope host — the seed of the path_probe catalog. Universal by design (standard recon hygiene); NOT a per-target static attack sequence (Lyndon #11 governs the ATTACK chain, not recon breadth). Stealth control, if ever needed, is a first-class `recon_policy` toggle (default on), never per-target hand-feeding.

- **12.26** Recon vector strategy (rubric + taxonomy + recon/Gamma boundary): add a payable vector ONLY if it (1) a paying client stack needs, (2) chains to reusable creds, (3) uses the moat — else WRAP/drop (anti-#4). Four classes, each with its own code path + auth gate: payable content-probe (path_probe catalog), surface-discovery (frontier feeder, separate catalog), exploitation (STOP-gated Gamma — DETECT is recon, ACT is Gamma), non-HTTP service (db_service, not a playbook). Header-matching = an ENGINE capability (header_contains/header_regex; headers already in observation, ignored) that unblocks a class — prioritised above any single template. Current payable set ~saturated for the known client base (WP/Laravel/Odoo/Spring).

- **12.27** REACH R3 exit-gate hardening: body+header-aware `CHALLENGE` verdict (CF/Sucuri/Imperva/Akamai), identical-body SHA-256 dedup, greedy-rule FP guard (no `default_creds`/`odoo` on nav-bar/404), exit gate = recorded fixtures with `cost==0` on junk (lab-green never advances a phase; live real-target = manual/authorized, never hard CI). Refines §12.22/§12.2/§12.3/REACH-R3.
- **12.28** Record/replay condition harness: transparent `RecordingHttpClient` → raw `status+headers+body` cassettes (JSON, per engagement, opt-in, default OFF). Record raw + gitignored (local/Oracle only, self-owned `lab_guard`); CI archetypes curated/scrubbed by hand. `docs/RECON_CONDITION_CATALOG.md` = SSOT archetype→signature→verdict→fixture→test. Feeds §12.27.
- **12.29** Goal-directed cognition (absorbs GAP-004+010): `EngagementObjective` first-class entity flows into `step(context)` (not `{}`), Planner/Executor + World-Model/belief-state, `GOAL_COMPLETED` stop reason + per-objective budget + multi-objective. Plan = f(graph,objective) (§12.0), requires clean graph (§12.27). Closes §8o-2.
- **12.30** Bounded curiosity: deterministic `curiosity_score()` over {status,headers,body,url} → re-prioritize frontier + ONE hypothesis-probe using EXISTING tool + record hypothesis. Stays in-scope/RECON_ONLY, `MAX_CURIOSITY_PROBES`, content=DATA (§8l), hypothesis→VERIFY→graph (§8j-2). Anti-generative. Upgrade path to §12.29.
- **12.31** Cross-tool verification tiers: `self_verified` vs `cross_verified`; high-FP findings require cross-validation (weighted by IntelligenceBase GAP-003); report distinguishes tiers, only `cross_verified` = payable "proven". Closes root cause of Bug #2/#14.
- **12.32** Post-access authenticated re-recon: `AuthenticatedCrawlMode` (diff unauth vs auth surface) = RECON (DETECT). Exploitation of IDOR/BAC/priv-esc = Gamma-gated (ACT, §12.26). Post-access sub-objective in planner (§12.29).
- **12.33** Adaptive evasion: CLASS-SCOPED — CHALLENGE+residential→browser_solve(9c), CHALLENGE+datacenter→NOT viable(ASN reputation), FINGERPRINT→tls_impersonate(9b), RULE_DENY→origin-direct. IP reputation doctrine: CF managed challenge from datacenter IP has no widget to click, browser_solve cannot solve regardless of fingerprint. A1 validation challenge_solved=false from datacenter = EXPECTED (C7 fail-loud). EXTENDED: reach strategy (scoping, NOT evasion) — RULE_DENY or CHALLENGE-without-viable-solve → ORIGIN_DIRECT, gated by SIGNED authorized_origins (§12.36), fail-closed. Commercial CAPTCHA solvers FORBIDDEN (engagement confidentiality). Origin candidates from discovery (CT/Shodan/DNS-history), never hand-fed. Implement `cf_curl_cffi` template; dynamic OPSEC via PolicyEnforcer (GAP-005).
- **12.34** Within-engagement credential mutation: `CredentialPatternMutator` (company+year+suffix → variants) used after literal reuse fails; bounded by auth tier + lockout governor §12.22; successful patterns → scratchpad (GAP-002) then IntelligenceBase (GAP-003). Within-engagement, not §8c cross-engagement.
- **12.35** Wiring gate + three-gate promotion (MUST COMPLY; full: `docs/adr_wiring_gate.md`). Rule 1: a component is done only when wired into a production path reachable from `main.py`/`run_recon` (outside its def file, tests/, live_fire/) — CI-enforced by `tests/governance/test_wiring_gate.py` (ratchet: WIRED_REQUIRED must stay wired, WIRING_DEBT forces a move on wire); a dead instantiation ≠ wired. Rule 2: unit-green ≠ wired — every component ships a W-test proving it runs through the real production path (non-island, anti-#2). Rule 3: three hard-stop gates — LAB-GREEN (unit+wired+make check) → FIELD-PROVEN (self-owned lab_guard + §12.28 real-condition cassettes) → PRODUCTION-AUTHORIZED (SOW + written scope + RoE + ALL safety gates active). "Client doesn't mind" ≠ authorization; a client's live systems are NEVER a QA ground; Gate-3 is unreachable while GAP-005/006 un-wired. Closes the dead-code and "lab-green→test-on-client" failure modes.
- **12.36** Front-loaded signed EngagementProfile (PROPOSED): ONE signed consent artifact at engagement creation — scope + OPSEC + evasion + technique opt-ins + blast_threshold, all over existing `policy.yaml` vocabulary. Confirming profile = auth state transition with RoE attached; agent runs autonomously within envelope. Signature = `sha256(canonical_json)` + identity + timestamp, event-sourced, immutable (supersede, never edit). ONLY runtime pause: blast > signed threshold (default `high`; client can set `medium`/`high`/`critical`/`off`; elevated autonomy requires explicit acknowledgment). Hard floor: `always_forbidden` techniques + out-of-scope targets NEVER overridable. Fail-safe: no profile → no OFFENSIVE_APPROVED. Anti-Lyndon: one type, one config source. Slices: 2a schema+signature → 2b OPSEC resolution → 2c technique opt-ins.
