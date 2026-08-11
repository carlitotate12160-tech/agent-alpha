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
- **12.1** Two-phase LLM gate: `RULE` / `SINGLE_LLM` / `CONSENSUS_LLM`. (AMENDED 2026-08-04: `CONSENSUS_LLM` restricted to Phase Gamma/Destructive. Recon & Beta MUST use `RULE` or `SINGLE_LLM` to reduce latency bottleneck).
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
- **12.13** Agent scaling model: hybrid orchestrated fan-out. Agents = ROLES (not singletons); Conductor partitions work into bounded units for N stateless workers via Celery+Redis. No agent-to-agent dispatch; only Conductor dispatches. Two patterns: data-parallel (partitioned target) and functional-parallel (different techniques). Invariants: gate never dilutes, bounded autonomy, deterministic aggregation, no direct A2A dispatch. Phase 0-2 = single worker; Phase 3 = fan-out-aware interface. (AMENDED 2026-08-04: Celery fan-out RESTRICTED to massive-scale tasks only. Targeted web recon & Beta must run in-process via asyncio/goroutines to eliminate latency overhead).
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
- **12.38** Origin-Scope by Ownership (PROPOSED): replaces hand-fed `authorized_origins` IP allowlist with two-proof runtime binding. Proof-1 = server-minted DNS-TXT domain ownership (token bound to engagement_id, client places `_agentalpha.<domain> TXT "agent-alpha=<t>"`). Proof-2 = `OriginBinder.serves(origin_ip, fronted_host)` — cert SAN match OR cryptographic origin marker (authorizing); body-identity is DIAGNOSTIC ONLY (cache/CDN/shared-host can echo owned site's body → collateral risk). Revised `assert_origin_authorized` gate: guardrail → owned target → `allow_evasion` consent → binder.serves → only then origin-direct authorized. OriginBinder rejects any origin_ip failing the shared internal-destination guard (reused from resolve_targets) before connecting. Schema: `authorized_origins` removed as client input; `ownership_tokens: Mapping[str,str]` added to signed canonical JSON. Build order: niagamas spine first, this second. Honest limit: sells origin-exposure bypass, NOT interactive challenge solve.
- **12.39** Alpha→Gamma skip-Beta routing (ACCEPTED design-intent): Alpha may route directly to Gamma IFF ALL FOUR: (1) no-auth exploitation, (2) `cross_verified` primitive not fingerprint, (3) reach solved, (4) auth+blast gate enforced. Bound to verification moat — cannot build until exploit-reachability oracle exists (condition #2's `cross_verified` stamp). Slice-1a stays clean: `router.py` implements ALPHA→{BETA,OMEGA} + BETA→{GAMMA,OMEGA} only, no speculative ALPHA→GAMMA branch. ChainOracle constraint: composition of independent per-edge oracles, NEVER graph traversal.
- **12.40** Content-Analysis Lane (PROPOSED): oracle-gated LLM hypothesis over already-fetched bodies. Closes recall ceiling vs Strix — 3 of Strix's 7 bernofarm findings were in the 195KB homepage Agent-Alpha already fetched but didn't analyse (SEO spam, plugin CVE, exposed nonce). LLM proposes Hypothesis{finding_class, locator, raw_evidence} → deterministic per-class verifier confirms/rejects → only Confirmed → SELF_VERIFIED node. Closed enum of 3 classes (plugin_cve ships first). Zero detection-time HTTP (reach-independent). Replaces wasted `generic_http_probe` fallback on unmatched OK bodies. Anti-Lyndon #3: unverified LLM claim is never a finding. Reach (§12.4x Caido/session pattern) + classifier soft-200 fix explicitly out-of-scope.
- **12.42** Vantage = EXTERNAL unauthenticated adversary (black-box, no implant/source/foothold at
  t0); Footprint = AGENTLESS (no implant ever, post-ex via LOLBin §8g). Attacker Doctrine:
  exhaustive-surface map (all entry points, not 3 doors), stop only when surface exhausted
  (§12.24), vuln-classes = gated oracle-verified lanes one at a time (§12.40), business-logic
  DEFERRED to Phase 5/6. Internal/assumed-breach = later SECONDARY profile via pivot. Scope guard
  vs #4/#5.
- **12.43** Proof standard (extends §12.31/§12.32): payable finding needs BOTH an INDEPENDENT
  oracle (different failure mode → cross_verified) AND a human-legible ProofArtifact (screenshot +
  HAR, storage_ref). Raw HAR vault-only; redacted artifact for client reports. Screenshot = EXHIBIT,
  not oracle (anti-#3). Access/login oracle = auth-vs-unauth ground-truth diff. Missing OR invalid
  oracle, visual, or storage_ref → downgrade, excluded from KPI.
- **12.44** Evasion technique catalog (extends §12.33/§12.42): ROI ladder — (1) origin-direct = bypass
  the edge, defeats ALL classes, datacenter-viable, highest ROI (invest in origin-discovery breadth);
  (2) fingerprint parity JA4/HTTP2/header-triad (FINGERPRINT, datacenter); (3) rate/behavioral +
  cf_clearance reuse; (4) IP-reputation/managed-challenge = INFRA-bound (residential proxy OR
  client-side SOW whitelist/lower-protection), NOT code, CAPTCHA solvers FORBIDDEN; (5) WAF-signature =
  DeepSeek/Gamma. `evasion/` package = EvasionTechnique registry + executors, each declaring class +
  viability(datacenter|infra|client_side|forbidden). Evasion is EXTERNAL-vantage-specific (irrelevant
  to a future internal product). Build slice-by-slice on real obstacles, not up front. alpha-ai.web.id
  full-CF from datacenter → only viable code lever is origin-direct.
  **Clarification (2026-08-05):** `evasion/` EXTENDS `transport_resilience.EvasionTechnique` (existing
  enum, 4 members), does NOT redefine it (anti-#6). If `StrEnum` extension is infeasible for
  `viability` field, rename the new descriptor type (e.g., `EvasionCatalogEntry`).
  `TECHNIQUE_FOR_MITIGATION_CLASS` stays single-source in `constants.py` (anti-#7).
- **12.45** Credential-result semantics (extends §12.43/§3a): a red team NEVER certifies "safe" —
  absence of a finding ≠ absence of vuln. Credential finding = POSITIVE only (no safe/strong node
  or report claim). Negatives carry a METHOD+LIMIT caveat, never a verdict; Omega forbidden from
  "safe/secure/not-predictable" phrasing. Password recall scales via offline hash-crack (harvest
  hash → hashcat/rockyou/rules, high-recall, safe, THE strong one, Gamma-adjacent) + credential
  stuffing (breach corpus), NEVER unsafe online spray. Methodology transparency in every cred
  section. Roadmap vectors tracked in BUGS_AND_GAPS; no code now.
- **12.46** Origin-binding runtime authorization (extends §12.36/§12.38/§12.42/§12.44): signed
  profile grants a CAPABILITY (`allow_origin_discovery: bool`), not a pre-signed IP list. Per-IP
  authorization DERIVED at runtime from two proofs: P1 = domain ownership (DNS-TXT or well-known HTTP
  token file, already built), P2 = origin binding (NEW: TLS cert SAN match OR ownership canary +
  content-identity corroboration). Canary = PRIMARY, reuses P1 token at
  `/.well-known/agent-alpha-<token>.txt` (one artifact, two fetches: CF-fronted + IP-direct).
  Authorize iff P1∧P2. Wildcard/shared cert without canary ⇒ REJECT (fail-closed, anti-co-tenant).
  Event-sourced: `OriginBindingProven` event carries binding artifact for audit; signature integrity
  preserved (never mutate signed profile). `assert_origin_authorized` extended: signed-list OR
  (capability on + binding event exists). Wires `discover_origin_ips` island into live path.
  Datacenter-viable, no infra. First slice: `verify_origin_binding` + consent + event + wire
  existing subdomain→IP pivot (bernofarm: 94 CT subdomains). Discovery-source breadth (DNS-history,
  Shodan, MX/SPF, SSRF) = later slices. RESOLVED (2026-08-03): (1) friction = hybrid — passive recon
  URL-only, origin-direct/offensive needs one-time per-domain ownership verification cached per
  account; IP optional (provided = shortcut, absent = discover+bind); (2) canary = reuse ownership
  token at well-known HTTP path, no separate marker, cert-SAN corroborating only; (3) candidate
  budget = 3 probes/host, backoff 5s→15s→60s with ±20% jitter via LockoutGovernor. Staging:
  user-facing friction low early, NEVER relax safety proofs (P1 for intrusive, P2 for every origin).
- **12.47** Recon-phase tool unification (PROPOSED): `Tool` (phase="recon") is the ONLY sanctioned
  home for new stack-specific recon capability — no new entries to `Alpha._dispatch_registry` /
  `CAPABILITY_CATALOG` for stacks not already there. New stacks (Laravel-complete, Spring, Node,
  .NET, …) added as `Tool` implementations in `ToolRegistry`, ranked by `applies_to(ctx)` against
  `TargetContext.tech_stack` — same mechanism access-phase tools already use (anti-#6). `run_recon`
  gains an ADDITIVE second dispatch path: existing `_dispatch_registry` (WP/Odoo/Tomcat/git/backup/
  js-secret — frozen, not rewritten) PLUS `ToolRegistry.ranked(ctx)` filtered `phase="recon"`.
  Existing WP battery (551 lines, ~26% of scout.py) frozen as-is; migration = separate future
  decision. Recon `Tool`s = DETECT only, read-only, proof artifact mandatory (§12.26). Closes
  scout.py slow drift toward god object (anti-#8). Build slice-by-slice on real need, not up front
  (anti-#1/#5).
- **12.48** [🔥 PRIORITAS UTAMA CLAUDE COWORK: SLICE 1] Passive-First Recon Doctrine (ACCEPTED 2026-08-04): mandatory Phase 0 = OSINT gathering
  (crt.sh + VirusTotal + DNSDumpster) BEFORE any HTTP request to target. `PassiveIntelMap` data
  contract holds subdomains, origin IP candidates, MX/TXT records, tech stack hints, protection
  posture (CF/Akamai/Sucuri detection from NS records), historical paths. Intel DRIVES active
  recon: stack-relevant paths only, origin-direct prioritized over front-door, unprotected subdomains
  before CF-fronted. Exhaustive surface strategy: try origin-direct → unprotected subdomains →
  MX/mail infra → TLS impersonation → LAST RESORT report + client whitelist recommendation.
  API keys in `.env`, per-engagement source toggle in EngagementProfile. Graceful degradation:
  missing API keys → source skipped, all fail → fall back to existing blind-probe behavior.
  Amends §12.25 (paths gated by intel), §12.42 (exhaustive surface, never give up after front-door
  block). Event: `PASSIVE_INTEL_GATHERED`.
- **12.49** [🔥 PRIORITAS UTAMA CLAUDE COWORK: SLICE 2] Proactive Evasion Posture (ACCEPTED 2026-08-04): evasion-by-default from FIRST request,
  not after N blocks. curl_cffi (`impersonate="chrome131"`) as DEFAULT transport (not fallback).
  `HttpClient.transport_mode`: `"stealth"` (curl_cffi, production default) | `"raw"` (httpx, lab
  only). Realistic browser headers: random UA from `BROWSER_UA_POOL` (5-10 current Chrome/Firefox/
  Safari, selected per-engagement for session consistency), full Sec-Fetch-* header set.
  Protection-aware: Phase 0 CF detection → origin-direct first, NEVER raw httpx to known-protected.
  Reactive evasion (§12.33 `EvasionPlanner`) RETAINED as Layer 2 escalation. `DEFAULT_OPSEC_PROFILE`
  changes `"announced"` → `"stealth"`. Two profiles: `stealth` (browser UA, curl_cffi, human pacing)
  = red team default; `announced` (identifying UA, httpx, rate-limited) = compliance/audit.
  Event: `EVASION_POSTURE_SELECTED`.
  **Clarification (2026-08-05):** "stealth" default sits INSIDE existing §12.36 consent envelope —
  "default" ≠ "authorized". `stealth` maps to `blend` semantics (`evasion: true` in `policy.yaml`).
  `resolve_opsec_profile()` fail-closes to `announced` when `evasion_authorized=False` (i.e.,
  `opsec_stealth=False` / `allow_evasion=False` in signed EngagementProfile). Without signed consent
  → `announced`, never silent stealth. `test_opsec_profile.py` / `test_policy_yaml.py` MUST assert
  this fail-closed behavior. If `stealth` ≠ `blend` semantics, rename to avoid conflating with
  existing `announced`/`blend` authorization pair (anti-#3).
- **12.50** [🔥 PRIORITAS UTAMA CLAUDE COWORK: SLICE 3] Human-Like Behavioral Fingerprint (ACCEPTED 2026-08-04): replace fixed-interval
  `RateLimiter` (0.5s periodic = scanner signature) with `StealthPacer` burst-and-pause pattern.
  BURST (3-5 reqs, 50-200ms intervals) → READ PAUSE (2-8s ±20% jitter) → BURST → THINK PAUSE
  (10-30s, every 3-5 bursts) → occasional IDLE (60-120s, every 10-15 bursts). Burst size adapts:
  single req for new host, 3-5 for same-host follow-up. `RateLimiter` retained as floor (safety
  bound). `StealthPacer` in `agents/stealth_pacer.py`, duck-typed with `RateLimiter` via `acquire()`.
  All timing constants in `constants.py` (`STEALTH_BURST_*`, `STEALTH_*_PAUSE_S`, `STEALTH_JITTER_FACTOR`).
  `"announced"` profile keeps plain `RateLimiter`. Extends §12.49/§12.33.
- **12.51** [⏸️ STATUS: FUTURE SLICE (DEFERRED)] Gamma Exploit Generation (PROPOSED): 3-Layer Hybrid Dual-Engine. Uses Curated Tools for
  known patterns, LLM ExploitSynthesizer for novel attacks. Synthesis bounded by 3 layers:
  Constraint-Guided Generation (no free-form coding) → Sandbox Verification (structural+safety checks)
  → Graduated Execution (Dry Run, Proof, Cleanup). EDR evasion scope restricted to Web-Layer
  (Living-off-the-Land) until Phase Gamma/Delta proper. Gamma remains STOP-gated behind blast-radius.
- **12.52** [🔥 PRIORITAS UTAMA CLAUDE COWORK: SLICE 4] Governance Simplification (ACCEPTED 2026-08-04): Reduce friction for red team agility.
  (1) LLM Consensus restricted to Phase Gamma/high-blast actions; Alpha/Beta must use Rule/Single_LLM.
  (2) Celery fan-out restricted to massive horizontal scale; targeted web recon uses in-process asyncio/goroutines.
  (3) Formalizes Reactive Evasion relegation to Layer 2 (per §12.49).
- **12.53** [🔥 PRIORITAS UTAMA CLAUDE COWORK: SLICE 5] Deep Evasion Stack (ACCEPTED 2026-08-04): Mimic legitimate user journeys.
  Requires Session Persistence (Cookie Governor), Strict Header Ordering (matching UA pool), and Residential Proxy routing hooks.
- **12.54** [🔥 PRIORITAS UTAMA CLAUDE COWORK: SLICE 6] Deep Recon Quick Wins (ACCEPTED 2026-08-04): Expand Phase 0 with Wayback Machine (historical endpoints) and Credential Breach OSINT (Dehashed/HIBP) for high-ROI intelligence.
- **12.55** Doctrine of Realistic Exploitation (ACCEPTED 2026-08-04): Agent is a 1-day/misconfig weaponizer, NOT a 0-day hunter. Requires real-time CVE/NVD integration. Gamma ToolComposer adapts known PoCs rather than hallucinating novel exploits.
- **12.56** Passive Supply Chain Recon & Assume Breach (ACCEPTED 2026-08-05): 3rd-party hacking strictly forbidden. Agent MUST simulate supply chain threats ethically via: (1) Asset Hijacking (Subdomain/CDN), (2) Dependency OSINT, (3) Assume Breach Mode. Implementation queued post-foundation.
- **12.57** Alpha as a Gate-Respecting Operator — Closed Feedback Loop (ACCEPTED 2026-08-08): Alpha becomes an operator by CLOSING the feedback loop (findings steer behaviour), gate-respecting. Four behaviours: (1) finding → recon-side follow-through + gated Alpha→Beta hand-off (Alpha RECON_ONLY, never access); (2) mid-engagement pattern-group exhaustion (deterministic, anti-#6); (3) fingerprint drives path hard-filter (remove irrelevant, not just add); (4) strategy pivot on failure (bounded ≤3, playbook-driven, never LLM). Rejected: event-driven parallel pivot (Phase 5+ — RECON_ONLY + no mutable shared state); LLM "judgment layer" (hallucination-prone; LLM stays in ORIENT, DECIDE is deterministic). Concrete slices: GAP-020 → GAP-021 → GAP-022.
- **12.58** Strategic Situation Reasoning / "operator instinct" (PROPOSED / SEED 2026-08-09): deterministic strategic control-loop + heuristic reprioritization of the work queue. NOT "awareness/instinct" — concrete buildable capability. "APT instinct" = experience-encoded pattern heuristics (dead host → skip; hard front → find flank; have creds → reuse). Deterministic rules, NOT LLM (§12.57 rejects LLM judgment layer). Build ONE concrete heuristic first; extract `SituationAssessor` container only when 2–3 instincts exist (promotion-on-repeat). First instinct = entry-selection / dead-target pivot (reprioritize frontier by reachability + softness + value; skip WAF-confirmed-dead targets). Trigger-driven, not heavy periodic. Rejected: LLM strategic brain (§12.57); big-bang framework before proven instinct (#1/#4); per-target hardcoded behaviour (#11). Open: trigger set vs periodic cadence; composition with BoundedAutonomy stall semantics; reprioritization signal (reachability + softness + value); determinism + seeded replay. Cardinal test: GIVEN all primary targets WAF-unreachable AND one in-scope subdomain reachable → strategic reprioritization selects reachable subdomain, skips dead apex (deterministic, universal, no per-client logic). Field evidence: niagamas (apex dead, hub/pos reachable — no pivot) + bernofarm (same mechanical non-pivoting behaviour).
- **12.59** Hybrid Cognition Roadmap — deterministic-first (ACCEPTED, Phase-6 OPEN 2026-08-09): operationalises §12.58 into a build order. Phase 4 = deterministic instincts one-at-a-time, field-proven (entry-selection #1 → dead-target pivot → cred-reuse). Phase 5 = promote to `SituationAssessor` container (still deterministic, promotion-on-repeat, only at 3–5 instincts). Phase 6 = LLM advisor in DECIDE = OPEN QUESTION, not locked; empirical trigger (robot-feel persists on CONTROL after SituationAssessor stable) decides it. Reaffirms §12.57 (LLM in ORIENT, never DECIDE) for Phase 4–5. Key insight: the more-than-deterministic layer (novel hypothesis) is ORIENT and already LLM-backed; DECIDE is where determinism is the strength (reproducible/gate-safe/seeded-replay). Flaw in "LLM propose, validator approve": circular unless the validator has an independent oracle for out-of-menu proposals + full record-and-replay. Rejected: LLM-in-DECIDE for Phase 4–5; locking Phase-6 architecture now. Deferred (not rejected): periodic assessment (§12.58 Q1).
- **12.60** Two-Tier Proof + Field-Feedback Ratchet (ACCEPTED 2026-08-09): lab-green ≠ field-ready — a lab built to match a capability omits what the capability omits (same failure mode = not verification, Independent Verification Axiom; deeper Lyndon #9 = lab vs field). Tier-1 lab-seal = reproducibility (necessary, not sufficient; fixture MUST include field-known adversarial shapes). Tier-2 field-prove on real/self-owned hostile target = THE bar. Field-Feedback Ratchet: every field failure → permanent synthetic fixture in a test_field_regression corpus (promotion-on-repeat at the test layer) so it never silently regresses and the lab grows toward field realism = the anti-frustration-#5 milestone. Every slice forward carries a field-shaped Tier-1 fixture + a Tier-2 note. Rejected: lab-green=done; field-only (no seeded-replay); big-bag field-sim framework up-front.
- **12.61** Flank-when-CF-hard: origin-discovery breadth (ACCEPTED, menu 2026-08-09). CF "ceiling" is only bruteing the edge (infra-deferred); the operator FLANKS — find origin via side channels (historical DNS ★, mail/MX, cert/favicon pivot, grey-cloud subs) or skip the perimeter (leaked-cred stuffing, exposed secrets, S3, subdomain takeover), mostly PASSIVE/datacenter-friendly. Build as a MENU, one slice at a time (order: historical DNS → cert/favicon → leaked-cred); moat = composition + PROOF, not API-wrapping (#6); auth two-proof binding unchanged; §12.60 two-tier (field-prove on niagamas/bernofarm). Full-CF-no-origin → sellable defensive-validation report (SEA market). Rejected: edge-brute from datacenter IP (infra), build-all framework (#1/#5), per-target discovery (#11).
