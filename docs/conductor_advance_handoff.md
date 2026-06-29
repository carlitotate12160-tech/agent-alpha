# Conductor handoff-consumer — integration spec (audit A1 + Step 3c)

**Lane:** Conductor orchestration (Claude). Security-critical (touches dispatch + auth
read) → on Oracle implement carefully, route Opus/GPT-5.1. **Verify Oracle ARM64 only.**
Files authored (mount): `advance.py` → `agent_alpha/conductor/advance.py`,
`test_conductor_advance.py` → `tests/phase_3/`.

> Mounted tree is #42; I designed against #61 facts from the audit (HEAD 32968df). Confirm
> the items below on #61 before wiring — do NOT assume (#2).

## What this closes

Audit A1 was RED: Conductor never consumes handoffs; the payable chain only runs via
`live_fire/chain_runner.py:152 main()` (single-process script). This module makes the
**Conductor** advance Alpha→Beta on the **Celery** path, gate-validated, and it is the
call-site where the applicator factory (3c) feeds Beta's `cred_reuse` task. A1, A6-chain,
and 3c collapse into this one deliverable.

## New event types (add to `agent_alpha/events/event_types.py`)

```
HANDOFF_READY      # appended by an agent task on completion (status + next_recommended)
AGENT_DISPATCHED   # appended by Conductor when it enqueues the next agent (idempotency key)
AWAITING_APPROVAL  # appended when the next agent needs a higher tier than granted (park)
CHAIN_COMPLETE     # appended when no next agent remains (Omega done)
```

CONFIRM first: does Alpha/`recon_runner` already emit a handoff-ish event under another
name? If so, reuse it and adapt `latest_handoff()` to its payload shape instead of adding
HANDOFF_READY. One canonical handoff event (#6) — do not create a second.

### Handoff contract — from `proto/a2a.proto` (the single source of truth, NOT a2a_pb2.py)

The generated `a2a_pb2.py` is gitignored and is the WRONG thing to read — `proto/a2a.proto`
is canonical (its own header says so). The handoff is an **`A2AMessage`** with
`message_type = MessageType.HANDOFF_READY (=0)` carrying a serialized **`HandoffPayload`**:

```
HandoffPayload: from_phase(str) to_phase(str) status(PhaseStatus) findings_count(int32)
                handoff_data(bytes) proof_artifacts([]str) next_recommended(AgentRole)
                confidence(float)
A2AMessage envelope: engagement_id, from_agent(AgentRole), to_agent(AgentRole),
                message_type(MessageType), payload(bytes), confidence, requires_human
PhaseStatus: PENDING=0 RUNNING=1 COMPLETE=2 FAILED=3 BLOCKED=4
AgentRole:   CONDUCTOR=0 ALPHA=1 BETA=2 GAMMA=3 DELTA=4 EPSILON=5 OMEGA=6
```

**Two proto3 zero-value traps `advance.py` already guards (keep them):**
- `status` defaults to `PENDING(0)` → only `COMPLETE(2)` advances (never the default).
- `next_recommended` defaults to `CONDUCTOR(0)` → treated as "unset / no next" (we never
  auto-dispatch to the Conductor). Don't "fix" this by removing the guard.

**Persistence bridge (the one real unknown):** an `A2AMessage(HANDOFF_READY)` must land in
the event stream for `advance` to read it. Define the agent-completion tail to append
`EventType.HANDOFF_READY` with payload `{from_agent, status, next_recommended, ...}` (enum
ints, per above). `latest_handoff()` reads exactly those keys — adapt key NAMES if you pick
a different event shape, never the enum types.

## Wiring on the Celery path (`conductor/main.py`)

1. **Each agent task ends by signalling the Conductor to advance — it never calls the next
   agent.** Concretely: at the tail of `run_engagement_task` (and the future Beta task),
   after the agent appends its `HANDOFF_READY`, enqueue a Conductor advance step:
   `advance_engagement_task.delay(engagement_id, tenant_id)`. (Agent→Conductor is allowed;
   agent→agent is not.)
2. **`advance_engagement_task`** (new Conductor Celery task) resolves the per-tenant store
   (`store_provider.for_tenant`) + the auth state machine, then calls
   `advance_engagement(...)` with:
   - `dispatcher`: a `Dispatcher` impl whose `dispatch(agent=...)` calls
     `run_agent_task.delay(engagement_id, tenant_id, agent)` (mirrors `CeleryTaskRevoker`'s
     injected-control pattern). The generic `run_agent_task` constructs the right agent and,
     for Beta, passes the injected `applicators` into `CredReuseTool(applicators=...)`.
   - `applicator_builder`: a thin wrapper over `build_applicators_for_engagement(...)`
     (the §3b factory) that supplies `auth`, `graph_store` (per-tenant), `web_target`, and
     the candidate applicators. Returns `[]` for non-Beta agents.
3. **Beta task** constructs `CredReuseTool(applicators=<bound list>, http_client,
   graph_store, secrets=<per-tenant vault provider>)`. This is where A6 flips to GREEN: the
   chain now runs on the Celery path with the shared vault, not in `chain_runner`.

## Step 3c lands here (not separately)

The cred_reuse constructor gains ONE dep — `applicators` — and `run()` iterates the
`BoundApplicator` list calling `apply(target=b.target, ...)`. cred_reuse still has NO
`auth`/`scope` handle (the stop-signal guard `test_cred_reuse_has_no_auth_or_scope_handle`
stays GREEN). The factory output is produced Conductor-side in `applicator_builder` and
injected via the dispatcher → factory stops being dead code (audit-confirmed).

## Decommission the script path (anti-#2, anti-#6)

Once the Celery path runs the chain green, `chain_runner.py` becomes a **dev/live-fire
harness only** — it must NOT be a second production orchestration path (two canonical
orchestrators = #6). Either delete it or clearly mark it test-harness and ensure prod
dispatch only flows through `advance_engagement`.

## Test contract

```
Pure decide_advance (no I/O): dispatch when forward+tier-granted; PARK across an
  ungranted tier (never auto-promote); PARK on backward/replay; noop on emergency_stop;
  noop on non-complete handoff; idempotent noop when already dispatched; halt on no-next;
  OMEGA always forward.  [test_conductor_advance.py — pure block]
advance_engagement (fakes): dispatches Beta WITH factory-built applicators; parks across
  tier WITHOUT calling dispatcher or factory; idempotent under double-run (Beta dispatched
  once).  [effectful block]
Integration (Oracle, after wiring): create engagement → enable_active → run recon task →
  assert a Beta task was enqueued (spy/broker) and that NO agent enqueued another agent
  (only Conductor appends AGENT_DISPATCHED).  [add to tests/integration]
```

## Phase placement & exit criteria

This is **core Phase 3** ("Beta + Celery non-blocking") — currently only recon is
non-blocking. Add to the revised Phase-3 exit criteria (ADR §12.20 list):

```
[ ] Conductor auto-advances Alpha→Beta on the Celery path (no agent-to-agent)
[ ] Auto-advance PARKS across an ungranted auth tier (gate not softened)
[ ] cred-reuse chain runs on the Celery path with the shared vault (A6 green)
[ ] chain_runner is harness-only, not a second prod orchestrator (#6)
```

**Confidence ~85%** — decision logic is solid and unit-proven; residual is the #61
integration shape: the exact handoff event Alpha emits, and the generic `run_agent_task`
surface. Confirm both, then wire.
