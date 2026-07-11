# ADR — Bounded-Autonomy Stall Semantics: NO_PROGRESS is suppressed while the frontier is non-empty

**Status:** Accepted + Sealed (Oracle regression pass, Layer V-B field-proven 2026-07-11)
**Phase touched:** Phase 2 (SEALED components — `agents/base.py`, `agents/alpha/scout.py`)
**Supersedes:** nothing. Amends the "Bounded Autonomy" stop-condition contract only.
**Trigger:** Layer V-B live run on Oracle (`agentalpha.duckdns.org`) — `ValueError:
No odoo host discovered via passive frontier`.

---

## Context / the flaw (stated before the fix)

Real `crt.sh` for the V-B apex returned **9** subdomains, because several
unrelated self-owned labs share the DuckDNS apex and each holds its own Let's
Encrypt cert (all CT-logged). `_authorize_apex_subdomains` correctly authorized
all apex-subdomains (an apex SOW authorizes them). The Alpha frontier, sorted, put
the live Odoo target at position 6:

| pos | host | probe result | new node? |
|-----|------|--------------|-----------|
| 1 | `agentalpha.duckdns.org` | 200, apex HTML, orient-fail | no |
| 2 | `laravel-hardened.…` | unreachable | no |
| 3 | `laravel-vuln.…` | unreachable | no |
| 4 | `spa-hardened.…` | unreachable | no |
| 5 | `spa-vuln.…` | unreachable | no |
| **6** | **`vuln.agentalpha.duckdns.org`** | **never reached** | — |

`run_cognitive_loop` increments `iters_without_progress` on every step that adds
no graph node, and `ALPHA_RECON_NO_PROGRESS_ITERS = 5`. Five consecutive duds ⇒
`StopReason.NO_PROGRESS` fires **before** the loop drains to the live target.

**Root cause is semantic, not a config value.** `NO_PROGRESS` was measuring "the
last N pops happened to be duds," when it should measure "the agent is out of
productive options." While the frontier still holds un-probed hosts, the agent has
**not** stalled — it has more work. Bounding a draining-but-unproductive queue is
the job of the hard ceilings (`max_iterations` / `time_budget` / `cost_budget`),
not of the stall detector.

## Decision

`NO_PROGRESS` is **suppressed while the frontier is non-empty**.

- `Agent.step()` additionally reports `work_remaining` — the count of un-probed
  frontier items after this pop. Alpha reports `len(self._work_queue)` via a thin
  wrapper (`step` → `_step_once`); the cycle logic is unchanged.
- `run_cognitive_loop`: if `should_stop(...)` returns `NO_PROGRESS` **and**
  `work_remaining > 0`, the stop is ignored and the loop continues. The hard
  ceilings still apply and still bound a large all-dud queue.
- `BoundedAutonomy.should_stop` signature is **unchanged** (its unit tests are
  untouched); the suppression lives in the driver.

## Alternatives rejected

1. **Add noise hosts to YAML `exclusions`** (the first-proposed fix). REJECTED —
   (a) re-introduces hand-feeding (uses out-of-band lab topology to steer
   discovery to the known target), the exact thing Layer V exists to eliminate; a
   real client apex always carries un-pre-excludable noise; (b) masks this real
   product defect — V-B would go green while the product still stalls on any
   realistic multi-subdomain client (Lyndon #3, false success by masking).
2. **Raise `ALPHA_RECON_NO_PROGRESS_ITERS`.** REJECTED — a magic-number band-aid
   (Lyndon #7 flavor); it re-breaks at the next noisier surface and never fixes
   the semantics.
3. **Change `should_stop`'s contract.** REJECTED for blast radius — many tests
   call it directly; the driver-level gate achieves the same with none of that
   churn (Lyndon #10: don't cascade a change across files when the interface can
   stay put).

## Test contract (`tests/phase_2/test_bounded_autonomy_frontier.py`)

- **Late target not starved:** frontier `[0,0,0,0,0,0,1]`, `threshold=5` ⇒ the
  productive 7th pop is still reached (`probed == 7`, `nodes_discovered == 1`).
  RED without the fix (stops at pop 5, `nodes_discovered == 0`).
- **Exhausted frontier still stops:** all duds, queue drains ⇒ `NO_PROGRESS` 
  fires once `work_remaining == 0` (the fix must not run forever).
- **Hard ceiling still bounds duds:** `[0]*10_000`, `max_iterations=50` ⇒
  `MAX_ITERATIONS` at iteration 50.

## Integration points

- **Callers of `run_cognitive_loop`:** `layer_v_runner`, `odoo_chain_runner` /
  `wp_chain_runner` (indirectly via Alpha recon), and the Conductor
  `recon_runner` live path — all benefit; none change call sites.
- **`step()` contract:** agents that do not report `work_remaining` are unaffected
  (driver defaults it to `0`, preserving prior behavior). Only Alpha reports it.

## Blast radius / regression gate

Phase-2 SEALED components changed ⇒ before merge:
- `tests/phase_2/` + `tests/phase_2_5/` 100% green on **Oracle ARM64** (not local).
- `make check` clean.
- Layer V-B live run reaches `vuln.agentalpha.duckdns.org` and yields
  `CHAIN PROVEN: True` with `host_discovery_sourced: True`.

## Seal verification (Oracle ARM64, 2026-07-11)

- `make check` passed: ruff + format + mypy clean.
- Full suite: 922 passed, 2 skipped (the 2 failures were source-inspection guards that
  were updated honestly to cover `step()` + `_step_once()`, not weakened).
- Layer V-B live run: `CHAIN PROVEN: True`, `host_discovery_sourced: True`,
  `edge_from_harvested_cred: True`, `db_enumerated: True`, `leak_suspected: False`.

## Note

If, after this fix, `odoo_host` is still `None`, the failure has moved **past**
budget starvation to fingerprint/reachability of `vuln.agentalpha.duckdns.org` 
(does it resolve, serve Odoo, and fingerprint `tech_stack=['odoo']`?) — a
different defect, to be triaged on its own trace, not by re-touching the loop.
