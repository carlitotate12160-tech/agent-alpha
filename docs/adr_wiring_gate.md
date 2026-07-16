# ADR §12.35 — Wiring Gate + Three-Gate Promotion (MUST COMPLY)

**Status:** LOCKED (2026-07-13). Append-only. If conflict → `ADR.md` wins.
**Origin:** Audit found `SessionStore`, `PolicyEnforcer`, `IntelligenceBase`,
and graph analytics fully implemented + unit-green but **never wired into the
production path** (dead code, Lyndon #2). Separately: lab-green results did not
hold on real targets, tempting the shortcut "test on a client because they don't
mind." Both failure modes are closed here.

---

## Rule 1 — Anti-dead-code Wiring Gate (CI-enforced)

A component is **not "done" when its unit tests pass**. It is "done" only when it
is referenced from a production wiring target that is reachable from an entrypoint
(`conductor/main.py` or `Alpha.run_recon`), **outside** its own definition file,
`tests/`, and `live_fire/`.

- Machine check: `tests/governance/test_wiring_gate.py`.
  - `WIRED_REQUIRED` — components that must stay wired; regression → CI FAIL.
  - `WIRING_DEBT` — known un-wired components, tracked in the open; when wired,
    the ratchet FAILS on purpose, forcing a move into `WIRED_REQUIRED`.
- A **dead instantiation does not count as wired.** The wiring target is the
  *use/enforcement* site, never the constructor call (e.g. `PolicyEnforcer()` in
  `main.py` is dead until `execute_agent`/`recon_runner` actually call it).
- Adding a new component to `agent_alpha/` without a wiring target (or a
  `WIRING_DEBT` entry citing a GAP/ADR) is a CI failure.

## Rule 2 — "Wired-Proof" is a mandatory exit criterion

Unit-green ≠ wired. Every component ships with a **W-test** that proves it is
exercised through the **real production path** (`Alpha.run_recon` or the Conductor
`advance`/`execute_agent` path), not an isolated unit — the non-island pattern
(anti-Lyndon #2). No component passes review on unit tests alone.

## Rule 3 — Three-Gate Promotion (hard stops, non-skippable)

| Gate | Name | Requirement |
|------|------|-------------|
| 1 | **LAB-GREEN** | unit + Rule-2 wired-proof + `make check` on Oracle ARM64 (§9). |
| 2 | **FIELD-PROVEN** | live-fire on a **self-owned** lab (`lab_guard`), with real-world response conditions replayed from §12.28 record/replay cassettes. |
| 3 | **PRODUCTION-AUTHORIZED** | a real engagement — **only** with signed SOW + written scope + RoE + **all safety gates ACTIVE** (PolicyEnforcer + blast-radius wired, GAP-005/006). This is a client **deliverable**, never a QA run. |

**Non-negotiables of Rule 3:**
- "Client doesn't mind" is **not** authorization. Authorization = SOW + written
  scope + RoE (§0, §1). No exceptions.
- A client's live systems are **never** a testing ground for immature capability.
  You do not debug the tool on real targets.
- Gate 3 is **impossible to reach while GAP-005/006 are un-wired** — the safety
  layer must be live before any real engagement. The governance closes the
  "lab-green → test on client" shortcut by construction.

**Lab-vs-real divergence is fixed at Gate 2, not Gate 3:** reproduce real-world
conditions (CF challenge, 415, identical-body CDN, etc.) via §12.28 cassettes in
CI — bring the real world into the lab, never take the immature tool to the client.
