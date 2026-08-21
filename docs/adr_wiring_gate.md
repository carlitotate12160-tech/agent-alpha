# ADR-GOV-001 — Autonomous Wiring and Capability Promotion

**Decision status:** ACCEPTED. The Canonical Authority Contract in `ADR.md` governs terminology and precedence; current implementation evidence lives in `docs/Session_Handoff.md`.
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

## Rule 3 — Named Promotion Gates (hard stops, non-skippable)

| Gate | Requirement |
|------|-------------|
| **UNIT_VERIFIED** | focused unit/contract tests + `make check` on Oracle ARM64. |
| **AUTONOMOUS_LAB_VERIFIED** | Rule-2 wired proof through the full Conductor path on a controlled self-owned target, including §12.28 field-shaped replay fixtures. |
| **REPRESENTATIVE_FIELD_VERIFIED** | expected observable on a real authorized target not constructed to match the capability; never used to debug immature code. |
| **PRODUCTION_AUTHORIZED** | signed SOW + written scope + RoE + all safety gates active. This is an authorization posture for client delivery, not a finding-confidence tier. |

**Non-negotiables of Rule 3:**
- "Client doesn't mind" is **not** authorization. Authorization = SOW + written
  scope + RoE (§0, §1). No exceptions.
- A client's live systems are **never** a testing ground for immature capability.
  You do not debug the tool on real targets.
- `PRODUCTION_AUTHORIZED` is **impossible while required safety enforcement is unwired** — the
  safety layer must be live before any real engagement. Governance closes the
  "unit-green → debug on client" shortcut by construction.

**Field shapes enter at `AUTONOMOUS_LAB_VERIFIED`:** reproduce real-world conditions (CF
challenge, 415, identical-body CDN, etc.) via §12.28 cassettes. Only after that gate may an
authorized field engagement establish `REPRESENTATIVE_FIELD_VERIFIED` evidence.
