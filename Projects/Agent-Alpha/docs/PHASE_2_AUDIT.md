# Phase 2 — Audit & Seal Report

**Date:** 2026-06-19
**Auditor:** Claude (senior security architect, peer review)
**Method:** Static anti-Lyndon trace on the codebase + live-fire result review.
**Authoritative verification environment:** Oracle ARM64 only (anti-Lyndon #9).

> Verdict (updated 2026-06-19): **SEALED.** All Section-D conditions resolved on
> Oracle ARM64 (245 tests pass / 243 + 2 live-skip, `make check` clean). The kill
> chain produces a real finding with proof. One scoped, documented deferral: the
> inner-monologue **user-delivery transport** (Redis pub/sub → WebSocket) moves to
> Phase 3, because a connected user requires the Celery non-blocking execution path
> built there; the monologue **emission core is implemented + tested** now. See E.

---

## A. Exit Criteria Status (Phase 2)

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Alpha → Omega end-to-end (scan → graph → narrative report) | ✅ MET | Live-fire: `vuln:127.0.0.1:laravel_debug` + edge + MITRE T1592.002 in report |
| 2 | Cognitive loop OBSERVE→PERSIST completes without crash | ✅ MET | `run_cognitive_loop` + BoundedAutonomy; network-resilience patch stops crash-on-unreachable |
| 3 | **Inner monologue streamed to user in real-time** | ◐ EMISSION CORE MET; delivery deferred to Phase 3 | Loop-driven `ThoughtFrame` per phase, `MonologueSink` + DeepSeek `reasoning_content` captured — `test_monologue.py` (6) green. WebSocket/Redis delivery needs Phase-3 Celery user path (ADR §8j-2, signed off) |
| 4 | Stop conditions enforced (max_iter, time, cost, no-progress) | ✅ MET | `BoundedAutonomy.should_stop` |
| 5 | Report: MITRE ATT&CK mapped, PDF export works | ✅ MET | `report.pdf`, T1592.002 present |
| 6 | Live test: 3 real targets, <20% FP | ✅ MET | Lab run: TP=1, FP=0, FN=0, TN=2 → genuine PASS (TP≥1) |
| 7 | Test suite Phase 2: 100% pass | ✅ MET | Oracle: 245 pass (243 + 2 live-skip), `make check` clean (ruff+format+mypy, 42 src) |

**All 7 met (#3 via emission core + a signed Phase-3 delivery deferral).**

---

## B. Anti-Lyndon Static Audit

| Pattern | Result |
|---------|--------|
| #2 Dead code (unwired component) | ✅ RESOLVED — `memory/intelligence.py` classified keep+documented (C-2); module docstring now states "no live caller; Phase-6 consumer" |
| #3 False success (empty = success) | ✅ Fixed in scoring (`passed` now requires TP≥1); Alpha status FAILED on non-analyzable |
| #6 Duplicate canonical types | ✅ None |
| #7 Single source of truth | ✅ RESOLVED — C-1 fixed: `DEEPSEEK_HTTP_TIMEOUT_SEC` constant, both call sites reference it |
| #8 God object (>300 lines) | ✅ None critical (max `authorization.py` 390; watch, not violation) |
| Placeholders (`TODO`/bare `pass`/`...`) | ✅ Benign — all `pass` are exception bodies / except-fallthrough; `...` are Protocol stubs; `TODO` strings are explanatory docstrings, not code gaps |
| Deferred ToolRegistry half-wired | ✅ Absent (correctly not built) |
| Recent-change consistency | ✅ `scoring`/`runner` fully URL-keyed; `scout.py` does not import httpx (only `HttpClientError`) |

---

## C. Findings (actionable)

### C-1 — Lyndon #7: hardcoded timeout in `deepseek.py`
`agent_alpha/llm/providers/deepseek.py` lines ~54 and ~73 use `httpx.Client(timeout=30.0)`
literally, twice. Single-source-of-truth violation — the seed of the "three timeout
values for one tool" Lyndon failure.
**Fix (small):** add `DEEPSEEK_HTTP_TIMEOUT_SEC` to `config/constants.py`, reference it in
both call sites. Test: assert the client is constructed with the constant.

### C-2 — Lyndon #2: `memory/intelligence.py` has no live caller
`RecordBackedIntelligenceBase` (311 lines) is **not imported by any live path** — only
referenced in a `constants.py` comment. It is a Phase 6 component (learning loop, ADR
§12.8) parked early. The logic is real (not a hardcoded stub) and returns `InsufficientData`
because Phase 2 hasn't populated `tool_success_rates` yet.
**Decision required:** classify it explicitly — (a) keep, but documented as *Phase 6,
not in live path, not "done"*; or (b) quarantine until Phase 6. Either is fine; what is
NOT fine is treating an unexercised component as complete.

### C-3 — Report quality (not bugs, by-design)
- `asset:127.0.0.1` shows confidence 0.50, not 0.95: lab artifact of three targets sharing
  one loopback host (`add_node` upsert overwrites). **Real clients have distinct hosts → no
  overwrite.** Optional lab cleanup: bind targets to `127.0.0.1/.2/.3`.
- "Highest impact chain: (no attack chains found)": **correct.** Alpha is recon-only; no
  DATA/ACCESS_LEVEL node exists yet, so no path to a crown jewel. Honest, not broken. A real
  chain appears when Beta/Gamma exploit (Phase 3+), or if Alpha emits a CREDENTIAL node from
  the leaked `DB_PASSWORD` (an in-scope recon enhancement).

---

## D. Conditions to Declare Phase 2 SEALED

1. **Run the full Phase 2 + regression suite on Oracle ARM64 and confirm 100% green**
   (includes the scoring-contract, network-resilience, and URL-identity changes; must not
   regress the Phase 0+1 = 186 tests):
   ```bash
   .venv/bin/python3 -m pytest tests/ -q
   make check        # ruff + format + mypy
   ```
   Expected: all green, 2 live-DeepSeek skips acceptable (no key) — record the exact count.

2. **Resolve exit criterion #3 (inner monologue):** either implement it, or **explicitly
   defer with sign-off** (a conscious decision recorded here), since it is the only unmet
   exit criterion.

3. **Classify C-2 (`intelligence.py`)** as parked-Phase-6 or quarantine. Optionally fix
   C-1 (deepseek timeout) — small, recommended before seal.

---

## E. Sign-off

- [x] D-1 Oracle suite green: **245 pass** (243 + 2 live-DeepSeek skip), `make check` clean (ruff + format + mypy, 42 src files)
- [x] D-2 #3 inner monologue: **emission core implemented + tested** (`test_monologue.py` 6 green); user-delivery transport **deferred to Phase 3 with sign-off** (ADR §8j-2 — depends on Celery user path)
- [x] D-3 C-2 `intelligence.py`: **keep + documented** (module docstring classification added; tested foundation, Phase-6 consumer, not quarantined)
- [x] C-1 deepseek timeout: **fixed** (`DEEPSEEK_HTTP_TIMEOUT_SEC` constant)
- [x] ADR §8j-2 amended to the loop-driven inner-monologue framing
- [x] **Phase 2 SEALED** — Natanael (Eko) + Claude, 2026-06-20

### Carried into Phase 3 (not Phase 2 debt — explicit roadmap)
- Inner-monologue user-delivery transport (Redis pub/sub → WebSocket), wired to the Celery non-blocking execution path.
- Optional Phase-2 report capstone (deferred by choice): Alpha emits a CREDENTIAL node from leaked `DB_PASSWORD` (in-scope recon) — prompt + RED test contract drafted, not yet built.
