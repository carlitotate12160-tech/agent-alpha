# FP-Validation Runbook — Phase-2 Exit Gate

**Goal:** close the jumped Phase-2 exit criterion *"Live test: 3 real targets, <20% FP rate in findings"* — now meaningful because Alpha selects WP/Laravel/SPA vectors autonomously (fingerprint → RULE-tier playbook → dispatch → finding). Threshold is code: `MAX_FP_RATE = 0.20`.

**What it validates:** the full autonomous path end-to-end on real self-owned targets, and that Alpha does not over-report (false positives) across stacks. This is the graduation from bespoke chain-runner scripts to the autonomous agent.

---

## 1. Prerequisites (hard, fail-closed)

1. **Self-owned targets + lab allowlist.** `runner.py` is a lab-guarded attacker harness: it calls `assert_lab_only_target(url)` and `assert_lab_only_target(host)` for every target. Add each `host` to `LAB_TARGET_ALLOWLIST` in `agent_alpha/live_fire/lab_guard.py` (a code constant — never YAML). Any host not in the allowlist is refused. **Never a client/prod host** — client engagements run through Conductor + SOW, a different path.
2. **Known ground truth.** You plant the vuln (or verify the target is hardened). The scorer raises `KeyError` if a probed URL is missing from ground truth (anti-#3) — no silent gaps.
3. **`DEEPSEEK_API_KEY` set.** The runner constructs a reasoning provider even though WP/Laravel/SPA resolve deterministically via RULE-tier playbooks (no LLM call for those selections).
4. **Oracle ARM64 only.** Not local/Windows.

---

## 2. What each target must serve (ground-truth definitions)

`ground_truth_vulnerable` is **binary per URL**: does the target have a real, Alpha-detectable finding?

| Target | Stack signal Alpha fingerprints | Vulnerable (`true`) serves | Hardened (`false`) serves |
|---|---|---|---|
| wp-vuln | `wp-content` / `wp-includes` → `wp_config_probe` | readable `wp-config.php.bak` with real-format DB creds | WordPress, but 404/403 on all `wp-config.*` backup paths |
| laravel-vuln | `Whoops` / `Illuminate` → `laravel_debug_probe` | `APP_DEBUG=true` debug page leaking env | Laravel, `APP_DEBUG=false`, generic error page |
| spa-vuln | hashed bundle / `<div id="root">` → `js_secret_probe` | SPA whose `main.<hash>.js` contains a **planted synthetic** secret | same SPA build, bundle contains no secret |

The **hardened controls are the point** — they are where a false positive can occur, so they make the FP rate measurable. Secrets are always **planted synthetic** (never a real key), consistent with the existing SPA lab.

---

## 3. Run

```bash
# On Oracle ARM64, repo root, venv active:
export DEEPSEEK_API_KEY=...            # required even for deterministic fingerprints
.venv/bin/python3 -m agent_alpha.live_fire.runner engagement.fp_validation.yaml
```

Fill `engagement.fp_validation.yaml` from the template (`engagement/fp_validation_engagement.yaml`), replacing every `<REPLACE...>` host.

---

## 4. Read the scorecard

```
LIVE-FIRE SCORECARD
  TP: <found & vulnerable>   FP: <found but hardened>   FN: <missed vulnerable>   TN: <correctly silent>
  FP rate of findings: FP / (TP + FP)
  MAX_FP_RATE:         0.2000
  Verdict:             PASS | FAIL
  Report:              ./report.pdf   (Omega technical report)
```

**PASS = at least one real finding AND FP rate < 0.20.** Zero findings is a FAIL, never a silent "clean" (anti-#3). Exit code 0 on pass, 1 on fail.

---

## 5. Honest caveats (do not oversell the result)

- **The score is binary, not type-checked.** It counts "predicted vulnerable" vs ground truth — it does **not** verify Alpha found the *right kind* of vuln. A right-answer-for-wrong-reason (e.g. a Laravel target flagged via a spurious WP match) still scores TP. **So alongside the automated verdict, eyeball the Omega report per target and confirm the finding TYPE matches the stack.** Passing the FP gate ≠ breadth is proven; the manual type-check is what confirms breadth.
- **FN matters for breadth, even though the gate ignores it.** A vulnerable target Alpha misses (FN) doesn't hurt the FP rate but is exactly the false-negative gap already flagged (e.g. js_secret currently misses Vite dash-hash / Angular `<app-root>`). Use the FN column to decide whether to broaden the js_secret indicators **after** you see real target HTML — not before (anti-#1).
- **Lab-only, self-owned, SOW-clean.** This validates the tool on controlled targets. It is not, and must not be presented as, a paying-client result.

---

## 6. What "done" looks like for the gate

- Verdict PASS with FP rate < 0.20 across the 6 targets.
- Per-target Omega report finding TYPE matches the stack (manual check).
- Run reproduced on Oracle ARM64.
