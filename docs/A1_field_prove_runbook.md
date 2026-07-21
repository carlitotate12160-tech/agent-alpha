# A1 Field-Prove Runbook — Origin-Direct Validation

**Goal:** Field-prove that Agent-Alpha can reach a CF-CHALLENGE-gated
leaked-cred→admin chain via origin-direct when the front door is blocked, and
that the auth-honest consent model (signed EngagementProfile) genuinely gates
the reach.

**What it validates:** The full A1 chain (probe → origin-direct bundle fetch →
js_secret_probe → beta login → admin) plus the integrity of the consent model
(C8 + C9: origin IP must be in the *signed* authorized_origins, not silently
synthesised from the discovery candidate).

---

## 1. Prerequisites (hard, fail-closed)

1. **Self-owned target + lab allowlist.** Target = `alpha-ai.web.id` ONLY.
   Must be in `LAB_TARGET_ALLOWLIST`. Origin IP `168.110.192.62` is the known
   origin; bare-IP as target is refused by `assert_lab_only_target`.
2. **CF challenge active on /web.** The front door must return `cf-mitigated:
   challenge` on GET /web. Without this, C7 gate raises INVALID.
3. **`DEEPSEEK_API_KEY` set** (or `--browser-solve` endpoint if 9c is built).
4. **Oracle ARM64 only.** Not local/Windows.

---

## 2. Produce the signed profile

The CLI requires a **signed EngagementProfile** (`--profile`). Consent CANNOT
be derived from the `--origin` flag (CWE-862, CR-1 fix).

```bash
# On Oracle ARM64, repo root, venv active:
python -m scripts.sign_profile \
    --engagement-id a1-fp \
    --client-id lab \
    --target alpha-ai.web.id \
    --authorized-origin 168.110.192.62 \
    --output a1_profile.signed.json
```

This writes a JSON envelope with the profile fields + SHA-256 signature. Any
post-signing edit (e.g. adding an origin) will fail `load_signed_profile()`.

---

## 3. Run the field-prove (auth-honest)

```bash
# The payable seal — auth-honest, signed consent:
.venv312/bin/python3 -m agent_alpha.live_fire.a1_validation_runner \
    --engagement-id a1-fp \
    --target alpha-ai.web.id \
    --origin 168.110.192.62 \
    --profile a1_profile.signed.json
```

**Do NOT use `--lab-unsigned` for the payable field-prove.** `--lab-unsigned`
synthesises consent from the discovery candidate (the exact tautology we
removed). It is for throwaway lab debugging only.

For throwaway lab runs:
```bash
# NOT auth-honest — for debugging only, prints LOUD warning:
.venv312/bin/python3 -m agent_alpha.live_fire.a1_validation_runner \
    --engagement-id a1-fp \
    --target alpha-ai.web.id \
    --origin 168.110.192.62 \
    --lab-unsigned
```

---

## 4. Read the result

```
========================================================================
A1 VALIDATION RESULT
========================================================================
  valid_run                   : True
  challenge_encountered       : True
  challenge_solved            : False    ← origin-direct BYPASSES, never "solves"
  chain_proven                : True
  edge_from_harvested_cred    : True
  nuclei_findings             : 0
  scanner_missed_exploitability: True
  technique_used              : origin_direct
  origin_authorized           : True
========================================================================
```

**PASS = chain_proven=True + valid_run=True.** Exit code 0 on pass, 1 on fail.

---

## 5. What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `RuntimeError: requires a signed --profile` | `--origin` without `--profile` or `--lab-unsigned` | Produce a signed profile (step 2) |
| `ProfileSignatureError: signature mismatch` | Profile JSON was edited after signing | Re-sign with `scripts/sign_profile.py` |
| `OriginNotAuthorizedError: origin not in signed authorized_origins` | Discovery candidate ∉ profile consent | Add the origin to the profile and re-sign |
| `A1 INVALID: no CF challenge encountered` | CF challenge disabled on target | Re-enable the CF challenge on /web |
| `A1 INVALID: origin-direct run did not prove the leaked-cred→admin chain` | Login failed via origin | Check origin reachability, beta creds |

---

## 6. Honest caveats

- **origin-direct bypasses CF — it does NOT solve the challenge.** The honest
  story: "CF challenge NOT solved; bypassed via exposed origin." Setting
  `challenge_solved=True` would be Lyndon #3 (false success).
- **Lab-only, self-owned, SOW-clean.** This validates the tool on controlled
  targets. Production consent (§12.36) loads from the engagement store, not a
  CLI file.
- **`--lab-unsigned` is NOT the payable path.** It exists only for iterating
  on the chain without signing ceremony. The payable seal is `--profile`.

---

## 7. Follow-up (not built yet)

- **§12.36 slice-2a:** Production consent = signed EngagementProfile captured
  at `create_engagement` in the Conductor SOW path, loaded from the engagement
  store. Replaces the CLI `--profile` file.
