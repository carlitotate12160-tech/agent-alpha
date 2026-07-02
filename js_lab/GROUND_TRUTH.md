# SPA JS-Secret Field-Prove — Ground Truth & Acceptance Contract

**Purpose.** Close the anti-Lyndon-#2 gap on the JS-bundle secret recon vector.
`agent_alpha/recon/js_secret_probe.py` (HEAD `f382c43`) is unit-green with a fake
HTTP client only. This lab field-proves it against a **real, served, self-owned**
SPA with **known ground truth**, so we get a real event stream (real
`timestamp_utc`s) — which is also the honest fixture for the next step,
`time_to_proof` in `EngagementMemoryProjector`.

**Phase placement.** Phase 3 recon. RECON_ONLY authorization. No SOW/OFFENSIVE
gate — passive GET of self-owned pages + their same-origin bundles.

**Non-negotiables honored.** Self-owned target only. Scope explicit from this
lab's YAML. Synthetic, non-functional secret, never committed (public repo +
GitGuardian). One canonical timing/finding concept — this reuses existing nodes
(`VULNERABILITY`, `CREDENTIAL`) and the existing verifier; **no new component.**

---

## 1. Setup (Natanael, on a self-owned box)

```bash
cd labs/spa_js_secret
python3 generate_bundle.py                 # writes assets/app.lab001.js + expected.local.json
# Point lab.example-you-own.dev DNS at this box, then:
caddy run --config ./Caddyfile             # real Let's Encrypt TLS (probe forces https://)
# sanity: curl -s https://lab.example-you-own.dev/assets/app.lab001.js | grep apiKey
```

Edit `engagement.spa.example.yaml` and the `Caddyfile` to your real self-owned
subdomain. **Do not proceed with a domain you do not own.**

---

## 2. Known Ground Truth (what the lab plants)

The generator (`generate_bundle.py`) plants, in `/assets/app.lab001.js`:

| Item | Value shape | Probe MUST |
|------|-------------|------------|
| `apiKey` | 32-char high-entropy generic string | **DETECT** → 1 `generic_assign`/`generic` secret |
| `demoKey` | `your_api_key_here` | **REJECT** (placeholder denylist) |
| `buildTag` | `aaaaaaaaaaaaaaaaaa` | **REJECT** (all-same-char, low entropy) |
| endpoints | `/api/v1/users`, `/api/v1/orders`, `/api/v1`, `/graphql` | **EXTRACT as intel** (not creds) |

Exact expected values (masked preview, kind, service, endpoints) are written to
`expected.local.json` at generate time. The field-prove asserts against that file
— never against a hardcoded raw secret.

The two decoys are the point: they prove the anti-#3 discriminator
(`_looks_like_secret`) works on a **real target**, not just in unit fixtures. A
scanner that flags them is noise; ours must not.

---

## 3. Acceptance Predicate (definition of "PROVEN")

Real interface under test (do not restate it wrong):

```python
verify_js_secret_leak(
    *, engagement_id, auth, http_client, scope_targets,
    graph_store, event_store, secrets_manager=None, timeout_s=10.0,
) -> int   # number of validated CREDENTIAL nodes added
```

A run is **PROVEN** iff ALL hold (load expected from `expected.local.json`):

1. **Return value** `== expected_creds_added` (== 1). Not `>= 1` — exactly the
   planted count, so a decoy leaking through would FAIL (anti-#3, anti-false-success).
2. **Graph state** contains:
   - node `vuln:<host>:js_secret_leak` (type `VULNERABILITY`)
   - exactly **one** `CREDENTIAL` node `cred:<host>:generic_assign`
     (`service == "generic"`, `access_level == "unverified"`)
   - a `LEADS_TO` edge vuln → cred
3. **Vault**: `secrets_manager.get(...)` for the stored ref returns a value whose
   `first4****last4` mask `== expected_secret_preview`. Raw value never logged.
4. **Decoys absent**: no `CREDENTIAL` node whose vaulted value maps to either
   decoy. (Implied by #1 but assert explicitly for a clear failure message.)
5. **Intel**: `NODE_DISCOVERED` events with `type == "api_endpoint"` exist for
   every entry in `expected_api_endpoints`.
6. **No false WAF**: zero `WAF_BLOCKED` events for this run (lab returns 200).
   If the lab is fronted by a CDN/WAF and you SEE `WAF_BLOCKED`, that is a
   *correct* discriminator result — but then the run is INCONCLUSIVE, not proven:
   remove the WAF for the field-prove.
7. **Determinism**: replay the engagement's event stream into a fresh
   `NetworkXGraphStore` → node/edge counts identical (event-sourced integrity).
8. **Environment**: executed on **Oracle ARM64**, `.venv/bin/python3`. Local /
   Windows results are not valid (Lyndon #9).

`{}` / zero creds / a decoy leaking / an unhandled `ConnectError` = **FAIL**.

---

## 4. IDE Prompt — thin field-prove runner (Claude's lane = contract; IDE writes impl)

The verifier is already wired; the field-prove runner is a thin, real harness. Do
**not** duplicate the verifier or invent a second timing type.

```
PROJECT: Agent-Alpha
PHASE: 3
FILE: agent_alpha/live_fire/spa_secret_field_prove.py
TASK: Field-prove verify_js_secret_leak against a live self-owned SPA lab.

CONTEXT:
Closes anti-#2 on js_secret_probe (unit-green only today). Mirrors the wiring in
live_fire/wp_chain_runner.py (AuthorizationStateMachine + Scope, HttpClient,
InMemoryEventStore, NetworkXGraphStore, SecretsManager) but RECON-ONLY and with
NO WP login step. Reads engagement.spa.example.yaml + labs/spa_js_secret/expected.local.json.

REQUIRED:
1. load_spa_config(path): parse client_id, scope.domains, recon_url from YAML.
2. main(argv): build AuthorizationStateMachine, set state RECON_ONLY, register
   Scope(domains=config.scope.domains); build HttpClient (real httpx, TLS verify ON),
   InMemoryEventStore, NetworkXGraphStore, SecretsManager.
3. Call verify_js_secret_leak(engagement_id, auth, http_client,
   scope_targets=config.scope.domains, graph_store, event_store, secrets_manager).
4. Load expected.local.json; compute a frozen SpaSecretFieldProveResult with a
   .proven property implementing ALL 8 acceptance predicate clauses in GROUND_TRUTH.md §3.
5. Print a one-line PROVEN/FAIL verdict + per-clause pass/fail; return 0 iff proven.

CONSTRAINTS:
- Do NOT touch: js_secret_probe.py, authorization.py, any agent.
- Do NOT add a new timing/metrics type (that is EngagementMemoryProjector's job).
- Do NOT hardcode the secret; read expected.local.json.
- A2A / events unchanged.

TEST CONTRACT:
- Against the live lab with the planted bundle: verify_js_secret_leak returns 1,
  graph has vuln+cred+LEADS_TO, vault preview matches expected, endpoints intel
  present, zero WAF_BLOCKED, replay-consistent -> .proven is True, exit 0.
- Against an unreachable host (stop Caddy): HttpClient raises ConnectError; runner
  must catch -> creds_added 0 -> .proven False -> exit 1 (FAILED, not a crash).
  [This doubles as the network-resilience check flagged in CLAUDE.md Next Action #1.]

VERIFY: Run on Oracle ARM64 only. Expected: proven on live lab, FAIL-not-crash on
unreachable.
```

---

## 5. Integration point

- **Calls:** `agent_alpha.recon.js_secret_probe.verify_js_secret_leak` (unchanged).
- **Reads:** `engagement.spa.example.yaml`, `expected.local.json`.
- **Produces:** a real engagement event stream (NodeDiscovered / EdgeDiscovered /
  NODE_DISCOVERED intel), timestamped — the fixture the next task
  (`time_to_proof` in `EngagementMemoryProjector`) verifies against.
- **Does NOT** touch the verifier, auth, or any agent. Zero files in
  `agent_alpha/` modified — new runner only (anti-#10).
