## Summary

<!-- Brief description of what this PR does and why -->

## Security Checklist (required for red team agent)

Reviewer must verify ALL of the following before approving:

- [ ] **No hardcoded secrets** — no API keys, passwords, tokens, or private keys in code
- [ ] **No backdoor patterns** — no `eval()`, `exec()`, `subprocess`, `os.system`, `pickle.loads`, `__import__`
- [ ] **No obfuscated code** — no base64-encoded payloads, no hex-encoded executable strings
- [ ] **No data exfiltration** — no outbound HTTP calls to non-API endpoints, no telemetry
- [ ] **No privilege escalation** — no `NOSUPERUSER` bypass, no `BYPASSRLS`, no `chmod 777`
- [ ] **Secrets use SecretsManager** — credentials stored via `SecretsManager`, not plaintext
- [ ] **Untrusted input fenced** — target body passed through `sanitize_observation` before LLM
- [ ] **Tests added/updated** — new code has test coverage, no tests weakened or deleted
- [ ] **CI passes** — all 9 gates green (lint, format, typecheck, pip-audit, bandit, gitleaks, CodeQL, tests, coverage)

## Anti-Duplication Checklist (required — see agent_rules.md §Anti-Duplication)

- [ ] **No local `_persist_node`/`_persist_edge`** — imported from `graph/persist.py` (or not touched)
- [ ] **No local `HttpClientProtocol`** — imported from `agents/http_client.py` (or not touched)
- [ ] **No new `verify_*` self-sweeper** — new recon vectors use `PathProbeSpec` catalog entry in `path_probe.py`
- [ ] **No copy-paste `load_*_config()`** — reuse `load_engagement_config` from `runner.py`
- [ ] **No `hasattr(graph_store, "_graph")`** — use public `graph_store.clear()` if graph reset needed
- [ ] **No bare `except Exception:`** — use `# noqa: BLE001` + `_log.exception()` or catch specific exception

## Test Results

```
<!-- paste test output: pytest, bandit, gitleaks results -->
```

## Documentation Status Update (required if PR closes an ADR, bug, or GAP)

PR author must update the relevant status fields before requesting review:

- [ ] **ADR**: Add/update `**Status**:` in the related `docs/ADR.md` section and include an `Implemented in:` or `Verified in:` reference (PR/commit).
- [ ] **Bug**: Update `**Status**:` in `docs/BUGS.md` to `FIXED`/`DONE`/`ADDRESSED`/`WONTFIX` and add `Closed by:` / `Fixed in:` / `Verified in:` (PR/commit).
- [ ] **GAP**: Update `**Status**:` in `docs/BUGS_AND_GAPS.md` and add `Closed by:` / `Implemented in:` / `Verified in:` if moving to `DONE`.
- [ ] **None** — this PR does not change any ADR/bug/GAP state.

## Related Issues

<!-- Link to issues, ADR sections, or progress tracker entries -->
