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

## Test Results

```
<!-- paste test output: pytest, bandit, gitleaks results -->
```

## Related Issues

<!-- Link to issues, ADR sections, or progress tracker entries -->
