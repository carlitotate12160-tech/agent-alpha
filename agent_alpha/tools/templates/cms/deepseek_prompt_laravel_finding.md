PROJECT: Agent-Alpha
PHASE: 2 (tool-layer finding template — closes live-fire "proof, not pass-saja")
FILE: agent_alpha/tools/templates/cms/laravel_finding.py
TASK: Implement build() and verify() bodies for LaravelFindingTemplate. Nothing else.

CONTEXT:
- Conforms to agent_alpha/tools/contracts.py :: Template (build/verify).
- Detects + PROVES a Laravel APP_DEBUG=true / config exposure. RECON_ONLY, read-only.
- Public signatures live in agent_alpha/tools/playbooks/laravel_debug.yaml
  ("Whoops", "Illuminate", regex "Laravel v[0-9]+").
- The probe is executed by the existing HttpClient (httpx) at the egress RateLimiter;
  verify() consumes the dict that HttpClient returns (keys: url, status, headers, body).

REQUIRED:
§3  build(ctx: TargetContext) -> dict[str, Any]
    1. Return a read-only probe request dict for ctx.target ONLY (never a derived/guessed
       host — ctx.target is already in-scope + SSRF-screened, CWE-918).
    2. Stay within RECON_ONLY: GET/HEAD-style, no payload that mutates state.
    3. Honor the engagement budget (caller passes ResourceBudget; do not exceed rps).

§4  verify(response: dict[str, Any]) -> ToolResult
    1. PROOF, not assumption. Confirm exposure from response["body"]/status using the
       playbook signatures; a bare 500 or a version string alone is NOT a finding.
    2. On confirmed exposure: return ToolResult(success=True, confidence>=0.7,
       findings=(<one finding dict: type, evidence-summary, redacted snippet>,),
       proof_artifacts=(<id/ref of the captured, REDACTED evidence>,)).
    3. On ambiguous/empty/hardened: ToolResult(success=False, no findings, no proof).
    4. Redact any leaked secret (DB_PASSWORD/APP_KEY/etc.) before it enters findings or
       proof — reuse agent_alpha redaction; secrets must never appear raw.

CONSTRAINTS:
- Do NOT touch: template_id, mitre_technique, required_auth, the class skeleton, or
  tests/phase_2/test_laravel_finding.py.
- Do NOT add non-security logic. Do NOT widen scope beyond RECON_ONLY.
- A successful ToolResult without a finding is structurally impossible (contract) —
  do not try to fake success; emit real proof or success=False.

TEST CONTRACT (definition of done — must all pass):
- tests/phase_2/test_laravel_finding.py :: all tests GREEN, specifically:
  - test_verify_exposed_returns_proof_bearing_success  (exposed -> success + proof)
  - test_verify_hardened_is_not_a_false_positive       (hardened -> success=False, no FP)
  - test_verify_empty_response_is_failure_not_crash    (empty -> fail, no crash)
  - test_build_acts_only_on_the_in_scope_target        (build uses ctx.target only)
- No regression: full suite stays green.

VERIFY: Run on Oracle ARM64 only.
  .venv/bin/python3 -m pytest tests/phase_2/test_laravel_finding.py -v
  then: make check   (ruff + format + mypy)
Expected: 8 tests pass, 0 fail; full suite still green.
