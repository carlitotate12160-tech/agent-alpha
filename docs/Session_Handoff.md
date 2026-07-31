> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-08-01)

Resume with: "lanjut Agent-Alpha — REACH ARC SEALED (tls_impersonate + CF-filter +
origin_resolver + multi-origin ORIGIN_DIRECT all merged). Reach to CF-fronted origins now
works when a real non-CF origin IP is known. NEXT = BUG 3 frameset href extraction (active
bernofarm blocker), THEN GAP-015 username-derived cred candidates (the Alpha→Beta proven-exploit
moat). Do NOT start the conductor refactor. Do NOT build Gamma. One vertical slice at a time —
the backlog below is a MENU, not a checklist to finish."

---

## Phase

Phase 4 (recon + reach). Gamma/Delta/Epsilon = 0% built (STOP-gated, not stubbed).

**Success bar (the milestone the whole arc serves):** find something a conventional scanner
missed + prove it exploitable + produce a payable report, on a REAL target.
- quantum-laboratories.com (Odoo DB Manager, CVSS 7.5) = PAYABLE ✅
- unibis.co.id (3 WP findings + proof artifacts) = PAYABLE ✅
- Bar is PARTIALLY met. **Moat is still weak**: current findings overlap Nuclei templates
  (Odoo dbmanager, WP user-enum, WooCommerce, plugin namespaces). The real differentiator is
  the Alpha→Beta PROVEN-exploit chain (GAP-015) + attack-graph correlation + narrative report —
  not the detections themselves. That is why GAP-015 is the #2 priority.

---

## SEALED this arc (verified on main by tests)

- **tls_impersonate (curl_cffi)** — datacenter-viable CF-fingerprint bypass. `tls_impersonate_fetch` 
  + `is_tls_impersonate_available` gate; wired in autonomous conductor path AND lab runners
  (allow_evasion=True threaded through EngagementProfile).
- **#304 CF edge-IP filter** — `is_cloudflare_ip()` + `CF_IP_RANGES` (single source). CF edge IPs
  no longer qualify as authorized_origins, so `choose_reach` correctly falls through to
  TLS_IMPERSONATE on FINGERPRINT class instead of short-circuiting to ORIGIN_DIRECT-to-CF-edge.
- **origin_resolver.py** — crt.sh subdomains → DNS resolve → CF filter → host probe → confirmed
  non-CF origin IPs. Fail-closed auth gate (can_agent_proceed + is_in_scope) BEFORE any network
  I/O (mirrors PassiveDiscovery). CodeRabbit fixes landed: negative-max guard, HttpClientError
  catch, distinct-IP test.
- **One-engagement refactor** — `run_live_fire` no longer creates its own engagement; the caller
  owns create+authorize+engagement_id. Killed the double-engagement (profile bound to eng_A while
  recon ran under eng_B) that would have made origin-discovery's scope check always fail.
- **#306 multi-origin ORIGIN_DIRECT** — `_attempt_reach` now iterates ALL authorized non-CF origins
  and returns the first USEFUL response (verdict not BLOCKED/CHALLENGE AND status not
  redirect/404), not just the first candidate's 302/404. Each origin emits its own
  ORIGIN_DIRECT_ATTEMPT audit event.
- **Plugin REST namespace prober** — `WP_PLUGIN_DANGEROUS_NAMESPACES` + inline probe in
  `_handle_wp_rest_routes`. Host-scoped run-once guard, allow_redirects=False, honest nodes_added.
  22 tests green.
- **WP proof_artifacts + CVSS** — wp_rest_users (5.3), woocommerce (5.3), wp_version (3.1) mint
  ProofArtifact so standalone vuln nodes surface in the Omega report (#300/#301).

**Field result — bernofarm.com (2026-08-01):** reach SOLVED. Origin-direct reached
103.113.118.202 → 200 (homepage, 1 node). 0 findings because (a) homepage is a 314-byte
`<frameset>` → `_extract_hrefs` finds 0 links → no content discovered [BUG 3], and (b) target is
Apache/PHP 7.1.33, NOT WordPress → 24 catalog paths all 404. Beta SKIPPED (0 attack surface).

---

## HONESTY DEBT — register before claiming reach "done" (Lyndon #2 watch)

- **bernofarm origin IPs were HAND-FED via a fallback**, not discovered by origin_resolver.
  crt.sh returned no CT subdomains for bernofarm → `discover_origin_ips` returns []. The field
  harness used a manual "fallback origin IPs" list + re-signed the profile. So the AUTONOMOUS
  origin-discovery path does NOT cover no-CT-subdomain sites. Do NOT claim origin discovery
  "works for CF sites" generally. Options: accept the honest limitation (passive-only), or add
  DNS-history/Censys later (paid — DEFER). Register this as tracked wiring-debt in
  `tests/governance/test_wiring_gate.py` so CI records the gap.

---

## NEXT — one slice at a time (do NOT parallelize)

### 1. BUG 3 — frameset/iframe href extraction  [ACTIVE bernofarm blocker; small]
`_extract_hrefs` (scout.py ~1822) regex matches only `<a ... href>`. Add `<frame src>` and
`<iframe src>`. Frameset sites (common on older Indonesian corporate sites) currently yield 0
links → 0 recon depth. General recon-completeness fix, not bernofarm-specific.
- Test: frameset body with `<frame src="/recruitment">` → /recruitment extracted, same-origin
  filtered, scope-gated in enqueue_discovered_url as usual.
- Model: SWE-1.6 Fast (single-file mechanical).

### 2. GAP-015 — username-derived credential candidates  [THE MOAT]
Alpha enumerates WP users (wp_rest_users). Beta currently needs hardcoded CREDENTIAL_PAIRS
(Natanael refuses hardcoded password lists). Replace with context-derived candidates, bounded
to MAX 5 per user: [username, username+"123", domain_stem, domain_stem+"123", "password"].
This closes the Alpha→Beta loop for WP → "we enumerated 3 users, one reused domain_stem123, we
reached admin" = PROVEN exploitable = what Nuclei cannot do. Auth gate: Beta STRIKE requires
OFFENSIVE_APPROVED — remind on every offensive-capability discussion.
- Test: derive-not-spray (exactly the 5, no combinatorial blowup); bound enforced; no hardcoded
  wordlist file.
- Model: GPT-5.1 High Thinking (security-critical, cred path).

### 3. odoo_version_disclosure proof_artifacts  [small, closes a report gap]
`verify_odoo_version` (odoo_dbmanager_probe.py ~237) does NOT attach proof_artifacts, so the
finding is invisible in the Omega standalone-evidence pass. Mirror the dbmanager pattern
(artifact_id first, storage_ref = engagements/{eng}/proofs/{artifact_id}).
- Model: SWE-1.6 Fast.

---

## DEFER — tracked, NON-blocking (do NOT start now)

- count-before-dedup on `_organic_crawl_count` (scout.py ~530) — VERIFY: the counter now sits
  behind `and self.enqueue_discovered_url(href)` (bool return), so it may already be correct.
  Confirm with a `test_duplicate_hrefs_do_not_consume_budget` regression before closing.
- `apply_event` wholesale replace (networkx_store) — VULNERABILITY nodes overwritten (no merge)
  on re-probe; last event wins. Latent, only manifests on re-probe of the same host.
- GAP-016 — WooCommerce auth probe (verify unauth data access to wc/v3 resource endpoints,
  separate from namespace detection). Extra HTTP request; deferred.
- Double-recon at the Layer V compose boundary — discovery fingerprints vuln.<apex> once, then
  the delegated chain re-runs run_recon on the same host. Redundant HTTP (stealth/efficiency).
- A7-b LLM-cost metric — needs a new event (dead-seam risk); deferred.
- time_to_first_proof_s still None in 3 live_fire runners.
- /health/queue returns GLOBAL depth — per-tenant scoping is a later refinement.
- test naming: test_scout_crawl_budget.py should consolidate into test_scout.py (existing
  mass-rename = deferred, churn/blame loss).
- Origin discovery for no-CT-subdomain sites (DNS history / Censys) — paid APIs, later.
- CLAUDE.md repo status block is STALE (still "Phase 4 Odoo arc / backup_file slice-1b") —
  reconcile to THIS doc on next commit.

---

## GATE — do NOT touch until exit criteria pass

- **Gamma / ANCHOR (Exploitation)** — STOP-gated. ToolComposer + blast-radius gate FIRST; gate =
  Claude lane, destructive bodies = DeepSeek lane. Phase 5+.
- **Conductor refactor** — main.py is 1052 lines; run_engagement_task carries `# noqa: C901`.
  Functional and the autonomous path is correct. Do NOT refactor now (explicitly parked).
- **No self-modifying code** — learning loop stays data/playbook only (IntelligenceBase).
- **scout.py ~1963 lines** — watch, not act. If GAP-015 + handlers push past ~2200, extract
  `_handle_*` into `alpha/handlers/` subpackage. Not now.

---

## Non-negotiables (unchanged)

Security-only domain. Auth gate in Conductor only, never bypassed. A2A = structured English JSON.
Event-sourced state. RUNNER-SEAL ≠ AUTONOMOUS-WIRED (grep the live path, not the runner, before
claiming sealed). Oracle ARM64 + .venv312 is the ONLY valid test env — `.venv312/bin/python3 -m
pytest` / `make check`, NEVER bare pytest. Gap ledger of record: docs/BUGS_AND_GAPS.md.

Test env: Oracle ARM64, Python 3.12.13, .venv312. main HEAD at handoff = d83a16c (#306).
