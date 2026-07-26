> CANONICAL SOURCE: current status — done/next/phase. THE ONLY status doc.

# Agent-Alpha — Session Handoff (2026-07-26)

Resume with: "lanjut Agent-Alpha — Conductor autonomous kill-chain is WIRED (routing = f(graph),
verification autonomous, e2e proven). STACK_WP consolidation LANDED (canonical label + single
merge_tech_stack helper + guard test, 5/5 green). NEXT = the pre-Gamma conductor refactor
(D1/D2/D3) with slice-1d as the safety net."

## Current Project Status

```
Project Phase  : Phase 4. AUTONOMOUS kill-chain spine CLOSED for WP cred-reuse:
                 Conductor drives Alpha→Beta→Omega by itself and produces a CROSS_VERIFIED
                 payable report — NOT via wp_chain_runner (RUNNER-SEAL != AUTONOMOUS-WIRED
                 closed for the WP path). Gamma still STOP-gated.

Landed (green on Oracle, ~1389 pass / 1 xfailed / make check clean):
  - PR #252  §12.36 auth integrity: keyed HMAC-SHA-256 EngagementProfile (not unkeyed
             sha256), consent gate (elevated/allow_evasion/opsec_stealth require verified
             consent), exact DNS-TXT, public-origin validation, trailing-dot norm.
  - PR #253  A1-reach autonomous wiring: origin_direct_fetch hoisted to
             recon/reach_transport (agents no longer import live_fire — test_layering guard),
             reach wired into scout.
  - slice-1a ROUTING: conductor/router.py route_next(graph) — next agent = f(AttackGraph),
             NOT hardcoded (Lyndon #11 killed: scout/strike/main next_recommended → CONDUCTOR).
             Bug #22 fixed: FAILED/BLOCKED → OMEGA (partial report), not noop.
             advance.py consumes route_next; blast gate reuses the SINGLE graph rebuild.
             router has NO vacuous http/https fallback; _AUTH_SURFACE_LABELS is semantic.
  - slice-1b WP applicator ordering: applicator_factory.beta_web_applicators (WpLogin BEFORE
             HttpForm — opsec: no wrong-field login at wp-login.php first). Factory host-match
             on the WP login target (#10).
  - slice-1c VERIFICATION autonomous: conductor/verification.verify_access_nodes runs
             CredReuseOracle post-Beta → CROSS_VERIFIED fires on the live path (not only the
             a1 runner). test_wiring_gate xfail for run_verification_pass REMOVED (debt paid).
  - slice-1d AUTONOMOUS E2E: tests/integration proves the Conductor chain (eager Celery
             cascade) yields a CROSS_VERIFIED WP finding without wp_chain_runner. Exposed two
             real integration bugs (see NEXT).

Open PR (#260): bundles 1a+1b+1c+1d + Claude provider + origin-scope ADR (over-bundled —
             split-discipline not applied). Review found band-aids to root-cause first.

DONE — STACK_WP consolidation PR (#262, merged):
  1. constants.STACK_WP = "wp" — ONE canonical WordPress label (Lyndon #7). All sites
     (router, wp_config_probe, applicator, planner, path_probe, default_creds) now source
     from constants.STACK_WP. No more "wordpress" literal in agent_alpha/.
  2. graph/nodes.merge_tech_stack — ONE merge site (Lyndon #6). scout.py:910 + path_probe.py
     both route through the helper. No inline dict.fromkeys copies remain.
  3. tests/integration/test_autonomous_wp_chain_e2e.py → test_conductor_chain.py (renamed)
     + 2 CodeRabbit fixes (monkeypatch.setitem for _stores; fake login checks log AND pwd).
  4. tests/phase_3/test_stack_label.py — 4 guard tests (routing, default-creds, merge
     anti-clobber, single-source literal guard). 5/5 green.

Next Action (BLOCKING before Gamma) — pre-Gamma conductor refactor (BUGS_AND_GAPS D1/D2/D3):
  D1 split main.py (724 LOC, 4 concerns), D2 extract agent_factory closure → role-keyed
  builder (trigger: Gamma), D3 reconcile Alpha (run_engagement_task) onto execute_agent
  (the "ONE path" docstring overclaim — D3-a fixes the doc now). slice-1d is the safety net.

Parked designs (ADR-recorded, NOT built):
  - Origin-scope by ownership (§12.38): client gives URL only → Conductor mints server-side
    DNS-TXT token (bound to engagement) → verify ownership. Hitting a DISCOVERED origin needs
    TWO proofs: (1) domain ownership, (2) origin-binding via cert SAN (NOT body-identity —
    diagnostic only) + SSRF gate reusing resolve_targets' internal-IP block. authorized_origins
    (hand-fed IPs) removed. origin_discovery seam = wiring-debt xfail (injected None on live path).
  - Alpha→Gamma (skip Beta): allowed IFF unauth-exploitable + CROSS_VERIFIED (not fingerprint)
    + reach solved + auth/blast gate holds. Blocked on an exploit-reachability oracle
    (ChainOracle, roadmap #5) — built WITH Gamma, never before. Router branch NOT in slice-1a.

Real engagements (all SOW; market ask = "seberapa kuat proteksi kami bisa ditembus" = WAF/CDN
  evasion; clients WITHHOLD origin IP → origin-scope-by-ownership is the mechanism):
  - niagamas.com — WordPress + WooCommerce, no CDN        → WP chain (spine target, first).
  - <site #2>     — WordPress, PHP5.6/LiteSpeed, no CDN    → WP chain.
  - ibudanbalita.com — Laravel (main) + Magento (shop), CloudFront → needs reach + laravel_chain.
  - cimbniaga.co.id — AEM/Java, Imperva WAF (BANK)         → LAST; add to _GUARDBRAIL_DOMAINS;
                       origin-exposure only, NOT challenge-defeat (browser_solve parked).
  - kalbe.co.id   — DNN/ASP.NET legacy + OpenShift/3scale  → new stack, DEFER.

Honest product boundary: sells ORIGIN-EXPOSURE bypass (origin reachable + serves owned
  domain), NOT interactive challenge-defeat (browser_solve parked = datacenter egress; true
  solve needs residential/mobile proxy = INFRA, not code). Never fake "bypassed" (#3).

Test env       : Oracle ARM64, Python 3.12.13, .venv312 — ALWAYS `.venv312/bin/python3 -m
                 pytest` or `make check` (NEVER bare pytest — system python 3.10 fails StrEnum).

Phase status (verified on Oracle):
  Phase 0/1/2/3 : DONE. Phase 4 : autonomous WP spine CLOSED; Gamma STOP-gated behind
                  ToolComposer + blast gate + exploit-reachability oracle.

Wiring-debt (test_wiring_gate): OPEN xfail = origin_discovery (§12.38). Tracked (not islands):
  check_technique/check_scope (GAP-005), find_critical_paths (GAP-006), SessionStore (GAP-002),
  IntelligenceBase (GAP-003). run_verification_pass = CLOSED by slice-1c.

NOTE: repo CLAUDE.md status block + the imported Claude.ai project memory are STALE (stuck at
  early phases). This handoff is the operative status. Reconcile CLAUDE.md on next commit.
```
