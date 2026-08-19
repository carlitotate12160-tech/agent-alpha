# agent_alpha/live_fire/a1_validation_runner.py
"""§12.33 slice-9d — A1 validation vs Nuclei through real CF challenge.

Field-prove that browser_solve reaches a CHALLENGE-gated leaked-cred→admin chain
that Nuclei cannot. This runner is the Claude-lane harness: it owns the seam
(BrowserSolveTransport), the fail-loud default (_NoopBrowserSolve), the C7
validity gate (assert_valid_or_raise), and the scoring against Nuclei jsonl.

The actual browser_solve body (camoufox/Turnstile) is DeepSeek lane (9c). This
file ONLY consumes the transport interface — it never implements the solver.

REUSE (anti-#6 — do NOT rebuild):
  - assert_lab_only_target (lab_guard)
  - classify_mitigation / MitigationClass (transport_resilience)
  - scan_js_for_secrets (js_secret_probe — parses creds from JS bundle body)
  - HttpFormApplicator (applicator — beta login with reused cred)
  - parse_nuclei_jsonl + compare (validation_vs_scanner)

CONSTRAINTS:
  - Target = alpha-ai.web.id ONLY. NEVER 168.110.192.62 (origin IP).
  - assert_valid_or_raise MUST run (C7): no challenge → raise, not pass.
  - browser_solve body is DeepSeek lane — this file only consumes the interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    assert_origin_authorized,
    load_signed_profile,
)
from agent_alpha.config.stores import build_event_store
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.browser_solve import DeepSeekBrowserSolve
from agent_alpha.live_fire.lab_guard import assert_lab_only_target
from agent_alpha.live_fire.validation_vs_scanner import (
    NucleiFinding,
    compare,
    parse_nuclei_jsonl,
)
from agent_alpha.recon.origin_discovery import OriginDiscovery, StaticOriginDiscovery
from agent_alpha.recon.reach_strategy import ReachStrategy, choose_reach
from agent_alpha.recon.reach_transport import OriginDirectResult, origin_direct_fetch
from agent_alpha.recon.transport_resilience import MitigationClass, classify_mitigation
from agent_alpha.security.secrets import SecretsManager, get_profile_signing_key

# ── Target constant ───────────────────────────────────────────────────────────

A1_TARGET = "alpha-ai.web.id"
A1_BUNDLE_PATH = "/web/assets/app.a1b2c3.js"
A1_LOGIN_PATH = "/web/login"
A1_WEB_PATH = "/web"

# ── Transport seam (DeepSeek lane owns the implementation) ────────────────────


class ChallengeSolveResult(Protocol):
    """Outcome of a browser_solve attempt against a CF challenge-gated URL.

    Read-only carrier — members are properties so a frozen dataclass
    (BrowserSolveResponse) structurally satisfies it (mypy: frozen attrs are
    read-only; a plain ``x: T`` protocol member demands settable → mismatch).
    """

    @property
    def status_code(self) -> int: ...

    @property
    def body(self) -> str: ...

    @property
    def headers(self) -> dict[str, str]: ...

    @property
    def cleared_cookies(self) -> dict[str, str]: ...

    @property
    def challenge_encountered(self) -> bool: ...

    @property
    def challenge_solved(self) -> bool: ...


class BrowserSolveTransport(Protocol):
    """Transport interface for solving CF challenges (9c, DeepSeek lane)."""

    def solve_and_fetch(self, url: str, *, engagement_id: str) -> ChallengeSolveResult: ...


class _NoopBrowserSolve:
    """FAIL-LOUD default (anti false-success). 9c unbuilt → A1 RAISES, never
    silently 'passes'. Mirrors _NoopGitDumper (#144)."""

    def solve_and_fetch(self, url: str, *, engagement_id: str) -> ChallengeSolveResult:
        raise RuntimeError(
            "browser_solve transport not provided (9c unbuilt): refusing to run A1 "
            "without a real Turnstile solver — a plain fetch would fake the reach."
        )


# ── Origin-direct fetch (scoping, NOT evasion — §12.33) ───────────────────────


class _OriginDirectHttpClientWrapper:
    """Wraps an http_client to inject Host header for origin-direct login.

    HttpFormApplicator calls http_client.get/post with the login URL — when
    origin-direct, the URL points to the origin IP, so the Host header MUST
    be set to the real domain. Without this, the origin server would reject
    the request or route it to the wrong vhost.
    """

    def __init__(self, inner: Any, host: str) -> None:
        self._inner = inner
        self._host = host

    def get(self, url: str, **kwargs: Any) -> Any:
        headers = dict(kwargs.get("headers") or {})
        headers["Host"] = self._host
        kwargs["headers"] = headers
        # LAB-SCOPED TLS override (ADR §12.33): origin cert matches *domain*,
        # NOT the origin IP literal → verify=True always fails the handshake.
        # Production origin-direct MUST use SNI-override domain-cert verification
        # (anti-MITM), NOT blanket verify=False.
        kwargs["verify"] = False
        return self._inner.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        headers = dict(kwargs.get("headers") or {})
        headers["Host"] = self._host
        kwargs["headers"] = headers
        # LAB-SCOPED TLS override — see get() above.
        kwargs["verify"] = False
        return self._inner.post(url, **kwargs)


# ── Result dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class A1Result:
    """A1 validation result with C7 validity gate.

    C7: valid_run is False if no challenge was encountered (CF pass-through).
    This closes the pass-through false-positive trap caught 2026-07-20.
    """

    valid_run: bool
    challenge_encountered: bool
    challenge_solved: bool
    chain_proven: bool
    edge_from_harvested_cred: bool
    nuclei_findings: int
    scanner_missed_exploitability: bool
    technique_used: str = "browser_solve"  # "browser_solve" | "origin_direct"
    origin_authorized: bool = False


def assert_valid_or_raise(r: A1Result) -> None:
    """C7 gate: a run where no challenge was encountered is INVALID, not a pass.

    Closes the pass-through false-positive trap caught 2026-07-20.
    """
    if not r.challenge_encountered:
        raise RuntimeError(
            "A1 INVALID: no CF challenge encountered — target is pass-through or CF "
            "challenge is disabled on /web. Re-enable the CF challenge and rerun."
        )

    # Technique-aware validity: origin-direct must both observe a CF challenge at the
    # front door and prove the leaked-cred→admin chain via the authorized origin.
    if r.technique_used == "origin_direct" and not r.chain_proven:
        raise RuntimeError(
            "A1 INVALID: origin-direct run did not prove the leaked-cred→admin chain "
            "despite a CF challenge at the front door. Investigate origin "
            "authorization and beta login before claiming A1 reach."
        )


# ── Runner ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _ReachOutcome:
    """Result of the C8/C9 reach decision. ``bundle_result`` is set ONLY when the
    origin-direct path fetched the bundle; otherwise the caller fetches via browser_solve."""

    bundle_result: Any | None
    technique_used: str
    origin_authorized: bool
    use_origin_direct: bool
    origin_ip_used: str | None


def _resolve_origin_direct_reach(
    *,
    target: str,
    engagement_id: str,
    mitigation_class: MitigationClass | None,
    browser_solve_viable: bool,
    origin_discovery: OriginDiscovery | None,
    engagement_profile: EngagementProfile | None,
    event_store: Any | None,
) -> _ReachOutcome:
    """C8/C9 reach decision, extracted to keep ``run_a1_validation`` complexity bounded.

    Default = browser_solve. Only a SIGNED, authorized origin (candidate ∈ authorized_origins,
    §12-C9) with a chosen ORIGIN_DIRECT strategy bypasses the challenge via origin-direct fetch.
    ANTI-#3: challenge_solved stays False — reached ≠ solved; the honest story ("challenge NOT
    solved; bypassed via exposed origin") IS the payable finding.
    """
    default = _ReachOutcome(None, "browser_solve", False, False, None)
    if origin_discovery is None or engagement_profile is None:
        return default

    origin_ip = next(
        (
            ip
            for ip in origin_discovery.candidates(target)
            if ip in engagement_profile.authorized_origins
        ),
        None,
    )
    strategy = choose_reach(
        mitigation_class,
        browser_solve_viable=browser_solve_viable,
        authorized_origin=origin_ip,
    )
    if strategy is not ReachStrategy.ORIGIN_DIRECT or origin_ip is None:
        return default

    # C8: fail-closed — raises OriginNotAuthorizedError if origin is not signed-authorized.
    assert_origin_authorized(origin_ip, target, engagement_profile)
    bundle_result = origin_direct_fetch(target, origin_ip, A1_BUNDLE_PATH)

    # Typed event (audit-sensitive: hitting client origin bypasses WAF).
    if event_store is not None:
        from agent_alpha.events.event_types import EventType

        event_store.append(
            EventType.ORIGIN_DIRECT_ATTEMPT,
            engagement_id,
            "alpha",
            {
                "host": target,
                "origin_ip": origin_ip,
                "authorized": True,
                "discovered_via": "origin_discovery",
            },
        )
    return _ReachOutcome(bundle_result, "origin_direct", True, True, origin_ip)


def _mint_credentials(
    *, hits: list[Any], secrets_manager: Any | None, graph_store: Any | None, engagement_id: str
) -> tuple[bool, str | None]:
    """Vault each harvested secret (no raw secret in events, anti-#3). Returns
    (cred_minted, last_secret_id) — the secret_ref is all that reaches the graph."""
    if not (hits and secrets_manager is not None and graph_store is not None):
        return False, None
    secret_id: str | None = None
    for hit in hits:
        record = secrets_manager.store(
            label=f"{hit.service}:{hit.kind}",
            value=getattr(hit, "_raw_value", ""),  # noqa: W0212 — no public accessor on hit
            engagement_id=engagement_id,
        )
        secret_id = record.secret_id
    return True, secret_id


def _beta_login_with_reused_cred(
    *,
    http_client: Any,
    secrets_manager: Any,
    secret_id: str,
    target: str,
    use_origin_direct: bool,
    origin_ip_used: str | None,
) -> tuple[str, bool]:
    """Reuse the vaulted harvested secret for a real login (origin-direct via Host header,
    or front-door). Returns (access_level, edge_from_harvested_cred)."""
    from agent_alpha.tools.contracts import ResourceBudget
    from agent_alpha.tools.internal.access.applicator import HttpFormApplicator

    if use_origin_direct and origin_ip_used is not None:
        login_url = f"https://{origin_ip_used}{A1_LOGIN_PATH}"
        login_client: Any = _OriginDirectHttpClientWrapper(http_client, target)
    else:
        login_url = f"https://{target}{A1_LOGIN_PATH}"
        login_client = http_client

    secret = secrets_manager.retrieve(secret_id)
    applicator = HttpFormApplicator(http_client=login_client)
    budget = ResourceBudget(max_requests=5, max_seconds=30, max_cost_usd=0.0)
    auth_result = applicator.apply(
        username="admin",
        secret=secret,
        target=login_url,
        budget=budget,
    )
    if auth_result.success:
        return auth_result.access_level, True
    return "", False


def _run_attestor_pass(
    *, graph_store: Any | None, event_store: Any | None, secrets_manager: Any, engagement_id: str
) -> None:
    """Promote SELF_VERIFIED → CROSS_VERIFIED via the SAME run_verification_pass the autonomous
    Conductor path uses (one impl). No-op if the graph/event stores are absent."""
    if graph_store is None or event_store is None:
        return
    from agent_alpha.attestation.attestor import CredReuseAttestor, run_verification_pass

    run_verification_pass(
        graph_store,
        event_store,
        [CredReuseAttestor(secrets_manager, engagement_id)],
        engagement_id,
    )


def _score_and_build_result(
    *,
    nuclei_jsonl_path: str | None,
    cred_minted: bool,
    access_level: str,
    edge_from_harvested_cred: bool,
    challenge_encountered: bool,
    challenge_solved: bool,
    use_origin_direct: bool,
    technique_used: str,
    origin_authorized: bool,
) -> A1Result:
    """Score vs Nuclei jsonl (C6) + build the A1Result. Extracted to keep
    run_a1_validation complexity bounded."""
    nuclei_findings: list[NucleiFinding] = []
    if nuclei_jsonl_path is not None:
        nuclei_findings = parse_nuclei_jsonl(nuclei_jsonl_path)

    chain_proven = cred_minted and access_level in ("user", "admin") and edge_from_harvested_cred

    from agent_alpha.live_fire.odoo_chain_runner import OdooChainResult

    chain_result = OdooChainResult(
        leak_creds_added=1 if cred_minted else 0,
        web_access_level=access_level,
        edge_from_harvested_cred=edge_from_harvested_cred,
        db_enumerated=True,
        leak_suspected=False,
        cross_verified=False,
    )
    verdict = compare(chain_result, nuclei_findings)

    valid_run = challenge_encountered and (chain_proven if use_origin_direct else True)

    return A1Result(
        valid_run=valid_run,
        challenge_encountered=challenge_encountered,
        challenge_solved=challenge_solved,
        chain_proven=chain_proven,
        edge_from_harvested_cred=edge_from_harvested_cred,
        nuclei_findings=len(nuclei_findings),
        scanner_missed_exploitability=verdict.scanner_missed_exploitability,
        technique_used=technique_used,
        origin_authorized=origin_authorized,
    )


def run_a1_validation(
    *,
    engagement_id: str,
    browser_solve: BrowserSolveTransport | None = None,
    http_client: Any | None = None,
    secrets_manager: Any | None = None,
    graph_store: Any | None = None,
    event_store: Any | None = None,
    nuclei_jsonl_path: str | None = None,
    target: str = A1_TARGET,
    origin_discovery: OriginDiscovery | None = None,
    engagement_profile: EngagementProfile | None = None,
    browser_solve_viable: bool = False,
) -> A1Result:
    """Run the A1 validation chain against a CF challenge-gated target.

    Flow:
      1. assert_lab_only_target — fail-closed on non-lab targets.
      2. Probe /web → classify_mitigation → assert CHALLENGE (C2).
      3. browser_solve /web + /web/assets/app.a1b2c3.js → reuse cleared_cookies.
      4. scan_js_for_secrets extracts api_user/api_key from bundle body.
      5. Mint vaulted credential (no raw secret in events).
      6. Beta login /web/login with reused cred → verified admin.
      7. Score vs Nuclei jsonl (C6).
      8. assert_valid_or_raise (C7).

    Args:
        browser_solve: the transport for solving CF challenges. Defaults to
            _NoopBrowserSolve (fail-loud) — real solver passed only in field-prove.
        http_client: HTTP client for probe + beta login.
        secrets_manager: vault for minting credentials.
        graph_store: attack graph for persisting nodes/edges.
        event_store: append-only event store.
        nuclei_jsonl_path: path to externally-produced Nuclei JSONL.
        target: the lab target (default: alpha-ai.web.id).

    Returns:
        A1Result with all scoring fields populated.

    Raises:
        RuntimeError: if browser_solve is not provided (9c unbuilt) or if
            no challenge was encountered (C7 gate).
        LabOnlyViolation: if target is not in the lab allowlist.
    """
    # ── 0. Fail-loud default: no browser_solve → raise on browser-solve path ─────
    solver: BrowserSolveTransport = browser_solve or _NoopBrowserSolve()

    # ── 1. Lab-only guard — fail-closed on non-self-owned targets ─────────
    assert_lab_only_target(target)

    # ── 2. Probe /web via plain HTTP → classify mitigation class (C2, OBSERVE) ──
    if http_client is None:
        raise RuntimeError("A1 requires http_client for the mitigation probe (OBSERVE step)")

    web_url = f"https://{target}{A1_WEB_PATH}"
    # No-follow: a 302 from the allowlisted host must NOT auto-follow to an
    # internal/off-scope destination before classification (CWE-918, CR-2).
    # A 3xx response is seen as-is by classify_mitigation → None (not a
    # challenge) → challenge_encountered=False → C7 correctly raises INVALID.
    # Full scope-validating redirect policy deferred to GAP-005.
    probe_resp = http_client.get(web_url, allow_redirects=False)

    mitigation_class = classify_mitigation(
        status_code=getattr(probe_resp, "status_code", 0),
        body=getattr(probe_resp, "text", ""),
        headers=getattr(probe_resp, "headers", {}) or {},
        path=A1_WEB_PATH,
    )

    challenge_encountered = mitigation_class == MitigationClass.CHALLENGE

    # ── 2b. Origin-direct reach strategy (optional, C8/C9) ────────────────
    reach = _resolve_origin_direct_reach(
        target=target,
        engagement_id=engagement_id,
        mitigation_class=mitigation_class,
        browser_solve_viable=browser_solve_viable,
        origin_discovery=origin_discovery,
        engagement_profile=engagement_profile,
        event_store=event_store,
    )
    technique_used = reach.technique_used
    origin_authorized = reach.origin_authorized
    use_origin_direct = reach.use_origin_direct
    origin_ip_used = reach.origin_ip_used

    # ── 3. Fetch bundle (browser_solve path, only if NOT origin-direct) ───
    bundle_url = f"https://{target}{A1_BUNDLE_PATH}"
    bundle_result: ChallengeSolveResult | OriginDirectResult
    if use_origin_direct:
        # Invariant: the origin-direct outcome always carries the fetched bundle.
        assert reach.bundle_result is not None
        bundle_result = reach.bundle_result
    else:
        bundle_result = solver.solve_and_fetch(bundle_url, engagement_id=engagement_id)

    challenge_solved = bundle_result.challenge_solved

    # ── 4. scan_js_for_secrets extracts api_user/api_key ──────────────────
    from agent_alpha.recon.js_secret_probe import scan_js_for_secrets

    # Origin-direct: bundle fetched successfully (no challenge), scan it.
    # Browser-solve: scan only if challenge was solved.
    hits = (
        scan_js_for_secrets(bundle_result.body) if (challenge_solved or use_origin_direct) else []
    )

    # ── 5. Mint vaulted credential (no raw secret in events) ─────────────
    cred_minted, minted_secret_id = _mint_credentials(
        hits=hits,
        secrets_manager=secrets_manager,
        graph_store=graph_store,
        engagement_id=engagement_id,
    )

    # ── 6. Beta login /web/login with reused cred → verified admin ────────
    access_level = ""
    edge_from_harvested_cred = False
    if cred_minted and http_client is not None and minted_secret_id is not None:
        access_level, edge_from_harvested_cred = _beta_login_with_reused_cred(
            http_client=http_client,
            secrets_manager=secrets_manager,
            secret_id=minted_secret_id,
            target=target,
            use_origin_direct=use_origin_direct,
            origin_ip_used=origin_ip_used,
        )

    # ── 7+8. Score vs Nuclei + build result (C6) ──────────────────────────
    result = _score_and_build_result(
        nuclei_jsonl_path=nuclei_jsonl_path,
        cred_minted=cred_minted,
        access_level=access_level,
        edge_from_harvested_cred=edge_from_harvested_cred,
        challenge_encountered=challenge_encountered,
        challenge_solved=challenge_solved,
        use_origin_direct=use_origin_direct,
        technique_used=technique_used,
        origin_authorized=origin_authorized,
    )

    # ── 9. C7 gate: no challenge → raise, not pass ────────────────────────
    assert_valid_or_raise(result)

    # ── 6b. Attestor verification pass — promote SELF_VERIFIED → CROSS_VERIFIED ──
    # Live-path consumer that makes CROSS_VERIFIED reachable via the SAME
    # run_verification_pass the autonomous Conductor path uses (one impl).
    _run_attestor_pass(
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets_manager,
        engagement_id=engagement_id,
    )

    return result


# ── CLI entry point ───────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for A1 field-prove validation.

    Origin-direct requires TWO independent inputs:
      --origin <IP>       Discovery candidate (StaticOriginDiscovery).
      --profile <path>    Signed consent (EngagementProfile loaded via
                          load_signed_profile — SHA-256 verified).

    Consent CANNOT be derived from discovery (CWE-862, CR-1).  If --origin is
    given without --profile, the runner raises unless --lab-unsigned explicitly
    opts in to an unsigned lab-only synth (with a LOUD warning).

    Without --origin AND without --browser-solve (9c), the browser-solve path
    RAISES _NoopBrowserSolve — no silent pass.
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="A1 validation: Agent-Alpha chain vs Nuclei through real CF challenge"
    )
    parser.add_argument(
        "--engagement-id", required=True, help="Engagement ID for the field-prove run"
    )
    parser.add_argument(
        "--nuclei", default=None, help="Path to nuclei JSONL output (produced by operator)"
    )
    parser.add_argument("--target", default=A1_TARGET, help=f"Lab target (default: {A1_TARGET})")
    parser.add_argument(
        "--browser-solve",
        default=None,
        help=(
            "DeepSeek browser_solve HTTP endpoint URL (9c). When omitted, falls "
            "back to A1_BROWSER_SOLVE_ENDPOINT env var. When neither is set and "
            "no --origin is given, _NoopBrowserSolve is used and the run fails loud."
        ),
    )
    parser.add_argument(
        "--origin",
        default=None,
        help=(
            "Candidate origin IP for origin-direct reach (DISCOVERY ONLY). "
            "Consent MUST come from a separate signed --profile — not from this flag."
        ),
    )
    parser.add_argument(
        "--profile",
        default=None,
        help=(
            "Path to a signed EngagementProfile JSON (produced by "
            "scripts/sign_profile.py). HMAC-SHA-256 verified on load — tampered "
            "profiles are rejected."
        ),
    )
    parser.add_argument(
        "--lab-unsigned",
        action="store_true",
        default=False,
        help=(
            "Lab-only: synthesise an unsigned EngagementProfile from --origin "
            "instead of requiring a signed --profile. NOT auth-honest — the run "
            "CANNOT be used as a payable field-prove. For throwaway lab runs only."
        ),
    )
    parser.add_argument(
        "--client-id", default="lab", help="Client ID for the (lab) signed engagement profile."
    )
    args = parser.parse_args(argv)

    solver: BrowserSolveTransport | None = None
    if args.browser_solve:
        solver = DeepSeekBrowserSolve(endpoint=args.browser_solve)
    else:
        solver = DeepSeekBrowserSolve.from_env()

    origin_discovery: OriginDiscovery | None = None
    engagement_profile: EngagementProfile | None = None

    if args.origin:
        # --origin is DISCOVERY ONLY.
        origin_discovery = StaticOriginDiscovery([args.origin])

        if args.profile:
            # --profile: load signed consent (HMAC-SHA-256 verified).
            signing_key = get_profile_signing_key()
            engagement_profile = load_signed_profile(args.profile, key=signing_key)
        elif args.lab_unsigned:
            # --lab-unsigned: LOUD warning — synthesise consent for lab-only runs.
            print(
                "=" * 72,
                "⚠  WARNING: --lab-unsigned — this run is NOT auth-honest.",
                "   Consent is synthesised from the discovery candidate.",
                "   This run CANNOT be used as a payable field-prove.",
                "   For auth-honest runs, use --profile <signed-profile.json>.",
                "=" * 72,
                sep="\n",
                file=sys.stderr,
            )
            engagement_profile = EngagementProfile(
                engagement_id=args.engagement_id,
                client_id=args.client_id,
                targets=frozenset({args.target}),
                authorized_origins=frozenset({args.origin}),
                authorization_level="RECON_ONLY",
                allow_evasion=True,  # lab consent: allow_evasion=True for field-prove runs
            )
        else:
            # --origin without --profile and without --lab-unsigned → refuse.
            raise RuntimeError(
                "origin-direct requires a signed --profile; consent cannot be "
                "derived from the discovery candidate. Use "
                "'scripts/sign_profile.py' to produce a signed profile, or pass "
                "--lab-unsigned for throwaway lab runs (NOT auth-honest)."
            )

    http_client = HttpClient(engagement_id=args.engagement_id)

    # Wire canonical stores for chain proof (cred minting → beta login → graph edge).
    # These are the SAME types used by sibling field-prove runners (actuator, backup_file).
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = build_event_store()

    try:
        result = run_a1_validation(
            engagement_id=args.engagement_id,
            browser_solve=solver,  # origin-direct path never invokes it (no raise)
            http_client=http_client,
            nuclei_jsonl_path=args.nuclei,
            target=args.target,
            origin_discovery=origin_discovery,
            engagement_profile=engagement_profile,
            browser_solve_viable=False,  # datacenter egress ⇒ origin-direct on CHALLENGE
            secrets_manager=secrets_manager,
            graph_store=graph_store,
            event_store=event_store,
        )
    except RuntimeError as e:
        print(f"A1 VALIDATION FAILED: {e}")
        return 1

    print("=" * 72)
    print("A1 VALIDATION RESULT")
    print("=" * 72)
    print(f"  valid_run                   : {result.valid_run}")
    print(f"  challenge_encountered       : {result.challenge_encountered}")
    print(f"  challenge_solved            : {result.challenge_solved}")
    print(f"  chain_proven                : {result.chain_proven}")
    print(f"  edge_from_harvested_cred    : {result.edge_from_harvested_cred}")
    print(f"  nuclei_findings             : {result.nuclei_findings}")
    print(f"  scanner_missed_exploitability: {result.scanner_missed_exploitability}")
    print(f"  technique_used              : {result.technique_used}")
    print(f"  origin_authorized           : {result.origin_authorized}")
    print("=" * 72)
    return 0 if result.chain_proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
