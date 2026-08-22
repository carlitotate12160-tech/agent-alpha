# ADR-GOV-001 — WIRING GATE. A component is NOT "done" until it is wired into the
# live production path (anti-Lyndon #2: dead code treated as done). This is the
# machine-enforced half of §12.35; the other half (a "wired-proof" W-test that
# exercises the component through run_recon / the Conductor, not just a unit) is a
# per-component review requirement.
#
# RATCHET SEMANTICS:
#   * WIRED_REQUIRED — components that MUST stay wired. If one regresses to dead
#     code, this test fails (blocks the regression).
#   * WIRING_DEBT — known un-wired components, tracked in the open. The moment a
#     debt item IS wired, its test fails on purpose — forcing the author to MOVE it
#     into WIRED_REQUIRED, so it can never silently regress afterward.
#
# Pure text scan (no agent_alpha import) → runs on any Python, incl. the pre-3.11
# lint box. Presence in a production wiring-target is the cheap tripwire; the
# wired-proof W-test (Rule 2) is the real teeth.

from __future__ import annotations

import pathlib
from typing import Any

import pytest

_PKG = pathlib.Path(__file__).resolve().parents[2] / "agent_alpha"


def _read(*rel_paths: str) -> str:
    text = ""
    for rel in rel_paths:
        p = _PKG / rel
        if p.exists():
            text += p.read_text()
    return text


# symbol -> production wiring-target module(s) that MUST reference it.
# NOT the definition file, NOT tests/, NOT live_fire/ (those never count as "wired").
WIRED_REQUIRED: dict[str, tuple[str, ...]] = {
    "rebuild_graph_from_events": ("conductor/main.py",),  # Bug #4 (graph replay)
    "persist_node": ("agents/alpha/scout.py",),  # event-sourced graph writes
    "AuthorizationStateMachine": ("conductor/recon_runner.py",),  # auth gate on the live path
    "PolicyEnforcer": ("conductor/advance.py",),  # OPSEC/blast-radius gate (GAP-005)
    "calculate_blast_radius": ("conductor/blast_gate.py",),  # Blast-radius evaluation (GAP-006)
    "engagement_profile": ("conductor/main.py",),  # §12.36: signed profile reaches Conductor
    "select_strike_entry": (
        "conductor/main.py",
    ),  # entry-selection: Beta strikes reachable auth-surface
    "STRIKE_ENTRY_SELECTED": ("conductor/main.py",),  # entry-selection observability event
    # GAP-035 multi-candidate: consumed on the live dispatch path in main.py
    # (NOT router.py — that is the definition; wiring = consumption on live path).
    "ranked_entries": ("conductor/main.py",),
    "STRIKE_CANDIDATE_ATTEMPTED": ("conductor/main.py",),
    "STRIKE_CANDIDATE_SKIPPED": ("conductor/main.py",),
    # GAP-034: reachability read-model consumed on the live entry-selection path.
    "unreachable_hosts": ("conductor/main.py",),
    # Slice-B SpaLoginApplicator: wired on the live Beta factory path.
    "SpaLoginApplicator": ("conductor/applicator_factory.py",),
    "login_endpoint_candidates": ("conductor/applicator_factory.py",),
    "wp_fingerprint": (
        "agents/alpha/scout.py",
    ),  # WP battery auto-seeds from fingerprint (PR #274 wiring)
    "discovered_in_scope": (
        "conductor/recon_runner.py",
    ),  # §12.41: in-scope passive subdomains → recon targets
    "UserDerivedCredsTool": (
        "agents/beta/strike.py",
    ),  # GAP-015: username-derived cred tool wired + run() authored (live)
    "GovernedApplicator": (
        "conductor/applicator_factory.py",
    ),  # §12.22 D2: lockout seam wraps every applicator in the factory
    "verify_access_nodes": (
        "conductor/main.py",
    ),  # §12.43: CROSS_VERIFIED on the autonomous Conductor path (canonical run_verification_pass wrapper)
    "build_passive_intel_map": (
        "conductor/recon_runner.py",
    ),  # §12.48 slice-1: PassiveIntelMap built + PASSIVE_INTEL_GATHERED emitted on the live passive stage
    "hackertarget_fallback": (
        "conductor/recon_runner.py",
    ),  # §12.48 slice-2: keyless crt.sh fallback wired into the live passive stage
    "enrich_with_dns": (
        "conductor/recon_runner.py",
    ),  # §12.48 slice-3: DNS enrichment (MX/NS/TXT + protection_detected) wired into the live passive stage
    "certspotter_discover": (
        "conductor/recon_runner.py",
    ),  # §12.48 slice-4: CertSpotter primary CT source wired into the live passive chain
    "enrich_with_otx": (
        "conductor/recon_runner.py",
    ),  # §12.48 slice-5: OTX enrichment (origin-IP candidates + historical paths) wired into the passive stage
    "build_otx_client": (
        "conductor/main.py",
    ),  # §12.48 slice-5: OTX source built + injected on the live Conductor path
    "build_mnemonic_client": (
        "conductor/recon_runner.py",
    ),  # §12.61 A1: Mnemonic PDNS client built + injected on the live Conductor path
    "enrich_with_historical_dns": (
        "conductor/recon_runner.py",
    ),  # §12.61 A1: Mnemonic PDNS enrichment wired into the passive stage
    "CompositeOriginDiscovery": (
        "conductor/main.py",
    ),  # GAP-017: OTX origin_ip_candidates unioned into the binding candidate path (consumer wired)
    "OdooAccessTool": (
        "agents/beta/strike.py",
    ),  # Beta autonomous access tool wired into the ToolRegistry candidate set (protects wiring;
    # NOTE: autonomous-WIN proof via run_strike/run_beta still owed — tracked in BUGS_AND_GAPS)
    "resolve_and_bind_origin": (
        "agents/alpha/scout.py",
    ),  # §12.46 Slice A: origin-binding wired into _attempt_reach (verify_origin_binding transitively via this)
    "LiveOriginDiscovery": (
        "conductor/main.py",
    ),  # §12.46 Slice B: real CT/DNS origin discovery injected on the live Conductor path (discover_origin_ips transitively via this)
    "protection_detected": (
        "recon/fingerprint.py",
    ),  # Bug #26 Layer 5: WAF posture suppresses blind path spray in seed_fingerprint_first (GAP-169)
    "historical_paths": (
        "agents/alpha/scout.py",
    ),  # Bug #26 Layer 1: OTX historical paths seeded into the frontier in run_recon (consumer wired)
    "_scope_seed_hosts": (
        "recon/origin_resolver.py",
    ),  # GAP-018: LiveOriginDiscovery.candidates() seeds in-scope domains → discover_origin_ips
    # yields origin candidates even when crt.sh is down (T4 CF-bypass MOAT reachable)
}

# symbol -> (wiring-target module(s), GAP/ADR reference). Deliberately EXCLUDES a
# dead instantiation site (e.g. PolicyEnforcer is built in main.py but never used —
# the target is the ENFORCEMENT site, not the constructor call).
# N/A decision (recon-stage catalog tools): a leak/fingerprint probe dispatched via
# PATH_PROBE_CATALOG / CAPABILITY_CATALOG is NOT tracked here. Its symbol never appears
# by name in a consumer module (dispatch is data-driven through the registry), so neither
# WIRED_REQUIRED (symbol-in-module) nor WIRING_DEBT (symbol-absent-until-wired) can express
# its state — a debt entry for it is a permanent false-green that mislabels a proven-wired
# tool as un-wired. The correct regression guard is test_every_catalog_tool_is_dispatchable
# (catalog tool -> Alpha._dispatch_registry) plus the behavioural driver proof. Example:
# codeigniter_config_probe is a RECON-stage (E1->E3) vector proven through the Conductor recon
# driver (build_recon_pipeline -> _sweep_targets -> run_recon, see test_conductor_driver_*).
# execute_agent.py is the OFFENSIVE (Beta/Gamma/Omega) path — a recon leak probe never belongs
# there, so there is no execute_agent W-test to wait on. Wiring is SEALED via the catalog gate.
WIRING_DEBT: dict[str, tuple[tuple[str, ...], str]] = {
    "SessionStore": (
        ("conductor/recon_runner.py", "conductor/execute_agent.py"),
        "GAP-002 / ADR §12.11 (scratchpad wiring)",
    ),
    "IntelligenceBase": (
        ("tools/registry.py", "llm/orchestrator.py"),
        "GAP-003 / ADR §12.11 (cross-engagement learning)",
    ),
    "check_technique": (
        ("conductor/execute_agent.py",),
        "GAP-005 / OPSEC technique gate before offensive tool exec",
    ),
    "check_scope": (
        ("conductor/execute_agent.py",),
        "GAP-005 / scope gate before tool exec",
    ),
    "find_critical_paths": (
        ("conductor/advance.py",),
        "GAP-006 / attack-route prioritization (HVT), not report-only",
    ),
    "CredentialLockoutGovernor": (
        ("tools/internal/access/odoo_access.py",),
        "§12.22 D2: odoo submits creds via its own http path (off-roster) — must route through the lockout governor",
    ),
}


@pytest.mark.parametrize("symbol,targets", list(WIRED_REQUIRED.items()))
def test_required_component_stays_wired(symbol: str, targets: tuple[str, ...]) -> None:
    assert symbol in _read(*targets), (
        f"WIRING GATE (ADR-GOV-001): '{symbol}' must be referenced in a production "
        f"wiring target {targets}; it regressed to dead code (anti-Lyndon #2)."
    )


@pytest.mark.parametrize("symbol,spec", list(WIRING_DEBT.items()))
def test_wiring_debt_is_tracked_until_resolved(
    symbol: str, spec: tuple[tuple[str, ...], str]
) -> None:
    targets, ref = spec
    assert symbol not in _read(*targets), (
        f"WIRING GATE (ADR-GOV-001): '{symbol}' is now wired into {targets} ({ref}). "
        f"Move it from WIRING_DEBT to WIRED_REQUIRED so the gate protects it from "
        f"regressing back to dead code."
    )


def test_conductor_chain_calls_run_verification_pass():
    """CROSS_VERIFIED is reachable on the autonomous Conductor path (slice-1c wired it)."""
    conductor_src = "\n".join(
        p.read_text(encoding="utf-8") for p in pathlib.Path("agent_alpha/conductor").rglob("*.py")
    )
    assert "run_verification_pass" in conductor_src, (
        "run_verification_pass is not wired into the Conductor chain — autonomous "
        "findings cannot reach CROSS_VERIFIED (Lyndon #2, runner-seal != wired)."
    )


def test_origin_discovery_is_wired_with_real_instance():
    """WIRING-DEBT (§12.38) RESOLVED: origin_discovery is now wired — the
    Conductor task builds a StaticOriginDiscovery from the signed profile's
    authorized_origins and injects it into run_recon_for_engagement()."""
    import pathlib

    conductor_src = "\n".join(
        p.read_text(encoding="utf-8") for p in pathlib.Path("agent_alpha/conductor").rglob("*.py")
    )
    assert "origin_discovery" in conductor_src and "OriginDiscovery(" in conductor_src, (
        "origin_discovery is not wired into the Conductor path with a real instance — "
        "the seam is injected None (island, Lyndon #2)."
    )


def test_alpha_recon_handoff_status_is_not_hardcoded_complete():
    """187a (anti-Lyndon #3): the Alpha recon handoff must carry the HONEST engagement
    status derived from the run (recon_runner.derive_terminal_status → ReconRunResult.status),
    never a hardcoded COMPLETE. A hardcoded COMPLETE would false-advance the kill chain to
    Beta even on a failed / WAF-walled recon. This is the CI tripwire for the fix; the
    behavioural teeth are in tests/phase_2_5/test_recon_runner.py (result.status == FAILED on
    a walled sweep) and tests/phase_3/test_advance_wiring.py.

    Pure text-scan by design (this module runs import-free on any Python — see header).
    The POSITIVE assertion is the ratchet: reverting the emit to a hardcoded COMPLETE deletes
    ``status=run_result.status`` → this fails. That is sufficient and format-robust; a
    substring-window negative check was dropped as brittle (Sourcery)."""
    main_src = _read("conductor/main.py")
    assert "status=run_result.status" in main_src, (
        "run_engagement_task must hand off status=run_result.status (the derived honest "
        "terminal status), not a literal — else recon false-success reaches the spine (#3)."
    )


def test_recon_technique_attempt_is_called_at_dispatch():
    """§12.64 Step 0: the attempt emit (extracted to recon.recon_coverage so the Alpha
    god-object stays size-frozen, GAP-161) must be CALLED at the dispatch site(s), not just
    imported — else a covered recon technique dispatched without it stays permanent `not_run`
    (Lyndon #2). Counts the import + the two dispatch call sites (ORIENT/ACT + follow-up)."""
    scout_src = _read("agents/alpha/scout.py")
    assert scout_src.count("emit_recon_technique_attempt") >= 3, (
        "emit_recon_technique_attempt must be imported AND invoked at every dispatch site "
        "(>=2 calls) — a covered technique dispatched without it stays not_run (§12.64 / #2)."
    )


def test_fingerprint_first_seed_is_wired_into_run_recon():
    """GAP-169 §12.65 (RUNNER-SEAL != AUTONOMOUS-WIRED): the fingerprint-first seed must be
    CALLED from Alpha.run_recon — not merely defined in recon/fingerprint. If it is present but
    unwired, run_recon keeps the blind `select_leak_paths(labels=[])` pre-fetch spray and 169 is
    an ISLAND (Lyndon #2). Reverting the reorder (dropping the call) deletes this token → fails."""
    scout_src = _read("agents/alpha/scout.py")
    assert "seed_fingerprint_first(self" in scout_src, (
        "run_recon must call seed_fingerprint_first — else the fingerprint-first reorder is "
        "unwired and the blind pre-fetch DEFAULT spray remains (GAP-169 / #2)."
    )
    # The old blind pre-fetch seed must be GONE (its removal is the reorder).
    assert "select_leak_paths(labels=[]" not in scout_src, (
        "the blind pre-fetch seed `select_leak_paths(labels=[])` must be replaced by the "
        "fingerprint-first seed, not left alongside it (double-seed)."
    )


def test_recon_coverage_gate_is_wired_into_outcome_path():
    """187b-2 (RUNNER-SEAL != AUTONOMOUS-WIRED): recon_not_run_gaps + project_coverage must be
    CALLED in run_engagement_task's outcome path — not merely defined in coverage_ledger and
    exercised only by Omega reporting. If the gate is present but unwired, a task-COMPLETE run
    with an unrun recon technique reports 'done' instead of 'partial' — the exact false-success
    (#3) 187b exists to catch. The behavioural teeth are in tests/phase_0/test_run_engagement_task.py
    (COMPLETE + host gap → run_status 'partial'); this is the import-free CI tripwire.

    The call must live on the COMPLETE branch: reverting it (dropping recon_not_run_gaps from
    main.py) deletes this token → this fails."""
    main_src = _read("conductor/main.py")
    assert "recon_not_run_gaps(project_coverage(" in main_src, (
        "run_engagement_task must project coverage and gate on recon_not_run_gaps in the "
        "COMPLETE outcome branch — else a coverage-incomplete recon falsely reports 'done' (#3)."
    )



def test_authenticated_crawl_consumes_won_session_in_strike():
    """GAP-116-B (retires 116-A dead-state): the won session `_won_session_cookies` (added by
    116-A) has NO consumer until the authenticated crawl reads it. Assert Beta.run_strike CALLS
    run_authenticated_crawl AND passes the won session — else 116-A is Lyndon #2 (reserved-but-
    unused state). Dropping the call deletes these tokens → this gate fails."""
    strike_src = _read("agents/beta/strike.py")
    assert "run_authenticated_crawl(" in strike_src, (
        "run_strike must CALL run_authenticated_crawl — else the 116-A won session is dead state (#2)."
    )
    assert "session_cookies=self._won_session_cookies" in strike_src, (
        "the authenticated crawl must be fed self._won_session_cookies — the 116-A carrier's consumer."
    )


def test_p1_strike_threads_cred_and_attestor_reads_authsurface():
    """T-P1c-wiring (§12.43 independent oracle wiring gate): assert the P1 chain is connected:
    1. strike.py threads enabling_cred_id into run_authenticated_crawl.
    2. authenticated_crawl.py emits "auth_vs_unauth_diff" proof on SERVICE nodes.
    3. attestor.py reads ":authsurface:" SERVICE nodes for the independent oracle.
    Dropping any of these tokens breaks the chain → this gate fails."""
    strike_src = _read("agents/beta/strike.py")
    assert "enabling_cred_id=" in strike_src, (
        "strike.py must thread enabling_cred_id into run_authenticated_crawl — "
        "else the crawl cannot bind the diff to the enabling credential (P1 broken)."
    )

    crawl_src = _read("agents/beta/authenticated_crawl.py")
    assert '"auth_vs_unauth_diff"' in crawl_src, (
        "authenticated_crawl.py must emit an auth_vs_unauth_diff proof artifact — "
        "else the §12.43 independent oracle signal is never produced (P1 broken)."
    )

    attestor_src = _read("attestation/attestor.py")
    assert '":authsurface:"' in attestor_src, (
        "attestor.py must check :authsurface: SERVICE nodes for the independent diff — "
        "else the oracle reads nothing and CONFIRMED is unreachable (P1 broken)."
    )


# ── Dispatch-catalog wiring gate (GAP-161 / §12.47) ───────────────────────
# Precondition: every catalog tool MUST be dispatchable, and generic catalog
# derivation must not silently override SPECIAL handlers on collision.


def _alpha_with_stub() -> Any:
    """Minimal Alpha instance for dispatch-introspection tests."""
    from agent_alpha.agents.alpha.scout import Alpha
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.security.secrets import SecretsManager
    from agent_alpha.tools.playbook import PlaybookEngine

    class _StubProvider:
        model = "stub"

        @staticmethod
        def complete(*a: object, **k: object) -> object:
            return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()

    _playbook_dir = pathlib.Path("agent_alpha/tools/playbooks")
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="dispatch_test", target="test.example")
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=["test.example"], exclusions=[]))
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_playbook_dir), provider=_StubProvider()
    )

    class _FakeHttp:
        @staticmethod
        def get(url: str) -> object:
            return type("R", (), {"status_code": 404, "text": "", "headers": {}})()

    return Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orch,
        http_client=_FakeHttp(),
        secrets_manager=SecretsManager(),
    )


def test_every_catalog_tool_is_dispatchable() -> None:
    """Every tool in CAPABILITY_CATALOG + PATH_PROBE_CATALOG must appear in the
    Alpha dispatch registry. This makes half-wiring (e.g. adding a catalog spec
    without dispatch) un-mergeable."""
    from agent_alpha.recon.capability_probe import CAPABILITY_CATALOG
    from agent_alpha.recon.path_probe import PATH_PROBE_CATALOG

    alpha = _alpha_with_stub()
    registry = alpha._dispatch_registry

    missing: list[str] = []
    for spec in (*CAPABILITY_CATALOG, *PATH_PROBE_CATALOG):
        if spec.tool not in registry:
            missing.append(spec.tool)
    assert not missing, (
        f"Catalog tools missing from dispatch registry: {missing} — "
        "add the tool to CAPABILITY_CATALOG or PATH_PROBE_CATALOG and "
        "the dispatch now auto-wires (GAP-161 / §12.47)."
    )


def test_dispatch_map_unchanged_by_catalog_derivation() -> None:
    """CARDINAL: generic catalog derivation must not alter the 20 original
    tool→handler-name routing. New catalog tools are allowed to auto-appear.
    The 5 collision tools (in BOTH CAPABILITY_CATALOG and _special) MUST resolve
    to their SPECIAL handler, not the generic _handle_capability_fingerprint."""
    from agent_alpha.recon.capability_probe import CAPABILITY_CATALOG
    from agent_alpha.recon.path_probe import PATH_PROBE_CATALOG

    expected = {
        # GENERIC — derived from CAPABILITY_CATALOG
        "tomcat_fingerprint": "_handle_capability_fingerprint",
        "http_basic_auth_fingerprint": "_handle_capability_fingerprint",
        "s3_bucket_fingerprint": "_handle_capability_fingerprint",
        "graphql_fingerprint": "_handle_capability_fingerprint",
        "wp_fingerprint": "_handle_capability_fingerprint",
        # GENERIC — derived from PATH_PROBE_CATALOG
        "git_exposure_probe": "_handle_path_probe",
        "backup_file_probe": "_handle_path_probe",
        "actuator_probe": "_handle_path_probe",
        # SPECIAL — hand-listed, override generic on collision
        "laravel_debug_probe": "_handle_laravel_debug",
        "wp_config_probe": "_handle_wp_config_probe",
        "js_secret_probe": "_handle_js_secret_probe",
        "odoo_dbmanager_probe": "_handle_odoo_dbmanager",
        "auth_surface_probe": "_handle_auth_surface",
        "surface_discovery_probe": "_handle_surface_discovery",
        "odoo_fingerprint": "_handle_odoo_fingerprint",
        "wp_rest_routes": "_handle_wp_rest_routes",
        "wp_rest_users": "_handle_wp_rest_users",
        "woocommerce": "_handle_woocommerce",
        "wp_version": "_handle_wp_version",
        "wp_plugins": "_handle_wp_plugins",
    }

    alpha = _alpha_with_stub()
    actual = {tool: h.__name__ for tool, h in alpha._dispatch_registry.items()}

    # CARDINAL: every entry in the 20-entry baseline must keep its expected
    # handler. We do NOT require actual == expected because new catalog tools
    # auto-wire into the dispatch without needing this snapshot updated; that
    # coverage is enforced by test_every_catalog_tool_is_dispatchable.
    wrong: list[str] = []
    for tool, expected_handler in expected.items():
        if actual.get(tool) != expected_handler:
            wrong.append(
                f"{tool}: expected {expected_handler}, got {actual.get(tool)!r}"
            )
    assert not wrong, (
        "Dispatch map regression for 20 baseline tools:\n" + "\n".join(wrong)
    )

    # Collision guards: these tools are in CAPABILITY_CATALOG but have special
    # handlers. SPECIAL must WIN — _special is merged after _generic.
    collision_specials = {
        "odoo_fingerprint": "_handle_odoo_fingerprint",
        "wp_rest_routes": "_handle_wp_rest_routes",
        "wp_rest_users": "_handle_wp_rest_users",
        "woocommerce": "_handle_woocommerce",
        "wp_version": "_handle_wp_version",
    }
    for tool, expected_handler in collision_specials.items():
        actual_handler = alpha._dispatch_registry[tool].__name__
        assert actual_handler == expected_handler, (
            f"Collision tool '{tool}' resolved to {actual_handler} (generic) "
            f"instead of {expected_handler} (special)."
        )


def test_no_collision_between_capability_and_path_catalogs() -> None:
    """A tool name must not appear in both CAPABILITY_CATALOG and PATH_PROBE_CATALOG.

    If it did, the `_generic` merge in scout.py would silently overwrite the
    capability handler with the path-probe handler (or vice versa), producing
    a misrouted dispatch entry.
    """
    from agent_alpha.recon.capability_probe import CAPABILITY_CATALOG
    from agent_alpha.recon.path_probe import PATH_PROBE_CATALOG

    cap_tools = {spec.tool for spec in CAPABILITY_CATALOG}
    path_tools = {spec.tool for spec in PATH_PROBE_CATALOG}
    dupes = cap_tools & path_tools
    assert not dupes, (
        f"Tool(s) appear in both CAPABILITY_CATALOG and PATH_PROBE_CATALOG: {dupes}. "
        "This would cause silent dispatch overwrite in Alpha._dispatch_registry."
    )

