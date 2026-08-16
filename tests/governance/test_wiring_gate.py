# ADR §12.35 — WIRING GATE. A component is NOT "done" until it is wired into the
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
        "agents/alpha/scout.py",
    ),  # Bug #26 Layer 5: WAF posture suppresses blind path spray in run_recon (consumer wired)
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
        f"WIRING GATE (ADR §12.35): '{symbol}' must be referenced in a production "
        f"wiring target {targets}; it regressed to dead code (anti-Lyndon #2)."
    )


@pytest.mark.parametrize("symbol,spec", list(WIRING_DEBT.items()))
def test_wiring_debt_is_tracked_until_resolved(
    symbol: str, spec: tuple[tuple[str, ...], str]
) -> None:
    targets, ref = spec
    assert symbol not in _read(*targets), (
        f"WIRING GATE (ADR §12.35): '{symbol}' is now wired into {targets} ({ref}). "
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
