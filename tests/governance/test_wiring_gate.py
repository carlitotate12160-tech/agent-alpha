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
    "run_verification_pass": (
        ("conductor/main.py", "conductor/execute_agent.py"),
        "WIRING-DEBT (close in slice-1): CROSS_VERIFIED must be reachable on the autonomous Conductor path",
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
    """WIRING-DEBT (close in slice-1): CROSS_VERIFIED must be reachable on the
    autonomous Conductor path, not only the a1 runner. Fails until conductor/
    calls run_verification_pass post-Beta. Do NOT delete to make green — wire it."""
    conductor_src = "\n".join(
        p.read_text(encoding="utf-8") for p in pathlib.Path("agent_alpha/conductor").rglob("*.py")
    )
    assert "run_verification_pass" in conductor_src, (
        "run_verification_pass is not wired into the Conductor chain — autonomous "
        "findings cannot reach CROSS_VERIFIED (Lyndon #2, runner-seal != wired)."
    )
