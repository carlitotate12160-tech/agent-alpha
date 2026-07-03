"""RED gate: EVERY attacker field-prove harness must invoke the lab-only guard.

Flaw this closes (Lyndon #10 — tambah sulam tanpa arah):
    ``lab_guard.assert_lab_only_target`` was imported by ONLY ONE of the seven
    self-authorizing harnesses in ``agent_alpha/live_fire`` — namely
    ``spa_secret_field_prove`` (the one that got caught pointing at a real
    client). The other attacker harnesses (beta / chain / db_chain / runner /
    wp_chain) still build their own AuthorizationStateMachine from a hand-edited
    YAML and reach out to a network target with NO lab-only guard. That is the
    SAME Conductor-bypass hole, left open in six places — including the
    direct-database one. The guard was patched at the point of incident, not
    systemically.

Why a coverage gate and not another per-harness test:
    A per-harness test is exactly what let the hole reappear — add harness #8,
    forget the import, no test complains. This gate is fail-closed at the
    DISCOVERY level: every ``live_fire/*.py`` that defines a top-level ``main()``
    must be explicitly classified here as either an ATTACKER harness (chooses a
    target and hits it -> guard REQUIRED) or an EXEMPT server (only serves, never
    chooses a target -> guard N/A). A new, unclassified harness FAILS this test
    and forces a human to make the call — it cannot be silently skipped.

Interface decision this pins:
    ``assert_lab_only_target`` is THE single canonical lab-only guard (one class
    per concept — no wrapper, anti-#6). Every attacker harness calls it directly,
    before any network activity, for every in-scope target.

Honest residual (anti-oversell):
    This is a STRUCTURAL gate — it proves the guard is *called* in each attacker
    harness, not that it is called *before* the first network egress or for
    *every* target variable. Ordering-before-network is enforced by the guard
    living at the top of ``main()`` plus raw review; the guard's own fail-closed
    behaviour is pinned by tests/.../test_lab_guard.py (9 tests). Keep both.

Authoritative run: Oracle ARM64 (`.venv/bin/python3 -m pytest`). This file is
environment-independent (pure AST over source), but Oracle remains the only
accepted result per project rule #9.
"""

from __future__ import annotations

import ast
from pathlib import Path

import agent_alpha.live_fire as live_fire_pkg

GUARD_FUNCTION_NAME = "assert_lab_only_target"

# --- Canonical classification of every self-authorizing live_fire harness. ---
# A harness is ATTACKER if its main() takes a target (from YAML/argv) and sends
# traffic to it (HttpClient, socket, DB handshake). It is EXEMPT only if it never
# chooses a target — e.g. it stands up a mock server and serves. When you add a
# new harness, add its module stem to exactly ONE set below (fail-closed: an
# unclassified harness with a main() fails `test_every_harness_is_classified`).

ATTACKER_HARNESSES: frozenset[str] = frozenset(
    {
        "beta_runner",
        "chain_runner",
        "db_chain_runner",
        "runner",
        "wp_chain_runner",
        "spa_secret_field_prove",
    }
)

EXEMPT_SERVERS: frozenset[str] = frozenset(
    {
        # Stands up a mock vulnerable Laravel debug page via HTTPServer and
        # serve_forever(). It is the TARGET side, not an attacker — it never
        # chooses or reaches out to a target, so the lab-only guard does not
        # apply. (It should still only ever be run in a lab, but that is a
        # deployment concern, not a target-selection one.)
        "mock_laravel_debug",
    }
)


def _live_fire_dir() -> Path:
    return Path(live_fire_pkg.__file__).resolve().parent


def _module_has_top_level_main(tree: ast.Module) -> bool:
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main"
        for node in tree.body
    )


def _module_calls_guard(tree: ast.Module) -> bool:
    """True if the module body contains a call to ``assert_lab_only_target``.

    Matches both a bare call ``assert_lab_only_target(...)`` and an attribute
    call ``lab_guard.assert_lab_only_target(...)``.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == GUARD_FUNCTION_NAME:
            return True
        if isinstance(func, ast.Attribute) and func.attr == GUARD_FUNCTION_NAME:
            return True
    return False


def _harness_modules_with_main() -> dict[str, ast.Module]:
    """Map module-stem -> parsed AST for every live_fire/*.py defining main()."""
    found: dict[str, ast.Module] = {}
    for path in sorted(_live_fire_dir().glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _module_has_top_level_main(tree):
            found[path.stem] = tree
    return found


def test_every_harness_is_classified() -> None:
    """Fail-closed discovery: no harness with main() may be unclassified.

    This is the anti-#10 lock: a newly added attacker harness cannot slip in
    unguarded, because it will be neither ATTACKER nor EXEMPT and this test will
    fail until a human classifies it.
    """
    discovered = set(_harness_modules_with_main())
    classified = ATTACKER_HARNESSES | EXEMPT_SERVERS

    unclassified = discovered - classified
    assert not unclassified, (
        "Unclassified live_fire harness(es) with a main(): "
        f"{sorted(unclassified)}. Add each to ATTACKER_HARNESSES (if it chooses "
        "and hits a target -> must call assert_lab_only_target) or EXEMPT_SERVERS "
        "(if it only serves and never chooses a target)."
    )

    stale = classified - discovered
    assert not stale, (
        "Classified harness(es) no longer present / no longer define main(): "
        f"{sorted(stale)}. Remove them from the sets so the lists stay honest."
    )


def test_every_attacker_harness_calls_lab_guard() -> None:
    """Every ATTACKER harness must call assert_lab_only_target.

    RED until beta_runner / chain_runner / db_chain_runner / runner /
    wp_chain_runner each call the guard in main() before touching the network.
    """
    trees = _harness_modules_with_main()
    unguarded = sorted(
        name
        for name in ATTACKER_HARNESSES
        if name in trees and not _module_calls_guard(trees[name])
    )
    assert not unguarded, (
        "Attacker field-prove harness(es) that self-authorize from hand-YAML but "
        f"do NOT call {GUARD_FUNCTION_NAME}: {unguarded}. Each bypasses the "
        "Conductor SOW gate and can reach a network target — add the lab-only "
        "guard at the top of main(), for every in-scope target, before any "
        "network activity."
    )


def test_exempt_servers_do_not_falsely_claim_attacker_status() -> None:
    """Sanity: EXEMPT and ATTACKER sets are disjoint (a harness is one or none)."""
    overlap = ATTACKER_HARNESSES & EXEMPT_SERVERS
    assert not overlap, f"Harness classified as both attacker and exempt: {sorted(overlap)}"
