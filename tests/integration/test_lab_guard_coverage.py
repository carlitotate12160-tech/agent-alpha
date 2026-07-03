"""Integration tests: every live-fire harness must call assert_lab_only_target.

These tests verify that the lab-only guard coverage hole is closed — all 5
self-authorizing harnesses (+ spa_secret_field_prove, the existing exemplar)
call ``assert_lab_only_target`` in their ``main()`` before constructing any
network-touching object (HttpClient, socket probe, DB connector).

Tests are SOURCE-LEVEL (AST inspection), not runtime: they don't need a lab
server or valid engagement YAML. They pin the structural invariant.
"""

from __future__ import annotations

import ast
import inspect
import textwrap

import pytest

from agent_alpha.live_fire import (
    beta_runner,
    chain_runner,
    db_chain_runner,
    runner,
    spa_secret_field_prove,
    wp_chain_runner,
)

# Every module whose main() self-authorizes and reaches a network target.
_GUARDED_MODULES = [
    beta_runner,
    chain_runner,
    db_chain_runner,
    runner,
    spa_secret_field_prove,
    wp_chain_runner,
]


def _get_main_source(module: object) -> str:
    """Return dedented source of the module's ``main`` function."""
    fn = getattr(module, "main")
    return textwrap.dedent(inspect.getsource(fn))


def _get_main_ast(module: object) -> ast.FunctionDef:
    """Parse the ``main`` function into an AST node."""
    tree = ast.parse(_get_main_source(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            return node
    raise AssertionError(f"no main() found in {module}")


def _find_call_names(node: ast.FunctionDef) -> list[tuple[int, str]]:
    """Return (lineno, dotted-name) for every Call node in the function body."""
    results: list[tuple[int, str]] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        name = ""
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name:
            results.append((getattr(child, "lineno", 0), name))
    return results


# ── Test 1: every harness calls assert_lab_only_target in main() ──────


@pytest.mark.parametrize(
    "module",
    _GUARDED_MODULES,
    ids=[m.__name__.rsplit(".", 1)[-1] for m in _GUARDED_MODULES],
)
def test_main_calls_assert_lab_only_target(module: object) -> None:
    """main() must contain at least one call to assert_lab_only_target."""
    fn_node = _get_main_ast(module)
    call_names = [name for _, name in _find_call_names(fn_node)]
    assert "assert_lab_only_target" in call_names, (
        f"{module.__name__}.main() does not call assert_lab_only_target — "
        f"the lab-only guard coverage hole is open."
    )


# ── Test 2: the import is present in each module ─────────────────────


@pytest.mark.parametrize(
    "module",
    _GUARDED_MODULES,
    ids=[m.__name__.rsplit(".", 1)[-1] for m in _GUARDED_MODULES],
)
def test_module_imports_assert_lab_only_target(module: object) -> None:
    """The module must import assert_lab_only_target (at top-level or in main)."""
    source = inspect.getsource(module)
    assert "assert_lab_only_target" in source, (
        f"{module.__name__} does not reference assert_lab_only_target at all."
    )


# ── Test 3: guard call appears BEFORE network infrastructure ─────────

_NETWORK_CONSTRUCTORS = frozenset(
    {
        "HttpClient",
        "InMemoryEventStore",
        "AuthorizationStateMachine",
        "SecretsManager",
        "SocketDbHandshakeProbe",
    }
)


@pytest.mark.parametrize(
    "module",
    _GUARDED_MODULES,
    ids=[m.__name__.rsplit(".", 1)[-1] for m in _GUARDED_MODULES],
)
def test_guard_before_network_construction(module: object) -> None:
    """assert_lab_only_target must be called BEFORE any network constructor."""
    fn_node = _get_main_ast(module)
    calls = _find_call_names(fn_node)

    guard_line = None
    first_network_line = None

    for lineno, name in calls:
        if name == "assert_lab_only_target" and guard_line is None:
            guard_line = lineno
        if name in _NETWORK_CONSTRUCTORS and first_network_line is None:
            first_network_line = lineno

    assert guard_line is not None, (
        f"{module.__name__}.main() never calls assert_lab_only_target."
    )
    if first_network_line is not None:
        assert guard_line < first_network_line, (
            f"{module.__name__}.main() calls assert_lab_only_target (line {guard_line}) "
            f"AFTER a network constructor (line {first_network_line}). "
            f"The guard must run BEFORE any network activity."
        )
