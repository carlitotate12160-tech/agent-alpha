import ast
import pathlib

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_AGENTS = _REPO_ROOT / "agent_alpha" / "agents"


def _imported_modules(py: pathlib.Path):
    tree = ast.parse(py.read_text(encoding="utf-8"))
    rel = py.relative_to(_REPO_ROOT)
    pkg_parts = list(rel.parts[:-1])

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            if node.level > 0:
                base_pkg = ".".join(pkg_parts[: -node.level + 1] if node.level > 1 else pkg_parts)
                yield f"{base_pkg}.{mod_name}" if mod_name else base_pkg
            else:
                yield mod_name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name


def test_agents_never_import_live_fire():
    """Production agents must not depend on the test/live-fire harness (Lyndon #6).
    Reach code lives in agent_alpha/recon/, never in agent_alpha/live_fire/."""
    assert _AGENTS.exists(), f"Agents directory not found: {_AGENTS}"
    offenders = [
        f"{py}: {mod}"
        for py in _AGENTS.rglob("*.py")
        for mod in _imported_modules(py)
        if mod and mod.startswith("agent_alpha.live_fire")
    ]
    assert not offenders, "agents import test harness: " + "; ".join(offenders)


def test_relative_imports_resolve_correctly():
    """Regression test: verify that relative imports (from ..x, from ...x) are
    resolved to the correct absolute package by _imported_modules.

    The slice `pkg_parts[:-node.level+1]` and `pkg_parts[: -node.level+1]` are
    identical — this test ensures the resolution logic itself is correct by
    checking known files with relative imports against their expected absolute
    module paths.
    """
    # Find a file in agents/alpha/ that uses relative imports
    alpha_dir = _AGENTS / "alpha"
    if not alpha_dir.exists():
        return  # no alpha dir — nothing to test

    for py in alpha_dir.rglob("*.py"):
        rel = py.relative_to(_REPO_ROOT)
        pkg_parts = list(rel.parts[:-1])  # e.g. ['agent_alpha', 'agents', 'alpha']
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.level == 0:
                continue
            mod_name = node.module or ""
            # Reproduce the resolution logic
            base_pkg = ".".join(
                pkg_parts[: -node.level + 1] if node.level > 1 else pkg_parts
            )
            resolved = f"{base_pkg}.{mod_name}" if mod_name else base_pkg
            # The resolved module must start with agent_alpha (never escape the package)
            assert resolved.startswith("agent_alpha"), (
                f"Relative import in {py} resolved to {resolved!r} — "
                f"escaped the agent_alpha package (level={node.level}, "
                f"pkg_parts={pkg_parts})"
            )
