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
                base_pkg = ".".join(pkg_parts[:-node.level + 1] if node.level > 1 else pkg_parts)
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
