import ast
import pathlib

_AGENTS = pathlib.Path("agent_alpha/agents")


def _imported_modules(py: pathlib.Path):
    tree = ast.parse(py.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            yield node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name


def test_agents_never_import_live_fire():
    """Production agents must not depend on the test/live-fire harness (Lyndon #6).
    Reach code lives in agent_alpha/recon/, never in agent_alpha/live_fire/."""
    offenders = [
        f"{py}: {mod}"
        for py in _AGENTS.rglob("*.py")
        for mod in _imported_modules(py)
        if mod.startswith("agent_alpha.live_fire")
    ]
    assert not offenders, "agents import test harness: " + "; ".join(offenders)
