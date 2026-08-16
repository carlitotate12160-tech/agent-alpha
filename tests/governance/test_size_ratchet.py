# ADR §12.47 / GAP-161 — GOD-OBJECT SIZE RATCHET (anti-Lyndon #8).
#
# scout.py (class Alpha) drifted to ~2458 lines — ~61% of the Lyndon-#8 disaster
# (autonomous_loop.py, 4000 lines). §12.47 DECIDED the remedy: new stack-specific recon
# capability → a `Tool` in ToolRegistry (phase="recon"), NOT new methods on Alpha. This
# gate MACHINE-ENFORCES that decision: the ceiling only ever RATCHETS DOWN. A PR that
# raises the number is doing the wrong thing — extract into a Tool/module (GAP-161 slice-2)
# instead of bumping it. When a slice legitimately SHRINKS a file, LOWER its ceiling here to
# lock the gain in.
#
# Pure text scan (no agent_alpha import) → runs on any Python, incl. the pre-3.11 lint box.
from __future__ import annotations

import pathlib

import pytest

_PKG = pathlib.Path(__file__).resolve().parents[2] / "agent_alpha"

# module (relative to agent_alpha/) -> max allowed line count. RATCHET DOWN ONLY.
# scout.py ceiling absorbs in-flight Bug #37 (~+8 lines to enqueue_discovered_url); it is
# NOT headroom for new features. New recon capability goes to ToolRegistry (§12.47).
SIZE_CEILINGS: dict[str, int] = {
    "agents/alpha/scout.py": 2475,  # GAP-161: freeze the Alpha god-object (#8)
}


@pytest.mark.parametrize("rel_path,ceiling", list(SIZE_CEILINGS.items()))
def test_module_stays_under_size_ceiling(rel_path: str, ceiling: int) -> None:
    path = _PKG / rel_path
    assert path.exists(), f"SIZE RATCHET: tracked module {rel_path} not found at {path}"
    lines = len(path.read_text(encoding="utf-8").splitlines())
    assert lines <= ceiling, (
        f"SIZE RATCHET (§12.47 / GAP-161, anti-#8): {rel_path} is {lines} lines, over the "
        f"{ceiling} ceiling. Do NOT raise the ceiling — extract capability into a ToolRegistry "
        f"Tool (phase='recon') or its own module (GAP-161 slice-2). The ratchet only goes DOWN."
    )
