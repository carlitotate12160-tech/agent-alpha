"""RED test — Phase 4 slice 1, CORRECTED (supersedes #99).

#99 shipped a parallel ``ToolSpec`` catalog + a ``NODE_TYPE_EXPLOIT_PRIORITY``
node-type ladder (Lyndon #6 + #7 + K11) that nothing consumes. This pins the
ADR-faithful shape: ToolRegistry ranks the EXISTING ``contracts.Tool`` objects
by their OWN ``applies_to(ctx) -> float``, plan-not-execute. It is the
extraction of beta/strike.py's inline "seed of ToolRegistry" ranked selection
into one home — killing the #6 duplication and the K11 central ladder.

Reuses canonical contracts (Tool, TargetContext, ToolResult) — NO new state
type (anti-#6). Seal: Oracle ARM64 only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult
from agent_alpha.tools.registry import ToolRegistry


@dataclass(eq=False)
class _FakeTool:
    """Structurally conforms to contracts.Tool. ``run`` MUST NOT be called during
    ranking (plan-not-execute) — it raises to prove the registry never executes."""

    name: str
    _relevance: dict[str, float] = field(default_factory=dict)
    phase: str = "access"
    required_auth: str = "ACTIVE_APPROVED"
    mitre_technique: str = "T1078"

    def applies_to(self, ctx: TargetContext) -> float:
        return max((self._relevance.get(t, 0.0) for t in ctx.tech_stack.values()), default=0.0)

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        raise AssertionError("ranking must not execute a tool (plan-not-execute)")


def _ctx(**tech: str) -> TargetContext:
    return TargetContext(
        engagement_id="eng_test",
        tenant_id=None,
        target="app.client.example",
        tech_stack=dict(tech),
    )


def test_ranked_orders_by_applies_to_desc() -> None:
    high = _FakeTool("cred_reuse", {"wordpress": 0.9})
    low = _FakeTool("default_creds", {"wordpress": 0.2})
    registry = ToolRegistry([low, high])
    assert [t.name for t in registry.ranked(_ctx(cms="wordpress"))] == [
        "cred_reuse",
        "default_creds",
    ]


def test_ranked_first_tool_depends_on_context() -> None:
    web = _FakeTool("web_tool", {"php": 0.9})
    db = _FakeTool("db_tool", {"mysql": 0.9})
    registry = ToolRegistry([web, db])
    top_web = registry.ranked(_ctx(lang="php"))[0].name
    top_db = registry.ranked(_ctx(database="mysql"))[0].name
    assert top_web == "web_tool"
    assert top_db == "db_tool"
    assert top_web != top_db


def test_ranked_does_not_execute_tools() -> None:
    registry = ToolRegistry([_FakeTool("a", {"php": 0.5}), _FakeTool("b", {"php": 0.9})])
    registry.ranked(_ctx(lang="php"))


def test_empty_registry_ranks_to_empty() -> None:
    assert ToolRegistry([]).ranked(_ctx(lang="php")) == ()


def test_ranked_returns_the_same_tool_objects() -> None:
    a = _FakeTool("a", {"php": 0.9})
    b = _FakeTool("b", {"php": 0.1})
    ranked = ToolRegistry([a, b]).ranked(_ctx(lang="php"))
    assert ranked[0] is a
    assert set(ranked) == {a, b}


def test_ranked_is_deterministic() -> None:
    registry = ToolRegistry([_FakeTool("a", {"php": 0.9}), _FakeTool("b", {"php": 0.3})])
    ctx = _ctx(lang="php")
    assert [t.name for t in registry.ranked(ctx)] == [t.name for t in registry.ranked(ctx)]
