"""Contract: OdooAccessTool — validate Odoo credentials over XML-RPC (slice 1c).

Locks the NON-offensive surface (Claude's lane) before the body is written:
  * conforms to the canonical Tool protocol (no parallel type, #6)
  * phase=access + required_auth=ACTIVE_APPROVED (initial access, NOT offensive —
    the destructive master-password / DB-manager path is a separate OFFENSIVE slice)
  * applies_to() is HIGH on an Odoo target, LOW off-Odoo, near-zero once proven
  * run() requires an injected http_client (ValueError guard)

Slice-1c centrepiece — the DIFFERENTIAL that proves ToolRegistry.ranked orders by
CONTEXT (not a static sequence, K11): with three REAL tools registered, an Odoo
target ranks odoo_access first, while a non-Odoo auth surface ranks default_creds
ahead of it. This is the first time .ranked() is exercised by a genuine 3rd tool.

The single RED frontier is run()'s XML-RPC body (authenticate → uid) — DeepSeek's
K21 lane; its success/failure finding-shape tests land WITH that body (the
default_creds pattern), pinned by deepseek_prompt_odoo_access.md.
"""

from __future__ import annotations

import pytest

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, Tool
from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool
from agent_alpha.tools.internal.access.default_creds import DefaultCredsTool
from agent_alpha.tools.internal.access.odoo_access import OdooAccessTool
from agent_alpha.tools.registry import ToolRegistry


def _odoo_ctx(**overrides: object) -> TargetContext:
    defaults: dict[str, object] = {
        "engagement_id": "e",
        "tenant_id": None,
        "target": "https://odoo.lab-target.invalid",
        "tech_stack": {"framework": "Odoo 16.0"},
    }
    defaults.update(overrides)
    return TargetContext(**defaults)  # type: ignore[arg-type]


def _non_odoo_auth_ctx() -> TargetContext:
    return TargetContext(
        engagement_id="e",
        tenant_id=None,
        target="http://lab-target.invalid/wp-login.php",
        tech_stack={"cms": "WordPress 6.5"},
        open_ports=(22, 80),
    )


# ── A. Protocol conformance (no parallel type, #6) ───────────────


def test_conforms_to_canonical_tool_protocol() -> None:
    assert isinstance(OdooAccessTool(), Tool)


def test_declares_access_phase_and_active_tier() -> None:
    tool = OdooAccessTool()
    assert tool.phase == "access"
    # NOT OFFENSIVE_APPROVED — the destructive DB-manager/master-password path is a
    # separate slice; a uid over XML-RPC is non-destructive initial access.
    assert tool.required_auth == "ACTIVE_APPROVED"


# ── B. applies_to relevance scoring ──────────────────────────────


def test_applies_high_on_odoo_target() -> None:
    assert OdooAccessTool().applies_to(_odoo_ctx()) >= 0.8


def test_applies_low_off_odoo() -> None:
    assert OdooAccessTool().applies_to(_non_odoo_auth_ctx()) < 0.5


def test_applies_near_zero_when_access_already_proven() -> None:
    ctx = _odoo_ctx(prior_findings=("Odoo access via XML-RPC: uid=2 (admin)",))
    assert OdooAccessTool().applies_to(ctx) <= 0.15


# ── C. run() requires the injected transport ─────────────────────


def test_run_requires_http_client() -> None:
    budget = ResourceBudget(max_requests=20, max_seconds=30.0, max_cost_usd=0.0)
    with pytest.raises(ValueError, match="http_client"):
        OdooAccessTool().run(_odoo_ctx(), budget)


# ── D. ToolRegistry.ranked differential — the slice-1c centrepiece ─
#     Three REAL tools; ordering is a function of context, never static (K11).


def _three_tools() -> list[Tool]:
    return [
        CredReuseTool(graph_store=NetworkXGraphStore()),  # empty graph → low
        DefaultCredsTool(),
        OdooAccessTool(),
    ]


def test_ranked_puts_odoo_access_first_on_odoo_target() -> None:
    ranked = ToolRegistry(_three_tools()).ranked(_odoo_ctx())
    assert ranked[0].name == "odoo_access"


def test_ranked_prefers_default_creds_on_non_odoo_auth_surface() -> None:
    ranked = ToolRegistry(_three_tools()).ranked(_non_odoo_auth_ctx())
    names = [t.name for t in ranked]
    # Same three tools, different target → different order: this is the proof that
    # .ranked() is context-driven, not a fixed pipeline.
    assert names[0] == "default_creds"
    assert names.index("odoo_access") > names.index("default_creds")
