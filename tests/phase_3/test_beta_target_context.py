"""Contract: Beta projects the live AttackGraph into the TargetContext it ranks on.

Regression guard for the tested-not-wired gap (#2): Beta.step used to hand ToolRegistry
an EMPTY context, so fingerprint routing (applies_to) never fired in the live path — a
tech-specific tool like odoo_access scored its off-target floor and lost to default_creds.
This pins that the projection reads Alpha's recon (ASSET tech_stack, credentials) so the
ranking is actually context-driven in the live agent, not just in hand-built unit ctx.
"""

from __future__ import annotations

from agent_alpha.agents.beta.strike import _project_target_context
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool
from agent_alpha.tools.internal.access.default_creds import DefaultCredsTool
from agent_alpha.tools.internal.access.odoo_access import OdooAccessTool
from agent_alpha.tools.registry import ToolRegistry


def _graph_with_asset(
    host: str, tech: list[str], ports: tuple[int, ...] = ()
) -> NetworkXGraphStore:
    g = NetworkXGraphStore()
    g.apply_event(
        "NodeDiscovered",
        {
            "id": f"asset:{host}",
            "type": "asset",
            "properties": {"host": host, "tech_stack": list(tech), "open_ports": list(ports)},
            "confidence": 0.9,
            "agent": "alpha",
            "timestamp_utc": "2026-07-06T00:00:00Z",
        },
    )
    return g


def test_projects_odoo_tech_from_asset_node() -> None:
    g = _graph_with_asset("vuln.odoo.lab", ["odoo"], (8069,))
    ctx = _project_target_context(
        g, engagement_id="e", tenant_id=None, target="https://vuln.odoo.lab/xmlrpc/2/common"
    )
    assert "odoo" in " ".join(ctx.tech_stack.values()).lower()
    assert 8069 in ctx.open_ports


def test_projected_ctx_ranks_odoo_access_first() -> None:
    """THE fix: with the live ctx now populated, fingerprint routing actually fires."""
    g = _graph_with_asset("vuln.odoo.lab", ["odoo"])
    ctx = _project_target_context(
        g, engagement_id="e", tenant_id=None, target="https://vuln.odoo.lab/xmlrpc/2/common"
    )
    tools = [CredReuseTool(graph_store=NetworkXGraphStore()), DefaultCredsTool(), OdooAccessTool()]
    ranked = ToolRegistry(tools).ranked(ctx)
    assert ranked[0].name == "odoo_access"


def test_empty_graph_yields_empty_context() -> None:
    ctx = _project_target_context(
        NetworkXGraphStore(), engagement_id="e", tenant_id=None, target="https://x.lab/"
    )
    assert ctx.tech_stack == {}
    assert ctx.open_ports == ()
    assert ctx.prior_findings == ()


def test_credential_node_downranks_default_creds() -> None:
    g = _graph_with_asset("x.lab", [])
    g.apply_event(
        "NodeDiscovered",
        {
            "id": "cred:1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": "vault:1",
                "service": "odoo",
                "access_level": "user",
            },
            "confidence": 0.8,
            "agent": "alpha",
            "timestamp_utc": "2026-07-06T00:00:00Z",
        },
    )
    ctx = _project_target_context(g, engagement_id="e", tenant_id=None, target="https://x.lab/")
    assert any("credential" in f.lower() for f in ctx.prior_findings)
    assert DefaultCredsTool().applies_to(ctx) <= 0.15


def test_asset_for_other_host_not_projected() -> None:
    g = _graph_with_asset("other.lab", ["odoo"])
    ctx = _project_target_context(
        g, engagement_id="e", tenant_id=None, target="https://vuln.odoo.lab/"
    )
    assert "odoo" not in " ".join(ctx.tech_stack.values()).lower()
