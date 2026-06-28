"""Contract: cred_reuse — reuse Alpha-harvested credentials (the chain).

Locks the NON-offensive surface (Claude's lane) before the body is written:
  * conforms to the canonical Tool protocol (no parallel type, #6)
  * phase=access + required_auth=ACTIVE_APPROVED
  * applies_to() is HIGH when the graph holds harvested credentials (ranked above
    blind default_creds), zero without a graph
The single RED frontier is run() — resolve vault secret + reuse it.
"""

from __future__ import annotations

import pytest

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AttackNode, CredentialProperties, NodeType, node_to_dict
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, Tool
from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool


def _ctx() -> TargetContext:
    return TargetContext(engagement_id="e", tenant_id=None, target="http://lab-target.invalid/login")


def _graph_with_credential() -> NetworkXGraphStore:
    gs = NetworkXGraphStore()
    node = AttackNode(
        id="cred:lab-target.invalid:db_password",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="dbuser",
            secret_ref="vault-secret-id-123",  # vault id (post Alpha-vaulting change)
            service="mysql",
            access_level="unverified",
        ),
        confidence=0.85,
        agent="alpha",
        timestamp_utc="2026-06-27T00:00:00Z",
    )
    gs.apply_event("NodeDiscovered", node_to_dict(node))
    return gs


def test_conforms_to_canonical_tool_protocol() -> None:
    assert isinstance(CredReuseTool(), Tool)


def test_declares_access_phase_and_active_tier() -> None:
    tool = CredReuseTool()
    assert tool.phase == "access"
    assert tool.required_auth == "ACTIVE_APPROVED"


def test_applies_high_when_graph_has_harvested_credentials() -> None:
    tool = CredReuseTool(graph_store=_graph_with_credential())
    # Ranked above blind default_creds (0.7) — the chain is higher-signal.
    assert tool.applies_to(_ctx()) >= 0.9


def test_applies_low_when_no_credentials_harvested() -> None:
    tool = CredReuseTool(graph_store=NetworkXGraphStore())
    assert tool.applies_to(_ctx()) < 0.5


def test_applies_zero_without_a_graph() -> None:
    assert CredReuseTool().applies_to(_ctx()) == 0.0


def test_run_requires_http_client() -> None:
    """run() is now implemented (GLM lane filled); without http_client it raises
    ValueError, not NotImplementedError. The offensive body is no longer a stub."""
    tool = CredReuseTool(graph_store=_graph_with_credential())
    budget = ResourceBudget(max_requests=20, max_seconds=30.0, max_cost_usd=0.0)
    with pytest.raises(ValueError, match="http_client"):
        tool.run(_ctx(), budget)
