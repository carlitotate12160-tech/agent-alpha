from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.router import has_web_auth_surface, route_next
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    NodeType,
    merge_tech_stack,
)
from agent_alpha.graph.persist import persist_node
from agent_alpha.tools.contracts import TargetContext
from agent_alpha.tools.internal.access.default_creds import (
    _DEFAULT_CREDENTIALS,
    _build_credential_list,
)


def _graph_with_vaulted_cred_and_wp_asset() -> NetworkXGraphStore:
    graph = NetworkXGraphStore()
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "cred:wp-1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": "secret_wp_1",
                "service": "http",
                "access_level": "admin",
            },
            "confidence": 0.95,
        },
    )
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "asset:wp.lab.invalid",
            "type": "asset",
            "properties": {"host": "wp.lab.invalid", "tech_stack": [constants.STACK_WP]},
            "confidence": 0.9,
        },
    )
    return graph


def test_stack_wp_routes_alpha_to_beta() -> None:
    graph = _graph_with_vaulted_cred_and_wp_asset()

    assert has_web_auth_surface(graph) is True
    assert (
        route_next(
            graph,
            from_agent=a2a_pb2.ALPHA,
            status=a2a_pb2.COMPLETE,
            gamma_authorized=False,
        )
        == a2a_pb2.BETA
    )


def test_stack_wp_selects_wordpress_default_cred_set(monkeypatch: Any) -> None:
    ctx = TargetContext(
        engagement_id="eng-1",
        tenant_id=None,
        target="https://wp.lab.invalid/wp-login.php",
        tech_stack={"cms": constants.STACK_WP},
    )

    assert constants.STACK_WP in _DEFAULT_CREDENTIALS
    monkeypatch.setitem(
        _DEFAULT_CREDENTIALS,
        constants.STACK_WP,
        [("__wp_only_user__", "__wp_only_pass__")],
    )

    creds = _build_credential_list(ctx.tech_stack)

    assert ("__wp_only_user__", "__wp_only_pass__") in creds


def test_merge_tech_stack_preserves_existing_wp_label_on_later_web_write() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    engagement_id = "eng-merge"
    asset_id = "asset:wp.lab.invalid"

    persist_node(
        store,
        graph,
        engagement_id,
        AttackNode(
            id=asset_id,
            type=NodeType.ASSET,
            properties=AssetProperties(host="wp.lab.invalid", tech_stack=[constants.STACK_WP]),
            confidence=0.9,
        ),
        agent="alpha",
    )

    existing = graph.get_node(asset_id)
    assert existing is not None
    merged = merge_tech_stack(existing.properties.tech_stack, ["web"])

    persist_node(
        store,
        graph,
        engagement_id,
        AttackNode(
            id=asset_id,
            type=NodeType.ASSET,
            properties=AssetProperties(host="wp.lab.invalid", tech_stack=merged),
            confidence=0.9,
        ),
        agent="alpha",
    )

    updated = graph.get_node(asset_id)
    assert updated is not None
    assert updated.properties.tech_stack == [constants.STACK_WP, "web"]


def test_wordpress_literal_removed_from_wp_label_sites() -> None:
    root = Path(__file__).resolve().parents[2]
    label_sites = [
        root / "agent_alpha" / "recon" / "wp_config_probe.py",
        root / "agent_alpha" / "recon" / "path_probe.py",
        root / "agent_alpha" / "conductor" / "router.py",
        root / "agent_alpha" / "conductor" / "applicator_factory.py",
        root / "agent_alpha" / "agents" / "planner.py",
        root / "agent_alpha" / "tools" / "internal" / "access" / "default_creds.py",
    ]

    for path in label_sites:
        text = path.read_text(encoding="utf-8")
        assert '"wordpress"' not in text
        assert "'wordpress'" not in text
