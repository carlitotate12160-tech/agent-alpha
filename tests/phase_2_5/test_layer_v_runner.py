"""Tests for Layer V runner (the seal)."""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, AttackNode, NodeType, node_to_dict
from agent_alpha.live_fire.layer_v_runner import (
    LayerVConfig,
    LayerVResult,
    load_layer_v_config,
    run_layer_v_live_fire,
)
from agent_alpha.live_fire.odoo_chain_runner import OdooChainResult
from agent_alpha.recon.passive_discovery import PassiveDiscoveryResult

_CONFIG_OK = """
client_id: test_client
root_domain: example.com
scope:
  ip_ranges: []
  domains:
    - example.com
    - odoo.example.com
  exclusions: []
"""

_CONFIG_BAD = """
client_id: test_client
root_domain: example.com
recon_url: https://odoo.example.com/
scope:
  ip_ranges: []
  domains:
    - example.com
    - odoo.example.com
  exclusions: []
"""


def test_layer_v_config_loads_root_only(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "ok.yaml"
    p.write_text(_CONFIG_OK)
    config = load_layer_v_config(p)
    assert config.root_domain == "example.com"
    assert "recon_url" not in config.__dict__
    assert "entry_point" not in config.__dict__


def test_layer_v_config_rejects_hand_fed(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(_CONFIG_BAD)
    with pytest.raises(ValueError, match="LayerVConfig forbids hand-fed recon_url or entry_point"):
        load_layer_v_config(p)


def test_run_layer_v_derives_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    graph_store = NetworkXGraphStore()

    # 1. Fake the ASSET node that Alpha would persist
    odoo_host = "odoo.example.com"
    asset_node = AttackNode(
        id=f"asset:{odoo_host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=odoo_host, tech_stack=["odoo"]),
        confidence=0.9,
    )

    # 2. Mock PassiveDiscovery and run_cognitive_loop
    import agent_alpha.live_fire.layer_v_runner as runner_module

    class FakePassiveDiscovery:
        def __init__(self, *args, **kwargs):
            pass

        def discover(self, eng_id, domain):
            # Inject fake events into stores here, now that we know eng_id
            graph_store.apply_event("NodeDiscovered", node_to_dict(asset_node))
            event_store.append(EventType.NODE_DISCOVERED, eng_id, "alpha", node_to_dict(asset_node))
            return PassiveDiscoveryResult(domain, (), (), ())

    monkeypatch.setattr(runner_module, "PassiveDiscovery", FakePassiveDiscovery)
    monkeypatch.setattr(runner_module, "run_cognitive_loop", lambda a, p: None)

    # 3. Mock run_odoo_chain_live_fire to capture derived_url
    captured_config = []

    def fake_odoo_chain(config, **kwargs):
        captured_config.append(config)
        return OdooChainResult(
            leak_creds_added=1,
            web_access_level="admin",
            edge_from_harvested_cred=True,
            db_enumerated=True,
            leak_suspected=False,
        )

    monkeypatch.setattr(runner_module, "run_odoo_chain_live_fire", fake_odoo_chain)

    config = LayerVConfig(
        client_id="test",
        scope_ip_ranges=[],
        scope_domains=["example.com", "odoo.example.com"],
        scope_exclusions=[],
        root_domain="example.com",
    )

    run_layer_v_live_fire(
        config,
        auth=auth,
        http_client=None,
        orchestrator=None,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=None,
    )

    assert len(captured_config) == 1
    passed_config = captured_config[0]

    expected_url = f"https://{odoo_host}/"
    assert passed_config.recon_url == expected_url
    assert passed_config.entry_point == expected_url
    # Verify it is not present in input config
    assert not hasattr(config, "recon_url")
    assert not hasattr(config, "entry_point")


def test_host_discovery_sourced_false_when_no_event(monkeypatch: pytest.MonkeyPatch) -> None:
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    graph_store = NetworkXGraphStore()

    odoo_host = "handfed.example.com"
    asset_node = AttackNode(
        id=f"asset:{odoo_host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=odoo_host, tech_stack=["odoo"]),
        confidence=0.9,
    )

    import agent_alpha.live_fire.layer_v_runner as runner_module

    class FakePassiveDiscovery:
        def __init__(self, *args, **kwargs):
            pass

        def discover(self, eng_id, domain):
            # We add to graph store so the runner proceeds, but NOT event_store (simulating hand-fed magic)
            graph_store.apply_event("NodeDiscovered", node_to_dict(asset_node))
            return PassiveDiscoveryResult(domain, (), (), ())

    monkeypatch.setattr(runner_module, "PassiveDiscovery", FakePassiveDiscovery)
    monkeypatch.setattr(runner_module, "run_cognitive_loop", lambda a, p: None)

    def fake_odoo_chain(config, **kwargs):
        return OdooChainResult(
            leak_creds_added=1,
            web_access_level="admin",
            edge_from_harvested_cred=True,
            db_enumerated=True,
            leak_suspected=False,
        )

    monkeypatch.setattr(runner_module, "run_odoo_chain_live_fire", fake_odoo_chain)

    config = LayerVConfig(
        client_id="test",
        scope_ip_ranges=[],
        scope_domains=["example.com", "handfed.example.com"],
        scope_exclusions=[],
        root_domain="example.com",
    )

    result = run_layer_v_live_fire(
        config,
        auth=auth,
        http_client=None,
        orchestrator=None,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=None,
    )

    assert result.host_discovery_sourced is False
    assert result.chain_proven is False  # Fails the #3 guard


def test_layer_v_verdict_true_when_both_true() -> None:
    # Just test the dataclass property logic
    res = LayerVResult(
        leak_creds_added=1,
        web_access_level="admin",
        edge_from_harvested_cred=True,
        db_enumerated=True,
        leak_suspected=False,
        host_discovery_sourced=True,
    )
    assert res.chain_proven is True
