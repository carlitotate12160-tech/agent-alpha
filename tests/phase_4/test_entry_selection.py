from __future__ import annotations

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor import main as conductor_main
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.models import Scope
from agent_alpha.conductor.router import select_strike_entry, StrikeEntrySelection
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, AttackNode, NodeType, node_to_dict
from agent_alpha.graph.persist import persist_node


_DEF_TARGET = "https://apex.example/"


def _asset_node(host: str, tech_stack: list[str]) -> AttackNode:
    return AttackNode(
        id=f"asset:{host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, tech_stack=tech_stack),
        confidence=0.9,
        agent="alpha",
    )


def _graph_with_assets(*assets: tuple[str, list[str]]) -> NetworkXGraphStore:
    graph = NetworkXGraphStore()
    for host, tech_stack in assets:
        graph.apply_event("NodeDiscovered", node_to_dict(_asset_node(host, tech_stack)))
    return graph


def test_selects_reachable_auth_surface_over_dead_apex() -> None:
    graph = _graph_with_assets(("apex.example", []), ("hub.example", ["http_basic_auth"]))

    result = select_strike_entry(graph, default_target=_DEF_TARGET)
    assert result.selected_entry == "https://hub.example/"
    assert result.matched_label == "http_basic_auth"
    assert result.fallback_to_default is False
    assert result.candidates_considered == ("hub.example",)


def test_fallback_to_default_when_no_auth_surface() -> None:
    graph = _graph_with_assets(("apex.example", []), ("api.example", ["openapi"]))

    result = select_strike_entry(graph, default_target=_DEF_TARGET)
    assert result.selected_entry == _DEF_TARGET
    assert result.matched_label is None
    assert result.fallback_to_default is True
    assert result.candidates_considered == ()


def test_deterministic_order_two_surfaces() -> None:
    graph = _graph_with_assets(
        ("z.example", ["http_basic_auth"]),
        ("a.example", ["http_basic_auth"]),
    )

    results = {select_strike_entry(graph, default_target=_DEF_TARGET).selected_entry for _ in range(20)}

    assert results == {"https://a.example/"}


def test_wiring_run_beta_dispatches_selected_host(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    auth.enable_recon(
        record.engagement_id,
        Scope(ip_ranges=[], domains=["apex.example", "hub.example"], exclusions=[]),
    )
    auth.enable_active(record.engagement_id)

    seed_graph = NetworkXGraphStore()
    persist_node(
        store,
        seed_graph,
        record.engagement_id,
        _asset_node("apex.example", []),
        agent="alpha",
    )
    persist_node(
        store,
        seed_graph,
        record.engagement_id,
        _asset_node("hub.example", ["http_basic_auth"]),
        agent="alpha",
    )

    captured: dict[str, object] = {}

    class _FakeBeta:
        def __init__(self, **kwargs: object) -> None:
            captured["cred_applicators"] = kwargs["cred_applicators"]

        def run_strike(self, engagement_id: str, entry_point: str) -> a2a_pb2.A2AMessage:
            captured["entry_point"] = entry_point
            payload = a2a_pb2.HandoffPayload(
                status=a2a_pb2.COMPLETE,
                next_recommended=a2a_pb2.OMEGA,
                confidence=1.0,
            )
            return a2a_pb2.A2AMessage(
                engagement_id=engagement_id,
                from_agent=a2a_pb2.BETA,
                to_agent=a2a_pb2.CONDUCTOR,
                message_type=a2a_pb2.HANDOFF_READY,
                payload=payload.SerializeToString(),
                confidence=1.0,
            )

    monkeypatch.setattr(conductor_main, "event_store", store)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(conductor_main, "HttpClient", lambda engagement_id: object())
    monkeypatch.setattr(conductor_main, "resolve_reasoning_provider", lambda api_key: object())
    monkeypatch.setattr(conductor_main.PlaybookEngine, "from_directory", lambda path: object())
    monkeypatch.setattr(conductor_main, "LLMOrchestrator", lambda playbook, provider: object())
    monkeypatch.setattr(conductor_main, "Beta", _FakeBeta)
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *args: None)
    monkeypatch.setattr(conductor_main, "get_profile_signing_key", lambda: "k" * 64)
    monkeypatch.setattr(conductor_main, "beta_web_applicators", lambda http: ["candidate"])
    monkeypatch.setattr(conductor_main.advance_engagement_task, "delay", lambda eid, tid: None)

    def _capture_applicators(**kwargs: object) -> list[object]:
        captured["web_target"] = kwargs["web_target"]
        return []

    monkeypatch.setattr(conductor_main, "build_applicators_for_engagement", _capture_applicators)

    result = conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)

    assert result == {"engagement_id": record.engagement_id, "status": "completed"}
    assert captured["web_target"] == "https://hub.example/"
    assert captured["entry_point"] == "https://hub.example/"
    assert captured["entry_point"] != record.target


def test_emits_strike_entry_selected_on_autonomous_path() -> None:
    """STRIKE_ENTRY_SELECTED event emitted BEFORE applicators + run_strike."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    auth.enable_recon(
        record.engagement_id,
        Scope(ip_ranges=[], domains=["apex.example", "hub.example"], exclusions=[]),
    )
    auth.enable_active(record.engagement_id)

    seed_graph = NetworkXGraphStore()
    persist_node(
        store,
        seed_graph,
        record.engagement_id,
        _asset_node("apex.example", []),
        agent="alpha",
    )
    persist_node(
        store,
        seed_graph,
        record.engagement_id,
        _asset_node("hub.example", ["http_basic_auth"]),
        agent="alpha",
    )

    class _FakeBeta:
        def __init__(self, **kwargs: object) -> None:
            pass

        def run_strike(self, engagement_id: str, entry_point: str) -> a2a_pb2.A2AMessage:
            payload = a2a_pb2.HandoffPayload(
                status=a2a_pb2.COMPLETE,
                next_recommended=a2a_pb2.OMEGA,
                confidence=1.0,
            )
            return a2a_pb2.A2AMessage(
                engagement_id=engagement_id,
                from_agent=a2a_pb2.BETA,
                to_agent=a2a_pb2.CONDUCTOR,
                message_type=a2a_pb2.HANDOFF_READY,
                payload=payload.SerializeToString(),
                confidence=1.0,
            )

    from agent_alpha import events
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(conductor_main, "event_store", store)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(conductor_main, "HttpClient", lambda engagement_id: object())
    monkeypatch.setattr(conductor_main, "resolve_reasoning_provider", lambda api_key: object())
    monkeypatch.setattr(conductor_main.PlaybookEngine, "from_directory", lambda path: object())
    monkeypatch.setattr(conductor_main, "LLMOrchestrator", lambda playbook, provider: object())
    monkeypatch.setattr(conductor_main, "Beta", _FakeBeta)
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *args: None)
    monkeypatch.setattr(conductor_main, "get_profile_signing_key", lambda: "k" * 64)
    monkeypatch.setattr(conductor_main, "beta_web_applicators", lambda http: ["candidate"])
    monkeypatch.setattr(conductor_main.advance_engagement_task, "delay", lambda eid, tid: None)
    monkeypatch.setattr(conductor_main, "build_applicators_for_engagement", lambda **kw: [])

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)
    monkeypatch.undo()

    # Verify STRIKE_ENTRY_SELECTED event exists
    events = store.get_events(record.engagement_id)
    strike_events = [e for e in events if e.event_type == "StrikeEntrySelected"]
    assert len(strike_events) == 1
    event = strike_events[0]
    assert event.payload["selected_entry"] == "https://hub.example/"
    assert event.payload["matched_label"] == "http_basic_auth"
    assert event.payload["fallback_to_default"] is False
    assert event.payload["candidates_considered"] == ("hub.example",)


def test_event_records_fallback() -> None:
    """When no auth-surface, event records fallback_to_default=True."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    auth.enable_recon(
        record.engagement_id,
        Scope(ip_ranges=[], domains=["apex.example"], exclusions=[]),
    )
    auth.enable_active(record.engagement_id)

    seed_graph = NetworkXGraphStore()
    persist_node(
        store,
        seed_graph,
        record.engagement_id,
        _asset_node("apex.example", []),
        agent="alpha",
    )

    class _FakeBeta:
        def __init__(self, **kwargs: object) -> None:
            pass

        def run_strike(self, engagement_id: str, entry_point: str) -> a2a_pb2.A2AMessage:
            payload = a2a_pb2.HandoffPayload(
                status=a2a_pb2.COMPLETE,
                next_recommended=a2a_pb2.OMEGA,
                confidence=1.0,
            )
            return a2a_pb2.A2AMessage(
                engagement_id=engagement_id,
                from_agent=a2a_pb2.BETA,
                to_agent=a2a_pb2.CONDUCTOR,
                message_type=a2a_pb2.HANDOFF_READY,
                payload=payload.SerializeToString(),
                confidence=1.0,
            )

    from agent_alpha import events
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(conductor_main, "event_store", store)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(conductor_main, "HttpClient", lambda engagement_id: object())
    monkeypatch.setattr(conductor_main, "resolve_reasoning_provider", lambda api_key: object())
    monkeypatch.setattr(conductor_main.PlaybookEngine, "from_directory", lambda path: object())
    monkeypatch.setattr(conductor_main, "LLMOrchestrator", lambda playbook, provider: object())
    monkeypatch.setattr(conductor_main, "Beta", _FakeBeta)
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *args: None)
    monkeypatch.setattr(conductor_main, "get_profile_signing_key", lambda: "k" * 64)
    monkeypatch.setattr(conductor_main, "beta_web_applicators", lambda http: ["candidate"])
    monkeypatch.setattr(conductor_main.advance_engagement_task, "delay", lambda eid, tid: None)
    monkeypatch.setattr(conductor_main, "build_applicators_for_engagement", lambda **kw: [])

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)
    monkeypatch.undo()

    # Verify STRIKE_ENTRY_SELECTED event with fallback=True
    events = store.get_events(record.engagement_id)
    strike_events = [e for e in events if e.event_type == "StrikeEntrySelected"]
    assert len(strike_events) == 1
    event = strike_events[0]
    assert event.payload["selected_entry"] == _DEF_TARGET
    assert event.payload["matched_label"] is None
    assert event.payload["fallback_to_default"] is True
    assert event.payload["candidates_considered"] == ()
