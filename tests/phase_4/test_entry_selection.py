from __future__ import annotations

from urllib.parse import urlparse

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor import main as conductor_main
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.engagement_profile import EngagementProfile
from agent_alpha.conductor.models import Scope
from agent_alpha.conductor.router import (
    StrikeCandidate,
    select_strike_entry,
)
from agent_alpha.config.constants import MAX_STRIKE_CANDIDATES
from agent_alpha.events.event_types import EventType
from agent_alpha.events.reachability import unreachable_hosts
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

    results = {
        select_strike_entry(graph, default_target=_DEF_TARGET).selected_entry for _ in range(20)
    }

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
    _profile_event(store, record.engagement_id)  # §12.36: Beta dispatch requires it

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
    # §12.36: Beta dispatch fail-closes without a verified signed profile. These tests
    # exercise strike-entry SELECTION, not signature verification — return a dummy verified
    # profile so the gate passes (the ENGAGEMENT_PROFILE_SIGNED event is seeded per test).
    monkeypatch.setattr(
        conductor_main,
        "load_signed_profile_from_dict",
        lambda payload, key: EngagementProfile(
            engagement_id="e", client_id="c", targets=frozenset({"lab"})
        ),
    )
    monkeypatch.setattr(conductor_main, "beta_web_applicators", lambda http, **kw: ["candidate"])
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
    _profile_event(store, record.engagement_id)  # §12.36: Beta dispatch requires it

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
    # §12.36: Beta dispatch fail-closes without a verified signed profile. These tests
    # exercise strike-entry SELECTION, not signature verification — return a dummy verified
    # profile so the gate passes (the ENGAGEMENT_PROFILE_SIGNED event is seeded per test).
    monkeypatch.setattr(
        conductor_main,
        "load_signed_profile_from_dict",
        lambda payload, key: EngagementProfile(
            engagement_id="e", client_id="c", targets=frozenset({"lab"})
        ),
    )
    monkeypatch.setattr(conductor_main, "beta_web_applicators", lambda http, **kw: ["candidate"])
    monkeypatch.setattr(conductor_main.advance_engagement_task, "delay", lambda eid, tid: None)
    monkeypatch.setattr(conductor_main, "build_applicators_for_engagement", lambda **kw: [])

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)
    monkeypatch.undo()

    # Verify STRIKE_ENTRY_SELECTED event exists
    recorded_events = store.get_events(record.engagement_id)
    strike_events = [e for e in recorded_events if e.event_type == "StrikeEntrySelected"]
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
    _profile_event(store, record.engagement_id)  # §12.36: Beta dispatch requires it

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
    # §12.36: Beta dispatch fail-closes without a verified signed profile. These tests
    # exercise strike-entry SELECTION, not signature verification — return a dummy verified
    # profile so the gate passes (the ENGAGEMENT_PROFILE_SIGNED event is seeded per test).
    monkeypatch.setattr(
        conductor_main,
        "load_signed_profile_from_dict",
        lambda payload, key: EngagementProfile(
            engagement_id="e", client_id="c", targets=frozenset({"lab"})
        ),
    )
    monkeypatch.setattr(conductor_main, "beta_web_applicators", lambda http, **kw: ["candidate"])
    monkeypatch.setattr(conductor_main.advance_engagement_task, "delay", lambda eid, tid: None)
    monkeypatch.setattr(conductor_main, "build_applicators_for_engagement", lambda **kw: [])

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)
    monkeypatch.undo()

    # Verify STRIKE_ENTRY_SELECTED event with fallback=True
    recorded_events = store.get_events(record.engagement_id)
    strike_events = [e for e in recorded_events if e.event_type == "StrikeEntrySelected"]
    assert len(strike_events) == 1
    event = strike_events[0]
    assert event.payload["selected_entry"] == _DEF_TARGET
    assert event.payload["matched_label"] is None
    assert event.payload["fallback_to_default"] is True
    assert event.payload["candidates_considered"] == ()


# ── GAP-035: multi-candidate dispatch ──────────────────────────────────────────


def _patch_conductor(
    monkeypatch: pytest.MonkeyPatch, store: InMemoryEventStore, beta_cls: type
) -> None:
    """Shared monkeypatch harness for run_agent_task BETA dispatch tests."""
    monkeypatch.setattr(conductor_main, "event_store", store)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(conductor_main, "HttpClient", lambda engagement_id: object())
    monkeypatch.setattr(conductor_main, "resolve_reasoning_provider", lambda api_key: object())
    monkeypatch.setattr(conductor_main.PlaybookEngine, "from_directory", lambda path: object())
    monkeypatch.setattr(conductor_main, "LLMOrchestrator", lambda playbook, provider: object())
    monkeypatch.setattr(conductor_main, "Beta", beta_cls)
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *args: None)
    monkeypatch.setattr(conductor_main, "get_profile_signing_key", lambda: "k" * 64)
    # §12.36: Beta dispatch fail-closes without a verified signed profile. These tests
    # exercise strike-entry SELECTION, not signature verification — return a dummy verified
    # profile so the gate passes (the ENGAGEMENT_PROFILE_SIGNED event is seeded per test).
    monkeypatch.setattr(
        conductor_main,
        "load_signed_profile_from_dict",
        lambda payload, key: EngagementProfile(
            engagement_id="e", client_id="c", targets=frozenset({"lab"})
        ),
    )
    monkeypatch.setattr(conductor_main, "beta_web_applicators", lambda http, **kw: ["candidate"])
    monkeypatch.setattr(conductor_main.advance_engagement_task, "delay", lambda eid, tid: None)
    monkeypatch.setattr(conductor_main, "build_applicators_for_engagement", lambda **kw: [])


def _complete_beta(struck: list[str]) -> type:
    class _FakeBeta:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def run_strike(self, engagement_id: str, entry_point: str) -> a2a_pb2.A2AMessage:
            struck.append(entry_point)
            payload = a2a_pb2.HandoffPayload(
                status=a2a_pb2.COMPLETE, next_recommended=a2a_pb2.OMEGA, confidence=1.0
            )
            return a2a_pb2.A2AMessage(
                engagement_id=engagement_id,
                from_agent=a2a_pb2.BETA,
                to_agent=a2a_pb2.CONDUCTOR,
                message_type=a2a_pb2.HANDOFF_READY,
                payload=payload.SerializeToString(),
                confidence=1.0,
            )

    return _FakeBeta


def _profile_event(store: InMemoryEventStore, eid: str) -> None:
    """Seed the ENGAGEMENT_PROFILE_SIGNED event the §12.36 Beta gate requires (payload is
    opaque here — load_signed_profile_from_dict is patched to return a dummy profile)."""
    store.append(
        event_type=EventType.ENGAGEMENT_PROFILE_SIGNED,
        engagement_id=eid,
        agent="CONDUCTOR",
        payload={"signed": True},
    )


def _seed(store: InMemoryEventStore, eid: str, *assets: tuple[str, list[str]]) -> None:
    g = NetworkXGraphStore()
    for host, tech in assets:
        persist_node(store, g, eid, _asset_node(host, tech), agent="alpha")
    _profile_event(store, eid)


def test_ranked_entries_is_full_uncapped_list() -> None:
    """Router returns the FULL ranked candidate list (NOT capped). The MAX budget is
    applied by the Conductor after its scope gate (#3), never by rank in the router."""
    hosts = [(f"h{i}.example", ["http_basic_auth"]) for i in range(MAX_STRIKE_CANDIDATES + 2)]
    graph = _graph_with_assets(*hosts)

    result = select_strike_entry(graph, default_target=_DEF_TARGET)

    assert len(result.ranked_entries) == MAX_STRIKE_CANDIDATES + 2
    assert all(isinstance(c, StrikeCandidate) for c in result.ranked_entries)
    assert result.ranked_entries[0].entry_url == result.selected_entry


def test_ranked_entries_empty_on_fallback() -> None:
    graph = _graph_with_assets(("apex.example", []))
    result = select_strike_entry(graph, default_target=_DEF_TARGET)
    assert result.ranked_entries == ()


def test_multi_candidate_strikes_all_in_scope_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED before fix: hub (basic-auth) AND pos (login-form) both in scope ->
    Beta dispatched at BOTH. Single-dispatch struck only the top-ranked one."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    auth.enable_recon(
        record.engagement_id,
        Scope(ip_ranges=[], domains=["hub.example", "pos.example"], exclusions=[]),
    )
    auth.enable_active(record.engagement_id)
    _seed(
        store,
        record.engagement_id,
        ("hub.example", ["http_basic_auth"]),
        ("pos.example", ["login-form"]),
    )

    struck: list[str] = []
    _patch_conductor(monkeypatch, store, _complete_beta(struck))

    result = conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)

    assert result["status"] == "completed"
    # http_basic_auth sorts before login-form -> hub struck first, then pos.
    assert struck == ["https://hub.example/", "https://pos.example/"]
    attempts = [
        e
        for e in store.get_events(record.engagement_id)
        if e.event_type == "StrikeCandidateAttempted"
    ]
    assert [e.payload["host"] for e in attempts] == ["hub.example", "pos.example"]


def test_out_of_scope_candidate_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """pos.example is labelled but NOT in scope -> gate skips it, hub still struck."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    auth.enable_recon(
        record.engagement_id,
        Scope(ip_ranges=[], domains=["hub.example"], exclusions=[]),
    )
    auth.enable_active(record.engagement_id)
    _seed(
        store,
        record.engagement_id,
        ("hub.example", ["http_basic_auth"]),
        ("pos.example", ["login-form"]),
    )

    struck: list[str] = []
    _patch_conductor(monkeypatch, store, _complete_beta(struck))

    result = conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)

    assert result["status"] == "completed"
    assert struck == ["https://hub.example/"]
    skipped = [
        e
        for e in store.get_events(record.engagement_id)
        if e.event_type == "StrikeCandidateSkipped"
    ]
    assert len(skipped) == 1
    assert skipped[0].payload["host"] == "pos.example"
    assert skipped[0].payload["reason"] == "out_of_scope"


def test_dispatch_bounded_to_max_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    """More in-scope surfaces than the cap -> only MAX_STRIKE_CANDIDATES struck."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    hosts = [f"h{i}.example" for i in range(MAX_STRIKE_CANDIDATES + 3)]
    auth.enable_recon(record.engagement_id, Scope(ip_ranges=[], domains=hosts, exclusions=[]))
    auth.enable_active(record.engagement_id)
    _seed(store, record.engagement_id, *[(h, ["http_basic_auth"]) for h in hosts])

    struck: list[str] = []
    _patch_conductor(monkeypatch, store, _complete_beta(struck))

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)

    assert len(struck) == MAX_STRIKE_CANDIDATES


# ── GAP-035: aggregation branches (FAILED / mixed / none-in-scope) ──────────────
#
# These exercise run_beta's ExecOutcome aggregation, observed through the
# HANDOFF_READY event (execute_agent emits status + next_recommended) and a
# verify_access_nodes spy. Without them the FAILED path is dead-untested and a
# regression could silently return COMPLETE on an all-fail run (false success, #3).


def _status_beta(struck: list[str], statuses: list[int], nexts: list[int]) -> type:
    """Fake Beta whose run_strike returns a scripted status/next per call index."""

    class _FakeBeta:
        _i = 0

        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def run_strike(self, engagement_id: str, entry_point: str) -> a2a_pb2.A2AMessage:
            idx = _FakeBeta._i
            _FakeBeta._i += 1
            struck.append(entry_point)
            payload = a2a_pb2.HandoffPayload(
                status=statuses[idx], next_recommended=nexts[idx], confidence=1.0
            )
            return a2a_pb2.A2AMessage(
                engagement_id=engagement_id,
                from_agent=a2a_pb2.BETA,
                to_agent=a2a_pb2.CONDUCTOR,
                message_type=a2a_pb2.HANDOFF_READY,
                payload=payload.SerializeToString(),
                confidence=1.0,
            )

    _FakeBeta._i = 0
    return _FakeBeta


def _handoff_status(store: InMemoryEventStore, eid: str) -> int:
    handoffs = [e for e in store.get_events(eid) if e.event_type == "HandoffReady"]
    assert handoffs, "no HANDOFF_READY emitted"
    return int(handoffs[-1].payload["status"])


def _handoff_next(store: InMemoryEventStore, eid: str) -> int:
    handoffs = [e for e in store.get_events(eid) if e.event_type == "HandoffReady"]
    return int(handoffs[-1].payload["next_recommended"])


def _two_surface_engagement() -> tuple[InMemoryEventStore, AuthorizationStateMachine, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    auth.enable_recon(
        record.engagement_id,
        Scope(ip_ranges=[], domains=["hub.example", "pos.example"], exclusions=[]),
    )
    auth.enable_active(record.engagement_id)
    _seed(
        store,
        record.engagement_id,
        ("hub.example", ["http_basic_auth"]),
        ("pos.example", ["login-form"]),
    )
    return store, auth, record.engagement_id


def test_all_candidates_fail_returns_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both surfaces struck, both FAIL -> HANDOFF_READY status FAILED, verify never run.
    Guards against false-success (#3): overall_status must NOT reset to COMPLETE."""
    store, _auth, eid = _two_surface_engagement()
    struck: list[str] = []
    verify_calls: list[int] = []
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *a: verify_calls.append(1))
    _patch_conductor(
        monkeypatch,
        store,
        _status_beta(struck, [a2a_pb2.FAILED, a2a_pb2.FAILED], [a2a_pb2.OMEGA, a2a_pb2.OMEGA]),
    )
    # keep our verify spy (patch_conductor set its own) — reassert last:
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *a: verify_calls.append(1))

    conductor_main.run_agent_task.run(eid, None, a2a_pb2.BETA)

    assert struck == ["https://hub.example/", "https://pos.example/"]
    assert verify_calls == []  # no COMPLETE -> verify_access_nodes never called
    assert _handoff_status(store, eid) == a2a_pb2.FAILED


def test_first_fail_second_complete_returns_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    """hub FAILS, pos COMPLETES -> overall COMPLETE (FAILED->COMPLETE transition),
    verify_access_nodes called exactly once (for the completing candidate)."""
    store, _auth, eid = _two_surface_engagement()
    struck: list[str] = []
    verify_calls: list[int] = []
    _patch_conductor(
        monkeypatch,
        store,
        _status_beta(struck, [a2a_pb2.FAILED, a2a_pb2.COMPLETE], [a2a_pb2.OMEGA, a2a_pb2.GAMMA]),
    )
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *a: verify_calls.append(1))

    conductor_main.run_agent_task.run(eid, None, a2a_pb2.BETA)

    assert struck == ["https://hub.example/", "https://pos.example/"]
    assert verify_calls == [1]
    assert _handoff_status(store, eid) == a2a_pb2.COMPLETE
    # first-COMPLETE-wins: only pos completed, so its next (GAMMA) drives the chain.
    assert _handoff_next(store, eid) == a2a_pb2.GAMMA


def test_first_complete_wins_next_recommended(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both COMPLETE: hub(next=OMEGA) then pos(next=GAMMA) -> chain follows the
    FIRST (highest-ranked) completion = OMEGA, not the last."""
    store, _auth, eid = _two_surface_engagement()
    struck: list[str] = []
    _patch_conductor(
        monkeypatch,
        store,
        _status_beta(struck, [a2a_pb2.COMPLETE, a2a_pb2.COMPLETE], [a2a_pb2.OMEGA, a2a_pb2.GAMMA]),
    )
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *a: None)

    conductor_main.run_agent_task.run(eid, None, a2a_pb2.BETA)

    assert _handoff_status(store, eid) == a2a_pb2.COMPLETE
    assert _handoff_next(store, eid) == a2a_pb2.OMEGA


def test_all_out_of_scope_returns_failed_and_strikes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every labelled candidate is out of scope -> zero strikes, all skipped,
    HANDOFF_READY status FAILED (reason beta_no_in_scope_candidate)."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    # scope only covers the apex; the labelled surfaces are OUT of scope.
    auth.enable_recon(
        record.engagement_id, Scope(ip_ranges=[], domains=["apex.example"], exclusions=[])
    )
    auth.enable_active(record.engagement_id)
    _seed(
        store,
        record.engagement_id,
        ("hub.example", ["http_basic_auth"]),
        ("pos.example", ["login-form"]),
    )

    struck: list[str] = []
    _patch_conductor(monkeypatch, store, _complete_beta(struck))

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)

    assert struck == []
    attempts = [
        e
        for e in store.get_events(record.engagement_id)
        if e.event_type == "StrikeCandidateAttempted"
    ]
    skipped = [
        e
        for e in store.get_events(record.engagement_id)
        if e.event_type == "StrikeCandidateSkipped"
    ]
    assert attempts == []
    assert {e.payload["host"] for e in skipped} == {"hub.example", "pos.example"}
    assert _handoff_status(store, record.engagement_id) == a2a_pb2.FAILED


# ── CodeRabbit round 3: lockout / BLOCKED precedence / scope-then-cap ───────────


def test_lockout_governor_shared_across_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1: ONE CredentialLockoutGovernor for the whole engagement — the SAME instance
    is passed to build_applicators_for_engagement for every candidate (not a fresh
    per-candidate governor via the omitted-lockout default)."""
    store, _auth, eid = _two_surface_engagement()
    struck: list[str] = []
    seen_lockouts: list[object] = []

    def _capture(**kwargs: object) -> list[object]:
        seen_lockouts.append(kwargs.get("lockout"))
        return []

    _patch_conductor(monkeypatch, store, _complete_beta(struck))
    monkeypatch.setattr(conductor_main, "build_applicators_for_engagement", _capture)
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *a: None)

    conductor_main.run_agent_task.run(eid, None, a2a_pb2.BETA)

    assert len(seen_lockouts) == 2  # both surfaces struck
    assert seen_lockouts[0] is not None
    assert seen_lockouts[0] is seen_lockouts[1]  # SAME shared instance


def test_all_blocked_returns_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """#2: both candidates BLOCKED -> HANDOFF status BLOCKED, NOT collapsed to FAILED
    (execute_agent suppresses advance on BLOCKED — the signal must survive)."""
    store, _auth, eid = _two_surface_engagement()
    struck: list[str] = []
    _patch_conductor(
        monkeypatch,
        store,
        _status_beta(
            struck, [a2a_pb2.BLOCKED, a2a_pb2.BLOCKED], [a2a_pb2.CONDUCTOR, a2a_pb2.CONDUCTOR]
        ),
    )
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *a: None)

    conductor_main.run_agent_task.run(eid, None, a2a_pb2.BETA)

    assert _handoff_status(store, eid) == a2a_pb2.BLOCKED


def test_complete_over_blocked_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    """#2: one BLOCKED + one COMPLETE -> COMPLETE wins (COMPLETE > BLOCKED > FAILED)."""
    store, _auth, eid = _two_surface_engagement()
    struck: list[str] = []
    _patch_conductor(
        monkeypatch,
        store,
        _status_beta(
            struck, [a2a_pb2.BLOCKED, a2a_pb2.COMPLETE], [a2a_pb2.CONDUCTOR, a2a_pb2.OMEGA]
        ),
    )
    monkeypatch.setattr(conductor_main, "verify_access_nodes", lambda *a: None)

    conductor_main.run_agent_task.run(eid, None, a2a_pb2.BETA)

    assert _handoff_status(store, eid) == a2a_pb2.COMPLETE
    assert _handoff_next(store, eid) == a2a_pb2.OMEGA


def test_out_of_scope_ranked_above_does_not_starve_in_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#3: out-of-scope surfaces ranked ABOVE in-scope ones must NOT consume the
    MAX budget. With MAX in-scope surfaces available, exactly MAX are struck even
    when higher-ranked out-of-scope entries precede them."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    # in-scope hosts sort AFTER the out-of-scope ones (same label -> host-name order).
    in_scope = [f"z{i}.example" for i in range(MAX_STRIKE_CANDIDATES + 1)]
    auth.enable_recon(record.engagement_id, Scope(ip_ranges=[], domains=in_scope, exclusions=[]))
    auth.enable_active(record.engagement_id)
    oos = ["a-oos1.example", "a-oos2.example"]  # labelled but OUT of scope, rank first
    assets = [(h, ["http_basic_auth"]) for h in oos + in_scope]
    _seed(store, record.engagement_id, *assets)

    struck: list[str] = []
    _patch_conductor(monkeypatch, store, _complete_beta(struck))

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)

    # exactly MAX in-scope struck; the two out-of-scope never consumed budget.
    assert len(struck) == MAX_STRIKE_CANDIDATES
    assert all(u.startswith("https://z") for u in struck)
    skipped = [
        e
        for e in store.get_events(record.engagement_id)
        if e.event_type == "StrikeCandidateSkipped"
    ]
    assert {e.payload["host"] for e in skipped} == set(oos)


# ── GAP-034: reachability read-model demotes strike-dead hosts ──────────────────


def test_gap034_unreachable_hosts_only_from_host_abandoned() -> None:
    """CARDINAL product decision: ONLY HOST_ABANDONED marks a host strike-dead.
    WAF_BLOCKED does NOT (it is the origin-bypass target — the moat)."""
    store = InMemoryEventStore()
    store.append(EventType.HOST_ABANDONED, "e", "alpha", {"host": "dead.example"})
    store.append(EventType.WAF_BLOCKED, "e", "alpha", {"host": "waf.example"})

    assert unreachable_hosts(store.get_events("e")) == frozenset({"dead.example"})


def test_gap034_demotes_abandoned_host_below_live() -> None:
    """A dead host with a HIGHER-priority label must rank BELOW a live host with a
    lower-priority label once reachability is applied (demote, not delete)."""
    graph = _graph_with_assets(("dead.example", ["admin"]), ("live.example", ["http_basic_auth"]))

    # Baseline (no reachability): admin outranks http_basic_auth -> dead wins.
    base = select_strike_entry(graph, default_target=_DEF_TARGET)
    assert base.selected_entry == "https://dead.example/"

    # With reachability: dead demoted -> live wins, dead kept as last-resort.
    result = select_strike_entry(
        graph, default_target=_DEF_TARGET, unreachable_hosts=frozenset({"dead.example"})
    )
    assert result.selected_entry == "https://live.example/"
    assert [c.host for c in result.ranked_entries] == ["live.example", "dead.example"]


def test_gap034_abandoned_host_demoted_out_of_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Integration: a dead-but-high-label in-scope host must NOT consume a strike slot
    when MAX live surfaces exist. RED without GAP-034 (dead 'admin' ranks first)."""
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    record = auth.create_engagement(client_id="client-1", target=_DEF_TARGET)
    live = [f"z{i}.example" for i in range(MAX_STRIKE_CANDIDATES)]
    dead = "a-dead.example"  # sorts first alphabetically + highest-priority label below
    auth.enable_recon(
        record.engagement_id, Scope(ip_ranges=[], domains=live + [dead], exclusions=[])
    )
    auth.enable_active(record.engagement_id)
    _seed(store, record.engagement_id, (dead, ["admin"]), *[(h, ["http_basic_auth"]) for h in live])
    store.append(EventType.HOST_ABANDONED, record.engagement_id, "alpha", {"host": dead})

    struck: list[str] = []
    _patch_conductor(monkeypatch, store, _complete_beta(struck))

    conductor_main.run_agent_task.run(record.engagement_id, None, a2a_pb2.BETA)

    struck_hosts = {urlparse(u).hostname for u in struck}
    assert dead not in struck_hosts  # demoted out of the MAX budget
    assert len(struck) == MAX_STRIKE_CANDIDATES
    assert struck_hosts == set(live)
