"""Integration tests for the Conductor auto-advance wiring."""

from __future__ import annotations

import ast
import pathlib
from unittest.mock import MagicMock, patch

import pytest

import agent_alpha.conductor.main as main
from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.main import (
    advance_engagement_task,
    run_agent_task,
    run_engagement_task,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore


@pytest.fixture(autouse=True)
def clean_event_store():
    # Use a fresh InMemoryEventStore for each test to isolate them.
    store = InMemoryEventStore()
    main.event_store = store
    yield store


@pytest.fixture
def mock_recon():
    with patch("agent_alpha.conductor.main.recon_runner.run_recon_for_engagement") as m:
        m.return_value.node_count = 5
        m.return_value.targets_scanned = 1
        yield m


@pytest.fixture
def mock_beta_run_strike():
    with patch("agent_alpha.conductor.main.Beta.run_strike") as m:
        yield m


def test_t1_recon_produces_handoff(mock_recon):
    """T1: run_engagement_task completes recon and appends HANDOFF_READY."""
    auth = AuthorizationStateMachine(event_store=main.event_store)
    record = auth.create_engagement("client_1", "example.com")
    eng_id = record.engagement_id
    auth.enable_recon(eng_id, Scope(ip_ranges=["10.0.0.0/24"], domains=[], exclusions=[]))

    with patch("agent_alpha.conductor.main.advance_engagement_task.delay") as mock_delay:
        result = run_engagement_task(eng_id, tenant_id=None)
        assert result["status"] == "completed"

        events = main.event_store.get_events(eng_id)
        handoffs = [e for e in events if e.event_type == EventType.HANDOFF_READY]
        assert len(handoffs) == 1
        payload = handoffs[0].payload
        assert payload["from_agent"] == a2a_pb2.ALPHA
        assert payload["status"] == a2a_pb2.COMPLETE
        assert payload["next_recommended"] == a2a_pb2.BETA

        mock_delay.assert_called_once_with(eng_id, None)


def test_t2a_active_approved_dispatches_beta():
    """T2a: enable_active -> advance_engagement_task dispatches BETA exactly once."""
    auth = AuthorizationStateMachine(event_store=main.event_store)
    record = auth.create_engagement("client_1", "example.com", tenant_id="tenant_1")
    eng_id = record.engagement_id
    auth.enable_recon(eng_id, Scope(ip_ranges=["10.0.0.0/24"], domains=[], exclusions=[]))
    auth.enable_active(eng_id)

    # Fake a HANDOFF_READY from ALPHA
    main.event_store.append(
        event_type=EventType.HANDOFF_READY,
        engagement_id=eng_id,
        agent="ALPHA",
        payload={
            "from_agent": a2a_pb2.ALPHA,
            "status": a2a_pb2.COMPLETE,
            "next_recommended": a2a_pb2.BETA,
        }
    )

    with patch("agent_alpha.conductor.main.run_agent_task.delay") as mock_delay:
        decision = advance_engagement_task(eng_id, None)
        assert decision["action"] == "dispatch"
        assert decision["next_agent"] == a2a_pb2.BETA
        mock_delay.assert_called_once_with(eng_id, None, a2a_pb2.BETA)


def test_t2b_run_agent_task_calls_factory(mock_beta_run_strike):
    """T2b: run_agent_task(BETA) calls factory and constructs CredReuseTool with applicators."""
    auth = AuthorizationStateMachine(event_store=main.event_store)
    record = auth.create_engagement("client_1", "example.com")
    eng_id = record.engagement_id
    auth.enable_recon(eng_id, Scope(ip_ranges=["10.0.0.0/24"], domains=["example.com"], exclusions=[]))
    auth.enable_active(eng_id)

    # Fake an ASSET in the graph so we have something in scope
    def mock_build_applicators(*args, **kwargs):
        from agent_alpha.tools.internal.access.applicator import CredentialApplicator
        return [MagicMock(spec=CredentialApplicator)]

    with patch("agent_alpha.conductor.main.build_applicators_for_engagement", side_effect=mock_build_applicators) as m_build:
        with patch("agent_alpha.conductor.main.Beta.__init__", return_value=None) as m_beta:
            with patch("agent_alpha.conductor.main.advance_engagement_task.delay"):
                with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "dummy"}):
                    run_agent_task(eng_id, None, a2a_pb2.BETA)

            m_build.assert_called_once()
            _, kwargs = m_beta.call_args
            assert len(kwargs["cred_applicators"]) == 1


def test_t3_recon_only_parks():
    """T3: RECON_ONLY -> advance_engagement_task parks and AWAITING_APPROVAL appended."""
    auth = AuthorizationStateMachine(event_store=main.event_store)
    record = auth.create_engagement("client_1", "example.com", tenant_id="tenant_1")
    eng_id = record.engagement_id
    auth.enable_recon(eng_id, Scope(ip_ranges=["10.0.0.0/24"], domains=[], exclusions=[]))

    # Fake a HANDOFF_READY from ALPHA recommending BETA
    main.event_store.append(
        event_type=EventType.HANDOFF_READY,
        engagement_id=eng_id,
        agent="ALPHA",
        payload={
            "from_agent": a2a_pb2.ALPHA,
            "status": a2a_pb2.COMPLETE,
            "next_recommended": a2a_pb2.BETA,
        }
    )

    with patch("agent_alpha.conductor.main.run_agent_task.delay") as mock_delay:
        decision = advance_engagement_task(eng_id, None)
        assert decision["action"] == "park_awaiting_approval"
        mock_delay.assert_not_called()

        events = main.event_store.get_events(eng_id)
        awaiting = [e for e in events if e.event_type == EventType.AWAITING_APPROVAL]
        assert len(awaiting) == 1


def test_t4_idempotent_dispatch():
    """T4: advance_engagement_task run twice enqueues Beta exactly once."""
    auth = AuthorizationStateMachine(event_store=main.event_store)
    record = auth.create_engagement("client_1", "example.com", tenant_id="tenant_1")
    eng_id = record.engagement_id
    auth.enable_recon(eng_id, Scope(ip_ranges=["10.0.0.0/24"], domains=[], exclusions=[]))
    auth.enable_active(eng_id)

    main.event_store.append(
        event_type=EventType.HANDOFF_READY,
        engagement_id=eng_id,
        agent="ALPHA",
        payload={
            "from_agent": a2a_pb2.ALPHA,
            "status": a2a_pb2.COMPLETE,
            "next_recommended": a2a_pb2.BETA,
        }
    )

    with patch("agent_alpha.conductor.main.run_agent_task.delay") as mock_delay:
        advance_engagement_task(eng_id, None)
        advance_engagement_task(eng_id, None)
        assert mock_delay.call_count == 1


def test_t5_no_agent_enqueues_agent():
    """T5: AST guard to assert NO agent task enqueues another agent directly."""
    project_root = pathlib.Path(__file__).resolve().parent.parent.parent
    agent_dir = project_root / "agent_alpha" / "agents"

    for py_file in agent_dir.rglob("*.py"):
        code = py_file.read_text(encoding="utf-8")
        tree = ast.parse(code, filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                attr = node.func
                if attr.attr == "delay":
                    raise AssertionError(f"Agent module {py_file} enqueues a Celery task directly via .delay(): {ast.unparse(node)}")
