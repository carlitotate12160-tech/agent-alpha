import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import (
    AuthorizationStateMachine,
    InvalidScopeError,
    Scope,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore


def _store() -> InMemoryEventStore:
    return InMemoryEventStore()


def _engagement_in_recon_with_db_endpoint(sm: AuthorizationStateMachine) -> str:
    rec = sm.create_engagement("client_a", "10.0.0.0/24")
    scope = Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=[],
        exclusions=[],
        db_endpoints=["db.client.example:3306"],
    )
    sm.enable_recon(rec.engagement_id, scope)
    return rec.engagement_id


def test_db_endpoint_scope_survives_rebuild() -> None:
    store = _store()
    sm1 = AuthorizationStateMachine(event_store=store)
    engagement_id = _engagement_in_recon_with_db_endpoint(sm1)

    sm2 = AuthorizationStateMachine(event_store=store)
    assert sm2.is_db_endpoint_in_scope(engagement_id, "db.client.example", 3306) is True


def test_db_endpoint_scope_requires_exact_port() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    engagement_id = _engagement_in_recon_with_db_endpoint(sm)

    assert sm.is_db_endpoint_in_scope(engagement_id, "db.client.example", 5432) is False


def test_db_endpoint_scope_requires_exact_host() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    engagement_id = _engagement_in_recon_with_db_endpoint(sm)

    assert sm.is_db_endpoint_in_scope(engagement_id, "127.0.0.1", 3306) is False


def test_scope_validate_invalid_db_endpoint_raises() -> None:
    scope = Scope(
        ip_ranges=["10.0.0.0/24"],
        domains=[],
        exclusions=[],
        db_endpoints=["db.client.example:notaport"],
    )
    with pytest.raises(InvalidScopeError):
        scope.validate()


def test_is_db_endpoint_in_scope_unknown_engagement_returns_false() -> None:
    sm = AuthorizationStateMachine(event_store=_store())
    assert (
        sm.is_db_endpoint_in_scope("eng_unknown", "db.client.example", 3306)
        is False
    )


def test_pre_db_endpoints_event_replays_with_empty_db_endpoints() -> None:
    store = _store()
    engagement_id = "eng_legacy"

    store.append(
        event_type=EventType.ENGAGEMENT_CREATED,
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload={
            "client_id": "client_a",
            "target": "10.0.0.0/24",
            "state": a2a_pb2.CREATED,
        },
    )

    store.append(
        event_type=EventType.STATE_TRANSITIONED,
        engagement_id=engagement_id,
        agent="CONDUCTOR",
        payload={
            "from_state": a2a_pb2.CREATED,
            "to_state": a2a_pb2.RECON_ONLY,
            "scope": {
                "ip_ranges": ["10.0.0.0/24"],
                "domains": [],
                "exclusions": [],
                "verified": True,
            },
        },
    )

    sm = AuthorizationStateMachine(event_store=store)
    record = sm.get_record(engagement_id)
    assert record.scope is not None
    assert record.scope.db_endpoints == []
