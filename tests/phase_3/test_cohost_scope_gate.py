"""RED tests for cohost/scope default-DENY gate — offensive web actions bind to an
owned domain in scope.domains, never a bare IP; co-host discoveries never enter scope.

Grounded in a real client: client-target.com on Cloudways (managed VPS, multi-tenant —
1382146.cloudwaysapps.com, siblings share IP 206.189.93.100).
"""

from __future__ import annotations

import pytest

from agent_alpha.conductor.authorization import (
    AuthorizationStateMachine,
    Scope,
)
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    NodeType,
)

# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture()
def auth() -> AuthorizationStateMachine:
    return AuthorizationStateMachine(event_store=InMemoryEventStore())


@pytest.fixture()
def eng(auth: AuthorizationStateMachine) -> str:
    """Cloudways engagement: only client-target.com domain in scope, NO ip_ranges."""
    rec = auth.create_engagement("client-target", "client-target.com")
    scope = Scope(
        ip_ranges=["10.0.0.0/24"],  # Oracle lab only, NOT the Cloudways IP
        domains=["client-target.com", "www.client-target.com"],
        exclusions=[],
        db_endpoints=[],
    )
    auth.enable_recon(rec.engagement_id, scope)
    return rec.engagement_id


@pytest.fixture()
def graph() -> NetworkXGraphStore:
    return NetworkXGraphStore()


# ── Test 1: sibling domain on same IP is out of scope ─────────


def test_sibling_domain_on_same_ip_is_out_of_scope(
    auth: AuthorizationStateMachine, eng: str
) -> None:
    """A co-tenant domain on the same Cloudways IP is NOT in scope."""
    assert auth.is_in_scope(eng, "client-target.com") is True
    assert auth.is_in_scope(eng, "www.client-target.com") is True
    assert auth.is_in_scope(eng, "othercustomer.cloudwaysapps.com") is False, (
        "co-tenant domain must not be in scope"
    )


# ── Test 2: bare IP is never a valid offensive web target ──────


def test_bare_ip_is_never_a_valid_offensive_web_target(
    auth: AuthorizationStateMachine, eng: str
) -> None:
    """Even if the shared IP were in ip_ranges, an offensive WEB action must refuse it.

    On shared hosting, a bare-IP HTTP request hits the default vhost / an arbitrary
    co-tenant app, NOT deterministically the owned domain. Bare-IP offensive targeting
    = out-of-SOW third-party access.
    """
    # Even if 206.189.93.100 is in ip_ranges (it's not in this fixture, but the guard
    # must reject bare IPs regardless):
    assert auth.assert_offensive_web_target(eng, "206.189.93.100") is False, (
        "bare IP must never be accepted as an offensive web target"
    )


def test_bare_ip_in_ip_ranges_still_rejected_for_offensive_web(
    auth: AuthorizationStateMachine,
) -> None:
    """Even when the IP IS in ip_ranges, offensive web target must still be denied."""
    rec = auth.create_engagement("client_b", "206.189.93.0/24")
    scope = Scope(
        ip_ranges=["206.189.93.0/24"],
        domains=["client-target.com"],
        exclusions=[],
        db_endpoints=[],
    )
    auth.enable_recon(rec.engagement_id, scope)
    assert auth.is_in_scope(rec.engagement_id, "206.189.93.100") is True  # recon OK
    assert auth.assert_offensive_web_target(rec.engagement_id, "206.189.93.100") is False, (
        "bare IP must be rejected for offensive web even if in ip_ranges"
    )


# ── Test 3: domain target is valid offensive web target ────────


def test_domain_target_is_valid_offensive_web_target(
    auth: AuthorizationStateMachine, eng: str
) -> None:
    """An owned domain in scope.domains is a valid offensive web target."""
    assert auth.assert_offensive_web_target(eng, "client-target.com") is True
    assert auth.assert_offensive_web_target(eng, "www.client-target.com") is True


def test_unlisted_domain_rejected_as_offensive_web_target(
    auth: AuthorizationStateMachine, eng: str
) -> None:
    """A domain NOT in scope.domains is rejected."""
    assert auth.assert_offensive_web_target(eng, "evil.com") is False


def test_assert_offensive_web_target_unknown_engagement_returns_false(
    auth: AuthorizationStateMachine,
) -> None:
    """Gate query must never raise — unknown engagement returns False."""
    assert auth.assert_offensive_web_target("eng_unknown", "client-target.com") is False


# ── Test 4: reverse-IP co-host discovery does not enter scope ──


def test_reverse_ip_cohost_discovery_does_not_enter_scope(
    auth: AuthorizationStateMachine, eng: str, graph: NetworkXGraphStore
) -> None:
    """Recon discovers a co-host via reverse-IP; it is intel only, NOT scope.

    The co-host node is written to the graph as an ASSET (intel). The scope gate
    must still deny it — nothing auto-promotes graph discoveries into scope.
    """
    # Simulate recon discovering a co-host sibling app
    cohost_node = AttackNode(
        id="asset_cohost_sibling",
        type=NodeType.ASSET,
        properties=AssetProperties(
            host="sibling-app.cloudwaysapps.com",
            ip="206.189.93.100",
            open_ports=[443],
        ),
        confidence=0.9,
        agent="ALPHA",
        timestamp_utc="2026-07-02T06:00:00Z",
        verified=False,
    )
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": cohost_node.id,
            "type": cohost_node.type.value,
            "properties": {
                "host": "sibling-app.cloudwaysapps.com",
                "ip": "206.189.93.100",
                "cf_protected": False,
                "tech_stack": [],
                "open_ports": [443],
            },
            "confidence": 0.9,
            "proof_artifacts": [],
            "agent": "ALPHA",
            "timestamp_utc": "2026-07-02T06:00:00Z",
            "verified": False,
        },
    )

    # The co-host is in the graph as intel...
    assert graph.get_node("asset_cohost_sibling") is not None

    # ...but the scope gate still denies it
    assert auth.is_in_scope(eng, "sibling-app.cloudwaysapps.com") is False, (
        "co-host discovered via reverse-IP must not enter scope"
    )
    assert auth.assert_offensive_web_target(eng, "sibling-app.cloudwaysapps.com") is False, (
        "co-host must not be a valid offensive web target"
    )
