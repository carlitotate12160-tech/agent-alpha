"""RED tests for the Conductor-side applicator factory (Step 3, FLAW 1+2+3) and the
cred_reuse blindness guard (the "stop signal").

These are the executable test contract. They run against FAKE auth + FAKE graph so
they do NOT depend on the gate slice 3a being implemented yet — the fake supplies
is_db_endpoint_in_scope. The REAL gate method is RED-tested separately (slice 3a).

VERIFY: Oracle ARM64 only — `.venv/bin/python3 -m pytest tests/phase_3/test_applicator_factory.py`
(NEVER bare pytest; system python is 3.10 and chokes on StrEnum / a2a_pb2 build).
"""

from __future__ import annotations

import inspect

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.applicator_factory import (
    BoundApplicator,
    build_applicators_for_engagement,
)
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    NodeType,
    ServiceProperties,
)

ENG = "eng_test01"
WEB_TARGET = "https://app.client.example/login"


# ── Test doubles ──────────────────────────────────────────────────────────────


class _Applicator:
    """Minimal stand-in carrying only the selection metadata the factory reads."""

    def __init__(self, service: str, required_auth: str) -> None:
        self.service = service
        self.required_auth = required_auth

    # apply/applies_to are not exercised by the factory; selection is metadata-only.


class FakeAuth:
    """Read-only gate double. Records every call so a test can assert the factory —
    and ONLY the factory — reads auth/scope."""

    def __init__(self, *, state: int, in_scope_endpoints: set[tuple[str, int]]) -> None:
        self._state = state
        self._in_scope = in_scope_endpoints
        self.calls: list[str] = []

    def get_state(self, engagement_id: str) -> int:
        self.calls.append("get_state")
        return self._state

    def is_db_endpoint_in_scope(self, engagement_id: str, host: str, port: int) -> bool:
        self.calls.append("is_db_endpoint_in_scope")
        return (host, port) in self._in_scope

    def assert_offensive_web_target(self, engagement_id: str, target: str) -> bool:
        self.calls.append("assert_offensive_web_target")
        # Reject bare IPs (shared-hosting safety), accept domains
        try:
            import ipaddress

            ipaddress.ip_address(target)
            return False  # bare IP
        except ValueError:
            return True  # domain — assume in scope for test


class FakeGraph:
    def __init__(self, nodes: list[AttackNode]) -> None:
        self._nodes = nodes

    def nodes_by_type(self, node_type: NodeType) -> list[AttackNode]:
        return [n for n in self._nodes if n.type == node_type]


def _asset(host: str, open_ports: list[int]) -> AttackNode:
    return AttackNode(
        id=f"asset_{host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, open_ports=open_ports),
        confidence=0.9,
    )


def _mysql_service(port: int = 3306) -> AttackNode:
    return AttackNode(
        id=f"svc_mysql_{port}",
        type=NodeType.SERVICE,
        properties=ServiceProperties(name="mysql", port=port),
        confidence=0.9,
    )


def _http() -> _Applicator:
    return _Applicator(service="http", required_auth="ACTIVE_APPROVED")


def _mysql() -> _Applicator:
    return _Applicator(service="mysql", required_auth="OFFENSIVE_APPROVED")


# ── FLAW 1: tier gate ─────────────────────────────────────────────────────────


def test_active_approved_admits_http_excludes_mysql() -> None:
    """At ACTIVE_APPROVED, the OFFENSIVE-tier MySQL applicator must NOT appear; the
    ACTIVE-tier HTTP applicator must, bound to the web target."""
    auth = FakeAuth(state=a2a_pb2.ACTIVE_APPROVED, in_scope_endpoints={("db.client.example", 3306)})
    graph = FakeGraph([_asset("db.client.example", [3306]), _mysql_service()])

    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[_http(), _mysql()],
    )

    services = {b.applicator.service for b in bound}
    assert services == {"http"}
    assert any(b.target == WEB_TARGET for b in bound if b.applicator.service == "http")


def test_recon_only_admits_nothing() -> None:
    """RECON_ONLY satisfies no credential-application tier (both are ACTIVE+)."""
    auth = FakeAuth(state=a2a_pb2.RECON_ONLY, in_scope_endpoints=set())
    graph = FakeGraph([])
    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[_http(), _mysql()],
    )
    assert bound == []


def test_unknown_required_auth_is_denied_fail_closed() -> None:
    """An applicator with an unrecognized required_auth label is DENIED, never
    silently admitted (anti-Lyndon #3 false-success at the gate)."""
    rogue = _Applicator(service="http", required_auth="TOTALLY_PRIVILEGED")
    auth = FakeAuth(state=a2a_pb2.OFFENSIVE_APPROVED, in_scope_endpoints=set())
    graph = FakeGraph([])
    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[rogue],
    )
    assert bound == []


# ── FLAW 2: in-scope DB endpoint only ─────────────────────────────────────────


def test_offensive_binds_mysql_to_in_scope_endpoint() -> None:
    """At OFFENSIVE_APPROVED with the DB endpoint in SOW scope, MySQL binds to the
    ASSET host:port (NOT a leaked DB_HOST)."""
    auth = FakeAuth(
        state=a2a_pb2.OFFENSIVE_APPROVED,
        in_scope_endpoints={("db.client.example", 3306)},
    )
    graph = FakeGraph([_asset("db.client.example", [3306]), _mysql_service()])
    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[_mysql()],
    )
    db_targets = [b.target for b in bound if b.applicator.service == "mysql"]
    assert db_targets == ["db.client.example:3306"]


def test_offensive_rejects_out_of_scope_db_host() -> None:
    """A DB asset that the gate says is OUT of SOW scope yields no MySQL binding —
    even at OFFENSIVE_APPROVED. This is the localhost/leaked-DB_HOST trap (FLAW 2)."""
    auth = FakeAuth(
        state=a2a_pb2.OFFENSIVE_APPROVED,
        in_scope_endpoints={("db.client.example", 3306)},  # the legit one
    )
    # The graph also contains a leaked internal DB host that is NOT in SOW scope.
    graph = FakeGraph(
        [
            _asset("127.0.0.1", [3306]),  # leaked DB_HOST — must be rejected
            _mysql_service(),
        ]
    )
    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[_mysql()],
    )
    assert [b for b in bound if b.applicator.service == "mysql"] == []
    assert "is_db_endpoint_in_scope" in auth.calls  # the gate WAS consulted


# ── FLAW 3: host from AssetProperties, port from open_ports ────────────────────


def test_db_port_bound_only_to_asset_that_exposes_it() -> None:
    """A MySQL service on 3306 binds only to the asset whose open_ports include 3306;
    an in-scope asset that does NOT expose 3306 yields no binding (host⊕port joined
    via open_ports, never assumed co-located — ServiceProperties has no host)."""
    auth = FakeAuth(
        state=a2a_pb2.OFFENSIVE_APPROVED,
        in_scope_endpoints={("db.client.example", 3306), ("web.client.example", 3306)},
    )
    graph = FakeGraph(
        [
            _asset("db.client.example", [3306]),  # exposes DB port
            _asset("web.client.example", [443]),  # in scope but no DB port
            _mysql_service(),
        ]
    )
    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[_mysql()],
    )
    db_targets = sorted(b.target for b in bound if b.applicator.service == "mysql")
    assert db_targets == ["db.client.example:3306"]


def test_no_identified_db_service_yields_no_db_target() -> None:
    """An open 3306 port with NO identified MySQL service node yields no binding —
    we bind to PROVEN services, not guessed ports (anti-#3)."""
    auth = FakeAuth(
        state=a2a_pb2.OFFENSIVE_APPROVED, in_scope_endpoints={("db.client.example", 3306)}
    )
    graph = FakeGraph([_asset("db.client.example", [3306])])  # no service node
    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[_mysql()],
    )
    assert [b for b in bound if b.applicator.service == "mysql"] == []


def test_returns_bound_applicator_instances() -> None:
    """The output is BoundApplicator(applicator, target) — the pair cred_reuse needs
    so it can call apply(target=...) without ever choosing a target itself."""
    auth = FakeAuth(state=a2a_pb2.ACTIVE_APPROVED, in_scope_endpoints=set())
    graph = FakeGraph([])
    bound = build_applicators_for_engagement(
        engagement_id=ENG,
        auth=auth,
        graph_store=graph,
        web_target=WEB_TARGET,
        candidates=[_http()],
    )
    assert len(bound) == 1
    assert isinstance(bound[0], BoundApplicator)
    assert bound[0].target == WEB_TARGET


# ── The stop signal: cred_reuse must hold NO auth/scope handle ─────────────────


def test_cred_reuse_has_no_auth_or_scope_handle() -> None:
    """STOP-SIGNAL GUARD. cred_reuse must remain auth/scope-blind: it receives only
    BoundApplicators from the factory and iterates. The moment its constructor grows
    an `auth`/`authorization`/`auth_state`/`scope`/`policy`/`policy_enforcer` parameter,
    the gate has leaked into the tool (auth-gate softening) — this test goes RED on
    purpose to force a redesign back into the factory.

    NOTE: cred_reuse's `applicators` injection (Step 3c) is the only new dep allowed;
    this guard asserts what must NEVER appear, not what must."""
    from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool

    params = set(inspect.signature(CredReuseTool.__init__).parameters)
    forbidden = {"auth", "authorization", "auth_state", "scope", "policy", "policy_enforcer"}
    leaked = params & forbidden
    assert not leaked, f"cred_reuse must stay auth/scope-blind; leaked handle(s): {leaked}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
