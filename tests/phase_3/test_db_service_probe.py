# RED test for Piece 2 — verify_in_scope_db_services (RECON-tier DB discovery).
#
# TARGET PATH ON #61:  tests/phase_3/test_db_service_probe.py
# AUTHORED BY:         Claude (test/gate lane). Bodies under test (verify_in_scope_db_services
#                      gating+writes, parse_db_handshake) are the IDE/infra lane.
# STATE TODAY:         RED — verify_in_scope_db_services + parse_db_handshake raise
#                      NotImplementedError. GREEN when the IDE lands both against these
#                      assertions. That is "piece 2 done".
#
# PINS (the contract the bodies MUST honour):
#   T1  verified MySQL greeting on an in-scope endpoint ⇒ SERVICE(mysql,port) node +
#       the DB host's asset gains `port` in open_ports; the OFFENSIVE factory then binds
#       the mysql applicator to that host:port (consumption proof — anti-Lyndon #2, and
#       demonstrates the RECON-verify → OFFENSIVE-apply tier split).
#   T2  a non-MySQL banner (e.g. SSH on 3306) ⇒ parse returns None ⇒ NO SERVICE node
#       (anti-#3: an open port is not proof of MySQL).
#   T3  a closed/filtered port (probe raises) ⇒ SKIP, no node, no crash.
#   T4  scope-safety: an endpoint that fails is_db_endpoint_in_scope is NEVER probed
#       and never written (the probe transport is not even called for it).
#   T5  tier fail-closed: engagement below RECON_ONLY ⇒ nothing probed, empty result.
#
# SHAPE-CONFIRM ON #61 before trusting imports (#2): recon package path, Scope,
# AuthorizationStateMachine.get_state / is_db_endpoint_in_scope, factory + MySqlApplicator.

from __future__ import annotations

from agent_alpha.conductor.applicator_factory import build_applicators_for_engagement
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, NodeType, ServiceProperties
from agent_alpha.recon.db_service_probe import verify_in_scope_db_services
from agent_alpha.tools.internal.access.mysql_applicator import MySqlApplicator

_HOST = "10.0.0.1"
_PORT = 3306
_ENDPOINT = f"{_HOST}:{_PORT}"

# A plausible MySQL v10 greeting: 4-byte header, protocol byte 0x0a, NUL-terminated
# version. Exact bytes only matter once parse_db_handshake is implemented.
_MYSQL_GREETING = bytes([0x4A, 0, 0, 0]) + b"\x0a" + b"8.4.10\x00" + b"\x00" * 20
_SSH_BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"


class _FakeProbe:
    """Records every endpoint it was asked to touch — so a test can assert an
    out-of-scope endpoint was NEVER probed."""

    def __init__(self, responses: dict[tuple[str, int], bytes | Exception]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, int]] = []

    def read_handshake(self, *, host: str, port: int, timeout_s: float) -> bytes:
        self.calls.append((host, port))
        r = self._responses.get((host, port))
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise ConnectionRefusedError("no fake response configured")
        return r


def _recon_engagement(event_store: InMemoryEventStore, *, db_endpoints: list[str]):
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="db_probe_lab", target=_HOST)
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=["10.0.0.0/30"],
            domains=["app.client.invalid"],
            exclusions=[],
            db_endpoints=db_endpoints,
        ),
    )
    return auth, rec.engagement_id


# ── T1: verified MySQL ⇒ SERVICE node + open_ports + factory binds mysql ──────────


def test_verified_mysql_endpoint_is_written_and_consumed_by_factory() -> None:
    store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    auth, eid = _recon_engagement(event_store, db_endpoints=[_ENDPOINT])
    probe = _FakeProbe({(_HOST, _PORT): _MYSQL_GREETING})

    evidence = verify_in_scope_db_services(
        engagement_id=eid,
        auth=auth,
        scope_db_endpoints=[_ENDPOINT],
        graph_store=store,
        event_store=event_store,
        probe=probe,
        timeout_s=5.0,
    )

    assert len(evidence) == 1 and evidence[0].service in ("mysql", "mariadb")

    services = [
        n
        for n in store.nodes_by_type(NodeType.SERVICE)
        if isinstance(n.properties, ServiceProperties) and n.properties.name == "mysql"
    ]
    assert len(services) == 1 and services[0].properties.port == _PORT

    assets = [n for n in store.nodes_by_type(NodeType.ASSET) if n.properties.host == _HOST]
    assert assets and _PORT in assets[0].properties.open_ports

    # Consumption proof (anti-#2): escalate, then the OFFENSIVE factory binds mysql to
    # the RECON-verified endpoint — never a leaked DB_HOST.
    auth.enable_active(eid)
    auth.enable_offensive(eid, b"SIGNED-SOW")
    bound = build_applicators_for_engagement(
        engagement_id=eid,
        auth=auth,
        graph_store=store,
        web_target="https://app.client.invalid/login",
        candidates=[MySqlApplicator()],
    )
    mysql_bound = [b for b in bound if getattr(b.applicator, "service", "") == "mysql"]
    assert len(mysql_bound) == 1 and mysql_bound[0].target == _ENDPOINT


# ── T2: non-MySQL banner ⇒ no SERVICE node (anti-#3) ──────────────────────────────


def test_non_mysql_banner_writes_no_service_node() -> None:
    store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    auth, eid = _recon_engagement(event_store, db_endpoints=[_ENDPOINT])
    probe = _FakeProbe({(_HOST, _PORT): _SSH_BANNER})

    evidence = verify_in_scope_db_services(
        engagement_id=eid,
        auth=auth,
        scope_db_endpoints=[_ENDPOINT],
        graph_store=store,
        event_store=event_store,
        probe=probe,
        timeout_s=5.0,
    )
    assert evidence == []
    assert store.nodes_by_type(NodeType.SERVICE) == []


# ── T3: closed/filtered port ⇒ skip, no crash ────────────────────────────────────


def test_closed_port_is_skipped() -> None:
    store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    auth, eid = _recon_engagement(event_store, db_endpoints=[_ENDPOINT])
    probe = _FakeProbe({(_HOST, _PORT): ConnectionRefusedError("closed")})

    evidence = verify_in_scope_db_services(
        engagement_id=eid,
        auth=auth,
        scope_db_endpoints=[_ENDPOINT],
        graph_store=store,
        event_store=event_store,
        probe=probe,
        timeout_s=5.0,
    )
    assert evidence == []
    assert store.nodes_by_type(NodeType.SERVICE) == []


# ── T4: an out-of-scope endpoint is NEVER probed ─────────────────────────────────


def test_out_of_scope_endpoint_is_never_probed() -> None:
    store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    # SOW scopes 3306; caller is asked to consider 3399 (not in the signed scope).
    auth, eid = _recon_engagement(event_store, db_endpoints=[_ENDPOINT])
    off_scope = f"{_HOST}:3399"
    probe = _FakeProbe({(_HOST, 3399): _MYSQL_GREETING})

    evidence = verify_in_scope_db_services(
        engagement_id=eid,
        auth=auth,
        scope_db_endpoints=[off_scope],
        graph_store=store,
        event_store=event_store,
        probe=probe,
        timeout_s=5.0,
    )
    assert evidence == []
    assert probe.calls == [], "out-of-scope endpoint must never reach the probe transport"
    assert store.nodes_by_type(NodeType.SERVICE) == []


# ── T5: below RECON_ONLY ⇒ nothing probed (fail-closed) ──────────────────────────


def test_below_recon_tier_probes_nothing() -> None:
    store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="db_probe_lab", target=_HOST)  # CREATED, no recon
    probe = _FakeProbe({(_HOST, _PORT): _MYSQL_GREETING})

    evidence = verify_in_scope_db_services(
        engagement_id=rec.engagement_id,
        auth=auth,
        scope_db_endpoints=[_ENDPOINT],
        graph_store=store,
        event_store=event_store,
        probe=probe,
        timeout_s=5.0,
    )
    assert evidence == []
    assert probe.calls == []
