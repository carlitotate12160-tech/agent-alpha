# Field-prove the DIRECT-DB cred-reuse chain (Phase-3 Step 3d, end-to-end contract).
#
# TARGET PATH ON #61:  tests/phase_3/test_db_chain_field_prove.py
# AUTHORED BY:         Claude (test/gate lane). Uses REAL auth + graph + factory +
#                      cred_reuse; the mysql BODY is GLM's (already landed) and is
#                      driven here through an injected fake connector (no live DB needed).
#
# WHY THIS FILE EXISTS — THE BLOCKER (grep-verified on #61 HEAD 5baf9f7):
#   The Conductor factory resolves a DB target from a SERVICE(mysql) node + the
#   asset's open_ports. But NOTHING in the live path writes either:
#     grep NodeType.SERVICE / open_ports  → only READ (factory), never WRITTEN.
#     scope.db_endpoints                  → only a gate-check list, never projected
#                                            into the graph.
#   So even at OFFENSIVE_APPROVED with the DB endpoint in the signed SOW, the mysql
#   applicator can NEVER be bound to a target on the live path = green-but-dead
#   (Lyndon #2). Field-proving the DB chain is BLOCKED on "piece 2": a step that
#   DISCOVERS + VERIFIES the in-scope DB service and writes SERVICE(mysql)+open_ports.
#   Its design (which auth tier verifies the port) touches the auth state machine
#   (non-negotiable) and is an OPEN DECISION — so piece-2's own RED test is deliberately
#   NOT written here yet.
#
# WHAT THIS FILE PINS TODAY:
#   T1  the dead seam itself (canary): with the DB endpoint in scope but no discovered
#       SERVICE node, the factory binds NO mysql target. GREEN now — documents the gap
#       and fails loudly the day someone claims the DB chain runs without piece 2.
#   T2  everything DOWNSTREAM of discovery is sound: GIVEN a discovered SERVICE(mysql)
#       node (seeded here to stand in for piece 2's output), the real factory binds the
#       mysql applicator to the in-scope host:port, cred_reuse retrieves Alpha's vaulted
#       secret and applies it, and the finding proves db_root tied to Alpha's cred node.
#       This is NOT proof of the live path (piece 2 absent) — it isolates the gap to
#       piece 2 exactly, so we don't mistake T2-green for "chain field-proven".
#
#   db_root chain severity (=HIGH) is already covered by test_chain_finding_severity
#   (db_root ∈ _HIGH_VALUE_ACCESS_LEVELS / _CRITICAL_ACCESS_LEVELS) — not duplicated here.
#
# SHAPE-CONFIRM ON #61 before trusting imports (#2): Scope/AuthorizationStateMachine,
# build_applicators_for_engagement, CredReuseTool, MySqlApplicator, TargetContext.

from __future__ import annotations

import datetime

from agent_alpha.conductor.applicator_factory import (
    build_applicators_for_engagement,
)
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    CredentialProperties,
    NodeType,
    ServiceProperties,
    node_to_dict,
)
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.contracts import ResourceBudget, TargetContext
from agent_alpha.tools.internal.access.mysql_applicator import MySqlApplicator

_HOST = "10.0.0.1"
_PORT = 3306
_DB_ENDPOINT = f"{_HOST}:{_PORT}"
_LEAKED_DB_SECRET = "leaked-db-pass-9021"
_WEB_TARGET = "https://app.client.invalid/login"
_CRED_ID = f"cred:{_HOST}:db_password"
_BUDGET = ResourceBudget(max_requests=10, max_seconds=15.0, max_cost_usd=0.0)


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"


# ── Fake MySQL connector seam (the mysql BODY is real; we inject a fake conn) ──────


class _FakeConn:
    def __init__(self, *, databases: list[str], superuser: bool) -> None:
        self._databases = databases
        self._superuser = superuser
        self.closed = False

    def databases(self) -> list[str]:
        return list(self._databases)

    def has_superuser_grant(self) -> bool:
        return self._superuser

    def server_version(self) -> str:
        return "8.4.10"

    def close(self) -> None:
        self.closed = True


class _RootConnector:
    """Connects successfully and proves db_root (non-empty schema read + superuser)."""

    def connect(self, *, host: str, port: int, username: str, secret: str, timeout_s: float):
        return _FakeConn(databases=["information_schema", "clientdb"], superuser=True)


# ── Shared setup: engagement at OFFENSIVE_APPROVED, DB endpoint in SOW scope ──────


def _offensive_engagement(store: NetworkXGraphStore, event_store: InMemoryEventStore):
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="db_chain_lab", target=_HOST)
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=["10.0.0.0/30"],
            domains=["app.client.invalid"],
            exclusions=[],
            db_endpoints=[_DB_ENDPOINT],  # the SOW explicitly scopes host:3306
        ),
    )
    auth.enable_active(rec.engagement_id)
    auth.enable_offensive(rec.engagement_id, b"SIGNED-SOW: authorized direct-DB test")
    return auth, rec.engagement_id


def _seed_cred_node(store: NetworkXGraphStore, secrets: SecretsManager, engagement_id: str) -> None:
    """Stand in for Alpha's recon output: a vaulted DB credential node."""
    record = secrets.store(
        label="mysql:DB_PASSWORD", value=_LEAKED_DB_SECRET, engagement_id=engagement_id
    )
    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(
                id=_CRED_ID,
                type=NodeType.CREDENTIAL,
                properties=CredentialProperties(
                    username="root",
                    secret_ref=record.secret_id,
                    service="mysql",
                    access_level="unverified",
                ),
                confidence=0.85,
                agent="alpha",
                timestamp_utc=_now(),
            )
        ),
    )


def _seed_asset(store: NetworkXGraphStore, *, open_ports: list[int]) -> None:
    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(
                id=f"asset:{_HOST}",
                type=NodeType.ASSET,
                properties=AssetProperties(host=_HOST, open_ports=open_ports),
                confidence=0.9,
                agent="alpha",
                timestamp_utc=_now(),
            )
        ),
    )


def _seed_discovered_db_service(store: NetworkXGraphStore) -> None:
    """PIECE 2's output, seeded by hand here: a VERIFIED mysql SERVICE node. In
    production nothing writes this yet — that is the gap T1 documents."""
    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(
                id=f"service:{_HOST}:{_PORT}",
                type=NodeType.SERVICE,
                properties=ServiceProperties(name="mysql", port=_PORT, protocol="tcp"),
                confidence=0.9,
                agent="alpha",
                timestamp_utc=_now(),
            )
        ),
    )


# ── T1: the dead seam — no discovered SERVICE node ⇒ NO mysql target bound ────────


def test_dead_seam_no_db_service_means_no_mysql_binding() -> None:
    """Canary: the DB endpoint is in the signed SOW scope and the engagement is
    OFFENSIVE_APPROVED, but because no SERVICE(mysql) node was discovered (and the
    asset exposes no port), the factory binds NO mysql target. This is the current
    live-path reality — proving the DB chain cannot run until piece 2 exists."""
    store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    auth, engagement_id = _offensive_engagement(store, event_store)
    _seed_cred_node(store, SecretsManager(), engagement_id)
    _seed_asset(store, open_ports=[])  # scout does not populate open_ports today

    bound = build_applicators_for_engagement(
        engagement_id=engagement_id,
        auth=auth,
        graph_store=store,
        web_target=_WEB_TARGET,
        candidates=[MySqlApplicator(connector=_RootConnector())],
    )

    mysql_targets = [b for b in bound if getattr(b.applicator, "service", "") == "mysql"]
    assert mysql_targets == [], (
        "factory bound a mysql target with no discovered SERVICE node — the dead "
        "seam was silently filled; re-verify piece 2 before trusting this."
    )


# ── T2: given piece-2 discovery, the whole downstream chain proves db_root ────────


def test_db_chain_proves_db_root_downstream_of_discovery() -> None:
    """GIVEN a discovered mysql SERVICE node (piece 2's output, seeded here), the real
    factory binds the mysql applicator to the in-scope host:port, cred_reuse retrieves
    Alpha's vaulted secret and applies it, and the finding proves db_root tied to
    Alpha's credential node.

    NOT proof of the live path: piece 2 (writing that SERVICE node) is unbuilt — this
    isolates the remaining gap to piece 2 alone (anti-Lyndon #2)."""
    from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool

    store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    secrets = SecretsManager()
    auth, engagement_id = _offensive_engagement(store, event_store)
    _seed_cred_node(store, secrets, engagement_id)
    _seed_asset(store, open_ports=[_PORT])
    _seed_discovered_db_service(store)  # ← piece 2's output

    bound = build_applicators_for_engagement(
        engagement_id=engagement_id,
        auth=auth,
        graph_store=store,
        web_target=_WEB_TARGET,
        candidates=[MySqlApplicator(connector=_RootConnector())],
    )

    # The factory must bind the mysql applicator to the IN-SCOPE endpoint — never a
    # leaked DB_HOST / localhost (FLAW 2). Verify the bound target is exactly host:port.
    mysql_bound = [b for b in bound if getattr(b.applicator, "service", "") == "mysql"]
    assert len(mysql_bound) == 1
    assert mysql_bound[0].target == _DB_ENDPOINT

    tool = CredReuseTool(
        applicators=list(bound),
        http_client=object(),  # non-None; the mysql path never touches it
        graph_store=store,
        secrets_manager=secrets,
    )
    ctx = TargetContext(engagement_id=engagement_id, tenant_id=None, target=_DB_ENDPOINT)
    result = tool.run(ctx, _BUDGET)

    assert result.success is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["access_level"] == "db_root"
    # The chain edge source must be Alpha's harvested credential node — not a silo.
    assert finding["credential_node_id"] == _CRED_ID
    # The raw secret must never surface in the finding.
    assert _LEAKED_DB_SECRET not in repr(finding)
