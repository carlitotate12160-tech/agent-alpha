# RED test for Phase-3 Step 3d — MySqlApplicator.apply (offensive body = GLM/Kimi).
#
# TARGET PATH ON #61:  tests/phase_3/test_mysql_applicator.py
# AUTHORED BY:         Claude (test/interface lane). The body under test is GLM/Kimi's.
# STATE TODAY:         RED — every behavioural test ERRORS because apply() raises
#                      NotImplementedError. It goes GREEN only when GLM lands a body that
#                      satisfies these assertions. That is the definition of "3d done".
#
# WHAT THIS PINS (the contract the offensive body MUST honour):
#   1. anti-Lyndon #3 (no false success): a connection that opens but does not PROVE
#      data access (auth reject, closed port, or empty verification read) => success=False.
#   2. verified success: a real authenticated read (non-empty schema list) => success=True
#      with access_level db_root|db_user and SAFE proof fields only.
#   3. invariant: the raw secret NEVER appears anywhere in the returned AuthResult.
#   4. the injected-connector seam: apply() drives the DB through the connector passed to
#      __init__ — no driver import at module load, fully testable without a live DB.
#   5. service routing: select_applicator picks MySqlApplicator for a "database" credential.
#
# THE CONNECTOR CONTRACT (Claude-owned seam — GLM's body calls EXACTLY this surface):
#   connector.connect(*, host, port, username, secret, timeout_s) -> conn
#       raises on closed port / auth reject (do NOT swallow into a truthy conn).
#   conn.databases() -> list[str]   # verification READ; non-empty == proven access.
#   conn.has_superuser_grant() -> bool   # access_level: True->db_root else db_user.
#   conn.server_version() -> str    # safe proof field.
#   conn.close() -> None            # called in finally.
#
# SHAPE-CONFIRM BEFORE RUNNING ON #61 (#2 — the mount is stale vs #61): re-confirm
# AuthResult fields, ResourceBudget signature, and the access/ package path against #61
# HEAD before trusting these imports; adjust import paths only, never the assertions.

from __future__ import annotations

import pytest

from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.applicator import AuthResult, select_applicator
from agent_alpha.tools.internal.access.mysql_applicator import MySqlApplicator

_SECRET = "S3cr3t-DB-Pa55!"  # the raw secret; assert it NEVER leaks into any AuthResult.
_BUDGET = ResourceBudget(max_requests=10, max_seconds=15.0, max_cost_usd=0.0)
_TARGET = "10.10.0.5:3306"  # in-scope ASSET host:port (bound by the factory, FLAW 2/3).


# ── Fakes implementing the Claude-owned connector seam ────────────────────────────


class _FakeConn:
    def __init__(self, *, databases: list[str], superuser: bool, version: str = "8.0.36"):
        self._databases = databases
        self._superuser = superuser
        self._version = version
        self.closed = False

    def databases(self) -> list[str]:
        return list(self._databases)

    def has_superuser_grant(self) -> bool:
        return self._superuser

    def server_version(self) -> str:
        return self._version

    def close(self) -> None:
        self.closed = True


class _Connector:
    """Connects successfully and hands back a pre-baked conn."""

    def __init__(self, conn: _FakeConn):
        self._conn = conn
        self.captured: dict[str, object] = {}

    def connect(self, *, host: str, port: int, username: str, secret: str, timeout_s: float):
        # Record what the body sent on the wire so we can assert host:port came from the
        # bound in-scope target, not the leaked DB_HOST.
        self.captured = {
            "host": host,
            "port": port,
            "username": username,
            "secret": secret,
            "timeout_s": timeout_s,
        }
        return self._conn


class _RejectingConnector:
    """Models a closed port OR an auth reject: connect() raises (driver behaviour)."""

    def __init__(self, exc: Exception):
        self._exc = exc

    def connect(self, **_kwargs):
        raise self._exc


class _SpyConnector:
    """Counts connect() calls — proves the guard fires BEFORE any wire packet."""

    def __init__(self) -> None:
        self.connect_calls = 0

    def connect(self, **_kwargs):
        self.connect_calls += 1
        raise AssertionError("guard failed: connect() reached the wire")


def _flatten(result: AuthResult) -> str:
    """Every stringifiable field of the result, joined — used by the no-leak assertion."""
    return repr(result)


# ── T1: anti-#3 — connection opens but proves nothing => NOT a success ─────────────


def test_open_connection_with_empty_schema_read_is_not_success():
    # databases() empty: the port answered and creds may even be valid, but we did not
    # PROVE readable data. "Did not raise" is not access (Lyndon #3).
    applicator = MySqlApplicator(connector=_Connector(_FakeConn(databases=[], superuser=False)))
    result = applicator.apply(username="root", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    assert result.success is False
    assert result.access_level == ""


@pytest.mark.parametrize(
    "exc",
    [ConnectionRefusedError("port closed"), RuntimeError("Access denied for user")],
)
def test_closed_port_or_auth_reject_returns_failure_not_crash(exc: Exception):
    applicator = MySqlApplicator(connector=_RejectingConnector(exc))
    result = applicator.apply(username="root", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    assert result.success is False
    assert result.service == "mysql"


# ── T2: verified success — real authenticated read => success + access_level ───────


def test_verified_root_access_returns_success_db_root():
    conn = _FakeConn(databases=["information_schema", "mysql", "clientdb"], superuser=True)
    applicator = MySqlApplicator(connector=_Connector(conn))
    result = applicator.apply(username="root", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    assert result.success is True
    assert result.access_level == "db_root"
    assert result.service == "mysql"
    assert result.confidence > 0.0
    assert conn.closed is True  # connection released in finally


def test_verified_nonroot_access_returns_success_db_user():
    conn = _FakeConn(databases=["information_schema", "appdb"], superuser=False)
    applicator = MySqlApplicator(connector=_Connector(conn))
    result = applicator.apply(username="app", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    assert result.success is True
    assert result.access_level == "db_user"


# ── T3: invariant — the raw secret never appears in the returned AuthResult ────────


def test_raw_secret_never_appears_in_result_on_success():
    conn = _FakeConn(databases=["mysql", "clientdb"], superuser=True)
    applicator = MySqlApplicator(connector=_Connector(conn))
    result = applicator.apply(username="root", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    assert _SECRET not in _flatten(result)


def test_raw_secret_never_appears_in_result_on_failure():
    applicator = MySqlApplicator(connector=_RejectingConnector(RuntimeError(f"denied {_SECRET}")))
    result = applicator.apply(username="root", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    # Even if a driver echoes the secret in its exception text, the body must scrub it.
    assert _SECRET not in _flatten(result)


# ── T4: the body connects to the BOUND in-scope target, not a leaked DB_HOST ───────


def test_apply_connects_to_the_bound_target_host_port():
    conn = _FakeConn(databases=["clientdb"], superuser=False)
    connector = _Connector(conn)
    applicator = MySqlApplicator(connector=connector)
    applicator.apply(username="app", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    # target "10.10.0.5:3306" is the factory-bound in-scope endpoint (FLAW 2): the body
    # must dial THAT, never re-resolve a host of its own choosing.
    assert connector.captured["host"] == "10.10.0.5"
    assert connector.captured["port"] == 3306


# ── T5: proof carries only safe fields (server version / schema names), not the secret ─


def test_proof_carries_safe_fields_only():
    conn = _FakeConn(databases=["information_schema", "clientdb"], superuser=True, version="8.0.36")
    applicator = MySqlApplicator(connector=_Connector(conn))
    result = applicator.apply(username="root", secret=_SECRET, target=_TARGET, budget=_BUDGET)
    proof = {**result.proof_request, **result.proof_response}
    flat = repr(proof)
    assert "8.0.36" in flat or "clientdb" in flat  # access was actually evidenced
    assert _SECRET not in flat
    assert "password" not in flat.lower()


# ── T6: service routing + tier (no live DB needed) ────────────────────────────────


def test_applies_to_db_credentials_only():
    applicator = MySqlApplicator()
    assert applicator.applies_to("database", _TARGET) is True
    assert applicator.applies_to("mysql", _TARGET) is True
    assert applicator.applies_to("http", "https://app.example") is False
    assert applicator.applies_to("", "https://app.example") is False


def test_required_auth_is_offensive_tier():
    applicator = MySqlApplicator()
    assert applicator.required_auth == "OFFENSIVE_APPROVED"
    assert applicator.service == "mysql"


def test_select_applicator_routes_database_credential_to_mysql():
    mysql = MySqlApplicator()
    chosen = select_applicator([mysql], credential_service="database", target=_TARGET)
    assert chosen is mysql


# ── T7: safety guard — empty-username fragment never reaches the wire (anti-#10) ────


def test_empty_username_never_connects() -> None:
    """A fragment node (username="") must NOT send any auth packet to the DB.
    Anonymous-MySQL is a separate capability that must be gated deliberately —
    never an accidental side-effect of the web chain's db_password fragment."""
    spy = _SpyConnector()
    res = MySqlApplicator(connector=spy).apply(
        username="", secret=_SECRET, target=_TARGET, budget=_BUDGET
    )
    assert res.success is False
    assert spy.connect_calls == 0  # zero auth packets to the DB server
    assert "fragment" in res.error.lower()
