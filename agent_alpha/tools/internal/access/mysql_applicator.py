# agent_alpha/tools/internal/access/mysql_applicator.py
"""MySqlApplicator — reuse a harvested credential against MySQL/MariaDB directly.

Phase-3 Step 3d. Claude owns this shell (protocol conformance, seam, applies_to);
the ``apply()`` body is GLM/Kimi's (offensive lane K21).

required_auth="OFFENSIVE_APPROVED" — the Conductor scope gate (applicator_factory)
guarantees ``target`` is an in-scope SOW DB endpoint before this applicator is bound.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.applicator import AuthResult

_MAX_SCHEMA_NAMES = 10


class _RealConn:
    """Wrapper around a raw pymysql connection — exposes the connector contract."""

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    def databases(self) -> list[str]:
        with self._raw.cursor() as cur:
            cur.execute("SHOW DATABASES")
            return [row[0] for row in cur.fetchall()]

    def has_superuser_grant(self) -> bool:
        with self._raw.cursor() as cur:
            cur.execute("SHOW GRANTS")
            grants_text = " ".join(str(row[0]) for row in cur.fetchall())
        return "ALL PRIVILEGES" in grants_text.upper() or "SUPER" in grants_text.upper()

    def server_version(self) -> str:
        return str(self._raw.get_server_info())

    def close(self) -> None:
        try:
            self._raw.close()
        except Exception:  # nosec B110 — cleanup, ignore close errors
            pass


class _RealConnector:
    """Lazy real-driver connector — constructed inside apply(), never at module load.

    Mirrors the repo's lazy ``import psycopg`` pattern. The real driver
    (pymysql) is imported INSIDE connect(), not at module level.
    """

    def connect(
        self, *, host: str, port: int, username: str, secret: str, timeout_s: float
    ) -> _RealConn:
        import pymysql

        raw = pymysql.connect(
            host=host,
            port=port,
            user=username,
            password=secret,
            connect_timeout=int(timeout_s),
        )
        return _RealConn(raw)


class MySqlApplicator:
    """Reuse a harvested credential against MySQL/MariaDB and PROVE data access.

    OFFENSIVE_APPROVED action. The Conductor scope gate already guarantees
    ``target`` is an in-scope SOW endpoint — do NOT re-resolve or choose a host.
    """

    service = "mysql"
    required_auth = "OFFENSIVE_APPROVED"

    def __init__(self, *, connector: Any | None = None) -> None:
        self._connector = connector

    def applies_to(self, credential_service: str, target: str) -> bool:
        return credential_service in ("mysql", "mariadb", "database")

    def apply(
        self, *, username: str, secret: str, target: str, budget: ResourceBudget
    ) -> AuthResult:
        def _scrub(text: str) -> str:
            return text.replace(secret, "***") if secret else text

        def _fail(error: str) -> AuthResult:
            return AuthResult(
                success=False,
                access_level="",
                service="mysql",
                confidence=0.0,
                proof_request={},
                proof_response={},
                error=_scrub(error),
            )

        # ── Safety guard (anti-#10): refuse empty-username DB auth ──
        # A fragment node (username="") is NOT a login credential. Anonymous-MySQL
        # is a separate capability that must be gated deliberately — never an
        # accidental side-effect of the web chain's db_password fragment reaching
        # the DB applicator. Single guard point (anti-Lyndon #7).
        if not username:
            return _fail("refusing empty-username DB auth (fragment node, not a login credential)")

        host, port_str = target.rsplit(":", 1)
        port = int(port_str)

        connector = self._connector
        if connector is None:
            connector = _RealConnector()

        conn: Any = None
        try:
            try:
                conn = connector.connect(
                    host=host,
                    port=port,
                    username=username,
                    secret=secret,
                    timeout_s=budget.max_seconds,
                )
            except Exception as exc:
                return _fail(str(exc))

            try:
                dbs = conn.databases()
            except Exception as exc:
                return _fail(str(exc))

            if not dbs:
                return _fail("empty schema read — no databases accessible")

            try:
                is_superuser = conn.has_superuser_grant()
            except Exception:
                is_superuser = False

            try:
                version = conn.server_version()
            except Exception:
                version = "unknown"

            access_level = "db_root" if is_superuser else "db_user"

            return AuthResult(
                success=True,
                access_level=access_level,
                service="mysql",
                confidence=0.85,
                proof_request={
                    "host": host,
                    "port": port,
                    "username": username,
                },
                proof_response={
                    "server_version": version,
                    "schema_count": len(dbs),
                    "schemas": dbs[:_MAX_SCHEMA_NAMES],
                },
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # nosec B110 — cleanup, ignore close errors
                    pass
