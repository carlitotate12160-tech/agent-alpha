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


class _RealConnector:
    """Lazy real-driver connector — constructed inside apply(), never at module load.

    Mirrors the repo's lazy ``import psycopg`` pattern. The real driver
    (mysql.connector / pymysql / mysqlclient) is imported INSIDE the methods,
    not at module level.
    """

    def connect(
        self, *, host: str, port: int, username: str, secret: str, timeout_s: float
    ) -> Any:
        raise NotImplementedError

    def databases(self, conn: Any) -> list[str]:
        raise NotImplementedError

    def has_superuser_grant(self, conn: Any) -> bool:
        raise NotImplementedError

    def server_version(self, conn: Any) -> str:
        raise NotImplementedError

    def close(self, conn: Any) -> None:
        raise NotImplementedError


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
        raise NotImplementedError("MySqlApplicator.apply body — GLM/Kimi lane (K21)")
