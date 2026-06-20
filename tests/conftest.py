"""Top-level pytest config — CI guard against silent integration skips.

PLACEMENT MATTERS: this lives at tests/conftest.py (NOT tests/integration/),
because `pytest_configure` only fires for conftests loaded at startup. When CI
runs `pytest tests/`, a conftest under tests/integration/ is loaded lazily
during collection — AFTER pytest_configure — so a guard placed there would
silently never run. tests/conftest.py is an initial conftest and always fires.

WHAT IT DOES: on a dev laptop the integration tests skip without backends
(convenient). In CI that same skip is a green pass with zero DB coverage —
pipeline-level false success (Lyndon #3). Setting AGENT_ALPHA_REQUIRE_DB=1
(CI does) turns "backend missing or unreachable" into a HARD ERROR, so CI
cannot go green without actually exercising Postgres + Redis.
"""

from __future__ import annotations

import os

import pytest


def _require_db() -> bool:
    return os.environ.get("AGENT_ALPHA_REQUIRE_DB") == "1"


def pytest_configure(config: pytest.Config) -> None:
    if not _require_db():
        return

    problems: list[str] = []

    dsn = os.environ.get("AGENT_ALPHA_PG_DSN")
    if not dsn:
        problems.append("AGENT_ALPHA_PG_DSN is not set")
    else:
        try:
            import psycopg

            with psycopg.connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
        except Exception as exc:  # noqa: BLE001 — any failure must surface, not skip
            problems.append(f"Postgres unreachable: {exc}")

    url = os.environ.get("AGENT_ALPHA_REDIS_URL")
    if not url:
        problems.append("AGENT_ALPHA_REDIS_URL is not set")
    else:
        try:
            import redis

            redis.Redis.from_url(url, socket_connect_timeout=5).ping()
        except Exception as exc:  # noqa: BLE001
            problems.append(f"Redis unreachable: {exc}")

    if problems:
        raise pytest.UsageError(
            "AGENT_ALPHA_REQUIRE_DB=1 but integration backends are not usable — "
            "refusing to skip (that would be a false-success CI pass):\n  - "
            + "\n  - ".join(problems)
        )
