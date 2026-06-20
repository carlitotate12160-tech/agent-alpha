"""Unit + integration tests for agent_alpha.storage.rls_guard.

Unit test (always runs):
  Mocks psycopg to return superuser/bypass flags and asserts the guard
  raises RlsNotEnforcedError. No real DB needed.

Integration test (only with AGENT_ALPHA_SUPERUSER_DSN):
  Connects with a real superuser DSN and asserts both PostgresEventStore
  and PostgresEngagementMemoryStore refuse to construct.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from agent_alpha.storage.rls_guard import (
    RlsNotEnforcedError,
    assert_role_cannot_bypass_rls,
)


# ── Unit tests (no DB required) ──────────────────────────────────────


def _mock_connect(is_superuser: str, bypass_rls: bool, role: str = "test_role"):
    """Return a Callable[[], Connection] that yields canned flag values."""

    class _FakeCursor:
        def execute(self, _sql):
            pass

        def fetchone(self):
            return (role, is_superuser, bypass_rls)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    class _FakeConn:
        def cursor(self):
            return _FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    return lambda: _FakeConn()


def test_guard_passes_for_safe_role() -> None:
    """A role with is_superuser='off' and rolbypassrls=False is OK."""
    assert_role_cannot_bypass_rls(_mock_connect("off", False))


def test_guard_rejects_superuser() -> None:
    with pytest.raises(RlsNotEnforcedError, match="is_superuser='on'"):
        assert_role_cannot_bypass_rls(_mock_connect("on", False))


def test_guard_rejects_bypass_rls() -> None:
    with pytest.raises(RlsNotEnforcedError, match="rolbypassrls=True"):
        assert_role_cannot_bypass_rls(_mock_connect("off", True))


def test_guard_rejects_both_flags() -> None:
    with pytest.raises(RlsNotEnforcedError, match="can bypass Row-Level Security"):
        assert_role_cannot_bypass_rls(_mock_connect("on", True))


def test_error_message_names_role() -> None:
    with pytest.raises(RlsNotEnforcedError, match="my_bad_role"):
        assert_role_cannot_bypass_rls(
            _mock_connect("on", False, role="my_bad_role")
        )


# ── Integration: construct-as-superuser raises ───────────────────────

_SUPERUSER_DSN = os.environ.get("AGENT_ALPHA_SUPERUSER_DSN")


@pytest.mark.integration
@pytest.mark.skipif(
    not _SUPERUSER_DSN,
    reason="AGENT_ALPHA_SUPERUSER_DSN not set — superuser guard integration skipped",
)
class TestSuperuserDsnRejected:
    """Under a real superuser DSN, both Postgres stores must refuse to init."""

    def test_event_store_rejects_superuser_dsn(self) -> None:
        pytest.importorskip("psycopg")
        from agent_alpha.events.store import PostgresEventStore

        with pytest.raises(RlsNotEnforcedError):
            PostgresEventStore(dsn=_SUPERUSER_DSN, tenant_id="guard_test")

    def test_engagement_store_rejects_superuser_dsn(self) -> None:
        pytest.importorskip("psycopg")
        from agent_alpha.memory.engagement import PostgresEngagementMemoryStore

        with pytest.raises(RlsNotEnforcedError):
            PostgresEngagementMemoryStore(dsn=_SUPERUSER_DSN, tenant_id="guard_test")
