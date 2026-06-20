"""Contract: env-driven store selection keeps durable adapters wired (P2).

Hermetic — the Postgres branch is exercised by tests/integration/, here we only
prove the safe default (no DB -> in-memory) so the unit suite never touches a DB.
"""

from __future__ import annotations

import pytest

from agent_alpha.config.stores import PG_DSN_ENV, build_event_store
from agent_alpha.events.store import InMemoryEventStore


def test_build_event_store_defaults_to_in_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PG_DSN_ENV, raising=False)
    assert isinstance(build_event_store(), InMemoryEventStore)
