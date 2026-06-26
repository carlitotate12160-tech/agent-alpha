# tests/integration/test_store_selection.py
"""Integration: build_event_store() selects a WORKING PostgresEventStore when
AGENT_ALPHA_PG_DSN is set — proving the wiring reaches the real backend."""

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip("psycopg")

pytestmark = pytest.mark.integration


def test_build_event_store_selects_working_postgres() -> None:
    if not os.environ.get("AGENT_ALPHA_PG_DSN"):
        pytest.skip("AGENT_ALPHA_PG_DSN not set — Postgres integration skipped")

    from agent_alpha.config.stores import build_event_store
    from agent_alpha.events.store import PostgresEventStore

    store = build_event_store()
    assert isinstance(store, PostgresEventStore)

    engagement_id = "eng_sel_" + uuid.uuid4().hex[:8]
    event = store.append("NODE_DISCOVERED", engagement_id, "alpha", {"x": 1})
    assert store.replay(engagement_id) == [event]
