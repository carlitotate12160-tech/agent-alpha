"""Governance guard: enforce DSN↔VAULT_KEY paired configuration.

If AGENT_ALPHA_PG_DSN is set (Postgres-backed path), AGENT_ALPHA_VAULT_KEY
MUST also be set. A missing key manifests as a per-engagement "failed" —
a config error masquerading as a runtime failure (Lyndon #3).
Fail LOUD here instead.
"""

from __future__ import annotations

import os

import pytest


@pytest.mark.skipif(
    os.environ.get("AGENT_ALPHA_PG_DSN") is None,
    reason="Postgres-backed path not configured in this environment",
)
def test_pg_dsn_requires_vault_key() -> None:
    """If the Postgres store is configured, its vault key MUST also be present."""
    assert os.environ.get("AGENT_ALPHA_VAULT_KEY"), (
        "AGENT_ALPHA_PG_DSN is set but AGENT_ALPHA_VAULT_KEY is not — the Postgres vault "
        "cannot decrypt. Set both (matched pair) or neither."
    )
