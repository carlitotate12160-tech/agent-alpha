# tests/phase_3/test_postgres_secrets_vault.py
"""Phase-3 Step 2: Postgres shared vault — the multi-worker foundation.

These are INTEGRATION tests: they need a real Postgres reachable via
AGENT_ALPHA_PG_DSN under a NOSUPERUSER NOBYPASSRLS role (rls_guard fails closed
otherwise). Skipped when the DSN is absent (mirrors the other Postgres suites'
services-down skips). Run on Oracle ARM64 where Postgres is up.

What they pin:
1. Cross-INSTANCE retrieve — store via vault A, retrieve via a SEPARATE vault B
   (same DSN+key). This is the whole point: in-memory SecretsManager CANNOT do this
   (separate dicts), so it proves the chain can go multi-worker.
2. Encrypted at rest — the plaintext never appears in the stored column.
3. Tenant isolation — tenant B cannot retrieve tenant A's secret (RLS).
4. delete_engagement purges all of an engagement's secrets (engagement-end invariant).
"""

from __future__ import annotations

import os
import uuid

import pytest
from cryptography.fernet import Fernet

from agent_alpha.security.postgres_secrets_vault import PostgresSecretsVault
from agent_alpha.security.secrets import SecretNotFoundError

_DSN = os.environ.get("AGENT_ALPHA_PG_DSN")

pytestmark = pytest.mark.skipif(
    not _DSN,
    reason="AGENT_ALPHA_PG_DSN not set — Postgres vault integration tests need a live DB",
)


def _tenant() -> str:
    # Unique per test → RLS-scoped rows never collide across tests.
    return "t_" + uuid.uuid4().hex[:12]


def test_secret_survives_across_separate_vault_instances() -> None:
    key = Fernet.generate_key()
    tenant = _tenant()
    eng = "eng_" + uuid.uuid4().hex[:8]
    secret_value = "S3cr3t-db-pass-" + uuid.uuid4().hex

    writer = PostgresSecretsVault(_DSN, tenant, key)  # type: ignore[arg-type]
    record = writer.store(label="db_password", value=secret_value, engagement_id=eng)

    # A DIFFERENT instance (simulating another Celery worker) with the same key+DSN.
    reader = PostgresSecretsVault(_DSN, tenant, key)  # type: ignore[arg-type]
    assert reader.retrieve(record.secret_id) == secret_value

    writer.delete_engagement(eng)


def test_plaintext_is_never_stored_in_the_column() -> None:
    import psycopg

    key = Fernet.generate_key()
    tenant = _tenant()
    eng = "eng_" + uuid.uuid4().hex[:8]
    secret_value = "PlAinTextShouldNeverAppear-" + uuid.uuid4().hex

    vault = PostgresSecretsVault(_DSN, tenant, key)  # type: ignore[arg-type]
    record = vault.store(label="db_password", value=secret_value, engagement_id=eng)

    with psycopg.connect(_DSN, options=f"-c app.tenant_id={tenant}") as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT encrypted_value FROM vault_secrets WHERE tenant_id=%s AND secret_id=%s",
            (tenant, record.secret_id),
        )
        stored = bytes(cur.fetchone()[0])

    assert secret_value.encode() not in stored  # ciphertext, not plaintext

    vault.delete_engagement(eng)


def test_tenant_b_cannot_retrieve_tenant_a_secret() -> None:
    key = Fernet.generate_key()
    tenant_a, tenant_b = _tenant(), _tenant()
    eng = "eng_" + uuid.uuid4().hex[:8]

    vault_a = PostgresSecretsVault(_DSN, tenant_a, key)  # type: ignore[arg-type]
    record = vault_a.store(label="db_password", value="tenant-a-only", engagement_id=eng)

    vault_b = PostgresSecretsVault(_DSN, tenant_b, key)  # type: ignore[arg-type]
    with pytest.raises(SecretNotFoundError):
        vault_b.retrieve(record.secret_id)

    vault_a.delete_engagement(eng)


def test_delete_engagement_purges_all_secrets() -> None:
    key = Fernet.generate_key()
    tenant = _tenant()
    eng = "eng_" + uuid.uuid4().hex[:8]

    vault = PostgresSecretsVault(_DSN, tenant, key)  # type: ignore[arg-type]
    r1 = vault.store(label="a", value="v1", engagement_id=eng)
    r2 = vault.store(label="b", value="v2", engagement_id=eng)

    purged = vault.delete_engagement(eng)
    assert purged == 2
    with pytest.raises(SecretNotFoundError):
        vault.retrieve(r1.secret_id)
    with pytest.raises(SecretNotFoundError):
        vault.retrieve(r2.secret_id)
