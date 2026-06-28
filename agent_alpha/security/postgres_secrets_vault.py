# agent_alpha/security/postgres_secrets_vault.py
"""Postgres-backed shared secrets vault (Phase-3 Step 2).

WHY: SecretsManager (in-memory, per-instance Fernet key) only works single-process —
the cred-reuse CHAIN can be proven in a one-process harness but cannot run across Celery
workers (Alpha vaults in worker A, Beta retrieves in worker B). This backend shares the
ciphertext via Postgres and the Fernet KEY via one external source, so any worker with
the DSN + key can retrieve. Same store/retrieve/delete contract as SecretsManager
(SecretsVault Protocol — anti-Lyndon #6, one concept).

SECURITY:
* Tenant-isolated by Row-Level Security, mirroring PostgresEngagementMemoryStore:
  app.tenant_id connection option + FORCE RLS policy. A secret stored under tenant A
  CANNOT be retrieved under tenant B (proven in the RLS test). rls_guard fails closed if
  the DSN role can bypass RLS.
* The Fernet key comes from ONE external source (config.load_vault_key →
  AGENT_ALPHA_VAULT_KEY), NEVER generated per-instance — otherwise cross-worker decrypt
  is impossible. Single source of truth (#7).
* Plaintext is never stored: only Fernet ciphertext (bytea). Redaction elsewhere is
  unchanged; this is the one encrypted home for a reusable secret.

Claude lane (infra, non-offensive). Mirrors agent_alpha/memory/engagement.py exactly so
there is no second Postgres access pattern.
"""

from __future__ import annotations

import re
import typing

from cryptography.fernet import Fernet, InvalidToken

from agent_alpha.config.constants import SECRETS_ENCRYPTION_ALGO, VAULT_SECRETS_TABLE
from agent_alpha.security.secrets import (
    DecryptionError,
    SecretNotFoundError,
    SecretRecord,
    _new_secret_id,
    _utcnow,
)


class PostgresSecretsVault:
    """Encrypted, Postgres-backed, tenant-isolated secrets vault.

    Conforms to ``SecretsVault``. Construct one per (tenant) like the other
    Postgres stores; all rows are scoped to ``tenant_id`` via RLS.
    """

    _table = VAULT_SECRETS_TABLE
    encryption_algo = SECRETS_ENCRYPTION_ALGO

    def __init__(self, dsn: str, tenant_id: str, key: bytes) -> None:
        import psycopg  # lazy: unit suite never imports the driver

        from agent_alpha.storage.rls_guard import assert_role_cannot_bypass_rls

        if not re.fullmatch(r"[A-Za-z0-9_.-]+", tenant_id):
            raise ValueError(f"invalid tenant_id for RLS connection option: {tenant_id!r}")
        self._psycopg = psycopg
        self._dsn = dsn
        self._tenant_id = tenant_id
        self._fernet = Fernet(key)  # key from ONE external source — see config.load_vault_key
        self._conn_options = f"-c app.tenant_id={tenant_id}"
        self._ensure_schema()
        assert_role_cannot_bypass_rls(self._connect)

    def _connect(self) -> typing.Any:
        """Connection with app.tenant_id set so RLS scopes it to this tenant."""
        return self._psycopg.connect(self._dsn, options=self._conn_options)

    def _ensure_schema(self) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._table} (
                    tenant_id       text  NOT NULL,
                    secret_id       text  NOT NULL,
                    label           text  NOT NULL,
                    encrypted_value bytea NOT NULL,
                    engagement_id   text  NOT NULL,
                    created_at      text  NOT NULL,
                    PRIMARY KEY (tenant_id, secret_id)
                )
                """  # nosec B608 — table is a class constant
            )
            cur.execute(f"ALTER TABLE {self._table} ENABLE ROW LEVEL SECURITY")  # nosec B608
            cur.execute(f"ALTER TABLE {self._table} FORCE ROW LEVEL SECURITY")  # nosec B608
            cur.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {self._table}")  # nosec B608
            cur.execute(
                f"""
                CREATE POLICY tenant_isolation ON {self._table}
                    USING (tenant_id = current_setting('app.tenant_id', true))
                    WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
                """  # nosec B608 — table is a class constant
            )
            conn.commit()

    def store(self, label: str, value: str, engagement_id: str) -> SecretRecord:
        encrypted_value = self._fernet.encrypt(value.encode("utf-8"))
        record = SecretRecord(
            secret_id=_new_secret_id(),
            label=label,
            encrypted_value=encrypted_value,
            engagement_id=engagement_id,
            created_at=_utcnow(),
        )
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self._table} "  # nosec B608 — table is a class constant
                "(tenant_id, secret_id, label, encrypted_value, engagement_id, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    self._tenant_id,
                    record.secret_id,
                    record.label,
                    record.encrypted_value,
                    record.engagement_id,
                    record.created_at,
                ),
            )
            conn.commit()
        return record

    def retrieve(self, secret_id: str) -> str:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"SELECT encrypted_value FROM {self._table} "  # nosec B608 — table is a class constant
                "WHERE tenant_id = %s AND secret_id = %s",
                (self._tenant_id, secret_id),
            )
            row = cur.fetchone()
        if row is None:
            raise SecretNotFoundError(f"Secret '{secret_id}' not found")
        ciphertext = bytes(row[0])  # bytea -> memoryview/bytes; normalise
        try:
            plaintext = self._fernet.decrypt(ciphertext)
        except InvalidToken as exc:
            raise DecryptionError(f"Failed to decrypt secret '{secret_id}'") from exc
        return plaintext.decode("utf-8")

    def delete(self, secret_id: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"DELETE FROM {self._table} "  # nosec B608 — table is a class constant
                "WHERE tenant_id = %s AND secret_id = %s",
                (self._tenant_id, secret_id),
            )
            deleted = int(cur.rowcount)
            conn.commit()
        return deleted > 0

    def delete_engagement(self, engagement_id: str) -> int:
        """Purge every secret for an engagement (call on engagement end)."""
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"DELETE FROM {self._table} "  # nosec B608 — table is a class constant
                "WHERE tenant_id = %s AND engagement_id = %s",
                (self._tenant_id, engagement_id),
            )
            deleted = cur.rowcount
            conn.commit()
        return int(deleted)

    def list_labels(self, engagement_id: str) -> list[str]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"SELECT label FROM {self._table} "  # nosec B608 — table is a class constant
                "WHERE tenant_id = %s AND engagement_id = %s",
                (self._tenant_id, engagement_id),
            )
            return [row[0] for row in cur.fetchall()]
