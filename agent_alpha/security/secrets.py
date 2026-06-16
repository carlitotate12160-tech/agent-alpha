# agent_alpha/security/secrets.py
# ADR §8l: Secrets vault. Harvested credentials and API keys are stored
# encrypted at rest and NEVER appear in plaintext in logs, events, or the
# attack graph. Phase 0 uses Fernet symmetric encryption (provided by the
# `cryptography` package); HashiCorp Vault integration is deferred to Phase 1+.
# LOG_SCRUB_PATTERNS from constants.py are enforced here via LogScrubber.

import dataclasses
import datetime
import logging
import os
import re

from cryptography.fernet import Fernet, InvalidToken

from agent_alpha.config.constants import (
    LOG_SCRUB_PATTERNS,
    SECRETS_ENCRYPTION_ALGO,
)

_REDACTED = "[REDACTED]"


class SecretsError(Exception):
    pass


class SecretNotFoundError(SecretsError):
    pass


class DecryptionError(SecretsError):
    pass


def _utcnow() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def _new_secret_id() -> str:
    return "secret_" + os.urandom(4).hex()


@dataclasses.dataclass(frozen=True)
class SecretRecord:
    secret_id: str
    label: str
    encrypted_value: bytes
    engagement_id: str
    created_at: str


class SecretsManager:
    """Encrypted, in-memory secrets vault.

    Plaintext values are never retained: only the encrypted ciphertext is held
    in :class:`SecretRecord`. The Fernet key is private and never logged.
    """

    # Intended algorithm family for the vault (surfaced for audit/metadata).
    encryption_algo = SECRETS_ENCRYPTION_ALGO

    def __init__(self, key: bytes | None = None) -> None:
        self._key: bytes = key if key is not None else Fernet.generate_key()
        self._fernet: Fernet = Fernet(self._key)
        self._secrets: dict[str, SecretRecord] = {}

    def store(self, label: str, value: str, engagement_id: str) -> SecretRecord:
        encrypted_value = self._fernet.encrypt(value.encode("utf-8"))
        record = SecretRecord(
            secret_id=_new_secret_id(),
            label=label,
            encrypted_value=encrypted_value,
            engagement_id=engagement_id,
            created_at=_utcnow(),
        )
        self._secrets[record.secret_id] = record
        return record

    def retrieve(self, secret_id: str) -> str:
        record = self._secrets.get(secret_id)
        if record is None:
            raise SecretNotFoundError(f"Secret '{secret_id}' not found")
        try:
            plaintext = self._fernet.decrypt(record.encrypted_value)
        except InvalidToken as exc:
            raise DecryptionError(f"Failed to decrypt secret '{secret_id}'") from exc
        return plaintext.decode("utf-8")

    def delete(self, secret_id: str) -> bool:
        if secret_id in self._secrets:
            del self._secrets[secret_id]
            return True
        return False

    def list_labels(self, engagement_id: str) -> list[str]:
        return [
            record.label
            for record in self._secrets.values()
            if record.engagement_id == engagement_id
        ]

    def export_key(self) -> bytes:
        return self._key


class LogScrubber:
    """Redacts sensitive values from log/event text using LOG_SCRUB_PATTERNS."""

    def __init__(self) -> None:
        self._patterns: list[re.Pattern[str]] = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in LOG_SCRUB_PATTERNS
        ]

    def scrub(self, text: str) -> str:
        scrubbed = text
        for pattern in self._patterns:
            scrubbed = pattern.sub(_REDACTED, scrubbed)
        return scrubbed

    def install_logging_filter(self) -> None:
        scrubber = self

        class _ScrubFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                record.msg = scrubber.scrub(record.getMessage())
                record.args = None
                return True

        logging.getLogger().addFilter(_ScrubFilter())
