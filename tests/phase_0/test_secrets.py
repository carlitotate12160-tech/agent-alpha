import logging

import pytest
from cryptography.fernet import Fernet

from agent_alpha.security.secrets import (
    DecryptionError,
    LogScrubber,
    SecretNotFoundError,
    SecretRecord,
    SecretsManager,
)


def test_no_key_generates_valid_fernet_key() -> None:
    manager = SecretsManager()
    key = manager.export_key()
    # A valid Fernet key can be used to construct a Fernet instance.
    Fernet(key)


def test_store_returns_record_with_encrypted_value() -> None:
    manager = SecretsManager()
    record = manager.store("db_password", "supersecret123", "eng_1")
    assert isinstance(record, SecretRecord)
    assert record.encrypted_value != b"supersecret123"


def test_retrieve_returns_original_plaintext() -> None:
    manager = SecretsManager()
    record = manager.store("api_key", "plaintext-value", "eng_1")
    assert manager.retrieve(record.secret_id) == "plaintext-value"


def test_encrypted_value_differs_from_plaintext_bytes() -> None:
    manager = SecretsManager()
    record = manager.store("token", "hunter2", "eng_1")
    assert record.encrypted_value != b"hunter2"


def test_retrieve_unknown_id_raises_not_found() -> None:
    manager = SecretsManager()
    with pytest.raises(SecretNotFoundError):
        manager.retrieve("secret_deadbeef")


def test_delete_then_retrieve_raises() -> None:
    manager = SecretsManager()
    record = manager.store("db_password", "secret", "eng_1")
    assert manager.delete(record.secret_id) is True
    with pytest.raises(SecretNotFoundError):
        manager.retrieve(record.secret_id)


def test_delete_nonexistent_returns_false() -> None:
    manager = SecretsManager()
    assert manager.delete("secret_00000000") is False


def test_list_labels_returns_labels_only() -> None:
    manager = SecretsManager()
    manager.store("db_password", "v1", "eng_1")
    manager.store("api_key", "v2", "eng_1")
    labels = manager.list_labels("eng_1")
    assert sorted(labels) == ["api_key", "db_password"]
    assert "v1" not in labels
    assert "v2" not in labels


def test_list_labels_filtered_by_engagement() -> None:
    manager = SecretsManager()
    manager.store("a", "v", "eng_1")
    manager.store("b", "v", "eng_2")
    assert manager.list_labels("eng_1") == ["a"]
    assert manager.list_labels("eng_2") == ["b"]
    assert manager.list_labels("eng_missing") == []


def test_cross_manager_decryption_fails() -> None:
    manager_a = SecretsManager()
    manager_b = SecretsManager()
    record = manager_a.store("db_password", "secret", "eng_1")
    # Inject A's record into B (which holds a different key).
    manager_b._secrets[record.secret_id] = record
    with pytest.raises(DecryptionError):
        manager_b.retrieve(record.secret_id)


def test_scrub_removes_password_pattern() -> None:
    scrubber = LogScrubber()
    out = scrubber.scrub("connecting with password=supersecret123")
    assert out == "connecting with [REDACTED]"


def test_scrub_removes_bearer_token() -> None:
    scrubber = LogScrubber()
    out = scrubber.scrub("Authorization: Bearer eyJhbGc...")
    assert out == "Authorization: [REDACTED]"


def test_scrub_is_idempotent() -> None:
    scrubber = LogScrubber()
    text = "password=secret token=abc123 Bearer eyJhbGc"
    once = scrubber.scrub(text)
    twice = scrubber.scrub(once)
    assert once == twice


def test_install_logging_filter_scrubs_records(caplog: pytest.LogCaptureFixture) -> None:
    scrubber = LogScrubber()
    scrubber.install_logging_filter()
    logger = logging.getLogger("audit_channel")
    with caplog.at_level(logging.INFO):
        logger.info("password=secret")
    captured = caplog.records[0].getMessage()
    assert "secret" not in captured
    assert captured == "[REDACTED]"


def test_export_key_roundtrip() -> None:
    manager = SecretsManager()
    record = manager.store("db_password", "roundtrip-value", "eng_1")
    exported = manager.export_key()

    restored = SecretsManager(key=exported)
    restored._secrets[record.secret_id] = record
    assert restored.retrieve(record.secret_id) == "roundtrip-value"
