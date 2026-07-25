# tests/phase_0/test_engagement_profile_signature.py
# Phase 0 — Integrity hardening: keyed HMAC signature tests.
#
# Test contract:
#   Test 1 (#1, CARDINAL): forged profile with correct unkeyed SHA-256 → REJECTED.
#   Test 2 (#1): forged profile with HMAC of wrong key → REJECTED.
#   Test 3 (#1): real-key roundtrip (dump→load) → succeeds.
#   Test 4 (#1): legacy sha256 envelope → REJECTED (fail-closed).
#   Test 5 (#1): missing hmac field → REJECTED (fail-closed).
#   Test 6 (key): signing key too short → REJECTED.
#   Test 7 (#6): loopback origin → REJECTED before signing.
#   Test 8 (#6): private origin → REJECTED before signing.
#   Test 9 (#7): trailing dot normalised.

from __future__ import annotations

import hashlib
import json
import os

import pytest

from agent_alpha.conductor.authorization import (
    InvalidOriginError,
    _validate_origins,
)
from agent_alpha.conductor.domain_verification import _normalise_target
from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    ProfileSignatureError,
    dump_signed_profile,
    load_signed_profile,
)
from agent_alpha.security.secrets import SecretNotFoundError, get_profile_signing_key

# ── Test fixtures ─────────────────────────────────────────────

_REAL_KEY = b"A" * 32  # 32 bytes — minimum valid
_WRONG_KEY = b"B" * 32  # different 32-byte key


# ── Test 1 (CARDINAL): forgery with correct unkeyed SHA-256 ───


def test_forgery_with_unkeyed_hash_rejected(tmp_path) -> None:
    """Craft a profile dict with authorization_level=OFFENSIVE_APPROVED and a
    CORRECT UNKEYED sha256 → load_signed_profile RAISES ProfileSignatureError.

    This is the CARDINAL test — it MUST FAIL before the keyed-HMAC fix
    (forgery accepted) and PASS after (forgery rejected).
    """
    # Attacker crafts a profile with elevated authorization.
    profile_data = {
        "engagement_id": "eng-forged",
        "client_id": "attacker",
        "targets": [],
        "authorized_origins": [],
        "allow_evasion": True,
        "authorization_level": "OFFENSIVE_APPROVED",
        "scope_targets": ["victim.com"],
        "opsec_stealth": False,
        "consent": None,
    }
    # Compute canonical JSON the same way EngagementProfile does.
    canonical = json.dumps(profile_data, sort_keys=True, separators=(",", ":"))
    unkeyed_hash = hashlib.sha256(canonical.encode()).hexdigest()

    # Attacker writes envelope with unkeyed sha256 (the old forgeable format).
    envelope = {"profile": profile_data, "sha256": unkeyed_hash}
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    # Must be REJECTED — legacy sha256 envelope.
    with pytest.raises(ProfileSignatureError, match="legacy unkeyed sha256"):
        load_signed_profile(str(path), key=_REAL_KEY)


# ── Test 2: forgery with HMAC of wrong key ────────────────────


def test_forgery_with_wrong_key_rejected(tmp_path) -> None:
    """Profile signed with wrong key → load_signed_profile RAISES."""
    profile = EngagementProfile(
        engagement_id="eng-wrong-key",
        client_id="attacker",
        authorization_level="OFFENSIVE_APPROVED",
    )
    # Sign with WRONG key.
    envelope = dump_signed_profile(profile, key=_WRONG_KEY)
    path = tmp_path / "wrong_key.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    # Load with REAL key → mismatch.
    with pytest.raises(ProfileSignatureError, match="HMAC mismatch"):
        load_signed_profile(str(path), key=_REAL_KEY)


# ── Test 3: real-key roundtrip ────────────────────────────────


def test_roundtrip_with_real_key(tmp_path) -> None:
    """dump_signed_profile → load_signed_profile with the same key succeeds."""
    profile = EngagementProfile(
        engagement_id="eng-roundtrip",
        client_id="client-ok",
        targets=frozenset({"example.com"}),
        authorized_origins=frozenset({"198.51.0.10"}),
        authorization_level="RECON_ONLY",
    )
    envelope = dump_signed_profile(profile, key=_REAL_KEY)
    path = tmp_path / "roundtrip.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    loaded = load_signed_profile(str(path), key=_REAL_KEY)
    assert loaded == profile
    assert loaded.engagement_id == "eng-roundtrip"
    assert loaded.authorization_level == "RECON_ONLY"


# ── Test 4: legacy sha256 envelope → REJECTED ────────────────


def test_legacy_sha256_envelope_rejected(tmp_path) -> None:
    """Envelope with 'sha256' field (no 'hmac') → ProfileSignatureError.
    Fail-closed: no silent acceptance of unkeyed profiles."""
    profile_data = {
        "engagement_id": "eng-legacy",
        "client_id": "old-client",
        "targets": [],
        "authorized_origins": [],
        "allow_evasion": False,
        "authorization_level": "RECON_ONLY",
        "scope_targets": [],
        "opsec_stealth": False,
        "consent": None,
    }
    canonical = json.dumps(profile_data, sort_keys=True, separators=(",", ":"))
    envelope = {
        "profile": profile_data,
        "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
    }
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(ProfileSignatureError, match="legacy unkeyed sha256"):
        load_signed_profile(str(path), key=_REAL_KEY)


# ── Test 5: missing hmac field → REJECTED ─────────────────────


def test_missing_hmac_field_rejected(tmp_path) -> None:
    """Envelope missing both 'hmac' and 'sha256' → ProfileSignatureError."""
    envelope = {
        "profile": {
            "engagement_id": "eng-bare",
            "client_id": "bare-client",
            "targets": [],
            "authorized_origins": [],
            "allow_evasion": False,
        }
    }
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(ProfileSignatureError, match="missing 'hmac' field"):
        load_signed_profile(str(path), key=_REAL_KEY)


# ── Test 6: signing key too short ─────────────────────────────


def test_signing_key_too_short_rejected(monkeypatch) -> None:
    """PROFILE_SIGNING_KEY that decodes to <32 bytes → SecretNotFoundError."""
    # 16 hex chars = 8 bytes — way too short.
    monkeypatch.setenv("PROFILE_SIGNING_KEY", "abcd" * 4)
    with pytest.raises(SecretNotFoundError, match="too short"):
        get_profile_signing_key()


# ── Test 7: loopback origin → REJECTED (#6) ──────────────────


def test_authorized_origins_invalid_loopback() -> None:
    """authorized_origins={'127.0.0.1'} → InvalidOriginError before signing."""
    with pytest.raises(InvalidOriginError, match="not a public routable"):
        _validate_origins(frozenset({"127.0.0.1"}))


# ── Test 8: private origin → REJECTED (#6) ────────────────────


def test_authorized_origins_invalid_private() -> None:
    """authorized_origins={'10.0.0.5'} → InvalidOriginError before signing."""
    with pytest.raises(InvalidOriginError, match="not a public routable"):
        _validate_origins(frozenset({"10.0.0.5"}))


# ── Test 9: trailing dot normalised (#7) ──────────────────────


def test_trailing_dot_normalised() -> None:
    """'evil.com.' normalised to 'evil.com' — prevents guardrail bypass."""
    assert _normalise_target("evil.com.") == "evil.com"
    assert _normalise_target("  Evil.COM.  ") == "evil.com"
    assert _normalise_target("normal.com") == "normal.com"
