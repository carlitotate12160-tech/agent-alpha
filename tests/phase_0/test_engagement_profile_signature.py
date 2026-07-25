from __future__ import annotations

import json
import os
import pytest

from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    ProfileSignatureError,
    dump_signed_profile,
    load_signed_profile,
)
from agent_alpha.security.secrets import get_profile_signing_key

# ── Fixtures ──────────────────────────────────────────────────

_VALID_DOMAIN = "quantum-laboratories.com"

@pytest.fixture(autouse=True)
def setup_env():
    os.environ["PROFILE_SIGNING_KEY"] = "1234567890123456789012345678901234567890123456789012345678901234"
    yield

# ── Tests ─────────────────────────────────────────────────────

def test_legacy_sha256_rejected(tmp_path) -> None:
    """Legacy unkeyed sha256 envelopes are rejected outright."""
    profile = EngagementProfile(
        engagement_id="eng-1",
        client_id="client-1",
        targets=frozenset({_VALID_DOMAIN}),
    )
    
    # Manually create legacy envelope
    envelope = {
        "profile": {
            "engagement_id": profile.engagement_id,
            "client_id": profile.client_id,
            "targets": list(profile.targets),
            "authorized_origins": list(profile.authorized_origins),
        },
        "sha256": "fakehash123",
    }
    
    path = tmp_path / "legacy.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    
    key = get_profile_signing_key()
    with pytest.raises(ProfileSignatureError, match="legacy unkeyed sha256 envelope rejected"):
        load_signed_profile(str(path), key=key)

def test_missing_hmac_rejected(tmp_path) -> None:
    """Envelope without hmac field is rejected."""
    profile = EngagementProfile(
        engagement_id="eng-1",
        client_id="client-1",
        targets=frozenset({_VALID_DOMAIN}),
    )
    
    envelope = {
        "profile": {
            "engagement_id": profile.engagement_id,
            "client_id": profile.client_id,
            "targets": list(profile.targets),
            "authorized_origins": list(profile.authorized_origins),
        }
    }
    
    path = tmp_path / "missing.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    
    key = get_profile_signing_key()
    with pytest.raises(ProfileSignatureError, match="missing hmac signature field"):
        load_signed_profile(str(path), key=key)

def test_tampered_hmac_rejected(tmp_path) -> None:
    """Tampering with the payload invalidates the HMAC signature."""
    profile = EngagementProfile(
        engagement_id="eng-1",
        client_id="client-1",
        targets=frozenset({_VALID_DOMAIN}),
    )
    
    key = get_profile_signing_key()
    envelope = dump_signed_profile(profile, key=key)
    
    # Tamper with the profile payload
    envelope["profile"]["targets"].append("evil.com")
    
    path = tmp_path / "tampered.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    
    with pytest.raises(ProfileSignatureError, match="signature mismatch"):
        load_signed_profile(str(path), key=key)
