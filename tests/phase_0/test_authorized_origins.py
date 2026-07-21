# tests/phase_0/test_authorized_origins.py
# Phase A1 — Slice A: origin-authorization gate tests.
#
# Differential contract:
#   RED  before the gate  → OriginNotAuthorized
#   GREEN after the gate  → no raise
#
# Coverage:
#   1. Authorized origin + owned fronted host → passes
#   2. Origin NOT in authorized_origins → OriginNotAuthorized
#   3. Fronted host NOT in lab_allowlist → OriginNotAuthorized
#   4. authorized_origins changes the sha256 (proves it's signed)
#   5. Empty authorized_origins (default) → every origin refused (fail-closed)

from __future__ import annotations

import pytest

from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    OriginNotAuthorizedError,
    ProfileSignatureError,
    assert_origin_authorized,
    dump_signed_profile,
    load_signed_profile,
)

# ── Fixtures ──────────────────────────────────────────────────

# A small lab allowlist for test isolation (no dependency on live _LAB_HOSTS).
_TEST_ALLOWLIST: frozenset[str] = frozenset({"lab.example.com", "other-lab.test"})

_BASE_PROFILE = EngagementProfile(
    engagement_id="eng-001",
    client_id="client-42",
    targets=frozenset({"lab.example.com"}),
    authorized_origins=frozenset({"203.0.113.10"}),
)


# ── 1. Happy path: authorized origin + owned fronted host ─────


def test_authorized_origin_and_owned_host_passes() -> None:
    """Origin in signed authorized_origins + fronted host in allowlist → no raise."""
    assert_origin_authorized(
        origin_ip="203.0.113.10",
        fronted_host="lab.example.com",
        profile=_BASE_PROFILE,
        lab_allowlist=_TEST_ALLOWLIST,
    )  # no exception


# ── 2. Origin NOT in authorized_origins → OriginNotAuthorized ──


def test_origin_not_authorized_raises() -> None:
    """Origin IP absent from signed authorized_origins → OriginNotAuthorizedError."""
    with pytest.raises(OriginNotAuthorizedError, match="not in signed authorized_origins"):
        assert_origin_authorized(
            origin_ip="198.51.100.99",
            fronted_host="lab.example.com",
            profile=_BASE_PROFILE,
            lab_allowlist=_TEST_ALLOWLIST,
        )


# ── 3. Fronted host NOT in lab_allowlist → OriginNotAuthorized ─


def test_fronted_host_not_in_allowlist_raises() -> None:
    """Fronted host not in the lab target allowlist → refused even with valid origin."""
    with pytest.raises(OriginNotAuthorizedError, match="not a proven-owned target"):
        assert_origin_authorized(
            origin_ip="203.0.113.10",
            fronted_host="evil-client-site.com",
            profile=_BASE_PROFILE,
            lab_allowlist=_TEST_ALLOWLIST,
        )


# ── 4. authorized_origins changes the sha256 ──────────────────


def test_authorized_origins_changes_sha256() -> None:
    """Adding/removing an origin MUST change the profile hash — proves it is
    covered by the signature, not free-text metadata."""
    profile_a = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-42",
        targets=frozenset({"lab.example.com"}),
        authorized_origins=frozenset({"203.0.113.10"}),
    )
    profile_b = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-42",
        targets=frozenset({"lab.example.com"}),
        authorized_origins=frozenset({"203.0.113.10", "198.51.100.5"}),
    )
    assert profile_a.sha256() != profile_b.sha256()


def test_same_profile_same_sha256() -> None:
    """Identical profiles (including authorized_origins) → identical hash."""
    a = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-42",
        authorized_origins=frozenset({"10.0.0.1"}),
    )
    b = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-42",
        authorized_origins=frozenset({"10.0.0.1"}),
    )
    assert a.sha256() == b.sha256()


def test_verify_detects_tamper() -> None:
    """verify() returns False when the hash doesn't match the current state."""
    original_hash = _BASE_PROFILE.sha256()
    tampered = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-42",
        targets=frozenset({"lab.example.com"}),
        authorized_origins=frozenset(),  # tampered: origins removed
    )
    assert tampered.verify(original_hash) is False
    assert _BASE_PROFILE.verify(original_hash) is True


# ── 5. Empty authorized_origins → fail-closed ─────────────────


def test_empty_authorized_origins_refuses_all() -> None:
    """Default (empty) authorized_origins → every origin IP is refused."""
    empty_profile = EngagementProfile(
        engagement_id="eng-002",
        client_id="client-42",
        targets=frozenset({"lab.example.com"}),
        # authorized_origins defaults to frozenset()
    )
    with pytest.raises(OriginNotAuthorizedError, match="not in signed authorized_origins"):
        assert_origin_authorized(
            origin_ip="203.0.113.10",
            fronted_host="lab.example.com",
            profile=empty_profile,
            lab_allowlist=_TEST_ALLOWLIST,
        )


# ── Edge: fronted-host checked BEFORE origin ──────────────────


def test_fronted_host_checked_before_origin() -> None:
    """When both fronted_host and origin are invalid, the fronted-host check
    fires first (the cheaper, more categorical refusal)."""
    with pytest.raises(OriginNotAuthorizedError, match="not a proven-owned target"):
        assert_origin_authorized(
            origin_ip="198.51.100.99",
            fronted_host="not-a-lab.com",
            profile=_BASE_PROFILE,
            lab_allowlist=_TEST_ALLOWLIST,
        )


# ── Signed-profile loader / writer tests (CR-1 — verify() actually called) ───


def test_load_signed_profile_happy_path(tmp_path) -> None:
    """Valid signed JSON (built via dump_signed_profile) → returns a verified
    EngagementProfile with all fields intact."""
    import json

    profile = EngagementProfile(
        engagement_id="eng-happy",
        client_id="client-1",
        targets=frozenset({"lab.example.com"}),
        authorized_origins=frozenset({"203.0.113.10"}),
    )
    envelope = dump_signed_profile(profile)
    path = tmp_path / "good.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    loaded = load_signed_profile(str(path))
    assert loaded.engagement_id == "eng-happy"
    assert loaded.client_id == "client-1"
    assert loaded.targets == frozenset({"lab.example.com"})
    assert loaded.authorized_origins == frozenset({"203.0.113.10"})


def test_load_signed_profile_tamper_raises(tmp_path) -> None:
    """Profile JSON whose authorized_origins was edited after signing (sha256
    stale) → raises ProfileSignatureError."""
    import json

    profile = EngagementProfile(
        engagement_id="eng-tamper",
        client_id="client-1",
        targets=frozenset({"lab.example.com"}),
        authorized_origins=frozenset({"203.0.113.10"}),
    )
    envelope = dump_signed_profile(profile)

    # Tamper: sneak in an extra origin AFTER signing.
    envelope["profile"]["authorized_origins"].append("198.51.100.99")

    path = tmp_path / "tampered.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(ProfileSignatureError, match="signature mismatch"):
        load_signed_profile(str(path))


def test_dump_load_roundtrip(tmp_path) -> None:
    """dump_signed_profile → load_signed_profile returns an equal profile."""
    import json

    original = EngagementProfile(
        engagement_id="eng-rt",
        client_id="client-rt",
        targets=frozenset({"t1.example.com", "t2.example.com"}),
        authorized_origins=frozenset({"10.0.0.1", "10.0.0.2"}),
    )
    envelope = dump_signed_profile(original)
    path = tmp_path / "roundtrip.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    loaded = load_signed_profile(str(path))
    assert loaded == original
