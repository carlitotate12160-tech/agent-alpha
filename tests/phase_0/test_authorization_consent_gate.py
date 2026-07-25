# tests/phase_0/test_authorization_consent_gate.py
# Phase 0 — Consent gate tests for authorize_engagement().
#
# Test contract:
#   Test 1 (#4): OFFENSIVE_APPROVED + consent_items=None → ConsentRequiredError.
#   Test 2 (#4): allow_evasion=True + no consent → ConsentRequiredError.
#   Test 3 (#4): opsec_stealth=True + no consent → ConsentRequiredError.
#   Test 4 (#4): OFFENSIVE_APPROVED + full consent → returns EngagementProfile.
#   Test 5 (#3): TXT contains token as substring but not exact → ownership FAILS.

from __future__ import annotations

import pytest

from agent_alpha.conductor.authorization import (
    ConsentRequiredError,
    authorize_engagement,
)
from agent_alpha.conductor.domain_verification import (
    DNSResolver,
    DomainOwnershipError,
    verify_domain_ownership,
)
from agent_alpha.conductor.engagement_profile import EngagementProfile

# ── Test fixtures ─────────────────────────────────────────────

_TEST_KEY = b"C" * 32  # 32-byte test signing key


# ── Test 1: OFFENSIVE_APPROVED without consent → RAISES ───────


def test_offensive_without_consent_raises() -> None:
    """OFFENSIVE_APPROVED + consent_items=None → ConsentRequiredError."""
    with pytest.raises(ConsentRequiredError, match="elevated authorization"):
        authorize_engagement(
            "OFFENSIVE_APPROVED",
            engagement_id="eng-no-consent",
            client_id="client-test",
            scope_targets=frozenset({"example.com"}),
            consent_items=None,
            signed_by=None,
            signed_at=None,
            key=_TEST_KEY,
        )


# ── Test 2: allow_evasion without consent → RAISES ────────────


def test_evasion_without_consent_raises() -> None:
    """allow_evasion=True + no consent → ConsentRequiredError."""
    with pytest.raises(ConsentRequiredError, match="elevated authorization"):
        authorize_engagement(
            "RECON_ONLY",
            engagement_id="eng-evasion",
            client_id="client-test",
            scope_targets=frozenset({"example.com"}),
            allow_evasion=True,
            consent_items=None,
            signed_by=None,
            signed_at=None,
            key=_TEST_KEY,
        )


# ── Test 3: opsec_stealth without consent → RAISES ────────────


def test_stealth_without_consent_raises() -> None:
    """opsec_stealth=True + no consent → ConsentRequiredError."""
    with pytest.raises(ConsentRequiredError, match="elevated authorization"):
        authorize_engagement(
            "RECON_ONLY",
            engagement_id="eng-stealth",
            client_id="client-test",
            scope_targets=frozenset({"example.com"}),
            opsec_stealth=True,
            consent_items=None,
            signed_by=None,
            signed_at=None,
            key=_TEST_KEY,
        )


# ── Test 4: OFFENSIVE_APPROVED with full consent → succeeds ───


def test_offensive_with_consent_returns_profile() -> None:
    """OFFENSIVE_APPROVED + full consent_items + signed_by + signed_at →
    returns EngagementProfile (isinstance assert)."""
    profile = authorize_engagement(
        "OFFENSIVE_APPROVED",
        engagement_id="eng-consented",
        client_id="client-ok",
        scope_targets=frozenset({"example.com"}),
        authorized_origins=frozenset({"198.51.0.10"}),
        allow_evasion=True,
        consent_items=frozenset({"origin-direct", "browser_solve", "OFFENSIVE_APPROVED"}),
        signed_by="human-operator@example.com",
        signed_at="2026-07-25T12:00:00Z",
        key=_TEST_KEY,
    )
    assert isinstance(profile, EngagementProfile)
    assert profile.authorization_level == "OFFENSIVE_APPROVED"
    assert profile.allow_evasion is True
    assert profile.consent is not None
    assert profile.consent.signed_by == "human-operator@example.com"
    assert "example.com" in profile.scope_targets


# ── Test 5: TXT exact match required (#3) ─────────────────────


class _SubstringResolver:
    """Fake DNS resolver that returns a TXT record containing the token
    as a SUBSTRING but not an exact match."""

    def __init__(self, records: list[str]) -> None:
        self._records = records

    def resolve_txt(self, domain: str) -> list[str]:
        return self._records


def test_txt_exact_match_required() -> None:
    """TXT record contains token as substring but not exact → ownership FAILS.
    Example: token='abc123', TXT record='prefix-abc123-suffix' → must FAIL."""
    resolver = _SubstringResolver(["prefix-abc123-suffix", "other-record"])

    with pytest.raises(DomainOwnershipError, match="ownership token not found"):
        verify_domain_ownership("example.com", "abc123", resolver)


def test_txt_exact_match_succeeds() -> None:
    """TXT record is exact match → ownership succeeds."""
    resolver = _SubstringResolver(["abc123", "other-record"])
    result = verify_domain_ownership("example.com", "abc123", resolver)
    assert result == "example.com"


def test_txt_exact_match_strips_quotes() -> None:
    """TXT record with surrounding quotes → stripped, then exact match."""
    resolver = _SubstringResolver(['"abc123"', "other-record"])
    result = verify_domain_ownership("example.com", "abc123", resolver)
    assert result == "example.com"
