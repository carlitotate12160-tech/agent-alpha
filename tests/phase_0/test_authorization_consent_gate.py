from __future__ import annotations

import os
import pytest

from agent_alpha.conductor.authorization import authorize_engagement, ConsentRequiredError, InvalidOriginError
from agent_alpha.conductor.engagement_profile import ConsentRecord
from agent_alpha.events.store import InMemoryEventStore

# ── Fixtures ──────────────────────────────────────────────────

_VALID_DOMAIN = "quantum-laboratories.com"
_VALID_TOKEN = "dns-txt:agent-alpha=verify-abc123"

class StubDNSResolver:
    def __init__(self, txt_records: dict[str, list[str]]) -> None:
        self._records = txt_records

    def resolve_txt(self, domain: str) -> list[str]:
        return list(self._records.get(domain, []))

_VALID_DNS = StubDNSResolver({
    "quantum-laboratories.com": ["agent-alpha=verify-abc123"],
})

# Fake key for tests
_TEST_KEY = b"12345678901234567890123456789012"

# ── Tests ─────────────────────────────────────────────────────

def test_consent_gate_requires_consent_for_active() -> None:
    """ACTIVE_APPROVED requires explicit consent."""
    with pytest.raises(ConsentRequiredError, match="strictly requires explicit consent"):
        authorize_engagement(
            engagement_id="eng-1",
            client_id="client-1",
            targets=[_VALID_DOMAIN],
            authorization_level="ACTIVE_APPROVED",
            ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
            dns_resolver=_VALID_DNS,
            key=_TEST_KEY,
        )

def test_consent_gate_requires_consent_for_offensive() -> None:
    """OFFENSIVE_APPROVED requires explicit consent."""
    with pytest.raises(ConsentRequiredError, match="strictly requires explicit consent"):
        authorize_engagement(
            engagement_id="eng-1",
            client_id="client-1",
            targets=[_VALID_DOMAIN],
            authorization_level="OFFENSIVE_APPROVED",
            ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
            dns_resolver=_VALID_DNS,
            key=_TEST_KEY,
        )

def test_consent_gate_requires_consent_for_evasion() -> None:
    """allow_evasion requires explicit consent."""
    with pytest.raises(ConsentRequiredError, match="strictly requires explicit consent"):
        authorize_engagement(
            engagement_id="eng-1",
            client_id="client-1",
            targets=[_VALID_DOMAIN],
            authorization_level="RECON_ONLY",
            allow_evasion=True,
            ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
            dns_resolver=_VALID_DNS,
            key=_TEST_KEY,
        )

def test_consent_gate_passes_with_consent() -> None:
    """With valid consent, elevated capabilities are authorized."""
    os.environ["PROFILE_SIGNING_KEY"] = "1234567890123456789012345678901234567890123456789012345678901234"
    profile = authorize_engagement(
        engagement_id="eng-1",
        client_id="client-1",
        targets=[_VALID_DOMAIN],
        authorization_level="ACTIVE_APPROVED",
        allow_evasion=True,
        consent_items=frozenset({"scope_confirmed"}),
        signed_by="admin",
        signed_at="2026-07-24T10:00:00Z",
        ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
        dns_resolver=_VALID_DNS,
        key=_TEST_KEY,
    )
    assert profile.authorization_level == "ACTIVE_APPROVED"
    assert profile.allow_evasion is True
    assert profile.consent.signed_by == "admin"

def test_validate_origins_rejects_private_ips() -> None:
    """Anti-SSRF: Loopback and private IPs are rejected as origins."""
    with pytest.raises(InvalidOriginError, match="not globally routable"):
        authorize_engagement(
            engagement_id="eng-1",
            client_id="client-1",
            targets=[_VALID_DOMAIN],
            authorized_origins=frozenset({"127.0.0.1"}),
            ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
            dns_resolver=_VALID_DNS,
            key=_TEST_KEY,
        )
