# tests/phase_0/test_engagement_authorization_gate.py
# Phase 6 — §12.36 signed EngagementProfile: production authorization gate tests.
#
# Test contract (from the spec):
#   1. test_profile_signature_covers_scope_and_consent
#   2. test_target_requires_ownership
#   3. test_out_of_scope_target_rejected
#   4. test_evasion_requires_capability
#   5. test_level_gates_agents
#   6. test_guardrail_overrides_consent
#   7. test_engagement_authorized_event_emitted
#   8. Existing lab_guard + authorized_origins tests stay green.

from __future__ import annotations

import pytest

from agent_alpha.conductor.authorization import authorize_engagement
from agent_alpha.conductor.domain_verification import (
    DomainOwnershipError,
)
from agent_alpha.conductor.engagement_profile import (
    AuthorizationLevelError,
    CapabilityNotAuthorizedError,
    ConsentRecord,
    EngagementProfile,
    GuardrailError,
    TargetNotInScopeError,
    assert_authorization_level,
    assert_capability_authorized,
    assert_not_guardrailed,
    assert_origin_authorized,
    assert_target_in_scope,
    dump_signed_profile,
    load_signed_profile,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore

# ── Test DNS resolver stub ─────────────────────────────────────


class StubDNSResolver:
    """Test DNS resolver that returns canned TXT records."""

    def __init__(self, txt_records: dict[str, list[str]]) -> None:
        self._records = txt_records

    def resolve_txt(self, domain: str) -> list[str]:
        return list(self._records.get(domain, []))


# ── Fixtures ──────────────────────────────────────────────────

_VALID_DOMAIN = "quantum-laboratories.com"
_VALID_TOKEN = "dns-txt:agent-alpha=verify-abc123"
_VALID_DNS = StubDNSResolver({
    "quantum-laboratories.com": ["agent-alpha=verify-abc123"],
})

_CONSENT = ConsentRecord(
    accepted_items=frozenset({"scope_confirmed", "techniques_authorized"}),
    signed_by="client-admin",
    signed_at="2026-07-24T10:00:00Z",
)


# ── 1. Signature covers scope + consent ────────────────────────


def test_profile_signature_covers_scope_and_consent() -> None:
    """Mutating scope_targets / a capability flag / the consent record
    changes sha256 → verify() fails."""
    base = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        consent=_CONSENT,
    )
    original_hash = base.sha256()

    # Mutate scope_targets → hash changes
    mutated_scope = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN, "extra.com"}),
        consent=_CONSENT,
    )
    assert mutated_scope.sha256() != original_hash
    assert mutated_scope.verify(original_hash) is False

    # Mutate capability flag → hash changes
    mutated_cap = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_evasion=True,
        consent=_CONSENT,
    )
    assert mutated_cap.sha256() != original_hash
    assert mutated_cap.verify(original_hash) is False

    # Mutate consent → hash changes
    mutated_consent = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        consent=ConsentRecord(
            accepted_items=frozenset({"different_item"}),
            signed_by="client-admin",
            signed_at="2026-07-24T10:00:00Z",
        ),
    )
    assert mutated_consent.sha256() != original_hash
    assert mutated_consent.verify(original_hash) is False


def test_same_profile_same_sha256() -> None:
    """Identical profiles (including new fields) → identical hash."""
    a = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_evasion=True,
        consent=_CONSENT,
    )
    b = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_evasion=True,
        consent=_CONSENT,
    )
    assert a.sha256() == b.sha256()


# ── 2. Target requires ownership ───────────────────────────────


def test_target_requires_ownership_success() -> None:
    """authorize_engagement succeeds when DNS-TXT ownership is proven."""
    profile, profile_hash = authorize_engagement(
        engagement_id="eng-001",
        client_id="client-1",
        targets=[_VALID_DOMAIN],
        ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
        dns_resolver=_VALID_DNS,
        consent_items=frozenset({"scope_confirmed"}),
        signed_by="admin",
        signed_at="2026-07-24T10:00:00Z",
    )
    assert profile.scope_targets == frozenset({_VALID_DOMAIN})
    assert profile_hash == profile.sha256()


def test_target_requires_ownership_failure() -> None:
    """authorize_engagement raises if DNS-TXT ownership is unproven."""
    bad_dns = StubDNSResolver({})  # no TXT records
    with pytest.raises(DomainOwnershipError, match="ownership not proven"):
        authorize_engagement(
            engagement_id="eng-001",
            client_id="client-1",
            targets=[_VALID_DOMAIN],
            ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
            dns_resolver=bad_dns,
        )


def test_target_requires_ownership_no_resolver() -> None:
    """authorize_engagement raises if no DNS resolver is injected."""
    with pytest.raises(DomainOwnershipError, match="no DNS resolver"):
        authorize_engagement(
            engagement_id="eng-001",
            client_id="client-1",
            targets=[_VALID_DOMAIN],
            ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
            dns_resolver=None,
        )


def test_target_requires_ownership_missing_token() -> None:
    """authorize_engagement raises if ownership token not provided for a target."""
    with pytest.raises(ValueError, match="no ownership token"):
        authorize_engagement(
            engagement_id="eng-001",
            client_id="client-1",
            targets=[_VALID_DOMAIN],
            ownership_tokens={},  # missing token
            dns_resolver=_VALID_DNS,
        )


# ── 3. Out-of-scope target rejected ────────────────────────────


def test_out_of_scope_target_rejected() -> None:
    """assert_target_in_scope raises for a target not in signed scope."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
    )
    assert_target_in_scope(_VALID_DOMAIN, profile)  # in scope → no raise

    with pytest.raises(TargetNotInScopeError, match="not in signed scope_targets"):
        assert_target_in_scope("evil-other.com", profile)


# ── 4. Evasion requires capability ─────────────────────────────


def test_evasion_requires_capability_refused() -> None:
    """origin-direct/evasion path is refused unless allow_evasion is set."""
    profile_no_evasion = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_evasion=False,
    )
    with pytest.raises(CapabilityNotAuthorizedError, match="not authorized"):
        assert_capability_authorized("evasion", profile_no_evasion)


def test_evasion_requires_capability_allowed() -> None:
    """With allow_evasion=True, the capability is authorized."""
    profile_with_evasion = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_evasion=True,
    )
    assert_capability_authorized("evasion", profile_with_evasion)  # no raise


def test_origin_direct_requires_evasion_capability() -> None:
    """origin_direct capability maps to allow_evasion flag."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        allow_evasion=False,
    )
    with pytest.raises(CapabilityNotAuthorizedError):
        assert_capability_authorized("origin_direct", profile)


# ── 5. Level gates agents ──────────────────────────────────────


def test_level_gates_beta_refused_under_recon_only() -> None:
    """Beta refused under RECON_ONLY."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        authorization_level="RECON_ONLY",
    )
    with pytest.raises(AuthorizationLevelError, match="BETA.*ACTIVE_APPROVED"):
        assert_authorization_level("BETA", profile)


def test_level_gates_beta_allowed_under_active_approved() -> None:
    """Beta permitted under ACTIVE_APPROVED."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        authorization_level="ACTIVE_APPROVED",
    )
    assert_authorization_level("BETA", profile)  # no raise


def test_level_gates_alpha_allowed_under_recon_only() -> None:
    """Alpha permitted under RECON_ONLY (minimum level)."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        authorization_level="RECON_ONLY",
    )
    assert_authorization_level("ALPHA", profile)  # no raise


def test_level_gates_gamma_refused_without_offensive() -> None:
    """Gamma tier refused unless OFFENSIVE_APPROVED."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        authorization_level="ACTIVE_APPROVED",
    )
    with pytest.raises(AuthorizationLevelError, match="GAMMA.*OFFENSIVE_APPROVED"):
        assert_authorization_level("GAMMA", profile)


def test_level_gates_gamma_allowed_under_offensive() -> None:
    """Gamma permitted under OFFENSIVE_APPROVED (but Gamma agent not built → no-op)."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        authorization_level="OFFENSIVE_APPROVED",
    )
    assert_authorization_level("GAMMA", profile)  # no raise — level OK, agent unbuilt


# ── 6. Guardrail overrides consent ─────────────────────────────


def test_guardrail_blocks_gov_tld() -> None:
    """A .gov target is blocked by assert_not_guardrailed even with consent."""
    with pytest.raises(GuardrailError, match="guarded TLD"):
        assert_not_guardrailed("whitehouse.gov")


def test_guardrail_blocks_mil_tld() -> None:
    with pytest.raises(GuardrailError, match="guarded TLD"):
        assert_not_guardrailed("army.mil")


def test_guardrail_blocks_edu_tld() -> None:
    with pytest.raises(GuardrailError, match="guarded TLD"):
        assert_not_guardrailed("mit.edu")


def test_guardrail_blocks_big_tech() -> None:
    """Well-known big-tech domain blocked even with full profile."""
    with pytest.raises(GuardrailError, match="big-tech"):
        assert_not_guardrailed("google.com")


def test_guardrail_blocks_big_tech_subdomain() -> None:
    """Subdomain of big-tech domain also blocked."""
    with pytest.raises(GuardrailError, match="big-tech"):
        assert_not_guardrailed("cloud.aws.amazon.com")


def test_guardrail_overrides_consent_in_authorize() -> None:
    """A .gov target is blocked by authorize_engagement EVEN with a fully
    signed, ownership-verified profile."""
    with pytest.raises(GuardrailError):
        authorize_engagement(
            engagement_id="eng-001",
            client_id="client-1",
            targets=["agency.gov"],
            ownership_tokens={"agency.gov": "dns-txt:agent-alpha=verify"},
            dns_resolver=StubDNSResolver({"agency.gov": ["agent-alpha=verify"]}),
            consent_items=frozenset({"all_consent"}),
            signed_by="admin",
            signed_at="2026-07-24T10:00:00Z",
        )


def test_guardrail_overrides_consent_in_target_in_scope() -> None:
    """assert_target_in_scope raises GuardrailError for .gov even if
    the target is in scope_targets."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({"agency.gov"}),  # somehow in scope
    )
    with pytest.raises(GuardrailError):
        assert_target_in_scope("agency.gov", profile)


# ── 7. ENGAGEMENT_AUTHORIZED event emitted ─────────────────────


def test_engagement_authorized_event_emitted() -> None:
    """authorize_engagement emits ENGAGEMENT_AUTHORIZED with hash + consent +
    verified targets (audit trail)."""
    store = InMemoryEventStore()
    profile, profile_hash = authorize_engagement(
        engagement_id="eng-001",
        client_id="client-1",
        targets=[_VALID_DOMAIN],
        ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
        dns_resolver=_VALID_DNS,
        consent_items=frozenset({"scope_confirmed", "techniques_authorized"}),
        signed_by="client-admin",
        signed_at="2026-07-24T10:00:00Z",
        authorization_level="ACTIVE_APPROVED",
        allow_evasion=True,
        event_store=store,
    )

    events = store.get_events("eng-001")
    auth_events = [e for e in events if e.event_type == EventType.ENGAGEMENT_AUTHORIZED]
    assert len(auth_events) == 1

    payload = auth_events[0].payload
    assert payload["sha256"] == profile_hash
    assert payload["verified_targets"] == [_VALID_DOMAIN]
    assert payload["authorization_level"] == "ACTIVE_APPROVED"
    assert payload["consent"]["signed_by"] == "client-admin"
    assert payload["capabilities"]["allow_evasion"] is True


def test_engagement_authorized_no_event_store() -> None:
    """authorize_engagement works without event_store (no event emitted)."""
    profile, profile_hash = authorize_engagement(
        engagement_id="eng-001",
        client_id="client-1",
        targets=[_VALID_DOMAIN],
        ownership_tokens={_VALID_DOMAIN: _VALID_TOKEN},
        dns_resolver=_VALID_DNS,
    )
    assert profile.sha256() == profile_hash


# ── 8. Existing lab_guard + authorized_origins tests stay green ─


def test_origin_authorized_with_scope_targets() -> None:
    """assert_origin_authorized works with scope_targets (production path)."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        authorized_origins=frozenset({"203.0.113.10"}),
    )
    # Using a custom lab_allowlist that does NOT contain the domain —
    # the scope_targets path should still authorize.
    assert_origin_authorized(
        origin_ip="203.0.113.10",
        fronted_host=_VALID_DOMAIN,
        profile=profile,
        lab_allowlist=frozenset(),  # empty — not in lab
    )  # no raise — scope_targets covers it


def test_origin_authorized_lab_allowlist_still_works() -> None:
    """Lab allowlist path still works for field-prove harnesses."""
    _test_allowlist = frozenset({"lab.example.com"})
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        authorized_origins=frozenset({"203.0.113.10"}),
    )
    assert_origin_authorized(
        origin_ip="203.0.113.10",
        fronted_host="lab.example.com",
        profile=profile,
        lab_allowlist=_test_allowlist,
    )  # no raise


def test_origin_authorized_neither_lab_nor_scope() -> None:
    """Fronted host in neither lab allowlist nor scope_targets → refused."""
    profile = EngagementProfile(
        engagement_id="eng-001",
        client_id="client-1",
        scope_targets=frozenset({_VALID_DOMAIN}),
        authorized_origins=frozenset({"203.0.113.10"}),
    )
    with pytest.raises(Exception, match="not a proven-owned target"):
        assert_origin_authorized(
            origin_ip="203.0.113.10",
            fronted_host="random-site.com",
            profile=profile,
            lab_allowlist=frozenset(),
        )


# ── Dump/load roundtrip with new fields ────────────────────────


def test_dump_load_roundtrip_with_new_fields(tmp_path) -> None:
    """dump_signed_profile → load_signed_profile preserves all new fields."""
    import json

    original = EngagementProfile(
        engagement_id="eng-rt",
        client_id="client-rt",
        targets=frozenset({"t1.example.com"}),
        authorized_origins=frozenset({"10.0.0.1"}),
        allow_evasion=True,
        scope_targets=frozenset({"t1.example.com"}),
        scope_mode="single",
        allow_subdomain_enum=True,
        opsec_stealth=True,
        include_root=True,
        authorization_level="ACTIVE_APPROVED",
        consent=ConsentRecord(
            accepted_items=frozenset({"item1", "item2"}),
            signed_by="admin",
            signed_at="2026-07-24T10:00:00Z",
        ),
    )
    envelope = dump_signed_profile(original)
    path = tmp_path / "roundtrip.signed.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    loaded = load_signed_profile(str(path))
    assert loaded == original
    assert loaded.scope_targets == frozenset({"t1.example.com"})
    assert loaded.allow_evasion is True
    assert loaded.authorization_level == "ACTIVE_APPROVED"
    assert loaded.consent.signed_by == "admin"
