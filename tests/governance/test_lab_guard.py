"""Test suite for lab_guard provenance, expiry enforcement, and fail-closed behavior.

7 tests covering:
1. LabHost rejects empty ownership_proof
2. LAB_TARGET_ALLOWLIST is derived from _LAB_HOSTS (single source of truth)
3. assert_lab_only_target accepts a known lab host
4. assert_lab_only_target rejects a non-lab target (fail-closed)
5. assert_lab_only_target rejects an expired entry (fail-closed)
6. Verbal-only domain add is rejected (prose-only proof not allowed)
7. quantum-laboratories.com carries verifiable proof OR is absent
"""

from __future__ import annotations

import datetime as _dt

import pytest

from agent_alpha.live_fire.lab_guard import (
    _LAB_HOSTS,
    LAB_TARGET_ALLOWLIST,
    LabHost,
    LabOnlyViolation,
    assert_lab_only_target,
)


class TestLabHostProvenance:
    def test_lab_host_rejects_empty_ownership_proof(self) -> None:
        """LabHost with empty ownership_proof must raise ValueError."""
        with pytest.raises(ValueError, match="ownership_proof must be non-empty"):
            LabHost("evil.lab", "attacker", "", "#999")

    def test_verbal_only_domain_add_is_rejected(self) -> None:
        """Routable domains with prose-only proof are rejected at construction."""
        with pytest.raises(ValueError, match="prose-only proofs rejected"):
            LabHost("example.com", "attacker", "I own this, trust me", "#999")

    def test_lab_host_requires_localhost_proof_for_lab_hosts(self) -> None:
        """*.lab hosts must use localhost: proof, not dns-txt or prose."""
        with pytest.raises(ValueError, match="must use 'localhost:' proof"):
            LabHost("vuln.lab", "attacker", "dns-txt:foo=bar", "#999")

    def test_ephemeral_host_requires_expires(self) -> None:
        """Ephemeral hosts (*.trycloudflare.com) must have expires set."""
        with pytest.raises(ValueError, match="ephemeral hosts must have expires"):
            LabHost("foo.trycloudflare.com", "attacker", "dns-txt:foo=bar", "#999")

    def test_ephemeral_host_requires_dns_txt_or_acme_proof(self) -> None:
        """Ephemeral hosts must use dns-txt or acme proof."""
        with pytest.raises(ValueError, match="must use 'dns-txt:' or 'acme:' proof"):
            LabHost(
                "foo.trycloudflare.com",
                "attacker",
                "prose proof",
                "#999",
                expires=_dt.date(2026, 12, 31),
            )

    def test_public_test_proof_accepted_for_routable_domain(self) -> None:
        """Routable domains with public-test: proof (named platform) are accepted."""
        host = LabHost(
            "demo.testfire.net",
            "public-test",
            "public-test:ibm-alfresco-demo",
            "#999",
        )
        assert host.host == "demo.testfire.net"

    def test_public_test_proof_rejects_empty_platform_name(self) -> None:
        """public-test: proof must name the platform (no bare 'public-test:')."""
        with pytest.raises(ValueError, match="must name the platform"):
            LabHost(
                "demo.testfire.net",
                "public-test",
                "public-test:",
                "#999",
            )


class TestSingleSourceOfTruth:
    def test_allowlist_derived_from_lab_hosts(self) -> None:
        """LAB_TARGET_ALLOWLIST must be exactly the set of hosts in _LAB_HOSTS."""
        expected = frozenset(h.host for h in _LAB_HOSTS)
        assert LAB_TARGET_ALLOWLIST == expected


class TestAssertLabOnlyTarget:
    def test_accepts_known_lab_host(self) -> None:
        """A host in the allowlist must pass without error."""
        assert_lab_only_target("https://vuln.odoo.lab/some/path")

    def test_rejects_non_lab_target(self) -> None:
        """A host not in the allowlist must raise LabOnlyViolation."""
        with pytest.raises(LabOnlyViolation, match="refusing non-lab target"):
            assert_lab_only_target("https://evil.example.com/wp-config.php.bak")

    def test_rejects_expired_entry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An expired LabHost entry must be refused (fail-closed)."""
        expired_host = LabHost(
            "expired-test.example.com",
            "natanael",
            "dns-txt:agent-alpha=verified",
            "#test",
            expires=_dt.date(2020, 1, 1),  # clearly in the past
        )
        # Patch _LAB_HOSTS to include the expired entry + all real entries
        monkeypatch.setattr(
            "agent_alpha.live_fire.lab_guard._LAB_HOSTS",
            (*_LAB_HOSTS, expired_host),
        )
        allowlist_with_expired = frozenset(h.host for h in (*_LAB_HOSTS, expired_host))
        with pytest.raises(LabOnlyViolation, match="refusing expired lab target"):
            assert_lab_only_target(
                "https://expired-test.example.com/path",
                allowlist=allowlist_with_expired,
            )

    def test_quantum_is_client_approved(self) -> None:
        """quantum-laboratories.com is client-approved (dns-txt proof attached)."""
        assert "quantum-laboratories.com" in LAB_TARGET_ALLOWLIST

    def test_rejects_empty_target(self) -> None:
        """An empty or invalid target must raise LabOnlyViolation."""
        with pytest.raises(LabOnlyViolation, match="empty/invalid"):
            assert_lab_only_target("")


def test_direct_alpha_ai_sibling_is_owned_lab_host() -> None:
    """direct.alpha-ai.web.id is self-owned (domain-level DNS-TXT proof) and must
    be an allowlisted lab host so the integrated field-prove can scope it — added
    with proof, NOT by loosening the guard."""
    assert "direct.alpha-ai.web.id" in LAB_TARGET_ALLOWLIST
    # passes the fail-closed gate (no raise) for both bare host and URL forms
    assert_lab_only_target("direct.alpha-ai.web.id")
    assert_lab_only_target("https://direct.alpha-ai.web.id/")


class TestPublicTestTargets:
    """Public test targets (PortSwigger, Acunetix, OWASP) are explicitly
    authorized by their platform ToS — no DNS-TXT needed. Used for T3-lite
    testing of new stack playbooks (GAP-001) against real internet responses."""

    def test_testfire_net_is_allowlisted(self) -> None:
        """demo.testfire.net (IBM/Alfresco JSP demo) is a public-test target."""
        assert "demo.testfire.net" in LAB_TARGET_ALLOWLIST
        assert_lab_only_target("https://demo.testfire.net/")

    def test_vulnweb_targets_are_allowlisted(self) -> None:
        """Acunetix vulnweb test sites are public-test targets."""
        assert "testaspnet.vulnweb.com" in LAB_TARGET_ALLOWLIST
        assert "testasp.vulnweb.com" in LAB_TARGET_ALLOWLIST
        assert "testphp.vulnweb.com" in LAB_TARGET_ALLOWLIST

    def test_juice_shop_is_allowlisted(self) -> None:
        """OWASP Juice Shop (SPA/Angular) is a public-test target."""
        assert "juice-shop.herokuapp.com" in LAB_TARGET_ALLOWLIST
        assert_lab_only_target("https://juice-shop.herokuapp.com/")

    def test_google_gruyere_is_allowlisted(self) -> None:
        """Google Gruyere (Python/App Engine) is a public-test target."""
        assert "google-gruyere.appspot.com" in LAB_TARGET_ALLOWLIST

    def test_public_test_targets_pass_assert(self) -> None:
        """All public-test targets must pass the fail-closed gate."""
        for host in [
            "demo.testfire.net",
            "testaspnet.vulnweb.com",
            "testasp.vulnweb.com",
            "testphp.vulnweb.com",
            "juice-shop.herokuapp.com",
            "google-gruyere.appspot.com",
        ]:
            assert_lab_only_target(f"https://{host}/")


def test_vercel_lab_is_owned_and_passes_gate() -> None:
    """vercel-lab.alpha-ai.web.id is a Vercel-hosted multi-IP origin lab.
    It must be in the allowlist and pass the fail-closed gate.
    """
    assert "vercel-lab.alpha-ai.web.id" in LAB_TARGET_ALLOWLIST
    assert_lab_only_target("https://vercel-lab.alpha-ai.web.id/")
