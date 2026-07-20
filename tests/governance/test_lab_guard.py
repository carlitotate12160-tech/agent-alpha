"""Test suite for lab_guard provenance, expiry enforcement, and fail-closed behavior.

7 tests covering:
1. LabHost rejects empty ownership_proof
2. LAB_TARGET_ALLOWLIST is derived from _LAB_HOSTS (single source of truth)
3. assert_lab_only_target accepts a known lab host
4. assert_lab_only_target rejects a non-lab target (fail-closed)
5. assert_lab_only_target rejects an expired entry (fail-closed)
6. quantum-laboratories.com is IN the allowlist (re-added with ownership proof)
7. assert_lab_only_target rejects empty/invalid target
"""

from __future__ import annotations

import datetime as _dt

import pytest

from agent_alpha.live_fire.lab_guard import (
    LAB_TARGET_ALLOWLIST,
    LabHost,
    LabOnlyViolation,
    _LAB_HOSTS,
    assert_lab_only_target,
)


class TestLabHostProvenance:
    def test_lab_host_rejects_empty_ownership_proof(self) -> None:
        """LabHost with empty ownership_proof must raise ValueError."""
        with pytest.raises(ValueError, match="ownership_proof must be non-empty"):
            LabHost("evil.lab", "attacker", "", "#999")


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
            "expired-test.lab",
            "natanael",
            "test fixture",
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
                "https://expired-test.lab/path",
                allowlist=allowlist_with_expired,
            )

    def test_quantum_laboratories_in_allowlist(self) -> None:
        """quantum-laboratories.com is in the allowlist with ownership proof."""
        assert "quantum-laboratories.com" in LAB_TARGET_ALLOWLIST

    def test_rejects_empty_target(self) -> None:
        """An empty or invalid target must raise LabOnlyViolation."""
        with pytest.raises(LabOnlyViolation, match="empty/invalid"):
            assert_lab_only_target("")
