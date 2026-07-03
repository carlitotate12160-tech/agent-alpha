"""RED tests for the permanent lab-only guard on field-prove harnesses.

The guard is a PERMANENT structural control (never removed in production): a
field-prove harness self-authorizes and must therefore never be pointed at a
client/prod domain. These tests pin fail-closed behaviour.
"""

from __future__ import annotations

import pytest

from agent_alpha.live_fire.lab_guard import (
    LAB_TARGET_ALLOWLIST,
    LabOnlyViolation,
    assert_lab_only_target,
)

LAB = "agentalpha.duckdns.org"
ONLY_LAB = frozenset({LAB})


def test_registered_lab_target_allowed() -> None:
    # Must not raise.
    assert_lab_only_target(LAB, ONLY_LAB)


def test_registered_lab_with_scheme_and_path_allowed() -> None:
    assert_lab_only_target("https://agentalpha.duckdns.org/assets/app.lab001.js", ONLY_LAB)


def test_registered_lab_with_port_and_creds_allowed() -> None:
    assert_lab_only_target("https://user@agentalpha.duckdns.org:443/", ONLY_LAB)


def test_client_target_refused() -> None:
    with pytest.raises(LabOnlyViolation):
        assert_lab_only_target("quantum-laboratories.com", ONLY_LAB)


def test_fail_closed_empty_allowlist_refuses_even_a_lab_host() -> None:
    with pytest.raises(LabOnlyViolation):
        assert_lab_only_target(LAB, frozenset())


def test_empty_target_refused() -> None:
    with pytest.raises(LabOnlyViolation):
        assert_lab_only_target("", ONLY_LAB)


def test_bare_ip_refused() -> None:
    with pytest.raises(LabOnlyViolation):
        assert_lab_only_target("203.0.113.10", ONLY_LAB)


def test_lookalike_suffix_refused() -> None:
    # An attacker-controlled look-alike must not pass via substring/suffix.
    with pytest.raises(LabOnlyViolation):
        assert_lab_only_target("agentalpha.duckdns.org.evil.com", ONLY_LAB)


def test_shipped_default_allowlist_has_no_client_domain() -> None:
    # Regression guard: the committed default must never contain a client host.
    assert "quantum-laboratories.com" not in LAB_TARGET_ALLOWLIST
    assert LAB in LAB_TARGET_ALLOWLIST
