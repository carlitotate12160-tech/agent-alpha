import tempfile

import pytest

from agent_alpha.conductor.policy import (
    PolicyEnforcer,
    PolicyError,
    PolicyLoadError,
    PolicyViolation,
)


def test_enforcer_loads_without_error() -> None:
    enforcer = PolicyEnforcer()
    assert enforcer is not None


def test_check_technique_forbidden() -> None:
    enforcer = PolicyEnforcer()
    violation = enforcer.check_technique("T1498")
    assert isinstance(violation, PolicyViolation)
    assert violation.rule == "excluded_technique"
    assert violation.mitre_id == "T1498"


def test_check_technique_allowed() -> None:
    enforcer = PolicyEnforcer()
    violation = enforcer.check_technique("T1059")
    assert violation is None


def test_check_technique_case_insensitive() -> None:
    enforcer = PolicyEnforcer()
    violation = enforcer.check_technique("t1498")
    assert isinstance(violation, PolicyViolation)
    assert violation.mitre_id == "T1498"


def test_check_scope_excluded() -> None:
    enforcer = PolicyEnforcer()
    violation = enforcer.check_scope("169.254.1.1")
    assert isinstance(violation, PolicyViolation)
    assert violation.rule == "excluded_network"


def test_check_scope_allowed() -> None:
    enforcer = PolicyEnforcer()
    violation = enforcer.check_scope("192.168.1.1")
    assert violation is None


def test_get_opsec_profile() -> None:
    enforcer = PolicyEnforcer()
    profile = enforcer.get_opsec_profile("quiet")
    assert profile["rate_limit_rps"] == 2


def test_get_opsec_profile_invalid() -> None:
    enforcer = PolicyEnforcer()
    with pytest.raises(PolicyError):
        enforcer.get_opsec_profile("invalid")


def test_provider_allowed_for_payload() -> None:
    enforcer = PolicyEnforcer()
    assert enforcer.is_provider_allowed_for_payload("deepseek-v4-pro") is True


def test_provider_forbidden_for_payload() -> None:
    enforcer = PolicyEnforcer()
    assert enforcer.is_provider_allowed_for_payload("claude") is False


def test_provider_check_case_insensitive() -> None:
    enforcer = PolicyEnforcer()
    assert enforcer.is_provider_allowed_for_payload("CLAUDE") is False


def test_kimi_26_allowed_for_payload() -> None:
    enforcer = PolicyEnforcer()
    assert enforcer.is_provider_allowed_for_payload("kimi-2.6") is True


def test_kimi_partial_match_not_allowed() -> None:
    enforcer = PolicyEnforcer()
    assert enforcer.is_provider_allowed_for_payload("kimi") is False


def test_requires_human_approval() -> None:
    enforcer = PolicyEnforcer()
    assert enforcer.requires_human_approval("OFFENSIVE_APPROVED") is True


def test_invalid_policy_path_raises() -> None:
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        pass
    with pytest.raises(PolicyLoadError):
        PolicyEnforcer(policy_path=tmp.name)
