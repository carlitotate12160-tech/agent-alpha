"""Phase 0 — Policy-as-Code contract tests.

TEST CONTRACT (9 tests):
  1. yaml.safe_load(policy.yaml) → no error
  2. policy["version"] == "1.0"
  3. len(policy["excluded_techniques"]["always_forbidden"]) == 4
  4. "T1498" in [t["id"] for t in always_forbidden]
     "T1485" in [t["id"] for t in always_forbidden]
  5. policy["safe_in_production"]["data_destruction_allowed"] == False
  6. policy["scope"]["max_ips_per_engagement"] == 256
     (must match constants.MAX_SCOPE_IPS)
  7. "claude" in llm_routing["payload_generation_forbidden_providers"]
  8. policy["opsec_profiles"]["quiet"]["rate_limit_rps"] <
     policy["opsec_profiles"]["normal"]["rate_limit_rps"]
     policy["opsec_profiles"]["loud"]["rate_limit_rps"]
     (quiet < normal < loud — ordering must hold)
  9. all always_excluded_networks match constants.SCOPE_ALWAYS_EXCLUDED
     (consistency check between YAML and Python constants)

Run on Oracle ARM64 only (Rule 10).
"""
import yaml
from pathlib import Path

import pytest

from agent_alpha.config.constants import SCOPE_ALWAYS_EXCLUDED

POLICY_FILE = Path(__file__).resolve().parents[2] / "agent_alpha" / "config" / "policy.yaml"


@pytest.fixture(scope="module")
def policy():
    """Load policy.yaml once per module."""
    with open(POLICY_FILE, "r") as f:
        return yaml.safe_load(f)


def test_yaml_loads_cleanly(policy):
    """policy.yaml must be valid YAML (no syntax errors)."""
    assert policy is not None


def test_version(policy):
    """Policy version is exactly '1.0'."""
    assert policy["version"] == "1.0"


def test_always_forbidden_count(policy):
    """Exactly 4 techniques are always forbidden."""
    always_forbidden = policy["excluded_techniques"]["always_forbidden"]
    assert len(always_forbidden) == 4


def test_always_forbidden_includes_destructive_techniques(policy):
    """Always-forbidden list includes T1498 (DoS) and T1485 (data destruction)."""
    always_forbidden = policy["excluded_techniques"]["always_forbidden"]
    ids = [t["id"] for t in always_forbidden]
    assert "T1498" in ids
    assert "T1485" in ids


def test_data_destruction_not_allowed(policy):
    """safe_in_production.data_destruction_allowed is False."""
    assert policy["safe_in_production"]["data_destruction_allowed"] is False


def test_max_ips_matches_constants(policy):
    """max_ips_per_engagement matches constants.MAX_SCOPE_IPS (256)."""
    assert policy["scope"]["max_ips_per_engagement"] == 256


def test_claude_in_forbidden_providers(policy):
    """'claude' is in payload_generation_forbidden_providers."""
    forbidden = policy["llm_routing"]["payload_generation_forbidden_providers"]
    assert "claude" in forbidden


def test_opsec_profile_rate_limit_ordering(policy):
    """quiet < normal < loud rate limits (ordering must hold)."""
    quiet_rps = policy["opsec_profiles"]["quiet"]["rate_limit_rps"]
    normal_rps = policy["opsec_profiles"]["normal"]["rate_limit_rps"]
    loud_rps = policy["opsec_profiles"]["loud"]["rate_limit_rps"]
    assert quiet_rps < normal_rps < loud_rps


def test_always_excluded_networks_match_constants(policy):
    """always_excluded_networks matches constants.SCOPE_ALWAYS_EXCLUDED."""
    yaml_networks = set(policy["scope"]["always_excluded_networks"])
    const_networks = set(SCOPE_ALWAYS_EXCLUDED)
    assert yaml_networks == const_networks
