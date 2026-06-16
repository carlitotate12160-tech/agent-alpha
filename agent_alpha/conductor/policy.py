# agent_alpha/conductor/policy.py
# ADR §8o-5: Policy-as-Code enforcement layer. All Rules of Engagement checks
# that Conductor performs before authorizing an agent action go through this
# module. No RoE logic exists elsewhere in the codebase. The policy is loaded
# once from agent_alpha/config/policy.yaml at initialization.

import dataclasses
import ipaddress
import pathlib
import typing

import yaml

from agent_alpha.config.constants import (
    SCOPE_ALWAYS_EXCLUDED,
)


class PolicyError(Exception):
    pass


class PolicyLoadError(PolicyError):
    pass


@dataclasses.dataclass(frozen=True)
class PolicyViolation:
    rule: str
    detail: str
    mitre_id: str | None = None


class PolicyEnforcer:
    """Enforces Rules of Engagement from policy.yaml.

    The policy is loaded once at initialization; all checks reference the
    in-memory parsed structure. Scope exclusions from constants and the YAML
    file are merged (union, no duplicates).
    """

    def __init__(self, policy_path: pathlib.Path | None = None) -> None:
        if policy_path is None:
            policy_path = pathlib.Path(__file__).resolve().parent.parent / "config" / "policy.yaml"
        try:
            with open(policy_path) as f:
                self._policy: dict[str, object] = yaml.safe_load(f)
        except FileNotFoundError as exc:
            raise PolicyLoadError(f"Policy file not found: {policy_path}") from exc
        except yaml.YAMLError as exc:
            raise PolicyLoadError(f"Invalid YAML in policy file: {policy_path}") from exc

        # Merge scope exclusions from constants and policy.yaml (union, no duplicates).
        yaml_excluded = set(
            typing.cast(
                list[str],
                typing.cast(dict[str, object], self._policy["scope"])["always_excluded_networks"],
            )
        )
        const_excluded = set(SCOPE_ALWAYS_EXCLUDED)
        self._excluded_networks = list(yaml_excluded | const_excluded)

    def check_technique(self, mitre_id: str) -> PolicyViolation | None:
        always_forbidden = typing.cast(
            list[dict[str, object]],
            typing.cast(dict[str, object], self._policy["excluded_techniques"])["always_forbidden"],
        )
        for technique in always_forbidden:
            tech_dict = typing.cast(dict[str, object], technique)
            if typing.cast(str, tech_dict["id"]).upper() == mitre_id.upper():
                return PolicyViolation(
                    rule="excluded_technique",
                    detail=typing.cast(str, tech_dict["reason"]),
                    mitre_id=typing.cast(str, tech_dict["id"]),
                )
        return None

    def check_scope(self, target: str) -> PolicyViolation | None:
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            try:
                target_net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                return None
            else:
                target_obj: ipaddress.IPv4Network | ipaddress.IPv6Network = target_net
        else:
            target_obj = ipaddress.ip_network(target_ip, strict=False)

        for excluded in self._excluded_networks:
            if target_obj in ipaddress.ip_network(excluded, strict=False):
                return PolicyViolation(
                    rule="excluded_network",
                    detail=f"Target {target} is in excluded network {excluded}",
                )
        return None

    def get_opsec_profile(self, profile_name: str) -> dict[str, object]:
        profiles: dict[str, object] = typing.cast(dict[str, object], self._policy["opsec_profiles"])
        if profile_name not in profiles:
            raise PolicyError(f"OPSEC profile '{profile_name}' not found")
        return typing.cast(dict[str, object], profiles[profile_name])

    def is_provider_allowed_for_payload(self, provider: str) -> bool:
        forbidden = typing.cast(
            list[str],
            typing.cast(dict[str, object], self._policy["llm_routing"])["payload_generation_forbidden_providers"],
        )
        return provider.lower() not in [f.lower() for f in forbidden]

    def requires_human_approval(self, transition_to: str) -> bool:
        conditions = typing.cast(
            list[dict[str, object]],
            typing.cast(dict[str, object], self._policy["authorization"])["human_approval_required_when"],
        )
        for condition in conditions:
            if condition.get("state_transition_to") == transition_to:
                return True
        return False
