"""Playbook engine for RULE tier decision making."""

from __future__ import annotations

import dataclasses
import pathlib
import re
from typing import Any

import yaml

from agent_alpha.config import constants


@dataclasses.dataclass(frozen=True)
class PlaybookDecision:
    """Decision from playbook engine."""

    tool: str
    tier: str
    technique_id: str


@dataclasses.dataclass(frozen=True)
class PlaybookRule:
    """A single playbook rule."""

    name: str
    tool: str
    tier: str
    technique_id: str
    indicators: list[dict[str, str]]

    def matches(self, observation: dict[str, Any]) -> bool:
        """Check if this rule matches the observation."""
        body = observation.get("body", "")

        for indicator in self.indicators:
            if "body_contains" in indicator:
                if indicator["body_contains"] in body:
                    return True
            elif "body_regex" in indicator:
                if re.search(indicator["body_regex"], body) is not None:
                    return True

        return False


class PlaybookEngine:
    """Deterministic rule-based decision engine for known observations."""

    def __init__(self, rules: list[PlaybookRule]) -> None:
        self._rules = sorted(rules, key=lambda r: r.name)

    @classmethod
    def from_directory(cls, path: pathlib.Path) -> PlaybookEngine:
        """Load playbooks from a directory."""
        rules = []
        for playbook_file in path.glob("*.yaml"):
            rules.extend(cls._load_playbook(playbook_file))
        return cls(rules)

    @staticmethod
    def _load_playbook(path: pathlib.Path) -> list[PlaybookRule]:
        """Load rules from a single playbook YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        # Validate required keys
        required_keys = ["name", "match", "action"]
        for key in required_keys:
            if key not in data:
                raise ValueError(f"Playbook {path} missing required key: {key}")

        match = data["match"]
        if "any_indicator" not in match or not match["any_indicator"]:
            raise ValueError(f"Playbook {path} missing non-empty match.any_indicator")

        action = data["action"]
        for key in ["tool", "tier", "technique_id"]:
            if key not in action:
                raise ValueError(f"Playbook {path} missing action.{key}")

        # Validate tier is RULE
        if action["tier"] != constants.LLM_TIER_RULE:
            raise ValueError(
                f"Playbook {path} has invalid tier '{action['tier']}'; "
                f"must be '{constants.LLM_TIER_RULE}'"
            )

        return [
            PlaybookRule(
                name=data["name"],
                tool=action["tool"],
                tier=action["tier"],
                technique_id=action["technique_id"],
                indicators=match["any_indicator"],
            )
        ]

    def match(self, observation: dict[str, Any]) -> PlaybookDecision | None:
        """Find a matching rule for the observation."""
        for rule in self._rules:
            if rule.matches(observation):
                return PlaybookDecision(
                    tool=rule.tool,
                    tier=rule.tier,
                    technique_id=rule.technique_id,
                )
        return None
