# agent_alpha/agents/target_profile.py
"""TargetProfile — frozen read-only projection of tech-stack per host.

Phase 1a: profile-directed try_harder. This stays a THIN read-model over the
attack graph: source of truth is AssetProperties.tech_stack only. Step-2 OSINT
layers (waf_hint, dns, shodan, etc.) extend this same profile type; do not
introduce alternative profile classes.

Path selection lives in planner.try_harder via PATH_PROBE_CATALOG — this
dataclass is the host-specific INPUT to that selection, NOT the decision itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agent_alpha.graph.nodes import AssetProperties, NodeType

if TYPE_CHECKING:
    from agent_alpha.agents.world_model import WorldModel


@dataclass(frozen=True)
class TargetProfile:
    """Per-host tech profile projected from the WorldModel.

    The profile is read-only and derived solely from ASSET nodes whose
    properties.host matches *host*. It is intentionally minimal in this
    slice: step-2 OSINT / waf_hint fields extend this dataclass; keep it the
    ONE profile type used by planner and tools.
    """

    host: str
    tech_stack: frozenset[str]

    @classmethod
    def from_graph(cls, world_model: WorldModel, host: str) -> TargetProfile:
        """Collect tech_stack markers for *host* from ASSET nodes.

        PURE/read-only: iterates over world_model.all_beliefs() without
        mutating the graph store. All tech labels are normalised to
        lower-case strings.
        """

        labels: list[str] = []
        for node in world_model.all_beliefs():
            if node.type is not NodeType.ASSET:
                continue
            props = node.properties
            if isinstance(props, AssetProperties) and props.host == host:
                stack = getattr(props, "tech_stack", []) or []
                for entry in stack:
                    if not isinstance(entry, str):
                        continue
                    label = entry.lower()
                    if label not in labels:
                        labels.append(label)
        return cls(host=host, tech_stack=frozenset(labels))
