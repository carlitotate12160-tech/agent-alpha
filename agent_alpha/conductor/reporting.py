from __future__ import annotations

from agent_alpha.agents.omega.roaster import Omega, Report
from agent_alpha.events.store import EventStore
from agent_alpha.graph.store import GraphStore
from agent_alpha.memory.engagement import EngagementMemoryProjector, InMemoryEngagementMemoryStore


def build_engagement_report(
    graph_store: GraphStore, store: EventStore, engagement_id: str, *, style: str = "technical"
) -> Report:
    """Project the engagement memory record and generate the Omega report."""
    emr = EngagementMemoryProjector(store, InMemoryEngagementMemoryStore()).project(engagement_id)
    return Omega(graph_store).generate_report(
        style=style, time_to_first_proof_s=emr.time_to_first_proof_s
    )
