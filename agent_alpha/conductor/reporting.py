from __future__ import annotations

from datetime import datetime, timezone

from agent_alpha.agents.omega.roaster import Omega, Report
from agent_alpha.events.store import EventStore
from agent_alpha.graph.store import GraphStore
from agent_alpha.memory.engagement import EngagementMemoryProjector, InMemoryEngagementMemoryStore


def build_engagement_report(
    graph_store: GraphStore,
    store: EventStore,
    engagement_id: str,
    *,
    style: str = "technical",
    target: str = "",
) -> Report:
    """Project the engagement memory record and generate the Omega report."""
    emr = EngagementMemoryProjector(store, InMemoryEngagementMemoryStore()).project(engagement_id)
    assessed_at = datetime.now(timezone.utc).strftime("%d %B %Y")
    return Omega(graph_store).generate_report(
        style=style,
        time_to_first_proof_s=emr.time_to_first_proof_s,
        blocked_hosts=emr.blocked_hosts,
        target=target,
        engagement_id=engagement_id,
        assessed_at=assessed_at,
    )
