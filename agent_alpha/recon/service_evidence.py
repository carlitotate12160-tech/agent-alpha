"""S1 service-evidence persistence collaborator extracted from Alpha."""

from __future__ import annotations

from typing import Any

from agent_alpha.graph.persist import persist_node
from agent_alpha.recon.origin_reach import maybe_fingerprint_flank
from agent_alpha.recon.service_fingerprint import get_merged_service_nodes


def detect_and_persist_service_evidence(alpha: Any, resp: Any, url: str) -> int:
    """Extract, flank when eligible, and persist canonical SERVICE evidence."""
    nodes = get_merged_service_nodes(resp, url)

    # §12.67-S1 fingerprint-flank: edge gave no version-bearing nodes on an
    # edge-fronted host → flank to origin for the real stack.
    nodes = maybe_fingerprint_flank(alpha, resp, url, nodes)

    engagement_id = alpha._engagement_id  # skipcq: PYL-W0212
    nodes_added = 0
    for sn in nodes:
        ex = alpha.graph_store.get_node(sn.id)
        # Version-priority: never clobber version-bearing with versionless.
        if (
            ex
            and getattr(ex.properties, "version", "")
            and not getattr(sn.properties, "version", "")
        ):
            continue
        if not ex:
            nodes_added += 1
        persist_node(alpha.event_store, alpha.graph_store, engagement_id, sn, agent="alpha")

    return nodes_added
