# agent_alpha/conductor/blast_gate.py
"""Blast-radius approval gate (GAP-005/006 slice-1, ADR §1 blast-radius gate).

Wires the ALREADY-IMPLEMENTED `calculate_blast_radius` (graph analytics) into the
Conductor DECISION path — previously it fed only the Omega report (GAP-006). The
gate is SECONDARY to the auth-tier gate: an offensive-tier agent
(ANCHOR/HUNTER/SCOUT_HUNTER) whose transition is already auth-permitted must ALSO
clear a blast-radius check; if the graph's worst-case blast severity meets the
threshold, the engagement PARKS for human opt-in instead of auto-dispatching
(policy.yaml `blast_radius_gate_before` + `human_approval_required_when:
blast_radius_exceeds_threshold`).

PURE of I/O: operates on an already-rebuilt graph store. No offensive behavior —
this only ADDS a human checkpoint before high-impact dispatch.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.graph.narrative import calculate_blast_radius
from agent_alpha.graph.nodes import NodeType

# Canonical severity ordering (mirrors graph.narrative._SEVERITY_ORDER; kept local so
# this gate has no dependency on a private symbol).
_SEVERITY_RANK: tuple[str, ...] = ("low", "medium", "high", "critical")


def _rank(severity: str) -> int:
    try:
        return _SEVERITY_RANK.index(severity)
    except ValueError:
        return 0


def max_blast_severity(store: Any) -> str:
    """Worst-case blast severity over every ASSET node in the graph.

    Returns "low" for an empty/low graph (gate not triggered). Uses the canonical
    `calculate_blast_radius` per ASSET node and takes the max severity.
    """
    worst = "low"
    for node in store.nodes_by_type(NodeType.ASSET):
        severity = calculate_blast_radius(store, node.id).severity
        if _rank(severity) > _rank(worst):
            worst = severity
    return worst


def assess_blast_gate(
    *,
    store: Any,
    gate_before_agents: frozenset[str],
    next_agent_name: str | None,
    threshold: str,
) -> bool:
    """True iff dispatching to *next_agent_name* must PARK for human approval.

    Gate applies ONLY to agents listed in `gate_before_agents` (policy.yaml
    `blast_radius_gate_before`). For a gated agent, approval is required when the
    graph's worst-case blast severity is at/above *threshold*. Non-gated agents
    (Alpha/Beta) and low-blast graphs return False (dispatch proceeds under the
    auth gate as before).
    """
    if next_agent_name is None or next_agent_name not in gate_before_agents:
        return False
    return _rank(max_blast_severity(store)) >= _rank(threshold)
