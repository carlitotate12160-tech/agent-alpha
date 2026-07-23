# agent_alpha/oracle/verifier.py
"""Oracle protocol and CredReuseOracle — independent verification (Phase 5 Moat).

DOCTRINE: Independent Verification Axiom — the verification mechanism MUST differ
in failure mode from the finder. A tool self-reporting "I got access" is
SELF_VERIFIED. Only an independent signal (real auth event from a different
code path) can upgrade to CROSS_VERIFIED.

This module does NOT:
  - Confirm from graph structure/consistency alone.
  - Confirm from the tool's own verified flag (that's self-report).
  - Perform graph walks as verification.
  - Perform live re-authentication (Phase-6, Conductor-auth-gated,
    credential-keyed lockout — NOT wired here).
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


class Verdict(StrEnum):
    """Result of an oracle verification attempt.

    Confidence mapping:
      - CONFIRMED: independent signal validates the access claim. The access
        node may be promoted to CROSS_VERIFIED via run_verification_pass.
      - REFUTED: independent signal contradicts the claim (reserved for
        Phase-6 live re-auth — currently unreachable).
      - INCONCLUSIVE: insufficient independent evidence to confirm or refute.
        Node stays at its current tier (SELF_VERIFIED or UNVERIFIED).
    """

    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@runtime_checkable
class Oracle(Protocol):
    """Independent verification oracle — confirms, refutes, or is inconclusive."""

    def verify(self, node: Any, graph: Any) -> Verdict: ...


class CredReuseOracle:
    """Verifies ACCESS_LEVEL nodes by checking for real auth events backed by
    harvested credential reuse.

    Lyndon check: this oracle exists because a tool's self-report ("I got admin")
    is NOT proof. The tool and the verifier MUST differ in failure mode — a bug in
    the exploit tool should not also fool the verifier. CredReuseOracle checks for
    an independent auth signal (proof_artifacts of type "authenticated_request")
    that the finder tool did NOT produce as part of its own self-report.

    Tier schema:
      - UNVERIFIED: node discovered, no tool has claimed success.
      - SELF_VERIFIED: tool self-reports success (e.g. beta login returned 200).
        This is the tool's own claim — not independently confirmed.
      - CROSS_VERIFIED: an oracle (this class) has independently confirmed the
        claim via run_verification_pass. ONLY reachable through the oracle +
        provenance-checked NodeVerified event. Never from tool self-report,
        graph walk, or direct construction in production.

    Verdict rules (all must pass for CONFIRMED):
      1. Node is ACCESS_LEVEL type.
      2. Incoming ENABLES edge from a CREDENTIAL node exists.
      3. Credential has a non-empty secret_ref (harvested material).
      4. Access node has proof_artifacts containing "authenticated_request".
      5. Does NOT rely on node.verified (tool self-report).

    Integration: CredReuseOracle is consumed by run_verification_pass(), which
    iterates ACCESS_LEVEL nodes, runs each oracle, and emits NodeVerified events
    with oracle provenance on CONFIRMED. The graph store promotes nodes to
    CROSS_VERIFIED only when the event carries provenance.

    CONFIRMED: access node has proof_artifacts with type "authenticated_request"
               AND is reached via an ENABLES edge from a CREDENTIAL with a real
               secret_ref (harvested material, not empty).
    INCONCLUSIVE: access node exists but lacks independent auth proof.
    REFUTED: reserved for Phase-6 live re-auth (not wired here).

    Does NOT confirm from:
      - Graph consistency or reachability alone.
      - Tool self-report (node.verified / node.verification).
      - Inferred access without session/auth proof.
    """

    def verify(self, node: Any, graph: Any) -> Verdict:
        """Independently verify an access node.

        Checks (all must pass for CONFIRMED):
          1. Node is ACCESS_LEVEL type.
          2. Incoming ENABLES edge from a CREDENTIAL node exists.
          3. Credential has a non-empty secret_ref (harvested material).
          4. Access node has proof_artifacts containing "authenticated_request".
          5. Does NOT rely on node.verified (tool self-report).
        """
        from agent_alpha.graph.nodes import (
            CredentialProperties,
            NodeType,
            RelationshipType,
        )

        # Gate: only ACCESS_LEVEL nodes are eligible.
        if not hasattr(node, "type") or node.type != NodeType.ACCESS_LEVEL:
            return Verdict.INCONCLUSIVE

        # Find the backing CREDENTIAL via an incoming ENABLES edge.
        cred_node = None
        for edge in graph.all_edges():
            if edge.target_id == node.id and edge.relationship == RelationshipType.ENABLES:
                source = graph.get_node(edge.source_id)
                if source and source.type == NodeType.CREDENTIAL:
                    cred_node = source
                    break

        if cred_node is None:
            return Verdict.INCONCLUSIVE

        # Credential must have real harvested material (non-empty secret_ref).
        if not isinstance(cred_node.properties, CredentialProperties):
            return Verdict.INCONCLUSIVE
        if not cred_node.properties.secret_ref:
            return Verdict.INCONCLUSIVE

        # Access node must have proof artifacts (real auth event, not inferred).
        if not node.proof_artifacts:
            return Verdict.INCONCLUSIVE

        # At least one artifact must be a bound authenticated_request.
        has_bound_proof = False
        for a in node.proof_artifacts:
            if a.type == "authenticated_request":
                # subject_ref must match the enabling credential's identity (id or secret_ref)
                if a.subject_ref in (cred_node.id, cred_node.properties.secret_ref):
                    # access_level and target must match this access node
                    if a.access_level == getattr(node.properties, "level", "") and a.target in node.id:
                        has_bound_proof = True
                        break

        if not has_bound_proof:
            return Verdict.INCONCLUSIVE

        # All independent checks pass: confirmed.
        return Verdict.CONFIRMED


def run_verification_pass(
    graph_store: Any,
    event_store: Any,
    oracles: list[Oracle],
    engagement_id: str,
) -> None:
    """Run all oracles against ACCESS_LEVEL nodes and emit NodeVerified events.

    Pure orchestration: reads the graph, runs each oracle, emits events.
    Tier promotion (SELF_VERIFIED → CROSS_VERIFIED) happens via the
    NodeVerified event in the graph store (event-sourced), NOT by
    mutating the node directly.

    The provenance guard is on BOTH sides:
      - EMISSION (here): every NodeVerified event carries oracle provenance
        (oracle class name + verdict) so the source is auditable.
      - CONSUMPTION (networkx_store.apply_event): only promotes to
        CROSS_VERIFIED when the event payload contains a non-empty "oracle"
        field. A tool or arbitrary caller that emits NodeVerified without
        provenance will NOT promote the node.

    On Verdict.CONFIRMED: emits NodeVerified with provenance → store promotes.
    On Verdict.INCONCLUSIVE or REFUTED: does nothing (node stays at current tier).

    Args:
        graph_store: the NetworkXGraphStore (or duck-type) to read nodes/edges from
            and to apply the emitted NodeVerified events to.
        event_store: the EventStore to append NodeVerified events to (audit trail).
        oracles: list of Oracle instances to run against each ACCESS_LEVEL node.
        engagement_id: the engagement ID for the event store.
    """
    from agent_alpha.graph.nodes import NodeType

    access_nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)

    for node in access_nodes:
        for oracle in oracles:
            verdict = oracle.verify(node, graph_store)
            if verdict == Verdict.CONFIRMED:
                payload = {
                    "node_id": node.id,
                    "oracle": type(oracle).__name__,
                    "verdict": "confirmed",
                }
                # Append to the durable event store (audit trail).
                event_store.append(
                    "NodeVerified",
                    engagement_id,
                    "oracle",
                    payload,
                )
                # Apply to the graph store (promote tier via event-sourced path).
                graph_store.apply_event("NodeVerified", payload)
                logger.info(
                    "Oracle %s CONFIRMED node %s — promoted to CROSS_VERIFIED",
                    type(oracle).__name__,
                    node.id,
                )
                # First oracle to confirm wins — no need to run remaining oracles
                # for this node (the node is already promoted).
                break
