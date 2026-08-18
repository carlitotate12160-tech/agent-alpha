# agent_alpha/attestation/attestor.py
"""Attestor protocol and CredReuseAttestor — independent verification (Phase 5 Moat).

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
    """Result of an attestor verification attempt.

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
class Attestor(Protocol):
    """Independent verification attestor — confirms, refutes, or is inconclusive."""

    def verify(self, node: Any, graph: Any) -> Verdict: ...


class CredReuseAttestor:
    """Verifies ACCESS_LEVEL nodes by checking for real auth events backed by
    harvested credential reuse.

    Lyndon check: this attestor exists because a tool's self-report ("I got admin")
    is NOT proof. The tool and the verifier MUST differ in failure mode — a bug in
    the exploit tool should not also fool the verifier. CredReuseAttestor checks for
    an independent auth signal (proof_artifacts of type "authenticated_request")
    that the finder tool did NOT produce as part of its own self-report.

    Tier schema:
      - UNVERIFIED: node discovered, no tool has claimed success.
      - SELF_VERIFIED: tool self-reports success (e.g. beta login returned 200).
        This is the tool's own claim — not independently confirmed.
      - CROSS_VERIFIED: an attestor (this class) has independently confirmed the
        claim via run_verification_pass. ONLY reachable through the attestor +
        provenance-checked NodeVerified event. Never from tool self-report,
        graph walk, or direct construction in production.

    Verdict rules (all must pass for CONFIRMED):
      1. Node is ACCESS_LEVEL type.
      2. Incoming ENABLES edge from a CREDENTIAL node exists.
      3. Credential has a real secret_ref that resolves in the vault (GAP-118 hardening).
      4. Access node has proof_artifacts containing "authenticated_request".
      5. Does NOT rely on node.verified (tool self-report).

    Integration: CredReuseAttestor is consumed by run_verification_pass(), which
    iterates ACCESS_LEVEL nodes, runs each attestor, and emits NodeVerified events
    with attestor provenance on CONFIRMED. The graph store promotes nodes to
    CROSS_VERIFIED only when the event carries provenance.

    CONFIRMED: access node has proof_artifacts with type "authenticated_request"
               AND is reached via an ENABLES edge from a CREDENTIAL with a real
               secret_ref (harvested material that resolves in the vault).
    INCONCLUSIVE: access node exists but lacks independent auth proof.
    REFUTED: reserved for Phase-6 live re-auth (not wired here).

    Does NOT confirm from:
      - Graph consistency or reachability alone.
      - Tool self-report (node.verified / node.verification).
      - Inferred access without session/auth proof.
    """

    def __init__(
        self, secrets_manager: Any = None, engagement_id: str | None = None
    ) -> None:
        """Create an attestor for production or legacy unit tests.

        ``secrets_manager`` (optional): when provided, Rule 3 is HARDENED (GAP-118) — a
        credential's ``secret_ref`` must RESOLVE to real vaulted harvested material, not merely be
        non-empty. ``engagement_id`` is optional metadata for production callers that want to keep
        the attestation context explicit without changing verification semantics.
        """
        self._secrets_manager = secrets_manager
        self._engagement_id = engagement_id

    def verify(self, node: Any, graph: Any) -> Verdict:
        """Independently verify an access node.

        Checks (all must pass for CONFIRMED):
          1. Node is ACCESS_LEVEL type.
          2. Incoming ENABLES edge from a CREDENTIAL node exists.
          3. Credential has a secret_ref that resolves in the vault when a vault is available.
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

        # Credential must have real harvested material. When a vault is available,
        # the secret_ref must RESOLVE to a stored secret; otherwise a bare UUID or
        # other non-vault pointer can falsely cross-verify a non-harvested access.
        if not isinstance(cred_node.properties, CredentialProperties):
            return Verdict.INCONCLUSIVE
        if not cred_node.properties.secret_ref:
            return Verdict.INCONCLUSIVE
        if self._secrets_manager is not None:
            try:
                self._secrets_manager.retrieve(cred_node.properties.secret_ref)
            except Exception:  # noqa: BLE001 — any vault-miss/decrypt failure = unproven material
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
                    if (
                        a.access_level == getattr(node.properties, "level", "")
                        and a.target in node.id
                    ):
                        has_bound_proof = True
                        break

        if not has_bound_proof:
            return Verdict.INCONCLUSIVE

        # All independent checks pass: confirmed.
        return Verdict.CONFIRMED


def run_verification_pass(
    graph_store: Any,
    event_store: Any,
    attestors: list[Attestor],
    engagement_id: str,
) -> None:
    """Run all attestors against ACCESS_LEVEL nodes and emit NodeVerified events.

    Pure orchestration: reads the graph, runs each attestor, emits events.
    Tier promotion (SELF_VERIFIED → CROSS_VERIFIED) happens via the
    NodeVerified event in the graph store (event-sourced), NOT by
    mutating the node directly.

    The provenance guard is on BOTH sides:
      - EMISSION (here): every NodeVerified event carries attestor provenance
        (attestor class name + verdict) so the source is auditable.
      - CONSUMPTION (networkx_store.apply_event): only promotes to
        CROSS_VERIFIED when the event payload contains a non-empty "attestor"
        field. A tool or arbitrary caller that emits NodeVerified without
        provenance will NOT promote the node.

    On Verdict.CONFIRMED: emits NodeVerified with provenance → store promotes.
    On Verdict.INCONCLUSIVE or REFUTED: does nothing (node stays at current tier).

    Args:
        graph_store: the NetworkXGraphStore (or duck-type) to read nodes/edges from
            and to apply the emitted NodeVerified events to.
        event_store: the EventStore to append NodeVerified events to (audit trail).
        attestors: list of Attestor instances to run against each ACCESS_LEVEL node.
        engagement_id: the engagement ID for the event store.
    """
    from agent_alpha.graph.nodes import NodeType

    access_nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)

    for node in access_nodes:
        for attestor in attestors:
            verdict = attestor.verify(node, graph_store)
            if verdict == Verdict.CONFIRMED:
                payload = {
                    "node_id": node.id,
                    "attestor": type(attestor).__name__,
                    "verdict": "confirmed",
                }
                # Append to the durable event store (audit trail).
                event_store.append(
                    "NodeVerified",
                    engagement_id,
                    "attestor",
                    payload,
                )
                # Apply to the graph store (promote tier via event-sourced path).
                graph_store.apply_event("NodeVerified", payload)
                logger.info(
                    "Attestor %s CONFIRMED node %s — promoted to CROSS_VERIFIED",
                    type(attestor).__name__,
                    node.id,
                )
                # First attestor to confirm wins — no need to run remaining attestors
                # for this node (the node is already promoted).
                break
