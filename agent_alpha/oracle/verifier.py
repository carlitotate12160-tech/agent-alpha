# agent_alpha/oracle/verifier.py
"""Oracle protocol and CredReuseOracle — independent verification (Phase 5 Moat).

DOCTRINE: Independent Verification Axiom — the verification mechanism MUST differ
in failure mode from the finder. A tool self-reporting "I got access" is
SELF_VERIFIED. Only an independent signal (real auth event from a different
code path or a live re-auth attempt) can upgrade to CROSS_VERIFIED.

This module does NOT:
  - Confirm from graph structure/consistency alone.
  - Confirm from the tool's own verified flag (that's self-report).
  - Perform graph walks as verification.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class Verdict(StrEnum):
    """Result of an oracle verification attempt."""

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

    CONFIRMED: access node has proof_artifacts with type "authenticated_request"
               AND is reached via an ENABLES edge from a CREDENTIAL with a real
               secret_ref (harvested material, not empty).
    INCONCLUSIVE: access node exists but lacks independent auth proof.
    REFUTED: reverifier contradicts (failed re-auth attempt).

    Does NOT confirm from:
      - Graph consistency or reachability alone.
      - Tool self-report (node.verified / node.verification).
      - Inferred access without session/auth proof.

    Optional reverifier seam: if injected, performs a live re-auth to upgrade
    confidence. Respects lockout threshold to avoid account lockout / double recon.
    """

    def __init__(
        self,
        *,
        reverifier: Any | None = None,
        lockout_threshold: int = 3,
    ) -> None:
        self._reverifier = reverifier
        self._lockout_threshold = lockout_threshold
        self._attempt_count: dict[str, int] = {}

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

        # At least one artifact must be an authenticated_request.
        has_auth_proof = any(a.type == "authenticated_request" for a in node.proof_artifacts)
        if not has_auth_proof:
            return Verdict.INCONCLUSIVE

        # Optional reverifier seam — live re-auth (respects lockout).
        if self._reverifier is not None:
            node_key = node.id
            count = self._attempt_count.get(node_key, 0)
            if count < self._lockout_threshold:
                self._attempt_count[node_key] = count + 1
                reverify_result = self._reverifier.check(node, cred_node)
                if reverify_result is False:
                    return Verdict.REFUTED

        # All independent checks pass: confirmed.
        return Verdict.CONFIRMED
