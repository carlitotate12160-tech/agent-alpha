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
    an independent auth signal — the 116-B auth-vs-unauth DIFFERENTIAL — computed by
    a DIFFERENT code path (``authenticated_crawl._auth_only_diff``) from the login
    tool that self-reported access.

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
      4. A reachable SERVICE :authsurface: node (via LEADS_TO) carries an
         ``auth_vs_unauth_diff`` proof bound to this credential AND access level.
      5. Does NOT rely on node.verified (tool self-report).

    Integration: CredReuseAttestor is consumed by run_verification_pass(), which
    iterates ACCESS_LEVEL nodes, runs each attestor, and emits NodeVerified events
    with attestor provenance on CONFIRMED. The graph store promotes nodes to
    CROSS_VERIFIED only when the event carries provenance.

    CONFIRMED: a reachable SERVICE :authsurface: node carries an
               ``auth_vs_unauth_diff`` proof bound to the enabling credential
               AND is reached via an ENABLES edge from a CREDENTIAL with a real
               secret_ref (harvested material that resolves in the vault).
    INCONCLUSIVE: access node exists but lacks independent auth proof.
    REFUTED: reserved for Phase-6 live re-auth (not wired here).

    Does NOT confirm from:
      - Graph consistency or reachability alone.
      - Tool self-report (node.verified / node.verification).
      - The login tool's own ``authenticated_request`` proof (circular — same
        failure mode as the finder).
      - Inferred access without session/auth proof.
    """

    def __init__(self, secrets_manager: Any = None, engagement_id: str | None = None) -> None:
        """Create an attestor for production or legacy unit tests.

        ``secrets_manager`` (optional): when provided, Rule 3 is HARDENED (GAP-118) — a
        credential's ``secret_ref`` must RESOLVE to real vaulted harvested material, not merely be
        non-empty. ``engagement_id`` is optional metadata for production callers that want to keep
        the attestation context explicit without changing verification semantics.
        """
        self._secrets_manager = secrets_manager
        self._engagement_id = engagement_id

    def _resolves_to_harvested_material(self, cred_node: Any) -> bool:
        """Return True when the credential's secret_ref resolves to non-empty,
        engagement-owned vaulted material, or when no vault is configured (legacy fallback).

        GAP-118: with a vault, a non-resolving / foreign-engagement / empty payload
        is NOT proven harvested material → False. The secret_ref is NEVER logged
        (ADR §8l); only the credential node id identifies the affected credential.
        """
        ref = getattr(cred_node.properties, "secret_ref", None)
        if not ref:
            return False  # no ref → not proven harvested material

        if self._secrets_manager is None:
            return True  # legacy / unit-test path: ref non-empty is sufficient

        from agent_alpha.security.secrets import DecryptionError, SecretNotFoundError

        try:
            if self._engagement_id is not None:
                secret = self._secrets_manager.retrieve_for_engagement(ref, self._engagement_id)
            else:
                secret = self._secrets_manager.retrieve(ref)
        except (SecretNotFoundError, DecryptionError):
            # Expected downgrade for material that is not truly harvested (e.g. the
            # alpha-ai bare-UUID false-provenance): DEBUG, not WARNING — it is NOT a
            # vault outage.
            logger.debug(
                "credential %s did not resolve to engagement-owned material — access "
                "stays INCONCLUSIVE (not proven harvested)",
                cred_node.id,
            )
            return False
        except Exception:  # noqa: BLE001 — infra outage must not crash the COMPLETE path
            # A vault OUTAGE (connection/RLS/backend failure) is NOT the same as
            # "unproven material". Fail CLOSED (False) and log WARNING so it is
            # distinguishable from the DEBUG downgrade above.
            logger.warning(
                "vault resolve failed for credential %s — treating access as "
                "INCONCLUSIVE (vault outage, not a verdict)",
                cred_node.id,
                exc_info=True,
            )
            return False
        return bool(secret)

    @staticmethod
    def _find_backing_credential(node: Any, graph: Any) -> Any:
        """The CREDENTIAL node reaching this access via an incoming ENABLES edge, else None.

        No instance state (static): pure graph traversal. Extracted from ``verify`` to keep
        its cyclomatic complexity bounded."""
        from agent_alpha.graph.nodes import NodeType, RelationshipType

        for edge in graph.all_edges():
            if edge.target_id == node.id and edge.relationship == RelationshipType.ENABLES:
                source = graph.get_node(edge.source_id)
                if source and source.type == NodeType.CREDENTIAL:
                    return source
        return None

    @staticmethod
    def _has_independent_auth_diff(node: Any, cred_node: Any, graph: Any) -> bool:
        """True iff an authsurface SERVICE node reachable via LEADS_TO from this access node
        carries an ``auth_vs_unauth_diff`` proof BOUND to the enabling credential AND this
        access level. §12.43 independent oracle: the auth-vs-unauth differential is computed by
        ``authenticated_crawl._auth_only_diff`` — a DIFFERENT code path from the login tool that
        self-reported access — so a bug in the login tool does not also fool this check.

        No instance state (static): pure graph traversal + artifact inspection. An empty
        ``subject_ref`` NEVER binds (guards against an unwired/optional enabling_cred_id)."""
        from agent_alpha.graph.nodes import RelationshipType

        subjects = (cred_node.id, getattr(cred_node.properties, "secret_ref", ""))
        level = getattr(node.properties, "level", "")
        for edge in graph.all_edges():
            if edge.source_id != node.id or edge.relationship != RelationshipType.LEADS_TO:
                continue
            svc = graph.get_node(edge.target_id)
            if svc is None or ":authsurface:" not in svc.id:
                continue
            for art in getattr(svc, "proof_artifacts", ()):
                if (
                    art.type == "auth_vs_unauth_diff"
                    and art.subject_ref  # empty never binds
                    and art.subject_ref in subjects
                    and art.access_level == level
                ):
                    return True
        return False

    def verify(self, node: Any, graph: Any) -> Verdict:
        """Independently verify an access node.

        Checks (all must pass for CONFIRMED):
          1. Node is ACCESS_LEVEL type.
          2. Incoming ENABLES edge from a CREDENTIAL node exists.
          3. Credential's secret_ref resolves to engagement-owned harvested material (Rule 3).
          4. A reachable SERVICE :authsurface: node carries an ``auth_vs_unauth_diff``
             proof bound to this cred + access (§12.43 independent oracle).
          5. Does NOT rely on node.verified (tool self-report).
        """
        from agent_alpha.graph.nodes import CredentialProperties, NodeType

        # Gate: only ACCESS_LEVEL nodes are eligible.
        if not hasattr(node, "type") or node.type != NodeType.ACCESS_LEVEL:
            return Verdict.INCONCLUSIVE

        # Backing CREDENTIAL via an incoming ENABLES edge.
        cred_node = self._find_backing_credential(node, graph)
        if cred_node is None or not isinstance(cred_node.properties, CredentialProperties):
            return Verdict.INCONCLUSIVE

        # Rule 3 (GAP-118): secret_ref must resolve to NON-EMPTY, engagement-owned vaulted
        # material — not merely be non-empty. A bare-UUID proof pointer (confirmed live on
        # alpha-ai: cred `wpvuln`) previously passed and cross-verified a NON-harvested access.
        if not self._resolves_to_harvested_material(cred_node):
            return Verdict.INCONCLUSIVE

        # Independent auth signal: §12.43 auth-vs-unauth DIFFERENTIAL (116-B), NOT the login
        # tool's own authenticated_request self-report (circular). Passes `graph` (traverses edges).
        if not self._has_independent_auth_diff(node, cred_node, graph):
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
