# tests/phase_3/test_conductor_verification.py
"""Slice-1c: the Conductor autonomous path promotes a proven access node to
CROSS_VERIFIED (independent oracle), and leaves an inferred access node unverified."""

from __future__ import annotations

import uuid

from agent_alpha.conductor.verification import verify_access_nodes
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    ProofArtifact,
    RelationshipType,
    VerificationTier,
    node_to_dict,
)
from agent_alpha.security.secrets import SecretsManager

_HOST = "shop.example.com"
_CRED_ID = f"cred:{_HOST}:admin"
_ACCESS_ID = f"access:{_HOST}"
_ENG = "eng-slice1c"


def _emit_node(store: NetworkXGraphStore, node: AttackNode) -> None:
    store.apply_event("NodeDiscovered", node_to_dict(node))


def _emit_edge(store: NetworkXGraphStore, edge: AttackEdge) -> None:
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "relationship": edge.relationship.value,
            "confidence": edge.confidence,
            "technique_id": edge.technique_id,
        },
    )


def _credential(store: NetworkXGraphStore, secret_ref: str) -> None:
    _emit_node(
        store,
        AttackNode(
            id=_CRED_ID,
            type=NodeType.CREDENTIAL,
            properties=CredentialProperties(
                username="admin",
                secret_ref=secret_ref,
                service="http",
                access_level="admin",
            ),
            confidence=0.85,
            agent="alpha",
        ),
    )


def _access(store: NetworkXGraphStore, *, with_proof: bool) -> None:
    proof = (
        [
            ProofArtifact(
                artifact_id=str(uuid.uuid4()),
                type="authenticated_request",
                storage_ref="event://proof-1",
                description="admin via wp cred reuse",
                captured_at="2026-07-25T00:00:00Z",
                agent="beta",
                subject_ref=_CRED_ID,
                target=_HOST,
                access_level="admin",
            )
        ]
        if with_proof
        else []
    )
    _emit_node(
        store,
        AttackNode(
            id=_ACCESS_ID,
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(level="admin", user_context="web"),
            confidence=0.80,
            agent="beta",
            verification=VerificationTier.SELF_VERIFIED,
            proof_artifacts=proof,
        ),
    )
    _emit_edge(
        store,
        AttackEdge(_CRED_ID, _ACCESS_ID, RelationshipType.ENABLES, 0.80, "T1078"),
    )


def test_verify_access_promotes_bound_access_to_cross_verified() -> None:
    store = NetworkXGraphStore()
    events = InMemoryEventStore()
    vault = SecretsManager()
    rec = vault.store("db_pw", "P@ss", _ENG)  # real harvested material — resolves for _ENG
    _credential(store, rec.secret_id)
    _access(store, with_proof=True)

    assert store.get_node(_ACCESS_ID).verification == VerificationTier.SELF_VERIFIED

    verify_access_nodes(store, events, _ENG, secrets_manager=vault)

    assert store.get_node(_ACCESS_ID).verification == VerificationTier.CROSS_VERIFIED
    kinds = [getattr(e, "event_type", None) for e in events.get_events(_ENG)]
    assert any(str(k) == "NodeVerified" or k == "NodeVerified" for k in kinds)


def test_verify_access_leaves_inferred_access_unverified() -> None:
    """DIFFERENTIAL — must be able to FAIL. Harvested material resolves, so this fails
    SPECIFICALLY on the missing bound proof (not on Rule 3) → stays SELF_VERIFIED, no event."""
    store = NetworkXGraphStore()
    events = InMemoryEventStore()
    vault = SecretsManager()
    rec = vault.store("db_pw", "P@ss", _ENG)  # resolves — isolates the no-proof cause
    _credential(store, rec.secret_id)
    _access(store, with_proof=False)

    verify_access_nodes(store, events, _ENG, secrets_manager=vault)

    assert store.get_node(_ACCESS_ID).verification == VerificationTier.SELF_VERIFIED
    assert events.count(_ENG) == 0
