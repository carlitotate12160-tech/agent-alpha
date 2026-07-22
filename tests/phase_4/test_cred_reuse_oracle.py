# tests/phase_4/test_cred_reuse_oracle.py
"""Phase 5 (Moat): CredReuseOracle + VerificationTier semantics.

Tests verify:
  T1: CONFIRMED on real auth backing (proof artifact + harvested cred + ENABLES edge).
  T2: INCONCLUSIVE on inferred access (no proof artifacts).
  T3: Oracle rejects self-report — does not rely on node.verified.
  T4: verified property is True only for CROSS_VERIFIED.
  T5: Migration guard — existing code passing verified=True gets CROSS_VERIFIED.
  T6: SELF_VERIFIED nodes have verified=False.
  T7: Reverifier seam — REFUTED when re-auth fails.
  T8: Lockout governance — respects threshold.
"""

from __future__ import annotations

import uuid

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AssetProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    ProofArtifact,
    RelationshipType,
    VerificationTier,
    node_to_dict,
)
from agent_alpha.oracle.verifier import CredReuseOracle, Oracle, Verdict

_HOST = "oracle.lab.internal"
_CRED_ID = f"cred:{_HOST}:admin"
_ACCESS_ID = f"access:{_HOST}"


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


def _proven_store() -> NetworkXGraphStore:
    """Graph with a proven cred-reuse chain: CREDENTIAL --ENABLES--> ACCESS_LEVEL
    where ACCESS_LEVEL has proof_artifacts (authenticated_request) and CREDENTIAL
    has a real secret_ref."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(
            id=_CRED_ID,
            type=NodeType.CREDENTIAL,
            properties=CredentialProperties(
                username="admin",
                secret_ref="vault://eng/secret-oracle-1",
                service="http",
                access_level="admin",
            ),
            confidence=0.85,
            agent="alpha",
        ),
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
            proof_artifacts=[
                ProofArtifact(
                    artifact_id=str(uuid.uuid4()),
                    type="authenticated_request",
                    storage_ref="event://proof-abc",
                    description="Verified admin access via cred reuse",
                    captured_at="2026-07-22T00:00:00Z",
                    agent="beta",
                ),
            ],
        ),
    )
    _emit_edge(
        store,
        AttackEdge(_CRED_ID, _ACCESS_ID, RelationshipType.ENABLES, 0.80, "T1078"),
    )
    return store


def _inferred_store() -> NetworkXGraphStore:
    """Graph with an access node that has NO proof artifacts — inferred, not proven."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(
            id=_CRED_ID,
            type=NodeType.CREDENTIAL,
            properties=CredentialProperties(
                username="admin",
                secret_ref="vault://eng/secret-oracle-2",
                service="http",
                access_level="admin",
            ),
            confidence=0.85,
            agent="alpha",
        ),
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
            # NO proof_artifacts — inferred access
        ),
    )
    _emit_edge(
        store,
        AttackEdge(_CRED_ID, _ACCESS_ID, RelationshipType.ENABLES, 0.80, "T1078"),
    )
    return store


# ── T1: CONFIRMED on real auth backing ──────────────────────────────────────


def test_confirmed_on_real_auth_backing() -> None:
    """Oracle returns CONFIRMED when access node is backed by a real
    authenticated_request proof + harvested credential with secret_ref."""
    store = _proven_store()
    oracle = CredReuseOracle()
    node = store.get_node(_ACCESS_ID)
    assert node is not None

    verdict = oracle.verify(node, store)
    assert verdict == Verdict.CONFIRMED


# ── T2: INCONCLUSIVE on inferred access ─────────────────────────────────────


def test_inconclusive_on_inferred_access() -> None:
    """Oracle returns INCONCLUSIVE when access node has no proof artifacts."""
    store = _inferred_store()
    oracle = CredReuseOracle()
    node = store.get_node(_ACCESS_ID)
    assert node is not None

    verdict = oracle.verify(node, store)
    assert verdict == Verdict.INCONCLUSIVE


# ── T3: Oracle rejects self-report ──────────────────────────────────────────


def test_oracle_rejects_self_report() -> None:
    """Oracle does NOT confirm a node just because it has verification=SELF_VERIFIED.
    Without proof artifacts, even a SELF_VERIFIED node stays INCONCLUSIVE."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(
            id=_ACCESS_ID,
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(level="admin"),
            confidence=0.9,
            agent="beta",
            verification=VerificationTier.SELF_VERIFIED,
            # No proof, no credential backing — just the tool's self-report.
        ),
    )
    oracle = CredReuseOracle()
    node = store.get_node(_ACCESS_ID)
    assert node is not None

    verdict = oracle.verify(node, store)
    assert verdict == Verdict.INCONCLUSIVE


# ── T4: verified property is CROSS_VERIFIED only ────────────────────────────


def test_verified_property_is_cross_only() -> None:
    """node.verified returns True ONLY when verification == CROSS_VERIFIED."""
    unverified = AttackNode(
        id="a",
        type=NodeType.ASSET,
        properties=AssetProperties(host="x"),
        confidence=0.9,
    )
    self_verified = AttackNode(
        id="b",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="u", secret_ref="r", service="s", access_level="a"
        ),
        confidence=0.9,
        verification=VerificationTier.SELF_VERIFIED,
    )
    cross_verified = AttackNode(
        id="c",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level="admin"),
        confidence=0.9,
        verification=VerificationTier.CROSS_VERIFIED,
    )

    assert unverified.verified is False
    assert unverified.verification == VerificationTier.UNVERIFIED

    assert self_verified.verified is False
    assert self_verified.verification == VerificationTier.SELF_VERIFIED

    assert cross_verified.verified is True
    assert cross_verified.verification == VerificationTier.CROSS_VERIFIED


# ── T5: Migration guard — verified=True → CROSS_VERIFIED (backward compat) ──


def test_migration_guard_verified_true_maps_to_cross_verified() -> None:
    """Existing code passing verified=True gets CROSS_VERIFIED via __post_init__ sync."""
    node = AttackNode(
        id="legacy",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level="admin"),
        confidence=0.9,
        agent="beta",
        verified=True,
    )
    assert node.verified is True
    assert node.verification == VerificationTier.CROSS_VERIFIED


# ── T6: SELF_VERIFIED nodes have verified=False ──────────────────────────────


def test_self_verified_has_verified_false() -> None:
    """SELF_VERIFIED tier means the tool asserted success, but verified property
    is False because it's not independently confirmed."""
    node = AttackNode(
        id="self",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level="user"),
        confidence=0.8,
        verification=VerificationTier.SELF_VERIFIED,
    )
    assert node.verified is False
    assert node.verification == VerificationTier.SELF_VERIFIED


# ── T7: Reverifier seam — REFUTED when re-auth fails ────────────────────────


class _FailingReverifier:
    """Simulates a re-auth attempt that fails (account locked, cred rotated)."""

    def check(self, node: object, cred_node: object) -> bool:
        return False


def test_reverifier_refutes_on_failed_reauth() -> None:
    """When the reverifier returns False, oracle returns REFUTED."""
    store = _proven_store()
    oracle = CredReuseOracle(reverifier=_FailingReverifier())
    node = store.get_node(_ACCESS_ID)
    assert node is not None

    verdict = oracle.verify(node, store)
    assert verdict == Verdict.REFUTED


# ── T8: Lockout governance ───────────────────────────────────────────────────


class _CountingReverifier:
    """Counts how many times check() is called."""

    def __init__(self) -> None:
        self.call_count = 0

    def check(self, node: object, cred_node: object) -> bool:
        self.call_count += 1
        return True


def test_lockout_threshold_respected() -> None:
    """Oracle stops calling reverifier after lockout_threshold attempts."""
    store = _proven_store()
    reverifier = _CountingReverifier()
    oracle = CredReuseOracle(reverifier=reverifier, lockout_threshold=2)
    node = store.get_node(_ACCESS_ID)
    assert node is not None

    # First two calls go through to reverifier.
    oracle.verify(node, store)
    oracle.verify(node, store)
    assert reverifier.call_count == 2

    # Third call respects lockout — reverifier not called.
    oracle.verify(node, store)
    assert reverifier.call_count == 2


# ── T9: Oracle satisfies the Protocol ────────────────────────────────────────


def test_cred_reuse_oracle_satisfies_protocol() -> None:
    """CredReuseOracle is a valid Oracle (structural subtyping)."""
    oracle = CredReuseOracle()
    assert isinstance(oracle, Oracle)


# ── T10: Non-ACCESS_LEVEL node → INCONCLUSIVE ───────────────────────────────


def test_non_access_level_node_is_inconclusive() -> None:
    """Oracle only verifies ACCESS_LEVEL nodes; others are INCONCLUSIVE."""
    store = NetworkXGraphStore()
    asset = AttackNode(
        id="asset:x",
        type=NodeType.ASSET,
        properties=AssetProperties(host="x"),
        confidence=0.9,
    )
    _emit_node(store, asset)
    oracle = CredReuseOracle()
    node = store.get_node("asset:x")
    assert node is not None

    assert oracle.verify(node, store) == Verdict.INCONCLUSIVE
