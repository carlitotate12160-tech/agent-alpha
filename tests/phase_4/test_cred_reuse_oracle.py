# tests/phase_4/test_cred_reuse_oracle.py
"""Phase 5 (Moat): CredReuseOracle + VerificationTier semantics + live-path wiring.

Tests verify:
  T1: CONFIRMED on real auth backing (proof artifact + harvested cred + ENABLES edge).
  T2: INCONCLUSIVE on inferred access (no proof artifacts).
  T3: Oracle rejects self-report — does not rely on node.verified.
  T4: verified property is True only for CROSS_VERIFIED.
  T5: Migration guard — existing code passing verified=True gets SELF_VERIFIED (NOT CROSS).
  T6: SELF_VERIFIED nodes have verified=False.
  T9: Oracle satisfies the Protocol.
  T10: Non-ACCESS_LEVEL node → INCONCLUSIVE.

  NON-ISLAND (de-island proof):
  T11: run_verification_pass promotes CONFIRMED access to CROSS_VERIFIED.
  T12: run_verification_pass does NOT promote when no auth ground-truth (DIFFERENTIAL).
  T13: A1 runner invokes run_verification_pass (wiring proof).

  PROVENANCE:
  T14: NodeVerified without oracle provenance does NOT promote.
  T15: NodeVerified WITH oracle provenance promotes.

  LEGACY:
  T16: Legacy verified=True reconstructs to SELF_VERIFIED, never CROSS_VERIFIED.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import ANY, patch

from agent_alpha.events.store import InMemoryEventStore
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
    _reconstruct_node,
    node_to_dict,
)
from agent_alpha.oracle.verifier import CredReuseOracle, Oracle, Verdict, run_verification_pass

_HOST = "oracle.lab.internal"
_CRED_ID = f"cred:{_HOST}:admin"
_ACCESS_ID = f"access:{_HOST}"
_ENGAGEMENT_ID = "eng-oracle-test"


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
                    subject_ref=_CRED_ID,
                    target=_HOST,
                    access_level="admin",
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


def test_oracle_confirms_only_bound_proof() -> None:
    """Oracle returns CONFIRMED when access node is backed by a real
    authenticated_request proof + harvested credential with secret_ref,
    and the proof is properly bound to the credential and target."""
    store = _proven_store()
    oracle = CredReuseOracle()
    node = store.get_node(_ACCESS_ID)
    assert node is not None

    verdict = oracle.verify(node, store)
    assert verdict == Verdict.CONFIRMED


def test_oracle_rejects_unbound_proof() -> None:
    """DIFFERENTIAL — must be able to FAIL. SAME graph shape but the proof's subject_ref is a DIFFERENT credential."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(
            id=_CRED_ID,
            type=NodeType.CREDENTIAL,
            properties=CredentialProperties(
                username="admin", secret_ref="vault://abc", service="http", access_level="admin"
            ),
            confidence=0.85,
        ),
    )

    # Access node has proof for a DIFFERENT credential
    _emit_node(
        store,
        AttackNode(
            id=_ACCESS_ID,
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(level="admin", user_context="web"),
            confidence=0.80,
            verification=VerificationTier.SELF_VERIFIED,
            proof_artifacts=[
                ProofArtifact(
                    artifact_id=str(uuid.uuid4()),
                    type="authenticated_request",
                    storage_ref="event://proof-abc",
                    description="Verified admin access via cred reuse",
                    captured_at="2026-07-22T00:00:00Z",
                    agent="beta",
                    subject_ref="cred:some_other_host:admin",  # Unbound / mismatched proof
                    target=_HOST,
                    access_level="admin",
                )
            ],
        ),
    )
    _emit_edge(store, AttackEdge(_CRED_ID, _ACCESS_ID, RelationshipType.ENABLES, 0.80, "T1078"))

    oracle = CredReuseOracle()
    node = store.get_node(_ACCESS_ID)
    assert node is not None
    assert oracle.verify(node, store) == Verdict.INCONCLUSIVE


def test_invalid_c7_run_emits_no_nodeverified() -> None:
    """A run that fails assert_valid_or_raise leaves NO NodeVerified event and NO CROSS_VERIFIED node in the store."""
    from agent_alpha.live_fire.a1_validation_runner import run_a1_validation

    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()

    class _InvalidChallengeResult:
        status_code = 200
        body = "no challenge here"
        headers: dict[str, str] = {}
        cleared_cookies: dict[str, str] = {}
        challenge_encountered = False
        challenge_solved = False

    class _MockSolver:
        def solve_and_fetch(self, url: str, *, engagement_id: str) -> Any:
            return _InvalidChallengeResult()

    class _MockHttpClient:
        def get(self, url: str, **kwargs: object) -> Any:
            class Resp:
                status_code = 200
                text = "no challenge"
                headers: dict[str, str] = {}

            return Resp()

        def post(self, url: str, **kwargs: object) -> Any:
            return self.get(url, **kwargs)

    try:
        run_a1_validation(
            engagement_id="eng-test-c7-fail",
            browser_solve=_MockSolver(),
            http_client=_MockHttpClient(),
            graph_store=graph_store,
            event_store=event_store,
            target="alpha-ai.web.id",
        )
    except RuntimeError:
        pass  # expected C7 fail

    events = event_store.get_events("eng-test-c7-fail")
    node_verified_events = [e for e in events if e.event_type == "NodeVerified"]
    assert len(node_verified_events) == 0

    access_nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)
    for n in access_nodes:
        assert n.verification != VerificationTier.CROSS_VERIFIED


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


# ── T5: Migration guard — verified=True → SELF_VERIFIED (NOT CROSS) ─────────


def test_migration_guard_verified_true_maps_to_self_verified() -> None:
    """Existing code passing verified=True gets SELF_VERIFIED via __post_init__ sync.

    This is the anti-theater fix: verified=True is a legacy tool self-report.
    It must NOT auto-promote to CROSS_VERIFIED — that would give unearned
    cross-verification status to every legacy self-report.
    """
    node = AttackNode(
        id="legacy",
        type=NodeType.ACCESS_LEVEL,
        properties=AccessLevelProperties(level="admin"),
        confidence=0.9,
        agent="beta",
        verified=True,
    )
    # Legacy verified=True → SELF_VERIFIED (tool self-report), NOT CROSS_VERIFIED.
    assert node.verification == VerificationTier.SELF_VERIFIED
    # The verified property derives from verification == CROSS_VERIFIED,
    # so it is now False (correctly — this node was never cross-verified).
    assert node.verified is False


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


# ── T11: NON-ISLAND — run_verification_pass promotes confirmed access ────────


def test_verification_pass_promotes_confirmed_access() -> None:
    """NON-ISLAND proof: build an A1-shaped graph where the access node is
    SELF_VERIFIED and backed by a real auth ground-truth (harvested cred +
    authenticated_request proof). Run run_verification_pass. Assert the
    access node is now CROSS_VERIFIED — proving the LIVE oracle path
    promotes, not a constructed node."""
    store = _proven_store()
    event_store = InMemoryEventStore()

    # Pre-condition: access node is SELF_VERIFIED.
    node_before = store.get_node(_ACCESS_ID)
    assert node_before is not None
    assert node_before.verification == VerificationTier.SELF_VERIFIED

    # Run the live oracle path.
    run_verification_pass(store, event_store, [CredReuseOracle()], _ENGAGEMENT_ID)

    # Post-condition: access node is now CROSS_VERIFIED.
    node_after = store.get_node(_ACCESS_ID)
    assert node_after is not None
    assert node_after.verification == VerificationTier.CROSS_VERIFIED
    assert node_after.verified is True

    # The event store must have a NodeVerified event with oracle provenance.
    events = event_store.get_events(_ENGAGEMENT_ID)
    node_verified_events = [e for e in events if e.event_type == "NodeVerified"]
    assert len(node_verified_events) == 1
    evt = node_verified_events[0]
    assert evt.payload["node_id"] == _ACCESS_ID
    assert evt.payload["oracle"] == "CredReuseOracle"
    assert evt.payload["verdict"] == "confirmed"


# ── T12: DIFFERENTIAL — no promote on inferred (no auth ground-truth) ────────


def test_verification_pass_no_promote_on_inferred() -> None:
    """DIFFERENTIAL proof: identical graph SHAPE but no auth ground-truth
    (no authenticated_request proof). Run the pass. Assert the node stays
    SELF_VERIFIED (NOT promoted) — proves the oracle uses the independent
    signal, not graph shape."""
    store = _inferred_store()
    event_store = InMemoryEventStore()

    # Pre-condition: access node is SELF_VERIFIED.
    node_before = store.get_node(_ACCESS_ID)
    assert node_before is not None
    assert node_before.verification == VerificationTier.SELF_VERIFIED

    # Run the live oracle path.
    run_verification_pass(store, event_store, [CredReuseOracle()], _ENGAGEMENT_ID)

    # Post-condition: access node is STILL SELF_VERIFIED (not promoted).
    node_after = store.get_node(_ACCESS_ID)
    assert node_after is not None
    assert node_after.verification == VerificationTier.SELF_VERIFIED
    assert node_after.verified is False

    # No NodeVerified events emitted.
    events = event_store.get_events(_ENGAGEMENT_ID)
    node_verified_events = [e for e in events if e.event_type == "NodeVerified"]
    assert len(node_verified_events) == 0


# ── T13: A1 runner invokes run_verification_pass ─────────────────────────────


def test_a1_runner_invokes_verification_pass() -> None:
    """Spy/patch run_verification_pass; assert the A1 runner calls it during
    a chain run. Proves non-island wiring in the live path."""
    from agent_alpha.live_fire.a1_validation_runner import run_a1_validation

    with (
        patch("agent_alpha.oracle.verifier.run_verification_pass") as mock_pass,
        patch("agent_alpha.live_fire.a1_validation_runner.classify_mitigation") as mock_classify,
    ):
        from agent_alpha.recon.transport_resilience import MitigationClass

        mock_classify.return_value = MitigationClass.CHALLENGE
        # Build minimal A1 args that reach the verification pass.
        # We provide a stub browser_solve and mock classify_mitigation to pass the C7 gate.
        run_a1_validation(
            engagement_id="eng-test-wiring",
            browser_solve=_StubBrowserSolve(),
            http_client=_StubHttpClient(),
            graph_store=NetworkXGraphStore(),
            event_store=InMemoryEventStore(),
        )

        # The verification pass must have been called.
        mock_pass.assert_called_once_with(
            ANY,  # graph_store
            ANY,  # event_store
            ANY,  # [CredReuseOracle()]
            "eng-test-wiring",  # engagement_id
        )


class _StubBrowserSolve:
    def solve_and_fetch(self, url: str, *, engagement_id: str) -> Any:
        return _StubChallengeResult()


class _StubChallengeResult:
    status_code = 200
    body = "no secrets here"
    headers: dict[str, str] = {}
    cleared_cookies: dict[str, str] = {}
    challenge_encountered = False
    challenge_solved = False


class _StubHttpClient:
    """Minimal HTTP client stub that returns a non-challenge response for A1."""

    def get(self, url: str, **kwargs: object) -> _StubResponse:
        return _StubResponse()


class _StubResponse:
    status_code = 200
    text = "<html>no challenge</html>"
    headers: dict[str, str] = {}


# ── T14: NodeVerified without oracle provenance does NOT promote ─────────────


def test_nodeverified_requires_oracle_provenance() -> None:
    """apply_event("NodeVerified", {node_id, ...}) WITHOUT an "oracle" field
    does NOT promote to CROSS_VERIFIED; WITH oracle provenance it does."""
    store = NetworkXGraphStore()
    _emit_node(
        store,
        AttackNode(
            id="n-prov",
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(level="user"),
            confidence=0.9,
            verification=VerificationTier.SELF_VERIFIED,
        ),
    )

    # Without provenance — must NOT promote.
    store.apply_event("NodeVerified", {"node_id": "n-prov"})
    node = store.get_node("n-prov")
    assert node is not None
    assert node.verification == VerificationTier.SELF_VERIFIED  # NOT promoted
    assert node.verified is False

    # With provenance — MUST promote.
    store.apply_event(
        "NodeVerified",
        {"node_id": "n-prov", "oracle": "CredReuseOracle", "verdict": "confirmed"},
    )
    node = store.get_node("n-prov")
    assert node is not None
    assert node.verification == VerificationTier.CROSS_VERIFIED
    assert node.verified is True


# ── T16: Legacy verified=True reconstructs to SELF_VERIFIED ──────────────────


def test_legacy_verified_not_cross() -> None:
    """A legacy payload with verified=True reconstructs to SELF_VERIFIED
    or UNVERIFIED, never CROSS_VERIFIED."""
    # Legacy payload: verified=True, no verification field.
    raw = {
        "id": "legacy-node",
        "type": "access_level",
        "properties": {"level": "admin"},
        "confidence": 0.9,
        "agent": "beta",
        "verified": True,
        # No "verification" key — legacy format.
    }
    node = _reconstruct_node(raw)
    assert node.verification == VerificationTier.SELF_VERIFIED
    assert node.verified is False  # verified property == (tier == CROSS_VERIFIED) → False

    # Legacy payload with explicit verification=self_verified stays SELF_VERIFIED.
    raw2 = {**raw, "verification": "self_verified"}
    node2 = _reconstruct_node(raw2)
    assert node2.verification == VerificationTier.SELF_VERIFIED
    assert node2.verified is False

    # Only explicit verification=cross_verified reaches CROSS_VERIFIED.
    raw3 = {**raw, "verification": "cross_verified"}
    node3 = _reconstruct_node(raw3)
    assert node3.verification == VerificationTier.CROSS_VERIFIED
    assert node3.verified is True
