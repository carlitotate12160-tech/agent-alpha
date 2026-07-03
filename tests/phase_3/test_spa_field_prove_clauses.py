"""RED tests for the SPA field-prove acceptance predicate (decision logic).

Why this file exists: the clause checks in
``agent_alpha/live_fire/spa_secret_field_prove.py`` decide PROVEN vs FAIL. They
were patched blind (HEAD "fix(field_prove): handle TN case in clauses 2 and 3")
with ZERO coverage — a live client run then showed clause 2 & 3 FAILing on a
zero-cred target, and we could not tell logic-bug from wiring/build-bug because
nothing pinned the intended semantics. These are pure, in-memory, live-target-free
tests that localise it deterministically.

Semantics under test:
  - A field-prove run is valid in TWO shapes:
      TP (expected_creds_added > 0): tool found exactly the planted secret(s).
      TN (expected_creds_added == 0): tool found NOTHING and fabricated nothing.
  - What must NEVER pass: nodes/secrets present when expected_creds_added == 0
    (a false positive) — that is the exact symptom the client run showed.
"""

from __future__ import annotations

import pytest

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)
from agent_alpha.live_fire.spa_secret_field_prove import (
    ExpectedGroundTruth,
    SpaSecretFieldProveResult,
    _check_clause_2,
    _check_clause_3,
)
from agent_alpha.recon.js_secret_probe import _mask
from agent_alpha.security.secrets import SecretsManager

TARGET = "lab.example-you-own.dev"
ENG = "eng_test"
TS = "2026-07-03T00:00:00Z"


def _expected(creds: int, preview: str = "AAAA****BBBB") -> ExpectedGroundTruth:
    return ExpectedGroundTruth(
        bundle_path="/assets/app.lab001.js",
        expected_creds_added=creds,
        expected_secret_kind="generic_assign",
        expected_secret_service="generic",
        expected_secret_preview=preview,
        rejected_decoys=["your_api_key_here", "a" * 18],
        expected_api_endpoints=["/api/v1/users"],
    )


def _vuln_node() -> AttackNode:
    return AttackNode(
        id=f"vuln:{TARGET}:js_secret_leak",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(affected_service="web", exploit_available=False),
        confidence=0.85,
        agent="alpha",
        timestamp_utc=TS,
    )


def _cred_node(secret_ref: str) -> AttackNode:
    return AttackNode(
        id=f"cred:{TARGET}:generic_assign",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="",
            secret_ref=secret_ref,
            service="generic",
            access_level="unverified",
        ),
        confidence=0.75,
        agent="alpha",
        timestamp_utc=TS,
    )


def _persist_node(store: NetworkXGraphStore, node: AttackNode) -> None:
    # Exactly mirrors js_secret_probe._persist_node (production path).
    store.apply_event("NodeDiscovered", node_to_dict(node))


def _persist_leads_to(store: NetworkXGraphStore, src: str, dst: str) -> None:
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": src,
            "target_id": dst,
            "relationship": RelationshipType.LEADS_TO.value,
            "confidence": 0.9,
            "technique_id": None,
        },
    )


def _tp_graph(secret_ref: str) -> NetworkXGraphStore:
    """A correct true-positive graph: vuln -> cred via LEADS_TO."""
    gs = NetworkXGraphStore()
    vuln = _vuln_node()
    cred = _cred_node(secret_ref)
    _persist_node(gs, vuln)
    _persist_node(gs, cred)
    _persist_leads_to(gs, vuln.id, cred.id)
    return gs


# ── Clause 2: graph state ────────────────────────────────────────────────────


def test_clause_2_true_negative_empty_graph_passes() -> None:
    """Zero expected, empty graph -> clean run -> PASS.

    This is the exact case that must PASS but the client run reported FAIL.
    """
    assert _check_clause_2(NetworkXGraphStore(), TARGET, _expected(0)) is True


def test_clause_2_false_positive_nodes_when_expected_zero_fails() -> None:
    """Zero expected but a CREDENTIAL node exists -> fabricated finding -> FAIL.

    Guards the quantum symptom: a zero-cred run must not leave cred/vuln nodes.
    """
    gs = NetworkXGraphStore()
    _persist_node(gs, _cred_node("engagements/x/proofs/js"))
    assert _check_clause_2(gs, TARGET, _expected(0)) is False


def test_clause_2_true_positive_correct_nodes_passes() -> None:
    gs = _tp_graph("engagements/x/proofs/js")
    assert _check_clause_2(gs, TARGET, _expected(1)) is True


def test_clause_2_true_positive_missing_edge_fails() -> None:
    gs = NetworkXGraphStore()
    _persist_node(gs, _vuln_node())
    _persist_node(gs, _cred_node("engagements/x/proofs/js"))
    # no LEADS_TO edge -> not a proven chain
    assert _check_clause_2(gs, TARGET, _expected(1)) is False


# ── Clause 3: vault preview ──────────────────────────────────────────────────


def test_clause_3_true_negative_empty_vault_passes() -> None:
    assert (
        _check_clause_3(NetworkXGraphStore(), SecretsManager(), ENG, TARGET, _expected(0)) is True
    )


def test_clause_3_true_positive_preview_matches() -> None:
    sm = SecretsManager()
    raw = "Zx9Qw3TrLm2Vn8Kp4Hd6Bf1Sg5Yc0Ej"
    rec = sm.store(label="generic:generic_assign", value=raw, engagement_id=ENG)
    gs = _tp_graph(rec.secret_id)
    assert _check_clause_3(gs, sm, ENG, TARGET, _expected(1, preview=_mask(raw))) is True


def test_clause_3_true_positive_wrong_preview_fails() -> None:
    sm = SecretsManager()
    raw = "Zx9Qw3TrLm2Vn8Kp4Hd6Bf1Sg5Yc0Ej"
    rec = sm.store(label="generic:generic_assign", value=raw, engagement_id=ENG)
    gs = _tp_graph(rec.secret_id)
    assert _check_clause_3(gs, sm, ENG, TARGET, _expected(1, preview="XXXX****YYYY")) is False


def test_clause_3_true_negative_detects_secret_vaulted_under_engagement() -> None:
    """Regression guard for the list_labels(engagement_id) fix.

    A secret vaulted under the engagement means the vault is NOT clean, so a
    "zero expected" check must return False. Before the fix, clause 3 queried
    list_labels(target-host) and missed it -> false 'vault clean'.
    """
    sm = SecretsManager()
    sm.store(label="generic:generic_assign", value="SOMESECRETVALUE1234", engagement_id=ENG)
    assert _check_clause_3(NetworkXGraphStore(), sm, ENG, TARGET, _expected(0)) is False


# ── .proven aggregation ──────────────────────────────────────────────────────


def _result(**overrides: bool) -> SpaSecretFieldProveResult:
    base = dict(
        creds_added=1,
        clause_1_return_value=True,
        clause_2_graph_state=True,
        clause_3_vault_preview=True,
        clause_4_decoys_absent=True,
        clause_5_intel_endpoints=True,
        clause_6_no_false_waf=True,
        clause_7_determinism=True,
        clause_8_environment=True,
        detail="",
    )
    base.update(overrides)
    return SpaSecretFieldProveResult(**base)  # type: ignore[arg-type]


def test_proven_true_when_all_clauses_pass() -> None:
    assert _result().proven is True


@pytest.mark.parametrize(
    "failing",
    [
        "clause_1_return_value",
        "clause_2_graph_state",
        "clause_3_vault_preview",
        "clause_4_decoys_absent",
        "clause_5_intel_endpoints",
        "clause_6_no_false_waf",
        "clause_7_determinism",
        "clause_8_environment",
    ],
)
def test_proven_false_when_any_single_clause_fails(failing: str) -> None:
    assert _result(**{failing: False}).proven is False
