"""ADR §12.66 Slice-1 — the predicate resolvers actually EVALUATE against the graph, not just
register strings (green != proven, anti-Lyndon #3). A registered predicate that mis-resolves would
silently mislead goal-backward scoring (Slice-2), so pin the resolution semantics here.

Uses a duck-typed graph/node stub (only the read surface the resolvers touch: nodes_by_type /
all_edges / get_node, and node.type / node.properties.<attr>) so this test has ZERO dependency on
the graph-store construction API or node constructor signatures — it pins the PREDICATE semantics,
nothing else.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_alpha.coverage.predicates import is_registered, registered_kinds, resolve
from agent_alpha.graph.nodes import NodeType, RelationshipType


class _FakeGraph:
    def __init__(self, nodes: list, edges: list) -> None:
        self._by_id = {n.id: n for n in nodes}
        self._nodes = nodes
        self._edges = edges

    def nodes_by_type(self, node_type: NodeType) -> list:
        return [n for n in self._nodes if n.type == node_type]

    def all_edges(self) -> list:
        return list(self._edges)

    def get_node(self, node_id: str):
        return self._by_id.get(node_id)


def _cred_access_graph() -> _FakeGraph:
    cred = SimpleNamespace(
        id="cred:h:u",
        type=NodeType.CREDENTIAL,
        properties=SimpleNamespace(username="u", secret_ref="secret_x"),
    )
    access = SimpleNamespace(
        id="access:h",
        type=NodeType.ACCESS_LEVEL,
        properties=SimpleNamespace(level="admin", user_context="u"),
    )
    edge = SimpleNamespace(
        source_id="cred:h:u", target_id="access:h", relationship=RelationshipType.ENABLES
    )
    return _FakeGraph([cred, access], [edge])


def test_credential_access_and_enables_resolve_true() -> None:
    g = _cred_access_graph()
    assert resolve("credential", g) is True
    assert resolve("access:user", g) is True  # admin satisfies a user requirement (>=)
    assert resolve("access:admin", g) is True
    assert resolve("enables_cred_access", g) is True


def test_negatives_on_empty_graph() -> None:
    g = _FakeGraph([], [])
    assert resolve("credential", g) is False
    assert resolve("access:admin", g) is False
    assert resolve("enables_cred_access", g) is False
    assert resolve("fronted_host", g) is False
    assert resolve("user_enumerated", g) is False


def test_user_only_admin_does_not_satisfy_when_only_user_access() -> None:
    access = SimpleNamespace(
        id="access:h", type=NodeType.ACCESS_LEVEL, properties=SimpleNamespace(level="user")
    )
    g = _FakeGraph([access], [])
    assert resolve("access:user", g) is True
    assert resolve("access:admin", g) is False  # user does NOT satisfy an admin requirement


def test_stack_and_auth_surface_and_fronted() -> None:
    asset = SimpleNamespace(
        id="asset:h",
        type=NodeType.ASSET,
        properties=SimpleNamespace(host="h", tech_stack=["wp", "mech_json_rpc"], cf_protected=True),
    )
    g = _FakeGraph([asset], [])
    assert resolve("stack:wp", g) is True
    assert resolve("stack:laravel", g) is False
    assert resolve("auth_surface", g) is True  # any mech_* present
    assert resolve("auth_surface:json_rpc", g) is True
    assert resolve("auth_surface:form_post", g) is False  # that mechanism not present
    assert resolve("fronted_host", g) is True


def test_auth_surface_also_matches_canonical_labels() -> None:
    # A host can be recognized as an auth surface before mechanism fingerprinting runs.
    asset = SimpleNamespace(
        id="asset:h",
        type=NodeType.ASSET,
        properties=SimpleNamespace(host="h", tech_stack=["login-form"], cf_protected=False),
    )
    g = _FakeGraph([asset], [])
    assert resolve("auth_surface", g) is True
    # Parameterized auth_surface still requires a valid mech_* label on the stack.
    assert resolve("auth_surface:form_post", g) is False


def test_bare_auth_surface_rejects_unknown_mech_labels() -> None:
    # `mech_telnet` is not in the closed mechanism vocabulary, so it must not satisfy
    # a bare `auth_surface` precondition that is supposed to be closed.
    asset = SimpleNamespace(
        id="asset:h",
        type=NodeType.ASSET,
        properties=SimpleNamespace(host="h", tech_stack=["mech_telnet"], cf_protected=False),
    )
    g = _FakeGraph([asset], [])
    assert resolve("auth_surface", g) is False


def test_enables_requires_cred_source_and_access_target() -> None:
    # An ENABLES edge that does NOT go CREDENTIAL -> ACCESS_LEVEL must not satisfy the predicate.
    cred = SimpleNamespace(id="cred:h", type=NodeType.CREDENTIAL, properties=SimpleNamespace())
    vuln = SimpleNamespace(id="vuln:h", type=NodeType.VULNERABILITY, properties=SimpleNamespace())
    edge = SimpleNamespace(
        source_id="vuln:h", target_id="cred:h", relationship=RelationshipType.ENABLES
    )
    g = _FakeGraph([cred, vuln], [edge])
    assert resolve("enables_cred_access", g) is False


def test_malformed_or_unregistered_predicates_are_not_registered() -> None:
    assert is_registered("credential") is True
    assert is_registered("access:admin") is True
    assert is_registered("access:root") is False  # rank not in vocabulary
    assert is_registered("auth_surface:telnet") is False
    assert is_registered("stack") is False  # stack requires a label arg
    assert is_registered("credential:x") is False  # no-arg kind given an arg
    assert is_registered("nonsense") is False

    # Malformed shapes must be rejected by the integrity gate (Qodo regression).
    assert is_registered("") is False
    assert is_registered("credential:") is False
    assert is_registered(":credential") is False
    assert is_registered("stack:wp:extra") is False
    assert is_registered("stack:") is False
    # Whitespace-only args must not register (CodeRabbit regression).
    assert is_registered("stack:   ") is False


def test_resolve_raises_on_malformed_predicate() -> None:
    g = _FakeGraph([], [])
    for malformed in ("", "credential:", "stack:wp:extra", "stack:", ":wp", "stack:   "):
        with pytest.raises(ValueError):
            resolve(malformed, g)


def test_vocabulary_is_the_closed_set() -> None:
    assert registered_kinds() == frozenset(
        {
            "credential",
            "access",
            "enables_cred_access",
            "stack",
            "auth_surface",
            "user_enumerated",
            "fronted_host",
        }
    )
