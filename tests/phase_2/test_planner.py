"""Planner unit tests — deterministic scorer extracted from scout (GAP-004 D2-a).

T2: Pure / deterministic — same inputs → same int, no world_model mutation.
T3: Objective-aware — target-matching credential scores higher.
T4: No-objective — login-path heuristic only, no graph target bonus.
T5: Structural — scout no longer defines _score_frontier_url/_objective_targets.
"""

from __future__ import annotations

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.objective import EngagementObjective
from agent_alpha.agents.planner import Planner
from agent_alpha.agents.world_model import WorldModel
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    CredentialProperties,
    NodeType,
)
from agent_alpha.graph.persist import persist_node

# ── Helpers ──────────────────────────────────────────────────────


def _make_wm_with_credential(host: str, access_level: str) -> WorldModel:
    """Build a WorldModel backed by a graph containing a single CREDENTIAL."""
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    node = AttackNode(
        id=f"cred_{host}",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="u", secret_ref="ref", service="svc", access_level=access_level
        ),
        confidence=0.9,
        agent="alpha",
    )
    persist_node(es, store, "test", node, agent="alpha")
    return WorldModel(store)


def _make_wm_with_asset(host: str, tech_stack: list[str] | None = None) -> WorldModel:
    """Build a WorldModel backed by a graph containing a single ASSET."""
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    node = AttackNode(
        id=f"asset_{host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, tech_stack=tech_stack or []),
        confidence=0.9,
        agent="alpha",
    )
    persist_node(es, store, "test", node, agent="alpha")
    return WorldModel(store)


def _empty_wm() -> WorldModel:
    return WorldModel(NetworkXGraphStore())


OBJECTIVE = EngagementObjective(
    target_access_levels=frozenset(["admin", "root", "db_root"]),
    description="test",
)


# ── T2: Pure / deterministic ────────────────────────────────────


def test_score_is_deterministic_same_inputs_same_output() -> None:
    """Same (url, world_model, objective) → identical int every call."""
    planner = Planner()
    wm = _make_wm_with_credential("a.example.com", "admin")
    url = "http://a.example.com/login"
    results = {planner.score(url, wm, OBJECTIVE) for _ in range(10)}
    assert len(results) == 1  # always the same int


def test_score_does_not_mutate_world_model() -> None:
    """Calling score() must NOT add/remove nodes or edges in the world model."""
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    node = AttackNode(
        id="cred_x",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="u", secret_ref="ref", service="svc", access_level="admin"
        ),
        confidence=0.9,
        agent="alpha",
    )
    persist_node(es, store, "test", node, agent="alpha")
    wm = WorldModel(store)

    nodes_before = len(list(store.all_nodes()))
    edges_before = len(list(store.all_edges()))

    planner = Planner()
    planner.score("http://x.com/login", wm, OBJECTIVE)

    assert len(list(store.all_nodes())) == nodes_before
    assert len(list(store.all_edges())) == edges_before


# ── T3: Objective-aware ─────────────────────────────────────────


def test_target_credential_scores_higher_than_unrelated() -> None:
    """A URL whose host has a CREDENTIAL matching objective.target_access_levels
    scores strictly higher than an unrelated host (target-enabling cred +150
    vs. non-target cred +50)."""
    planner = Planner()
    wm_target = _make_wm_with_credential("target.com", "admin")
    wm_other = _make_wm_with_credential("other.com", "viewer")

    score_target = planner.score("http://target.com/x", wm_target, OBJECTIVE)
    score_other = planner.score("http://other.com/x", wm_other, OBJECTIVE)

    assert score_target > score_other


def test_target_credential_bonus_is_150_nontarget_is_50() -> None:
    """Exact weights: target-matching credential = 150, non-target = 50."""
    planner = Planner()
    # Plain URL (no login keywords) so only graph evidence contributes.
    wm_target = _make_wm_with_credential("t.com", "db_root")
    wm_other = _make_wm_with_credential("o.com", "viewer")

    assert planner.score("http://t.com/x", wm_target, OBJECTIVE) == 150
    assert planner.score("http://o.com/x", wm_other, OBJECTIVE) == 50


# ── T4: No-objective ────────────────────────────────────────────


def test_no_objective_returns_login_heuristic_only() -> None:
    """score with objective=None returns the login-path heuristic only (no
    graph target bonus) — matches _objective_targets(None)==frozenset()."""
    planner = Planner()
    wm = _make_wm_with_credential("x.com", "admin")

    # /login path → +80, cred with no targets (frozenset()) → non-target +50
    score_login = planner.score("http://x.com/login", wm, None)
    score_plain = planner.score("http://x.com/page", wm, None)

    assert score_login > score_plain
    # With no objective, cred is always non-target (+50), login path +80.
    assert score_login == 80 + 50  # 130
    assert score_plain == 50


def test_no_objective_empty_graph_login_path() -> None:
    """Empty graph + no objective → only path heuristic."""
    planner = Planner()
    wm = _empty_wm()
    assert planner.score("http://x.com/login", wm, None) == 80
    assert planner.score("http://x.com/page", wm, None) == 0


# ── T5: Structural (anti-god-object) ────────────────────────────


def test_scout_no_longer_defines_score_frontier_url() -> None:
    """Alpha (scout) must NOT define _score_frontier_url — it's in Planner."""
    assert not hasattr(Alpha, "_score_frontier_url"), (
        "Alpha still defines _score_frontier_url; it should have been moved to Planner"
    )


def test_scout_no_longer_defines_objective_targets() -> None:
    """Alpha (scout) must NOT define _objective_targets — it's in Planner."""
    assert not hasattr(Alpha, "_objective_targets"), (
        "Alpha still defines _objective_targets; it should have been moved to Planner"
    )


def test_planner_has_score_method() -> None:
    """Planner MUST expose a score() method."""
    planner = Planner()
    assert callable(getattr(planner, "score", None))


def test_planner_module_has_objective_targets() -> None:
    """The planner module must define _objective_targets (module-private)."""
    from agent_alpha.agents import planner as planner_mod

    assert callable(getattr(planner_mod, "_objective_targets", None))
