# tests/phase_2/test_target_profile.py
"""TargetProfile + profile-directed try_harder tests (Phase 2).

T1 narrowing: host tech_stack {"php/8.1"} → try_harder seeds GIT_LEAK_PATHS
    (universal) + BACKUP_FILE_PATHS (substring "php"), but NOT ACTUATOR_PATHS.

T2 spring: {"apache-coyote","spring"} → git + ACTUATOR, not BACKUP.

T3 unknown default: {"nginx/1.24"} (no leak-stack match) → git +
    DEFAULT_LEAK_PATHS incl. ".env.bak".

T4 surface gate: {"graphql"} includes SURFACE_DISCOVERY_PATHS; {"nginx"} does NOT.

T5 reduction: try_harder total candidates strictly FEWER than old all-paths.

T6 field-prove intact: TargetProfile.from_graph does not mutate graph.
"""

from __future__ import annotations

from agent_alpha.agents.planner import Planner
from agent_alpha.agents.target_profile import TargetProfile
from agent_alpha.agents.world_model import WorldModel
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, AttackNode, NodeType
from agent_alpha.graph.persist import persist_node


def _wm_with_asset(host: str, tech_stack: list[str] | None = None) -> WorldModel:
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    node = AttackNode(
        id=f"asset:{host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, tech_stack=tech_stack or []),
        confidence=0.5,
        agent="alpha",
    )
    persist_node(es, store, "test", node, agent="alpha")
    return WorldModel(store)


def _paths_from_urls(urls: list[str]) -> set[str]:
    """Extract path portion from https://host/path URLs."""
    from urllib.parse import urlparse

    return {urlparse(u).path for u in urls}


# ── T1: narrowing (php/8.1 → git + backup, NOT actuator) ─────────


def test_php_host_gets_git_and_backup_not_actuator() -> None:
    wm = _wm_with_asset("php.example", ["php/8.1"])
    urls = Planner().try_harder(wm, None, set())
    paths = _paths_from_urls(urls)

    # Universal (git) always present.
    for p in constants.GIT_LEAK_PATHS:
        assert p in paths

    # Backup matches "php" substring.
    for p in constants.BACKUP_FILE_PATHS:
        assert p in paths

    # Actuator must NOT be included.
    for p in constants.ACTUATOR_PATHS:
        assert p not in paths


# ── T2: spring host → git + actuator, NOT backup ─────────────────


def test_spring_host_gets_git_and_actuator_not_backup() -> None:
    wm = _wm_with_asset("spring.example", ["apache-coyote", "spring"])
    urls = Planner().try_harder(wm, None, set())
    paths = _paths_from_urls(urls)

    for p in constants.GIT_LEAK_PATHS:
        assert p in paths
    for p in constants.ACTUATOR_PATHS:
        assert p in paths
    for p in constants.BACKUP_FILE_PATHS:
        assert p not in paths


# ── T3: unknown default (nginx/1.24 → git + DEFAULT_LEAK_PATHS) ──


def test_unknown_host_gets_git_and_default_leak_paths() -> None:
    wm = _wm_with_asset("late.example", ["nginx/1.24"])
    urls = Planner().try_harder(wm, None, set())
    paths = _paths_from_urls(urls)

    # Universal git always present.
    for p in constants.GIT_LEAK_PATHS:
        assert p in paths

    # DEFAULT_LEAK_PATHS also seeded (superset includes git + .env.bak + .env).
    assert "/.env.bak" in paths
    assert "/.env" in paths

    # Must NOT include actuator or backup (not matched).
    for p in constants.ACTUATOR_PATHS:
        assert p not in paths
    for p in constants.BACKUP_FILE_PATHS:
        if p not in constants.DEFAULT_LEAK_PATHS:
            assert p not in paths


# ── T4: surface gate ──────────────────────────────────────────────


def test_graphql_host_includes_surface_discovery() -> None:
    wm = _wm_with_asset("api.example", ["graphql"])
    urls = Planner().try_harder(wm, None, set())
    paths = _paths_from_urls(urls)
    for p in constants.SURFACE_DISCOVERY_PATHS:
        assert p in paths


def test_nginx_host_excludes_surface_discovery() -> None:
    wm = _wm_with_asset("web.example", ["nginx/1.24"])
    urls = Planner().try_harder(wm, None, set())
    paths = _paths_from_urls(urls)
    for p in constants.SURFACE_DISCOVERY_PATHS:
        assert p not in paths


# ── T5: reduction — fewer candidates than old shotgun ─────────────


def test_try_harder_reduces_probe_count() -> None:
    """Profile-directed approach must seed strictly fewer paths than the
    old shotgun (all WELL_KNOWN_LEAK_PATHS + SURFACE_DISCOVERY_PATHS)."""
    # 3 fingerprinted hosts with distinct stacks.
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    for host, stack in [
        ("laravel.example", ["php/8.1", "laravel"]),
        ("spring.example", ["tomcat/9.0", "spring"]),
        ("plain.example", ["nginx/1.24"]),
    ]:
        node = AttackNode(
            id=f"asset:{host}",
            type=NodeType.ASSET,
            properties=AssetProperties(host=host, tech_stack=stack),
            confidence=0.5,
            agent="alpha",
        )
        persist_node(es, store, "test", node, agent="alpha")
    wm = WorldModel(store)

    new_urls = Planner().try_harder(wm, None, set())

    # Old shotgun: all hosts × (WELL_KNOWN_LEAK_PATHS + SURFACE_DISCOVERY_PATHS).
    old_count = 3 * (len(constants.WELL_KNOWN_LEAK_PATHS) + len(constants.SURFACE_DISCOVERY_PATHS))
    assert len(new_urls) < old_count


# ── T6: from_graph does not mutate the graph ──────────────────────


def test_from_graph_does_not_mutate_graph() -> None:
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    node = AttackNode(
        id="asset:h.example",
        type=NodeType.ASSET,
        properties=AssetProperties(host="h.example", tech_stack=["laravel"]),
        confidence=0.5,
        agent="alpha",
    )
    persist_node(es, store, "test", node, agent="alpha")
    wm = WorldModel(store)

    nodes_before = len(list(store.all_nodes()))
    edges_before = len(list(store.all_edges()))

    _ = TargetProfile.from_graph(wm, "h.example")

    assert len(list(store.all_nodes())) == nodes_before
    assert len(list(store.all_edges())) == edges_before
