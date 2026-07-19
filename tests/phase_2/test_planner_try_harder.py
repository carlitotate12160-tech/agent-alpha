# tests/phase_2/test_planner_try_harder.py
"""Planner.try_harder — deterministic dead-end recovery (GAP-004 D2-b).

T1: greedy-fails / planner-wins — a discovered-late host gets its
    profile-relevant leak paths probed via try_harder, finding a leak the
    greedy loop missed.
T2: termination — fully-probed graph → try_harder returns [] → dead-end.
T3: scope — out-of-scope host in the graph → its paths are NOT enqueued.
T4: single-source — try_harder references constants catalogs / TargetProfile,
    not literals.
T5: regression / narrowing — covered by the full test suite and explicit
    probe-count + field-prove guards in this module.
"""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.planner import Planner
from agent_alpha.agents.world_model import WorldModel
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, AttackNode, NodeType
from agent_alpha.graph.persist import persist_node

from .conftest import FakeHttpClient, FakeHttpResponse

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"

# ── Helpers ──────────────────────────────────────────────────────


def _wm_with_hosts(*hosts: str) -> WorldModel:
    """Build a WorldModel with ASSET nodes for the given hosts."""
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    for h in hosts:
        node = AttackNode(
            id=f"asset:{h}",
            type=NodeType.ASSET,
            properties=AssetProperties(host=h),
            confidence=0.5,
            agent="alpha",
        )
        persist_node(es, store, "test", node, agent="alpha")
    return WorldModel(store)


# ── T1: greedy-fails / planner-wins ─────────────────────────────


def test_try_harder_returns_unprobed_profile_relevant_for_late_host() -> None:
    """A late-discovered host's profile-relevant paths appear in try_harder output."""
    planner = Planner()
    wm = _wm_with_hosts("late.example.com")
    probed: set[str] = set()

    result = planner.try_harder(wm, None, probed)

    # Must include at least one leak/surface path for the late host.
    assert len(result) > 0
    assert all("late.example.com" in u for u in result)
    # Must include the canonical git-leak path for unknown hosts via DEFAULT_LEAK_PATHS.
    assert "https://late.example.com/.git/config" in result


def test_try_harder_excludes_already_probed() -> None:
    """URLs already in `probed` are excluded from try_harder output."""
    planner = Planner()
    wm = _wm_with_hosts("h.example.com")
    probed = {"https://h.example.com/.git/config"}

    result = planner.try_harder(wm, None, probed)

    assert "https://h.example.com/.git/config" not in result
    # Other paths should still be present.
    assert len(result) > 0


def test_try_harder_e2e_leak_found_at_dead_end() -> None:
    """_step_once dead-end recovery: greedy misses a sibling's leak; try_harder
    enqueues the sibling's well-known paths and the leak is found.

    Drives _step_once directly (not through run_cognitive_loop) to test the
    frontier-exhausted seam in isolation, independent of the no_progress
    threshold tuning.
    """
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.tools.playbook import PlaybookEngine

    # ── Auth + scope ─────────────────────────────────────────────
    es = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=es)
    rec = auth.create_engagement(client_id="c", target="lab-target.invalid")
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=[],
            domains=["lab-target.invalid", "sibling.lab-target.invalid"],
            exclusions=[],
        ),
    )

    # ── Fake HTTP ────────────────────────────────────────────────
    git_config_body = (
        "[core]\n"
        "    repositoryformatversion = 0\n"
        "    filemode = true\n"
        '[remote "origin"]\n'
        "    url = git@github.com:org/repo.git\n"
    )

    routes: dict[str, FakeHttpResponse] = {
        "https://sibling.lab-target.invalid/.git/config": FakeHttpResponse(
            status_code=200,
            text=git_config_body,
            headers={"content-type": "text/plain"},
            url="https://sibling.lab-target.invalid/.git/config",
        ),
    }
    http = FakeHttpClient(routes)

    # ── Graph: pre-seed the sibling as a discovered-late host ────
    graph_store = NetworkXGraphStore()
    sibling_node = AttackNode(
        id="asset:sibling.lab-target.invalid",
        type=NodeType.ASSET,
        properties=AssetProperties(host="sibling.lab-target.invalid"),
        confidence=0.5,
        agent="alpha",
    )
    persist_node(es, graph_store, rec.engagement_id, sibling_node, agent="alpha")

    # ── Build Alpha with minimal root frontier ───────────────────
    class _StubProvider:
        model = "deepseek-v4-pro"

        def complete(self, *a: object, **k: object):
            return type(
                "R",
                (),
                {
                    "text": '{"tool": "generic_http_probe"}',
                    "usage_cost_usd": 0.0,
                    "model": "deepseek-v4-pro",
                },
            )()

    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=_StubProvider(),
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=es,
        orchestrator=orchestrator,
        http_client=http,
    )

    # Initialise per-run state with a SMALL root frontier (1 URL).
    alpha._engagement_id = rec.engagement_id
    alpha._work_queue = ["https://lab-target.invalid/"]
    alpha._probed = set()
    alpha._findings = 0
    alpha._analyzable_probes = 0
    alpha._ran_campaigns = set()
    alpha._body_hashes = set()
    alpha._current_objective = None
    alpha._try_harder_fired = False

    # ── Drive _step_once until dead-end ──────────────────────────
    context: dict[str, object] = {"scratchpad": {}}
    max_steps = 200  # safety bound
    for _ in range(max_steps):
        result = alpha._step_once(context)
        context["scratchpad"] = result.get("scratchpad", {})
        # Dead-end: observation says "No unprobed URLs remaining"
        obs = context.get("scratchpad", {})
        if isinstance(obs, dict):
            observations = obs.get("observations", [])
            if any("No unprobed URLs remaining" in str(o) for o in observations):
                break
        # Also break if the work queue AND probed set fully cover the sibling
        if not alpha._work_queue and alpha._try_harder_fired:
            # try_harder already ran, no more work — we're at the real dead-end
            break
    else:
        pytest.fail("Loop did not terminate within max_steps")

    # The sibling's /.git/config URL MUST have been probed.
    assert "https://sibling.lab-target.invalid/.git/config" in http.calls, (
        f"try_harder did not cause the sibling's /.git/config to be probed.\n"
        f"Probed URLs: {http.calls}"
    )


# ── T2: termination ─────────────────────────────────────────────


def test_try_harder_returns_empty_when_all_profile_relevant_probed() -> None:
    """Fully-probed graph → try_harder returns [] → loop terminates."""
    planner = Planner()
    wm = _wm_with_hosts("h.example.com")

    # Pre-populate probed with ALL paths that would be seeded for an unknown host:
    # universal (GIT_LEAK_PATHS) + DEFAULT_LEAK_PATHS (superset includes git).
    from agent_alpha.recon.path_probe import PATH_PROBE_CATALOG

    all_paths: set[str] = set()
    for spec in PATH_PROBE_CATALOG:
        if not spec.applies_to_stacks:
            all_paths.update(spec.paths)
    all_paths.update(constants.DEFAULT_LEAK_PATHS)
    probed = {f"https://h.example.com{p}" for p in all_paths}

    result = planner.try_harder(wm, None, probed)
    assert result == []


def test_step_once_terminates_when_try_harder_yields_nothing() -> None:
    """_step_once with empty frontier + empty try_harder → dead-end finish."""
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.tools.playbook import PlaybookEngine

    es = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=es)
    rec = auth.create_engagement(client_id="c", target="empty.invalid")
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=["empty.invalid"], exclusions=[]),
    )

    class _StubProvider:
        model = "deepseek-v4-pro"

        def complete(self, *a: object, **k: object):
            return type(
                "R",
                (),
                {
                    "text": '{"tool": "generic_http_probe"}',
                    "usage_cost_usd": 0.0,
                    "model": "deepseek-v4-pro",
                },
            )()

    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=_StubProvider(),
    )
    graph_store = NetworkXGraphStore()
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=es,
        orchestrator=orchestrator,
        http_client=FakeHttpClient({}),
    )

    # Initialise per-run state manually (run_recon does this).
    alpha._engagement_id = rec.engagement_id
    alpha._work_queue = []
    alpha._probed = set()
    alpha._findings = 0
    alpha._analyzable_probes = 0
    alpha._ran_campaigns = set()
    alpha._body_hashes = set()
    alpha._current_objective = None
    alpha._try_harder_fired = False

    result = alpha._step_once({"scratchpad": {}})
    sp = result.get("scratchpad", {})
    obs = sp.get("observations", [])
    assert any("No unprobed URLs remaining" in str(o) for o in obs)


# ── T3: scope ────────────────────────────────────────────────────


def test_try_harder_out_of_scope_host_not_enqueued() -> None:
    """An out-of-scope host in the graph → its well-known paths are NOT enqueued."""
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.tools.playbook import PlaybookEngine

    es = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=es)
    rec = auth.create_engagement(client_id="c", target="in-scope.invalid")
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=[],
            domains=["in-scope.invalid"],  # out-of-scope.invalid NOT listed
            exclusions=[],
        ),
    )

    class _StubProvider:
        model = "deepseek-v4-pro"

        def complete(self, *a: object, **k: object):
            return type(
                "R",
                (),
                {
                    "text": '{"tool": "generic_http_probe"}',
                    "usage_cost_usd": 0.0,
                    "model": "deepseek-v4-pro",
                },
            )()

    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=_StubProvider(),
    )
    graph_store = NetworkXGraphStore()

    # Pre-seed an out-of-scope host in the graph.
    oos_node = AttackNode(
        id="asset:out-of-scope.invalid",
        type=NodeType.ASSET,
        properties=AssetProperties(host="out-of-scope.invalid"),
        confidence=0.5,
        agent="alpha",
    )
    persist_node(es, graph_store, rec.engagement_id, oos_node, agent="alpha")

    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=es,
        orchestrator=orchestrator,
        http_client=FakeHttpClient({}),
    )

    # Initialise per-run state.
    alpha._engagement_id = rec.engagement_id
    alpha._work_queue = []
    alpha._probed = set()
    alpha._findings = 0
    alpha._analyzable_probes = 0
    alpha._ran_campaigns = set()
    alpha._body_hashes = set()
    alpha._current_objective = None
    alpha._try_harder_fired = False

    # _step_once triggers try_harder, which produces candidates for
    # out-of-scope.invalid, but enqueue_discovered_url blocks them.
    alpha._step_once({"scratchpad": {}})

    # No out-of-scope URL should have been enqueued.
    assert all("out-of-scope.invalid" not in u for u in alpha._work_queue)
    assert all("out-of-scope.invalid" not in u for u in alpha._probed)


# ── T4: single-source / structural ───────────────────────────────


def test_try_harder_uses_constants_catalogs_only() -> None:
    """try_harder references PATH_PROBE_CATALOG + constants, not literal paths.

    It must depend on the catalog for path selection and
    constants.DEFAULT_LEAK_PATHS / SURFACE_APPLIES_TO for fallback/gating.
    """
    import inspect

    source = inspect.getsource(Planner.try_harder)

    # Must reference the catalog and constant names.
    assert "PATH_PROBE_CATALOG" in source
    assert "DEFAULT_LEAK_PATHS" in source
    assert "SURFACE_APPLIES_TO" in source
    assert "SURFACE_DISCOVERY_PATHS" in source

    # Must NOT contain literal well-known paths (no hardcoded /.git/config etc.).
    for path in constants.WELL_KNOWN_LEAK_PATHS[:3]:
        assert path not in source, f"Literal path {path!r} found in try_harder source"
    for path in constants.SURFACE_DISCOVERY_PATHS[:3]:
        assert path not in source, f"Literal path {path!r} found in try_harder source"
    # Sanity: DEFAULT_LEAK_PATHS must include .env.bak.
    assert "/.env.bak" in constants.DEFAULT_LEAK_PATHS


def test_try_harder_reduces_probe_count_with_profiles() -> None:
    """Catalog-directed try_harder must probe strictly FEWER URLs than the
    old all-WELL_KNOWN_LEAK_PATHS+SURFACE_DISCOVERY_PATHS shotgun for a
    graph with fingerprinted hosts.
    """
    planner = Planner()

    # Manually attach tech_stack markers via ASSET nodes for three hosts so
    # not all path-groups apply to each.
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    for host, stack in (
        ("laravel.example.com", ["php/8.1", "laravel"]),
        ("tomcat.example.com", ["tomcat/9.0", "spring"]),
        ("plain.example.com", ["nginx/1.24"]),
    ):
        node = AttackNode(
            id=f"asset:{host}",
            type=NodeType.ASSET,
            properties=AssetProperties(host=host, tech_stack=stack),
            confidence=0.5,
            agent="alpha",
        )
        persist_node(es, store, "test_probes", node, agent="alpha")
    wm_profiled = WorldModel(store)

    probed: set[str] = set()

    # New behaviour: per-host catalog-directed selection.
    profiled_urls = set(planner.try_harder(wm_profiled, None, probed))

    # Old behaviour (shotgun) for comparison: every host gets the full union.
    all_paths = [*constants.WELL_KNOWN_LEAK_PATHS, *constants.SURFACE_DISCOVERY_PATHS]
    unique_paths = list(dict.fromkeys(all_paths))
    shotgun_urls = {
        f"https://{host}{p}"
        for host in ("laravel.example.com", "tomcat.example.com", "plain.example.com")
        for p in unique_paths
    }

    # Catalog-directed must strictly reduce the number of probes.
    assert len(profiled_urls) < len(shotgun_urls)


# ── T5: structural ───────────────────────────────────────────────


def test_planner_has_try_harder_method() -> None:
    """Planner MUST expose a try_harder() method."""
    planner = Planner()
    assert callable(getattr(planner, "try_harder", None))


def test_try_harder_is_pure_no_world_model_mutation() -> None:
    """Calling try_harder must NOT add/remove nodes in the world model."""
    store = NetworkXGraphStore()
    es = InMemoryEventStore()
    node = AttackNode(
        id="asset:h.example.com",
        type=NodeType.ASSET,
        properties=AssetProperties(host="h.example.com"),
        confidence=0.5,
        agent="alpha",
    )
    persist_node(es, store, "test", node, agent="alpha")
    wm = WorldModel(store)

    nodes_before = len(list(store.all_nodes()))
    edges_before = len(list(store.all_edges()))

    planner = Planner()
    planner.try_harder(wm, None, set())

    assert len(list(store.all_nodes())) == nodes_before
    assert len(list(store.all_edges())) == edges_before


def test_try_harder_stable_order() -> None:
    """Results are in stable insertion order (host order × path order)."""
    planner = Planner()
    wm = _wm_with_hosts("a.example.com", "b.example.com")
    probed: set[str] = set()

    r1 = planner.try_harder(wm, None, probed)
    r2 = planner.try_harder(wm, None, probed)
    assert r1 == r2  # identical order across calls
