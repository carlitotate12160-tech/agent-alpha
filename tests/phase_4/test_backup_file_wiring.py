# RED wiring test (slice-1b) — verify_backup_file is REACHABLE in the LIVE recon
# path, not an island (anti-Lyndon #2). Slice-1 shipped the module green but with
# ZERO live callers; this pins the wiring so Alpha.run_recon actually reaches it.
#
# TARGET PATH:  tests/phase_4/test_backup_file_wiring.py
# AUTHORED BY:  Claude (test/gate lane). Wiring bodies (dispatch registration,
#               _handle_backup_file, BACKUP_FILE_PATHS seed into WELL_KNOWN_LEAK_PATHS,
#               backup_file.yaml playbook rule) are the IDE lane.
#
# DESIGN (why these pins, and how backup_file differs from git_exposure 1b):
#   * DIRECT, no dumper: a 200 on a backup path IS the recovered content, so there
#     is NO injectable-dumper seam to thread (git_exposure's W4 dumper pin has no
#     analog). W4 here instead pins that the LEAKED secret is the one vaulted.
#   * Selection is observation-driven: the backup paths are seeded into the frontier
#     (WELL_KNOWN_LEAK_PATHS composes BACKUP_FILE_PATHS) and a playbook rule maps a
#     leaked-.env body -> tool="backup_file_probe" (consistent with git/wp/js/odoo).
#
# PINS:
#   W1  "backup_file_probe" is registered in Alpha._dispatch_registry (not orphan).
#   W2  playbook rule selects "backup_file_probe" for a leaked backup-config body.
#   W3  Alpha.run_recon on a host serving /.env.bak (leaked DB creds) mints a VAULTED
#       CREDENTIAL node — via the LIVE loop, proving reach (non-island).
#   W4  the vaulted secret == the leaked password — extraction->assemble->vault is
#       threaded through the live dispatch, not fabricated.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_backup_file_wiring.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"
_ENV_BAK_URL = f"https://{_HOST}/.env.bak"
_LEAKED_PASSWORD = "sup3rs3cret"
_ENV_BAK_BODY = (
    "APP_ENV=production\n"
    "DB_USER=appuser\n"
    f"DB_PASSWORD={_LEAKED_PASSWORD}\n"
    "DB_NAME=app_prod\n"
    "DB_HOST=db.internal\n"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}


class FakeHttpClient:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self._responses = responses
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        # Unmapped paths return an EMPTY 404 (non-analyzable) — never raises.
        return self._responses.get(url, FakeResponse(404, ""))


class _StubProvider:
    """Never reached for the backup rule (rule tier is deterministic); present so
    the orchestrator constructs. Returns empty so any non-rule body is inert."""

    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _alpha(graph, store, http):
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="backup_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider=_StubProvider()
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph,
        event_store=store,
        orchestrator=orch,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    return alpha, rec.engagement_id


def test_w1_backup_file_registered_in_dispatch() -> None:
    store = InMemoryEventStore()
    alpha, _ = _alpha(NetworkXGraphStore(), store, FakeHttpClient({}))
    assert "backup_file_probe" in alpha._dispatch_registry


def test_w2_playbook_rule_selects_backup_file_for_leaked_env() -> None:
    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    decision = engine.match({"body": _ENV_BAK_BODY, "headers": {}})
    assert decision is not None
    assert decision.tool == "backup_file_probe"


def test_w3_run_recon_reaches_backup_file_and_mints_credential() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>"),
            _ENV_BAK_URL: FakeResponse(200, _ENV_BAK_BODY),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    assert len(creds) >= 1  # reached via the LIVE loop → not an island
    assert _ENV_BAK_URL in http.get_calls  # the seeded backup path was actually fetched


def test_w4_leaked_secret_is_the_one_vaulted() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>"),
            _ENV_BAK_URL: FakeResponse(200, _ENV_BAK_BODY),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    ref = getattr(creds[0].properties, "secret_ref", "")
    assert ref.startswith("secret_")
    assert alpha._secrets_manager.retrieve(ref) == _LEAKED_PASSWORD


# ── Stack-gated seed tests (Bug #26 Layer 3) ───────────────────────────────


def test_run_recon_does_not_seed_wp_paths_for_non_wp_host() -> None:
    """A non-WP host (generic HTML, no wp-content/wp-includes markers) must
    NEVER receive WP-specific backup paths (wp-config.php~, .save, .orig, .swp,
    .old, .dist, .txt) during run_recon. Those paths are gated behind
    wp_fingerprint detection (capability_probe.py frontier_seeds).

    Note: wp-config.php.bak IS seeded as a cross-stack backup path
    (DEFAULT_LEAK_PATHS) — backup files can be left on any server regardless
    of stack (field-proven on alpha-ai.web.id, an Odoo site with a real
    wp-config.php.bak containing DB credentials).
    """
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html><body>plain site, no WP markers</body></html>"),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    # WP-specific suffix variants — these should NOT be seeded for non-WP hosts.
    wp_specific_suffixes = ("~", ".save", ".orig", ".swp", ".old", ".dist", ".txt")
    wp_specific_paths = [
        u
        for u in http.get_calls
        if "wp-config" in u and any(u.endswith(s) for s in wp_specific_suffixes)
    ]
    assert not wp_specific_paths, (
        f"Non-WP host received WP-specific backup paths: {wp_specific_paths} — "
        "these should only seed via wp_fingerprint.frontier_seeds"
    )
    actuator_paths = [u for u in http.get_calls if "/actuator" in u or u.endswith("/env")]
    assert not actuator_paths, (
        f"Non-Tomcat host received actuator probe paths: {actuator_paths} — "
        "ACTUATOR_PATHS should only seed via tomcat_fingerprint.frontier_seeds"
    )


def test_run_recon_initial_seed_count_bounded() -> None:
    """First-wave request count to a new host must be <=
    len(select_leak_paths([])) + len(SURFACE_DISCOVERY_PATHS), NOT the full
    WELL_KNOWN_LEAK_PATHS union (which included 9 WP-config + 2 actuator paths).
    """
    from agent_alpha.agents.planner import Planner

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html><body>generic</body></html>"),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    max_expected = len(Planner().select_leak_paths(labels=[])) + len(
        constants.SURFACE_DISCOVERY_PATHS
    )
    # Subtract 1 for the seed URL itself (not a leak/surface path).
    # Subtract 1 for the GAP-044 soft-404 calibration probe (1 random path per host).
    actual_probe_count = len(http.get_calls) - 2  # -1 _ROOT seed, -1 soft404 calibration
    assert actual_probe_count <= max_expected, (
        f"Initial seed sent {actual_probe_count} probe paths, expected <= {max_expected} "
        f"(select_leak_paths([]) + SURFACE_DISCOVERY_PATHS). "
        f"WELL_KNOWN_LEAK_PATHS would have sent {len(constants.WELL_KNOWN_LEAK_PATHS)}. "
        f"calls={http.get_calls}"
    )


def test_ci_host_derives_ci_config_not_wp() -> None:
    """A 'codeigniter'-labeled host's selected paths include
    /application/config/database.php AND contain NO /wp-config.php* variant.

    Proves the observe→framework→derive seam: CI fingerprint → CI label →
    CI-specific paths (not WP paths). The Planner's select_leak_paths is the
    derivation point — it checks PATH_PROBE_CATALOG.applies_to_stacks against
    the host's labels. A CI label matches the codeigniter_config spec but NOT
    the backup_file spec (which gates on {laravel, wp, php, web}), and
    DEFAULT_LEAK_PATHS is suppressed when a stack-specific spec matched.
    """
    from agent_alpha.agents.planner import Planner

    paths = Planner().select_leak_paths([constants.STACK_CI])

    # CI config path IS derived
    assert "/application/config/database.php" in paths, (
        f"CI host should derive /application/config/database.php, got: {paths}"
    )
    # NO WP-specific path is derived
    wp_paths = [p for p in paths if "wp-config" in p]
    assert not wp_paths, (
        f"CI host received WP-specific paths: {wp_paths} — "
        "backup_file spec should not match 'codeigniter' label, "
        "and DEFAULT_LEAK_PATHS should be suppressed when a stack-specific spec matched"
    )


# CI config-path derivation reachable in the LIVE recon path (slice-1 CI, anti-Lyndon #2).
# Proves observe(codeigniter)->derive(CI config)->probe fires on run_recon end-to-end — not just the
# units (fingerprint / select_leak_paths / dispatch) in isolation. RUNNER-SEAL != AUTONOMOUS-WIRED.
_CI_ROOT_BODY = '<html><form><input name="csrf_test_name" value="a1b2"></form></html>'
_CI_CONFIG_URL = _ROOT.rstrip("/") + constants.CI_CONFIG_PATHS[0]  # /application/config/database.php


def test_w_run_recon_reaches_codeigniter_config() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, _CI_ROOT_BODY),  # CI marker -> fingerprint labels 'codeigniter'
            _CI_CONFIG_URL: FakeResponse(200, "<?php $db['default']['password'] = 'p';"),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    # observe->derive->probe fired on the LIVE loop (non-island):
    assert _CI_CONFIG_URL in http.get_calls, (
        f"CI config path never probed on the live path; got: {http.get_calls}"
    )
    # precision: a CI host must NOT be sprayed with WP-config variants (anti-scanner, section recon-precision):
    assert not any("wp-config" in u for u in http.get_calls)
