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
