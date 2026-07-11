# RED wiring test (slice-1b) — verify_git_exposure is REACHABLE in the LIVE recon
# path, not an island (anti-Lyndon #2). Slice-1 shipped the module green but with
# ZERO live callers; this pins the wiring so Alpha.run_recon actually reaches it.
#
# TARGET PATH:  tests/phase_4/test_git_exposure_wiring.py
# AUTHORED BY:  Claude (test/gate lane). Wiring bodies (dispatch registration,
#               _handle_git_exposure, WELL_KNOWN_LEAK_PATHS seed, git_exposure.yaml
#               playbook rule, Alpha.git_dumper seam) are the IDE lane.
#
# DESIGN (why these pins):
#   * The live path uses Alpha's default git-dumper (_NoopGitDumper, which RAISES).
#     So Alpha MUST accept an injectable `git_dumper`; the handler threads it into
#     verify_git_exposure. This decouples wiring (here) from the real dumper (1c).
#   * Selection is observation-driven: /.git/config is seeded into the frontier
#     (WELL_KNOWN_LEAK_PATHS) and a playbook rule maps the git-config body ->
#     tool="git_exposure_probe" (consistent with wp_config/js/odoo dispatch).
#
# PINS:
#   W1  "git_exposure_probe" is registered in Alpha._dispatch_registry (not orphan).
#   W2  playbook rule selects "git_exposure_probe" for a git-config observation.
#   W3  Alpha.run_recon on a host serving /.git/config (+ injected dumper carrying a
#       secret) mints a VAULTED CREDENTIAL node — via the LIVE loop, proving reach.
#   W4  the injected git_dumper is the one actually used (secret in graph == the
#       dumped secret) — the seam is threaded Alpha -> handler -> verify.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_git_exposure_wiring.py -v

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
_GIT_CONFIG_URL = f"https://{_HOST}/.git/config"
_GIT_CONFIG_BODY = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = x\n"
_RECOVERED = {
    "config/database.yml": (
        "production:\n  adapter: postgresql\n  database: app_prod\n"
        "  username: appuser\n  password: sup3rs3cret\n  host: db.internal\n"
    ),
}


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
        return self._responses.get(url, FakeResponse(404, ""))


class FakeGitDumper:
    def __init__(self, recovered: dict[str, str]) -> None:
        self._recovered = recovered
        self.dump_calls: list[str] = []

    def dump(self, base_url: str) -> dict[str, str]:
        self.dump_calls.append(base_url)
        return dict(self._recovered)


class _StubProvider:
    """Never reached for the git rule (rule tier is deterministic); present so the
    orchestrator constructs. Returns empty so any non-rule observation is inert."""

    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _alpha(graph, store, http, dumper) -> Alpha:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="git_lab", target=_HOST)
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
        git_dumper=dumper,  # RED: Alpha does not accept git_dumper yet
    )
    return alpha, rec.engagement_id


def test_w1_git_exposure_registered_in_dispatch() -> None:
    store = InMemoryEventStore()
    alpha, _ = _alpha(NetworkXGraphStore(), store, FakeHttpClient({}), FakeGitDumper({}))
    assert "git_exposure_probe" in alpha._dispatch_registry


def test_w2_playbook_rule_selects_git_exposure_for_git_config() -> None:
    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    decision = engine.match({"body": _GIT_CONFIG_BODY, "headers": {}})
    assert decision is not None
    assert decision.tool == "git_exposure_probe"


def test_w3_run_recon_reaches_git_exposure_and_mints_credential() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {_ROOT: FakeResponse(200, "<html>root</html>"), _GIT_CONFIG_URL: FakeResponse(200, _GIT_CONFIG_BODY)}
    )
    dumper = FakeGitDumper(_RECOVERED)
    alpha, eid = _alpha(graph, store, http, dumper)

    alpha.run_recon(eid, _ROOT)

    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    assert len(creds) >= 1  # reached via the LIVE loop → not an island
    assert dumper.dump_calls  # the wired dumper was actually invoked


def test_w4_injected_dumper_secret_is_the_one_vaulted() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {_ROOT: FakeResponse(200, "<html>root</html>"), _GIT_CONFIG_URL: FakeResponse(200, _GIT_CONFIG_BODY)}
    )
    dumper = FakeGitDumper(_RECOVERED)
    alpha, eid = _alpha(graph, store, http, dumper)

    alpha.run_recon(eid, _ROOT)

    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    ref = getattr(creds[0].properties, "secret_ref", "")
    assert ref.startswith("secret_")
    assert alpha._secrets_manager.retrieve(ref)  # the dumped secret is vaulted
