# RED (git_exposure refinement 1) — the field-prove runner drives the FULL live
# path (Alpha.run_recon → seed /.git/config → playbook rule → dispatch → handler →
# GitDumper → mint), NOT verify_git_exposure DIRECT.
#
# WHY: the runner already threads an `orchestrator` (line ~92) but never uses it —
# the direct verify_git_exposure call is an incomplete implementation. Routing
# through run_recon (a) closes the only un-proven intersection (real dumper +
# scout wiring, together, live), (b) removes the dead orchestrator param, (c) sets
# the correct field-prove template that backup_file will clone. Meets the same
# full-live-path bar Layer V set.
#
# DISCRIMINATOR: run_recon OBSERVEs the target ROOT first; a direct verify only
# fetches /.git/config. So `https://{host}/` appearing in http calls proves the
# runner went through run_recon.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_git_exposure_field_prove_wiring.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.git_exposure_field_prove import (
    GitExposureConfig,
    run_git_exposure_field_prove,
)
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"
_GIT_CONFIG_URL = f"https://{_HOST}/.git/config"
_GIT_CONFIG_BODY = "[core]\n\trepositoryformatversion = 0\n"
_RECOVERED = {
    "config/database.yml": (
        "production:\n  username: appuser\n  password: sup3rs3cret\n  host: db.internal\n"
    ),
}


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


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
    """Rule tier is deterministic for the git-config body; provider never reached."""

    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _config() -> GitExposureConfig:
    return GitExposureConfig(
        client_id="git-lab",
        scope_ip_ranges=[],
        scope_domains=[_HOST],
        scope_exclusions=[],
        recon_url=_ROOT,
    )


def test_field_prove_routes_through_run_recon() -> None:
    store = InMemoryEventStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>"),
            _GIT_CONFIG_URL: FakeResponse(200, _GIT_CONFIG_BODY),
        }
    )
    dumper = FakeGitDumper(_RECOVERED)
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider=_StubProvider()
    )

    results = run_git_exposure_field_prove(
        _config(),
        auth=AuthorizationStateMachine(event_store=store),
        http_client=http,
        orchestrator=orch,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        secrets_manager=SecretsManager(),
        dumper=dumper,
    )

    assert results[_HOST].chain_proven is True
    # Proof it went through run_recon (OBSERVEs the root), not verify_git_exposure
    # direct (which only fetches /.git/config).
    assert _ROOT in http.get_calls, (
        "root was never fetched — the field-prove bypassed run_recon (direct "
        f"verify_git_exposure). calls={http.get_calls}"
    )
    assert dumper.dump_calls  # the injected dumper was still used through the wired path
