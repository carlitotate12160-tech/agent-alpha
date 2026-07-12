# RED (slice-1c wiring) — the backup_file field-prove runner drives the FULL live
# path (Alpha.run_recon → seed backup paths → playbook rule → dispatch →
# _handle_backup_file → verify_backup_file → mint), NOT verify_backup_file DIRECT.
#
# WHY: this is the SAME full-live-path bar git_exposure 1c-ii and Layer V set. The
# runner must reach the vector the way production recon does, so the field-proof is
# proof of the wired path, not of an isolated verifier.
#
# DISCRIMINATOR: run_recon OBSERVEs the target ROOT first; a direct verify only
# fetches the backup paths. So `https://{host}/` in http calls proves run_recon.
# (backup_file is DIRECT — no dumper seam, unlike git_exposure.)
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_backup_file_field_prove_wiring.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.backup_file_field_prove import (
    BackupFileConfig,
    run_backup_file_field_prove,
)
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"
_ENV_BAK_URL = f"https://{_HOST}/.env.bak"
_LEAKED_PASSWORD = "SuperSecretPassword123"
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
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self._responses = responses
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        return self._responses.get(url, FakeResponse(404, ""))


class _StubProvider:
    """Rule tier is deterministic for the leaked-.env body; provider never reached."""

    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _config() -> BackupFileConfig:
    return BackupFileConfig(
        client_id="backup-lab",
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
            _ENV_BAK_URL: FakeResponse(200, _ENV_BAK_BODY),
        }
    )
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider=_StubProvider()
    )

    results = run_backup_file_field_prove(
        _config(),
        auth=AuthorizationStateMachine(event_store=store),
        http_client=http,
        orchestrator=orch,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        secrets_manager=SecretsManager(),
    )

    assert results[_HOST].chain_proven is True
    # Proof it went through run_recon (OBSERVEs the root), not verify_backup_file
    # direct (which only fetches the backup paths).
    assert _ROOT in http.get_calls, (
        "root was never fetched — the field-prove bypassed run_recon (direct "
        f"verify_backup_file). calls={http.get_calls}"
    )
    # The seeded backup path was actually probed on the live path.
    assert _ENV_BAK_URL in http.get_calls
