# RED (slice-1c wiring) — the actuator field-prove runner drives the FULL live path
# (Alpha.run_recon → seed ACTUATOR_PATHS → actuator.yaml rule → _handle_path_probe →
# process_path_hit (DIRECT, JSON) → mint), NOT an isolated verifier.
#
# DISCRIMINATOR: run_recon OBSERVEs the target ROOT first, so `https://{host}/` in the
# http calls proves the runner went through run_recon (not a direct probe).
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_actuator_field_prove_wiring.py -v

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.actuator_field_prove import (
    ActuatorConfig,
    run_actuator_field_prove,
)
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"
_ENV_URL = f"https://{_HOST}/actuator/env"
_LEAKED_PASSWORD = "SuperSecretPassword123"
_ENV_BODY = json.dumps(
    {
        "activeProfiles": ["prod"],
        "propertySources": [
            {
                "name": "applicationConfig",
                "properties": {
                    "spring.datasource.username": {"value": "appuser"},
                    "spring.datasource.password": {"value": _LEAKED_PASSWORD},
                },
            }
        ],
    }
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
    """Rule tier is deterministic for the actuator body; provider never reached."""

    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _config() -> ActuatorConfig:
    return ActuatorConfig(
        client_id="actuator-lab",
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
            _ENV_URL: FakeResponse(200, _ENV_BODY),
        }
    )
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider=_StubProvider()
    )

    results = run_actuator_field_prove(
        _config(),
        auth=AuthorizationStateMachine(event_store=store),
        http_client=http,
        orchestrator=orch,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        secrets_manager=SecretsManager(),
    )

    assert results[_HOST].chain_proven is True
    assert _ROOT in http.get_calls, (
        f"root was never fetched — the field-prove bypassed run_recon. calls={http.get_calls}"
    )
    assert _ENV_URL in http.get_calls  # the seeded actuator path was probed on the live path
