"""Contract: cred-reuse chain runner — Alpha harvest+vault → Beta reuse → access,
in ONE process sharing a SecretsManager. Proves the runner's scorecard, especially
edge_from_harvested_cred (the real-vs-fake chain check).

Credential-aware fake: the login grants access ONLY to the leaked DB_PASSWORD value
(models password reuse), so access cannot come from default_creds (admin/admin) —
it must be cred_reuse applying Alpha's vaulted secret.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any

import agent_alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.live_fire.chain_runner import ChainConfig, run_chain_live_fire
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(agent_alpha.__file__).parent / "tools" / "playbooks"
RECON_URL = "http://127.0.0.1:9201/trigger-error"
LOGIN_URL = "http://127.0.0.1:9201/login"
LEAKED = "s3cr3t-reuse-x9q2"

DEBUG_BODY = (
    "<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head>"
    "<body>Illuminate exception<table>"
    f"<tr><td>DB_PASSWORD</td><td>{LEAKED}</td></tr></table></body></html>"
)
LOGIN_PAGE = '<html><form><input type="password" name="password"></form> please log in</html>'
DASHBOARD = "<html>admin dashboard, welcome administrator</html>"


@dataclass
class _R:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""


class _ChainFake:
    """recon → Laravel debug leak; login → grants access ONLY to the leaked value."""

    def get(self, url: str, *, headers: Any = None, cookies: Any = None) -> _R:
        if "trigger-error" in url:
            return _R(500, DEBUG_BODY, {"server": "nginx"}, url)
        # login_url: a session cookie (confirm step) sees the dashboard; baseline sees login.
        if cookies:
            return _R(200, DASHBOARD, {}, url)
        return _R(200, LOGIN_PAGE, {}, url)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        password = (data or {}).get("password")
        if password == LEAKED:
            return _R(200, DASHBOARD, {"set-cookie": "session=abc123def456; Path=/; HttpOnly"}, url)
        return _R(200, LOGIN_PAGE, {}, url)


def _orchestrator() -> LLMOrchestrator:
    # Real playbooks (laravel_debug + default_credentials_login) → both agents
    # stay rule-tier; _NoLLMProvider raises if the LLM is ever reached.
    return LLMOrchestrator(PlaybookEngine.from_directory(PLAYBOOK_DIR), _NoLLMProvider())


def _config() -> ChainConfig:
    return ChainConfig(
        client_id="chain_lab",
        scope_ip_ranges=["127.0.0.1/32"],
        scope_domains=["127.0.0.1"],
        recon_url=RECON_URL,
        login_url=LOGIN_URL,
    )


def test_chain_runner_proves_real_chain() -> None:
    secrets_manager = SecretsManager()
    result = run_chain_live_fire(
        _config(),
        auth=AuthorizationStateMachine(event_store=InMemoryEventStore()),
        http_client=_ChainFake(),
        orchestrator=_orchestrator(),
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
        secrets_manager=secrets_manager,
    )

    assert result.gained_access is True  # Beta reused the leaked password
    assert (
        result.edge_from_harvested_cred is True
    )  # edge source = Alpha's vaulted node (REAL chain)
    assert result.leak_suspected is False  # no session value persisted
    assert result.chain_proven is True
