"""Contract: Alpha vaults leaked credentials — the chain prerequisite.

After Alpha recon on a Laravel debug body leaking DB_PASSWORD, the CREDENTIAL node's
secret_ref must resolve via secrets_manager.retrieve() to the real leaked value.
The plaintext value must NOT appear in any persisted event.

This is the GREEN test for Part 1 of the cred-reuse chain: Alpha vaults the secret
so cred_reuse can later retrieve it.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent.parent / "phase_2" / "fixtures" / "playbooks"

LARAVEL_DEBUG_BODY = (
    "<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head>"
    "<body><div class='exception'>Illuminate\\Database\\QueryException</div>"
    "<div>SQLSTATE[HY000] [1045] Access denied for user 'forge'@'localhost'</div>"
    "<table><tr><td>APP_ENV</td><td>production</td></tr>"
    "<tr><td>APP_DEBUG</td><td>true</td></tr>"
    "<tr><td>DB_PASSWORD</td><td>s3cr3t-leaked</td></tr></table>"
    "<footer>Laravel v10.3.1 (PHP v8.2.4)</footer></body></html>"
)

LEAKED_VALUE = "s3cr3t-leaked"
TARGET_URL = "https://lab-target.invalid/trigger-error"


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


class _FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict[str, str], url: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.url = url


class _FakeHttpClient:
    def __init__(self, routes: dict[str, _FakeResponse]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _FakeResponse:
        self.calls.append(url)
        try:
            return self._routes[url]
        except KeyError:
            return _FakeResponse(404, "", {}, url)


def _make_alpha(secrets_manager: SecretsManager) -> tuple[Alpha, AuthorizationStateMachine, str, NetworkXGraphStore, InMemoryEventStore]:
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="c", target="lab-target.invalid")
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=["lab-target.invalid"], exclusions=[]),
    )
    graph_store = NetworkXGraphStore()
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=_StubProvider(),
    )
    http_client = _FakeHttpClient({
        TARGET_URL: _FakeResponse(500, LARAVEL_DEBUG_BODY, {"server": "nginx"}, TARGET_URL),
    })
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    return alpha, auth, rec.engagement_id, graph_store, event_store


def test_alpha_vaults_leaked_secret_and_secret_ref_resolves() -> None:
    """After recon, the CREDENTIAL node's secret_ref is a vault id that resolves
    to the original leaked value via secrets_manager.retrieve()."""
    secrets_manager = SecretsManager()
    alpha, auth, engagement_id, graph_store, event_store = _make_alpha(secrets_manager)

    alpha.run_recon(engagement_id, TARGET_URL)

    cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
    assert len(cred_nodes) >= 1

    # Find the DB_PASSWORD credential node
    db_cred = None
    for node in cred_nodes:
        props = node.properties
        if hasattr(props, "secret_ref") and props.secret_ref.startswith("secret_"):
            db_cred = node
            break

    assert db_cred is not None, "Expected at least one vaulted credential node"
    secret_ref = db_cred.properties.secret_ref
    assert secret_ref.startswith("secret_"), f"secret_ref should be a vault id, got {secret_ref}"

    # The vault must return the original leaked value
    retrieved = secrets_manager.retrieve(secret_ref)
    assert retrieved == LEAKED_VALUE


def test_plaintext_secret_not_in_events() -> None:
    """The plaintext leaked value must NOT appear in any persisted event payload."""
    secrets_manager = SecretsManager()
    alpha, auth, engagement_id, graph_store, event_store = _make_alpha(secrets_manager)

    alpha.run_recon(engagement_id, TARGET_URL)

    blob = json.dumps(
        [e.payload for e in event_store.get_events(engagement_id)],
        default=str,
    )
    assert LEAKED_VALUE not in blob, "Plaintext secret leaked into event store"


def test_alpha_without_secrets_manager_falls_back_to_pointer() -> None:
    """Without a secrets_manager, Alpha falls back to the proof-path pointer
    (fail-open for recon; cred_reuse simply can't reuse it)."""
    alpha, auth, engagement_id, graph_store, event_store = _make_alpha(SecretsManager())
    # Rebuild without secrets_manager
    event_store2 = InMemoryEventStore()
    auth2 = AuthorizationStateMachine(event_store=event_store2)
    rec2 = auth2.create_engagement(client_id="c", target="lab-target.invalid")
    auth2.enable_recon(
        rec2.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=["lab-target.invalid"], exclusions=[]),
    )
    graph_store2 = NetworkXGraphStore()
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=_StubProvider(),
    )
    http_client = _FakeHttpClient({
        TARGET_URL: _FakeResponse(500, LARAVEL_DEBUG_BODY, {"server": "nginx"}, TARGET_URL),
    })
    alpha_no_vault = Alpha(
        authorization=auth2,
        graph_store=graph_store2,
        event_store=event_store2,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=None,
    )
    alpha_no_vault.run_recon(rec2.engagement_id, TARGET_URL)

    cred_nodes = graph_store2.nodes_by_type(NodeType.CREDENTIAL)
    assert len(cred_nodes) >= 1
    for node in cred_nodes:
        assert not node.properties.secret_ref.startswith("secret_"), \
            "Without vault, secret_ref should be a proof-path pointer, not a vault id"
