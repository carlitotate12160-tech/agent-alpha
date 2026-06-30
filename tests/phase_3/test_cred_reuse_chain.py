"""Contract: cred-reuse chain — Alpha leaks → vaults → Beta reuses → access.

End-to-end chain test: Alpha recon on a Laravel debug body leaking DB_PASSWORD vaults
the secret and writes a CREDENTIAL node. Beta on the same graph_store + secrets_manager
reuses the vaulted credential to gain access. The ENABLES edge connects Alpha's
CREDENTIAL node to the access node — the multi-hop chain a scanner can't assemble.

Alpha-vaulting assertions are GREEN now. Chain-completion assertions are xfail until
GLM fills CredReuseTool.run() (currently NotImplementedError).
"""

from __future__ import annotations

import json
import pathlib

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.beta.strike import Beta
from agent_alpha.conductor.applicator_factory import BoundApplicator
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.internal.access.applicator import HttpFormApplicator
from agent_alpha.tools.playbook import PlaybookEngine, PlaybookRule

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
RECON_URL = "https://lab-target.invalid/trigger-error"
LOGIN_URL = "https://lab-target.invalid/login"
SESSION_COOKIE = "session=chainproof1234567890"


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


class _NoLLMProvider:
    model = "none"

    def complete(self, *a: object, **k: object):
        raise RuntimeError("Beta should stay rule-tier; LLM must not be called")


class _FakeResponse:
    def __init__(
        self, status_code: int, text: str, headers: dict[str, str] | None = None, url: str = ""
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _ChainHttpClient:
    """URL-aware fake: recon URL returns Laravel debug body; login URL grants
    access ONLY when the correct vaulted secret is applied (via data/headers)."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._applied_data: dict[str, str] | None = None

    def get(self, url: str, *, headers=None, cookies=None, timeout: float = 10.0) -> _FakeResponse:
        self.calls.append(url)
        if RECON_URL in url:
            return _FakeResponse(500, LARAVEL_DEBUG_BODY, {"server": "nginx"}, url)
        if LOGIN_URL in url:
            if cookies or headers:
                return _FakeResponse(
                    200,
                    "<html>admin dashboard, welcome administrator</html>",
                    {"set-cookie": f"{SESSION_COOKIE}; Path=/; HttpOnly"},
                    url,
                )
            return _FakeResponse(
                200, '<html><form><input type="password"></form> login</html>', {}, url
            )
        return _FakeResponse(404, "", {}, url)

    def post(
        self, url: str, *, data=None, json_body=None, headers=None, cookies=None
    ) -> _FakeResponse:
        self.calls.append(url)
        self._applied_data = data
        if LOGIN_URL in url:
            # Grant access only if the correct secret was applied
            if data and data.get("password") == LEAKED_VALUE:
                return _FakeResponse(
                    200,
                    "<html>admin dashboard, welcome administrator</html>",
                    {"set-cookie": f"{SESSION_COOKIE}; Path=/; HttpOnly"},
                    url,
                )
            return _FakeResponse(
                401, '<html><form><input type="password"></form> Invalid</html>', {}, url
            )
        return _FakeResponse(404, "", {}, url)


def _login_orchestrator() -> LLMOrchestrator:
    rule = PlaybookRule(
        name="default_credentials_login",
        tool="default_creds",
        tier="rule",
        technique_id="T1078.001",
        indicators=[{"body_contains": 'type="password"'}],
    )
    return LLMOrchestrator(PlaybookEngine([rule]), _NoLLMProvider())


def _run_alpha_recon(
    secrets_manager: SecretsManager,
    graph_store: NetworkXGraphStore,
    event_store: InMemoryEventStore,
    http_client: _ChainHttpClient,
) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="chain_lab", target="lab-target.invalid")
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=["lab-target.invalid"], exclusions=[]),
    )
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
        provider=_StubProvider(),
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    alpha.run_recon(rec.engagement_id, RECON_URL)
    return auth, rec.engagement_id


# ── GREEN: Alpha vaults the secret ───────────────────────────────────


def test_alpha_vaults_secret_in_chain_context() -> None:
    """Alpha recon vaults DB_PASSWORD; secret_ref resolves to the real value."""
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    http_client = _ChainHttpClient()

    auth, engagement_id = _run_alpha_recon(secrets_manager, graph_store, event_store, http_client)

    cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
    assert len(cred_nodes) >= 1

    vaulted = [n for n in cred_nodes if n.properties.secret_ref.startswith("secret_")]
    assert len(vaulted) >= 1, "Expected at least one vaulted credential node"

    secret_ref = vaulted[0].properties.secret_ref
    assert secrets_manager.retrieve(secret_ref) == LEAKED_VALUE


def test_plaintext_not_in_events_in_chain_context() -> None:
    """The plaintext secret must not appear in any event payload after Alpha recon."""
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    http_client = _ChainHttpClient()

    auth, engagement_id = _run_alpha_recon(secrets_manager, graph_store, event_store, http_client)

    blob = json.dumps(
        [e.payload for e in event_store.get_events(engagement_id)],
        default=str,
    )
    assert LEAKED_VALUE not in blob


# ── Chain completion (GREEN after CredReuseTool.run implementation) ──


def test_beta_reuses_vaulted_secret_and_gains_access() -> None:
    """Beta retrieves the vaulted secret via cred_reuse and gains access."""
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    http_client = _ChainHttpClient()

    auth, engagement_id = _run_alpha_recon(secrets_manager, graph_store, event_store, http_client)

    # Enable active for Beta
    auth.enable_active(engagement_id)

    beta = Beta(
        cred_applicators=[BoundApplicator(HttpFormApplicator(http_client=http_client), LOGIN_URL)],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_login_orchestrator(),
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    msg = beta.run_strike(engagement_id, LOGIN_URL)
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)

    assert payload.status == a2a_pb2.COMPLETE


def test_chain_edge_exists_from_alpha_credential_to_access() -> None:
    """The ENABLES edge connects Alpha's CREDENTIAL node to the access node —
    the chain is connected, not two silos."""
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    http_client = _ChainHttpClient()

    auth, engagement_id = _run_alpha_recon(secrets_manager, graph_store, event_store, http_client)
    auth.enable_active(engagement_id)

    beta = Beta(
        cred_applicators=[BoundApplicator(HttpFormApplicator(http_client=http_client), LOGIN_URL)],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_login_orchestrator(),
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    beta.run_strike(engagement_id, LOGIN_URL)

    edges = graph_store.edges_by_relationship(RelationshipType.ENABLES)
    cred_nodes = graph_store.nodes_by_type(NodeType.CREDENTIAL)
    access_nodes = graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)

    assert len(access_nodes) >= 1, "Beta should have created an access node"
    assert len(edges) >= 1, "Expected ENABLES edge from credential to access"

    cred_ids = {n.id for n in cred_nodes}
    access_ids = {n.id for n in access_nodes}
    chain_edges = [e for e in edges if e.source_id in cred_ids and e.target_id in access_ids]
    assert len(chain_edges) >= 1, (
        "Expected at least one ENABLES edge from a CREDENTIAL to an ACCESS_LEVEL node"
    )


def test_secret_value_not_in_events_after_chain() -> None:
    """After the full chain (Alpha + Beta), the secret VALUE appears in NO
    persisted event."""
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    http_client = _ChainHttpClient()

    auth, engagement_id = _run_alpha_recon(secrets_manager, graph_store, event_store, http_client)
    auth.enable_active(engagement_id)

    beta = Beta(
        cred_applicators=[BoundApplicator(HttpFormApplicator(http_client=http_client), LOGIN_URL)],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_login_orchestrator(),
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    beta.run_strike(engagement_id, LOGIN_URL)

    blob = json.dumps(
        [e.payload for e in event_store.get_events(engagement_id)],
        default=str,
    )
    assert LEAKED_VALUE not in blob, "Secret value leaked into events after chain"


def test_chain_edge_source_is_alphas_harvested_credential() -> None:
    """Tighten: the ENABLES edge must originate from ALPHA'S harvested credential
    (its secret_ref resolves from the vault to the leaked value), NOT a Beta-minted
    default_creds node — else the 'chain' is two silos faking a connection."""
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    http_client = _ChainHttpClient()
    auth, engagement_id = _run_alpha_recon(secrets_manager, graph_store, event_store, http_client)
    auth.enable_active(engagement_id)
    Beta(
        cred_applicators=[BoundApplicator(HttpFormApplicator(http_client=http_client), LOGIN_URL)],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_login_orchestrator(),
        http_client=http_client,
        secrets_manager=secrets_manager,
    ).run_strike(engagement_id, LOGIN_URL)

    edges = graph_store.edges_by_relationship(RelationshipType.ENABLES)
    access_ids = {n.id for n in graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)}
    cred_by_id = {n.id: n for n in graph_store.nodes_by_type(NodeType.CREDENTIAL)}
    chain_edges = [e for e in edges if e.target_id in access_ids and e.source_id in cred_by_id]
    assert chain_edges, "no credential->access ENABLES edge"

    def _is_alpha_harvested(node: object) -> bool:
        ref = getattr(node.properties, "secret_ref", "")
        try:
            return secrets_manager.retrieve(ref) == LEAKED_VALUE
        except Exception:
            return False

    assert any(_is_alpha_harvested(cred_by_id[e.source_id]) for e in chain_edges), (
        "chain edge does not originate from Alpha's harvested credential — fake chain"
    )


def test_chain_edge_technique_attributes_to_cred_reuse_not_planning_playbook() -> None:
    """MITRE attribution follows the TOOL that executed (cred_reuse → T1078.003),
    NOT the planning playbook that matched the login form (default_credentials_login
    → T1078.001). Pins the Lyndon-#6 reporting-layer conflation fix."""
    secrets_manager = SecretsManager()
    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    http_client = _ChainHttpClient()

    auth, engagement_id = _run_alpha_recon(secrets_manager, graph_store, event_store, http_client)
    auth.enable_active(engagement_id)

    beta = Beta(
        cred_applicators=[BoundApplicator(HttpFormApplicator(http_client=http_client), LOGIN_URL)],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_login_orchestrator(),  # decision.technique_id == "T1078.001"
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    beta.run_strike(engagement_id, LOGIN_URL)

    access_ids = {n.id for n in graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)}
    chain_edges = [
        e
        for e in graph_store.edges_by_relationship(RelationshipType.ENABLES)
        if e.target_id in access_ids
    ]

    assert chain_edges, "expected a credential->access ENABLES edge"
    assert all(e.technique_id == "T1078.003" for e in chain_edges)
    assert all(e.technique_id != "T1078.001" for e in chain_edges)
