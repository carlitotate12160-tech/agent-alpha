from __future__ import annotations

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.path_probe import process_path_hit, spec_for_tool
from agent_alpha.recon.wp_config_probe import verify_wp_config_leak
from agent_alpha.security.secrets import SecretsManager


class FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


class FakeHttpClient:
    def __init__(self, status_code: int, text: str):
        self.resp = FakeResponse(status_code, text)

    def get(self, url: str):
        return self.resp


def _recon(store: InMemoryEventStore) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="backup_lab", target="vuln.example")
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=["vuln.example"], exclusions=[], db_endpoints=[]),
    )
    return auth, rec.engagement_id


def test_wp_config_backup_dedups_to_single_canonical_vuln() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    auth, eid = _recon(store)

    body = "define('DB_USER', 'appuser');\ndefine('DB_PASSWORD', 'sup3rs3cret');\n"
    host = "vuln.example"
    path = "/wp-config.php.bak"
    url = f"https://{host}{path}"

    client = FakeHttpClient(200, body)
    verify_wp_config_leak(
        engagement_id=eid,
        auth=auth,
        http_client=client,
        scope_hosts=[host],
        graph_store=graph,
        event_store=store,
        secrets_manager=SecretsManager(),
    )

    spec = spec_for_tool("backup_file_probe")
    process_path_hit(
        spec,
        resp=FakeResponse(200, body),
        url=url,
        engagement_id=eid,
        auth=auth,
        graph_store=graph,
        event_store=store,
        secrets_manager=SecretsManager(),
    )

    vuln_nodes = list(graph.nodes_by_type(NodeType.VULNERABILITY))
    assert len(vuln_nodes) == 1
    assert vuln_nodes[0].id == f"vuln:{host}:wp_config_leak"


def test_env_leak_still_backup_file() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    auth, eid = _recon(store)

    body = "DB_USER=appuser\nDB_PASSWORD=sup3rs3cret\n"
    host = "vuln.example"
    url = f"https://{host}/.env"

    spec = spec_for_tool("backup_file_probe")
    process_path_hit(
        spec,
        resp=FakeResponse(200, body),
        url=url,
        engagement_id=eid,
        auth=auth,
        graph_store=graph,
        event_store=store,
        secrets_manager=SecretsManager(),
    )

    vuln_nodes = list(graph.nodes_by_type(NodeType.VULNERABILITY))
    assert len(vuln_nodes) == 1
    assert vuln_nodes[0].id == f"vuln:{host}:backup_file_leak"


def test_actuator_spec_suffix_preserved() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    auth, eid = _recon(store)

    body = '{"propertySources": [{"properties": {"spring.datasource.username": {"value": "appuser"}, "spring.datasource.password": {"value": "sup3rs3cret"}}}]}'
    host = "vuln.example"
    url = f"https://{host}/actuator/env"

    spec = spec_for_tool("actuator_probe")
    process_path_hit(
        spec,
        resp=FakeResponse(200, body),
        url=url,
        engagement_id=eid,
        auth=auth,
        graph_store=graph,
        event_store=store,
        secrets_manager=SecretsManager(),
    )

    vuln_nodes = list(graph.nodes_by_type(NodeType.VULNERABILITY))
    assert len(vuln_nodes) == 1
    assert vuln_nodes[0].id == f"vuln:{host}:actuator_exposure"
