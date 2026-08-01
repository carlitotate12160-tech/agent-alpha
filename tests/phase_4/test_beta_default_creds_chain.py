from unittest.mock import Mock, patch

from agent_alpha.agents.beta.strike import Beta
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.models import Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.narrative import find_attack_chains, highest_impact_chain
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, AttackNode, NodeType, VulnerabilityProperties
from agent_alpha.graph.persist import persist_node
from agent_alpha.tools.contracts import ToolResult

_HOST = "lab-target.invalid"


def test_default_creds_win_forms_connected_chain():
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="client1", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    auth.enable_active(rec.engagement_id)
    eng_id = rec.engagement_id

    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()

    # Asset must exist for chain finding
    asset_node = AttackNode(
        id=f"asset:{_HOST}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=_HOST, tech_stack=["wp"]),
        confidence=1.0,
        agent="alpha",
    )
    persist_node(event_store, graph_store, eng_id, asset_node, agent="alpha")

    beta = Beta(
        cred_applicators=[],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=Mock(),
        orchestrator=Mock(),
    )
    beta._engagement_id = eng_id
    beta._entry_point = f"http://{_HOST}/login"
    beta._credential_refs = []
    beta._session_token_refs = []
    beta._proof_artifacts = []
    beta._strike_attempted = False

    # mock http_client to avoid actual requests
    beta.http_client = Mock()
    beta.http_client.get.return_value = Mock(status_code=200, text="login", headers={})

    # mock orchestrator
    beta.orchestrator.decide.return_value = Mock(cost_usd=0.0, technique_id="T1078.001")

    # Mock the tool result
    mock_result = ToolResult(
        tool="default_creds",
        success=True,
        confidence=0.9,
        findings=[
            {
                "username": "admin",
                "password": "password",
                "access_level": "admin",
                "proof_request": {},
                "proof_response": {},
                "session_cookie_name": "session",
                "service": "http",
            }
        ],
    )

    with patch("agent_alpha.agents.beta.strike.ToolRegistry") as mock_registry:
        mock_tool = Mock()
        mock_tool.run.return_value = mock_result
        mock_tool.mitre_technique = "T1078.001"
        mock_registry.return_value.ranked.return_value = [mock_tool]

        result = beta.step({})

    assert result["discovered_nodes"] > 0

    # check chains
    chains = find_attack_chains(graph_store)

    # filter for chains starting with the asset
    valid_chains = [c for c in chains if c.nodes and c.nodes[0].id == asset_node.id]
    assert len(valid_chains) >= 1

    # Verify the specific node types in the chain
    chain = valid_chains[0]
    nodes = chain.nodes
    types = [n.type for n in nodes]
    assert types == [
        NodeType.ASSET,
        NodeType.VULNERABILITY,
        NodeType.CREDENTIAL,
        NodeType.ACCESS_LEVEL,
    ]

    # verify highest impact
    impact = highest_impact_chain(graph_store)
    assert impact is not None
    # We don't have severity on the chain itself, severity is on BlastRadius or ChainFinding.
    # Impact score is a float. We just assert it is > 0
    assert impact.impact_score > 0.0


def test_no_fabricated_edge_to_unrelated_vuln():
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="client1", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    auth.enable_active(rec.engagement_id)
    eng_id = rec.engagement_id

    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()

    # unrelated vuln
    vuln_node = AttackNode(
        id=f"vuln:{_HOST}:odoo_dbmanager_exposed",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(affected_service="odoo"),
        confidence=1.0,
        agent="alpha",
    )
    persist_node(event_store, graph_store, eng_id, vuln_node, agent="alpha")

    beta = Beta(
        cred_applicators=[],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=Mock(),
        orchestrator=Mock(),
    )
    beta._engagement_id = eng_id
    beta._entry_point = f"http://{_HOST}/login"
    beta._credential_refs = []
    beta._session_token_refs = []
    beta._proof_artifacts = []
    beta._strike_attempted = False

    beta.http_client = Mock()
    beta.http_client.get.return_value = Mock(status_code=200, text="login", headers={})
    beta.orchestrator.decide.return_value = Mock(cost_usd=0.0, technique_id="T1078.001")

    mock_result = ToolResult(
        tool="default_creds",
        success=True,
        confidence=0.9,
        findings=[
            {
                "username": "admin",
                "password": "password",
                "access_level": "admin",
                "proof_request": {},
                "proof_response": {},
                "session_cookie_name": "session",
                "service": "http",
            }
        ],
    )

    with patch("agent_alpha.agents.beta.strike.ToolRegistry") as mock_registry:
        mock_tool = Mock()
        mock_tool.run.return_value = mock_result
        mock_tool.mitre_technique = "T1078.001"
        mock_registry.return_value.ranked.return_value = [mock_tool]

        beta.step({})

    edges = graph_store.all_edges()
    for e in edges:
        if e.source_id == vuln_node.id:
            assert e.target_id != f"cred:{_HOST}:admin", "Fabricated edge found"


def _run_beta_with_finding(finding: dict) -> tuple[NetworkXGraphStore, str]:
    """Drive Beta.step once with a mocked tool returning *finding*; return the graph +
    host so the caller can inspect the minted vuln node. Mirrors the harness above."""
    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="client1", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    auth.enable_active(rec.engagement_id)
    eng_id = rec.engagement_id

    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()
    persist_node(
        event_store,
        graph_store,
        eng_id,
        AttackNode(
            id=f"asset:{_HOST}",
            type=NodeType.ASSET,
            properties=AssetProperties(host=_HOST, tech_stack=["wp"]),
            confidence=1.0,
            agent="alpha",
        ),
        agent="alpha",
    )

    beta = Beta(
        cred_applicators=[],
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=Mock(),
        orchestrator=Mock(),
    )
    beta._engagement_id = eng_id
    beta._entry_point = f"http://{_HOST}/login"
    beta._credential_refs = []
    beta._session_token_refs = []
    beta._proof_artifacts = []
    beta._strike_attempted = False
    beta.http_client = Mock()
    beta.http_client.get.return_value = Mock(status_code=200, text="login", headers={})
    beta.orchestrator.decide.return_value = Mock(cost_usd=0.0, technique_id="T1110.001")

    mock_result = ToolResult(tool="t", success=True, confidence=0.9, findings=[finding])
    with patch("agent_alpha.agents.beta.strike.ToolRegistry") as mock_registry:
        mock_tool = Mock()
        mock_tool.run.return_value = mock_result
        mock_tool.mitre_technique = "T1110.001"
        mock_registry.return_value.ranked.return_value = [mock_tool]
        beta.step({})
    return graph_store, _HOST


def test_beta_mints_predictable_credential_vuln_from_finding_class() -> None:
    """A finding that declares finding_class='predictable_credential' (GAP-015) must be
    persisted as its OWN vuln node with the catalog's CVSS — NOT mislabelled as a
    default credential. This is the report-accuracy guarantee (payability)."""
    finding = {
        "username": "editor",
        "password": "editor123",  # derived guess; Beta.step never persists it raw
        "access_level": "admin",
        "proof_request": {},
        "proof_response": {},
        "session_cookie_name": "session",
        "service": "http",
        "finding_class": "predictable_credential",
    }
    graph, host = _run_beta_with_finding(finding)

    predictable = graph.get_node(f"vuln:{host}:predictable_credential")
    assert predictable is not None, "predictable-credential win was not minted under its own id"
    assert predictable.properties.cvss_score == 8.8
    assert graph.get_node(f"vuln:{host}:default_credentials") is None, "mislabelled as default"


def test_beta_defaults_to_default_credentials_when_class_absent() -> None:
    """Backward compatibility: a finding with no finding_class stays exactly the
    historical default_creds vuln node (id + CVSS 9.8)."""
    finding = {
        "username": "admin",
        "password": "admin",
        "access_level": "admin",
        "proof_request": {},
        "proof_response": {},
        "session_cookie_name": "session",
        "service": "http",
    }
    graph, host = _run_beta_with_finding(finding)

    default = graph.get_node(f"vuln:{host}:default_credentials")
    assert default is not None
    assert default.properties.cvss_score == 9.8
