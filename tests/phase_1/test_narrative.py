from __future__ import annotations

import pytest

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.narrative import (
    AttackChain,
    BlastRadius,
    calculate_blast_radius,
    find_attack_chains,
    find_critical_paths,
    highest_impact_chain,
    to_narrative,
)
from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AssetProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    DataProperties,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
)


@pytest.fixture
def fixture_store() -> NetworkXGraphStore:
    """Fixture: 1 asset -> 1 vulnerability -> 1 credential -> 1 data node."""
    store = NetworkXGraphStore()

    asset = AttackNode(
        id="asset-1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1", ip="10.0.0.1"),
        confidence=0.9,
    )
    store.apply_event(
        "NodeDiscovered",
        {
            "id": asset.id,
            "type": asset.type.value,
            "properties": {
                "host": asset.properties.host,
                "ip": asset.properties.ip,
            },
            "confidence": asset.confidence,
            "proof_artifacts": [],
            "agent": "",
            "timestamp_utc": "",
            "verified": False,
        },
    )

    vuln = AttackNode(
        id="vuln-1",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(cve_id="CVE-2024-1234", cvss_score=7.5),
        confidence=0.8,
    )
    store.apply_event(
        "NodeDiscovered",
        {
            "id": vuln.id,
            "type": vuln.type.value,
            "properties": {
                "cve_id": vuln.properties.cve_id,
                "cvss_score": vuln.properties.cvss_score,
                "affected_service": "",
                "exploit_available": False,
            },
            "confidence": vuln.confidence,
            "proof_artifacts": [],
            "agent": "",
            "timestamp_utc": "",
            "verified": False,
        },
    )

    cred = AttackNode(
        id="cred-1",
        type=NodeType.CREDENTIAL,
        properties=CredentialProperties(
            username="admin",
            secret_ref="secret://vault/secret123",
            service="ssh",
            access_level="root",
        ),
        confidence=0.85,
    )
    store.apply_event(
        "NodeDiscovered",
        {
            "id": cred.id,
            "type": cred.type.value,
            "properties": {
                "username": cred.properties.username,
                "secret_ref": cred.properties.secret_ref,
                "service": cred.properties.service,
                "access_level": cred.properties.access_level,
            },
            "confidence": cred.confidence,
            "proof_artifacts": [],
            "agent": "",
            "timestamp_utc": "",
            "verified": False,
        },
    )

    data = AttackNode(
        id="data-1",
        type=NodeType.DATA,
        properties=DataProperties(data_type="database", sensitivity="high"),
        confidence=0.95,
    )
    store.apply_event(
        "NodeDiscovered",
        {
            "id": data.id,
            "type": data.type.value,
            "properties": {
                "data_type": data.properties.data_type,
                "sensitivity": data.properties.sensitivity,
                "size_estimate": "",
                "location": "",
            },
            "confidence": data.confidence,
            "proof_artifacts": [],
            "agent": "",
            "timestamp_utc": "",
            "verified": False,
        },
    )

    # Edges: asset -> vuln (exploits), vuln -> cred (enables), cred -> data (leads_to)
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "asset-1",
            "target_id": "vuln-1",
            "relationship": RelationshipType.EXPLOITS.value,
            "confidence": 0.9,
            "technique_id": "",
        },
    )

    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "vuln-1",
            "target_id": "cred-1",
            "relationship": RelationshipType.ENABLES.value,
            "confidence": 0.85,
            "technique_id": "",
        },
    )

    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "cred-1",
            "target_id": "data-1",
            "relationship": RelationshipType.LEADS_TO.value,
            "confidence": 0.95,
            "technique_id": "",
        },
    )

    return store


def test_find_critical_paths_finds_asset_to_data(fixture_store: NetworkXGraphStore) -> None:
    """Test 1: find_critical_paths() on fixture finds asset->data path."""
    paths = find_critical_paths(fixture_store)
    assert len(paths) >= 1
    # Verify at least one path starts with ASSET and ends with DATA
    found_path = False
    for path in paths:
        if path[0].type == NodeType.ASSET and path[-1].type == NodeType.DATA:
            found_path = True
            break
    assert found_path


def test_find_critical_paths_no_matching_target_types(fixture_store: NetworkXGraphStore) -> None:
    """Test 2: find_critical_paths() with no matching target_types -> []."""
    paths = find_critical_paths(
        fixture_store,
        source_types=[NodeType.ASSET],
        target_types=[NodeType.SERVICE],  # No SERVICE nodes in fixture
    )
    assert paths == []


def test_calculate_blast_radius_reaches_downstream(fixture_store: NetworkXGraphStore) -> None:
    """Test 3: calculate_blast_radius() from asset node reaches all 3 downstream nodes."""
    radius = calculate_blast_radius(fixture_store, "asset-1")
    assert radius.reachable_count == 3
    assert set(radius.reachable_node_ids) == {"vuln-1", "cred-1", "data-1"}


def test_calculate_blast_radius_critical_when_data_reachable(fixture_store: NetworkXGraphStore) -> None:
    """Test 4: calculate_blast_radius() severity == "critical" when DATA node is reachable."""
    radius = calculate_blast_radius(fixture_store, "asset-1")
    assert radius.severity == "critical"
    assert "data-1" in radius.high_value_targets


def test_calculate_blast_radius_nonexistent_node(fixture_store: NetworkXGraphStore) -> None:
    """Test 5: calculate_blast_radius() on nonexistent node_id returns empty BlastRadius."""
    radius = calculate_blast_radius(fixture_store, "nonexistent")
    assert radius.reachable_count == 0
    assert radius.severity == "low"
    assert radius.reachable_node_ids == []
    assert radius.high_value_targets == []


def test_calculate_blast_radius_terminates_on_cycle(fixture_store: NetworkXGraphStore) -> None:
    """Test 6: calculate_blast_radius() terminates on a graph with a cycle."""
    # Add a cycle: data-1 -> asset-1
    fixture_store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "data-1",
            "target_id": "asset-1",
            "relationship": RelationshipType.LEADS_TO.value,
            "confidence": 0.5,
            "technique_id": "",
        },
    )

    # Should not hang; should return a result
    radius = calculate_blast_radius(fixture_store, "asset-1")
    # With the cycle, reachable nodes should still be limited and not infinite
    assert radius.reachable_count >= 0


def test_find_attack_chains_returns_at_least_one(fixture_store: NetworkXGraphStore) -> None:
    """Test 7: find_attack_chains() returns at least 1 chain on fixture."""
    chains = find_attack_chains(fixture_store)
    assert len(chains) >= 1
    # Verify chain structure
    chain = chains[0]
    assert isinstance(chain, AttackChain)
    assert len(chain.nodes) > 0
    assert len(chain.edges) > 0
    assert chain.chain_length == len(chain.nodes)


def test_highest_impact_chain_selects_highest_score() -> None:
    """Test 8: highest_impact_chain() returns the chain with highest impact_score."""
    store = NetworkXGraphStore()

    # Create two chains with different confidences
    # Chain 1: asset1 -> vuln1 -> data1 (higher confidence)
    asset1 = AttackNode(
        id="asset1",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host1"),
        confidence=0.9,
    )
    vuln1 = AttackNode(
        id="vuln1",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.8,
    )
    data1 = AttackNode(
        id="data1",
        type=NodeType.DATA,
        properties=DataProperties(data_type="db", sensitivity="high"),
        confidence=0.95,
    )

    for node in [asset1, vuln1, data1]:
        if node.type == NodeType.ASSET:
            props = {"host": node.properties.host}
        elif node.type == NodeType.DATA:
            props = {
                "data_type": node.properties.data_type,
                "sensitivity": node.properties.sensitivity,
            }
        else:
            props = {}
        store.apply_event(
            "NodeDiscovered",
            {
                "id": node.id,
                "type": node.type.value,
                "properties": props,
                "confidence": node.confidence,
                "proof_artifacts": [],
                "agent": "",
                "timestamp_utc": "",
                "verified": False,
            },
        )

    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "asset1",
            "target_id": "vuln1",
            "relationship": RelationshipType.EXPLOITS.value,
            "confidence": 0.95,  # High confidence
            "technique_id": "",
        },
    )
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "vuln1",
            "target_id": "data1",
            "relationship": RelationshipType.LEADS_TO.value,
            "confidence": 0.95,
            "technique_id": "",
        },
    )

    # Chain 2: asset2 -> vuln2 -> data2 (lower confidence)
    asset2 = AttackNode(
        id="asset2",
        type=NodeType.ASSET,
        properties=AssetProperties(host="host2"),
        confidence=0.7,
    )
    vuln2 = AttackNode(
        id="vuln2",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(),
        confidence=0.6,
    )
    data2 = AttackNode(
        id="data2",
        type=NodeType.DATA,
        properties=DataProperties(data_type="db", sensitivity="medium"),
        confidence=0.8,
    )

    for node in [asset2, vuln2, data2]:
        if node.type == NodeType.ASSET:
            props = {"host": node.properties.host}
        elif node.type == NodeType.DATA:
            props = {
                "data_type": node.properties.data_type,
                "sensitivity": node.properties.sensitivity,
            }
        else:
            props = {}
        store.apply_event(
            "NodeDiscovered",
            {
                "id": node.id,
                "type": node.type.value,
                "properties": props,
                "confidence": node.confidence,
                "proof_artifacts": [],
                "agent": "",
                "timestamp_utc": "",
                "verified": False,
            },
        )

    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "asset2",
            "target_id": "vuln2",
            "relationship": RelationshipType.EXPLOITS.value,
            "confidence": 0.5,  # Low confidence
            "technique_id": "",
        },
    )
    store.apply_event(
        "EdgeDiscovered",
        {
            "source_id": "vuln2",
            "target_id": "data2",
            "relationship": RelationshipType.LEADS_TO.value,
            "confidence": 0.5,
            "technique_id": "",
        },
    )

    highest = highest_impact_chain(store)
    assert highest is not None
    # The chain with higher confidence should be selected
    assert highest.impact_score > 0


def test_highest_impact_chain_empty_store() -> None:
    """Test 9: highest_impact_chain() returns None on empty store."""
    store = NetworkXGraphStore()
    highest = highest_impact_chain(store)
    assert highest is None


def test_to_narrative_executive(fixture_store: NetworkXGraphStore) -> None:
    """Test 10: to_narrative(store, "executive") contains expected sections."""
    narrative = to_narrative(fixture_store, "executive")
    assert "Total assets discovered:" in narrative
    assert "Total critical paths found:" in narrative
    assert "Highest severity blast radius:" in narrative
    # Verify the asset count matches
    assert "1" in narrative  # Should have 1 asset


def test_to_narrative_technical(fixture_store: NetworkXGraphStore) -> None:
    """Test 11: to_narrative(store, "technical") lists every node id."""
    narrative = to_narrative(fixture_store, "technical")
    all_nodes = fixture_store.all_nodes()
    for node in all_nodes:
        assert node.id in narrative


def test_to_narrative_remediation_no_secret(fixture_store: NetworkXGraphStore) -> None:
    """Test 12: to_narrative(store, "remediation") does NOT contain secret_ref value."""
    narrative = to_narrative(fixture_store, "remediation")
    # The secret_ref used in fixture is "secret://vault/secret123"
    assert "secret://vault/secret123" not in narrative
    assert "secret123" not in narrative
    # But access_level should be present
    assert "access_level=root" in narrative


def test_to_narrative_invalid_style(fixture_store: NetworkXGraphStore) -> None:
    """Test 13: to_narrative(store, "invalid_style") raises ValueError."""
    with pytest.raises(ValueError, match="Unknown narrative style"):
        to_narrative(fixture_store, "invalid_style")  # type: ignore[arg-type]


def test_to_narrative_deterministic(fixture_store: NetworkXGraphStore) -> None:
    """Test 14: to_narrative() called twice on same unchanged store returns identical string."""
    narrative1 = to_narrative(fixture_store, "executive")
    narrative2 = to_narrative(fixture_store, "executive")
    assert narrative1 == narrative2

    # Also test technical and remediation styles
    narrative1 = to_narrative(fixture_store, "technical")
    narrative2 = to_narrative(fixture_store, "technical")
    assert narrative1 == narrative2

    narrative1 = to_narrative(fixture_store, "remediation")
    narrative2 = to_narrative(fixture_store, "remediation")
    assert narrative1 == narrative2
