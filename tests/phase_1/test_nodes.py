import dataclasses

import pytest

from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AssetProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    DataProperties,
    NodeType,
    ProofArtifact,
    RelationshipType,
    ServiceProperties,
    VulnerabilityProperties,
    _reconstruct_node,
    node_to_dict,
)


def test_asset_properties_roundtrip():
    node = AttackNode(id="asset:example.com", type=NodeType.ASSET,
                      properties=AssetProperties(host="example.com"),
                      confidence=0.9)
    assert _reconstruct_node(node_to_dict(node)) == node

def test_credential_properties_no_secret_key_in_output():
    node = AttackNode(id="cred:admin", type=NodeType.CREDENTIAL,
                      properties=CredentialProperties(
                          username="admin",
                          secret_ref="vault://engagements/abc/creds/1",
                          service="ssh", access_level="root"),
                      confidence=0.8)
    d = node_to_dict(node)
    assert "secret" not in d["properties"].keys()
    assert "secret_ref" in d["properties"]
    assert "password" not in str(d)

def test_confidence_above_one_raises():
    with pytest.raises(ValueError):
        AttackNode(id="x", type=NodeType.ASSET,
                  properties=AssetProperties(host="h"), confidence=1.5)

def test_confidence_below_zero_raises():
    with pytest.raises(ValueError):
        AttackNode(id="x", type=NodeType.ASSET,
                  properties=AssetProperties(host="h"), confidence=-0.1)

def test_attack_edge_asdict():
    edge = AttackEdge(source_id="a", target_id="b",
                      relationship=RelationshipType.EXPLOITS,
                      confidence=0.7, technique_id="T1190")
    d = dataclasses.asdict(edge)
    assert d["technique_id"] == "T1190"

def test_reconstruct_unknown_type_raises_keyerror():
    with pytest.raises(KeyError, match="Unknown node type"):
        _reconstruct_node({"type": "unknown_type", "id": "x",
                          "confidence": 0.5, "properties": {}})

def test_proof_artifact_no_content_field():
    artifact = ProofArtifact(artifact_id="uuid-1", type="screenshot",
                            storage_ref="s3://bucket/eng/shot.png",
                            description="login panel",
                            captured_at="2026-01-01T00:00:00Z",
                            agent="alpha")
    node = AttackNode(id="asset:x", type=NodeType.ASSET,
                      properties=AssetProperties(host="x"),
                      confidence=0.5, proof_artifacts=[artifact])
    d = node_to_dict(node)
    assert "content" not in str(d)
    assert "raw_data" not in str(d)

@pytest.mark.parametrize("node_type,props", [
    (NodeType.ASSET, AssetProperties(host="h")),
    (NodeType.VULNERABILITY, VulnerabilityProperties()),
    (NodeType.CREDENTIAL, CredentialProperties(
        username="u", secret_ref="vault://x",
        service="s", access_level="a")),
    (NodeType.SERVICE, ServiceProperties(name="nginx")),
    (NodeType.DATA, DataProperties(data_type="pii", sensitivity="high")),
    (NodeType.ACCESS_LEVEL, AccessLevelProperties(level="root")),
])
def test_all_node_types_roundtrip(node_type, props):
    node = AttackNode(id=f"{node_type.value}:test", type=node_type,
                      properties=props, confidence=0.5)
    assert _reconstruct_node(node_to_dict(node)) == node
