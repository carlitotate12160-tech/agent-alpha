"""Contract: Odoo chain runner DECISION logic — honest chain_proven + the enumerated gate.

The full Alpha→Beta→odoo_access integration is validated by the FIELD-PROVE on the
self-owned odoo_lab (real HTTP), not a fragile fake here. These tests pin the runner's
verdict logic, which is where a silent false-success would hide (#3): every clause must
be required, and a GUESSED db must NOT count as a proven chain.
"""

from __future__ import annotations

import pytest

from agent_alpha.live_fire.odoo_chain_runner import (
    OdooChainResult,
    _db_enumerated,
    load_odoo_chain_config,
)


def _result(**over: object) -> OdooChainResult:
    base: dict[str, object] = {
        "leak_creds_added": 1,
        "web_access_level": "admin",
        "edge_from_harvested_cred": True,
        "db_enumerated": True,
        "leak_suspected": False,
    }
    base.update(over)
    return OdooChainResult(**base)  # type: ignore[arg-type]


def test_all_clauses_true_is_proven() -> None:
    assert _result().chain_proven is True


def test_guessed_db_is_not_proven() -> None:
    # THE 1d gate: authenticate succeeded but db was a host-label guess → NOT proven.
    assert _result(db_enumerated=False).chain_proven is False


def test_default_cred_access_is_not_proven() -> None:
    # No ENABLES edge from a vaulted cred → access came from a default, not reuse.
    assert _result(edge_from_harvested_cred=False).chain_proven is False


def test_no_leak_is_not_proven() -> None:
    assert _result(leak_creds_added=0).chain_proven is False


def test_no_access_is_not_proven() -> None:
    assert _result(web_access_level="").chain_proven is False


def test_session_leak_blocks_proof() -> None:
    assert _result(leak_suspected=True).chain_proven is False


class _E:
    def __init__(self, payload: object) -> None:
        self.payload = payload


class _ES:
    def __init__(self, events: list[_E]) -> None:
        self._events = events

    def get_events(self, engagement_id: str) -> list[_E]:
        return self._events


def test_db_enumerated_true_when_proof_says_enumerated() -> None:
    es = _ES([_E({"proof_request": {"method": "authenticate", "database_source": "enumerated"}})])
    assert _db_enumerated(es, "e") is True


def test_db_enumerated_false_when_guessed() -> None:
    es = _ES([_E({"proof_request": {"method": "authenticate", "database_source": "guessed"}})])
    assert _db_enumerated(es, "e") is False


def test_db_enumerated_false_when_no_authenticate_proof() -> None:
    es = _ES([_E({"proof_request": {"method": "list"}}), _E("not-a-dict")])
    assert _db_enumerated(es, "e") is False


def test_config_loader_rejects_missing_key(tmp_path: object) -> None:
    import pathlib

    p = pathlib.Path(str(tmp_path)) / "bad.yaml"
    p.write_text("client_id: x\nscope: {ip_ranges: [], domains: [], exclusions: []}\n")
    with pytest.raises(ValueError, match="recon_url"):
        load_odoo_chain_config(p)


# ── Omega report wiring ──────────────────────────────────────────────


def _build_proven_odoo_graph() -> NetworkXGraphStore:
    """CREDENTIAL --ENABLES--> ACCESS_LEVEL with vaulted secret_ref."""
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import (
        AccessLevelProperties,
        AttackNode,
        AssetProperties,
        CredentialProperties,
        NodeType,
        VulnerabilityProperties,
        node_to_dict,
    )

    store = NetworkXGraphStore()
    host = "vuln.odoo.lab"
    asset_id = f"asset:{host}"
    vuln_id = f"vuln:{host}:wp_config_leak"
    cred_id = f"cred:{host}:wp_config"
    access_id = f"access:{host}"

    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(asset_id, NodeType.ASSET, AssetProperties(host=host, tech_stack=["odoo"]), 0.90, agent="alpha")
        ),
    )
    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(vuln_id, NodeType.VULNERABILITY, VulnerabilityProperties(), 0.75, agent="alpha")
        ),
    )
    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(
                cred_id,
                NodeType.CREDENTIAL,
                CredentialProperties(
                    username="admin",
                    secret_ref="secret_wp_001",
                    service="odoo",
                    access_level="unverified",
                ),
                0.85,
                agent="alpha",
            )
        ),
    )
    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(
                access_id,
                NodeType.ACCESS_LEVEL,
                AccessLevelProperties(level="admin", user_context="web"),
                0.80,
                agent="beta",
                verified=True,
            )
        ),
    )
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": asset_id, "target_id": vuln_id, "relationship": "exploits", "confidence": 0.90, "technique_id": "T1595.002"},
    )
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": vuln_id, "target_id": cred_id, "relationship": "leads_to", "confidence": 0.85, "technique_id": "T1552.001"},
    )
    store.apply_event(
        "EdgeDiscovered",
        {"source_id": cred_id, "target_id": access_id, "relationship": "enables", "confidence": 0.80, "technique_id": "T1078"},
    )
    return store


def test_omega_report_produces_chain_finding_for_proven_odoo_graph() -> None:
    """Proven Odoo graph (CRED→ENABLES→ACCESS_LEVEL, vaulted) → cf not None,
    severity non-empty, access_level in {user, admin}."""
    from agent_alpha.agents.omega.roaster import Omega
    from agent_alpha.graph.narrative import ChainFinding

    store = _build_proven_odoo_graph()
    report = Omega(store).generate_report("technical")
    cf = report.chain_finding

    assert cf is not None
    assert isinstance(cf, ChainFinding)
    assert cf.severity != ""
    assert cf.access_level in {"user", "admin"}


def test_omega_report_no_chain_finding_for_hardened_graph() -> None:
    """Hardened/true-neg graph (no ACCESS_LEVEL) → cf is None, valid result, NOT a crash."""
    from agent_alpha.agents.omega.roaster import Omega
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import (
        AssetProperties,
        AttackNode,
        NodeType,
        node_to_dict,
    )

    store = NetworkXGraphStore()
    store.apply_event(
        "NodeDiscovered",
        node_to_dict(
            AttackNode(
                "asset:hardened.odoo.lab",
                NodeType.ASSET,
                AssetProperties(host="hardened.odoo.lab", tech_stack=["odoo"]),
                0.90,
                agent="alpha",
            )
        ),
    )
    report = Omega(store).generate_report("technical")
    assert report.chain_finding is None
