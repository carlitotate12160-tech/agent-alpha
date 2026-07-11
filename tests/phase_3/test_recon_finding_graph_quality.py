# Graph-quality tests for recon findings — assert ATT&CK classification and
# asset-node coherence on credential-disclosure edges.
#
# TARGET PATH:  tests/phase_3/test_recon_finding_graph_quality.py
#
# PINS (the contract the bodies MUST honour):
#   T1  wp_config_leak edges carry technique_id="T1552.001".
#   T2  js_secret_probe edges carry technique_id="T1552.001".
#   T3  credential_assembly LEADS_TO edges carry technique_id="T1552.001" (both
#       paired login and standalone credential).
#   T4  wp_config_leak persists an asset:{host} node (NodeType.ASSET,
#       AssetProperties(host, tech_stack=["wordpress"])).
#   T5  js_secret_probe persists an asset:{host} node (NodeType.ASSET,
#       AssetProperties(host, tech_stack=["javascript"])).
#   T6  wp and js asset nodes have EXPLOITS edge to the vuln node.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import (
    AssetProperties,
    NodeType,
    RelationshipType,
)
from agent_alpha.recon.js_secret_probe import verify_js_secret_leak
from agent_alpha.recon.wp_config_probe import verify_wp_config_leak
from agent_alpha.security.credential_assembly import assemble_leaked_credentials
from agent_alpha.security.secrets import SecretsManager

_HOST = "target.example.com"

_WP_CONFIG_BODY = (
    "<?php\n"
    "define('DB_NAME', 'wp_db');\n"
    "define('DB_USER', 'admin');\n"
    "define('DB_PASSWORD', 'S3cur3Pa55!');\n"
    "define('DB_HOST', 'localhost');\n"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


class FakeHttpClient:
    """Records every URL probed; returns canned responses."""

    def __init__(self, responses: dict[str, FakeResponse | Exception] | None = None) -> None:
        self._responses = responses or {}
        self.get_calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> FakeResponse:
        self.get_calls.append(url)
        r = self._responses.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            return FakeResponse(status_code=404, text="")
        return r


def _recon_context(
    event_store: InMemoryEventStore,
    domains: list[str] | None = None,
) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="graph_quality_lab", target=_HOST)
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=["10.0.0.1/32"],
            domains=domains or [_HOST],
            exclusions=[],
        ),
    )
    return auth, rec.engagement_id


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def wp_graph_ctx() -> dict[str, Any]:
    """Set up a WP config leak that produces at least one credential node."""
    from agent_alpha.config import constants

    events = InMemoryEventStore()
    auth, eid = _recon_context(events)
    graph = NetworkXGraphStore()
    secrets = SecretsManager()

    # Serve a wp-config body at the first backup path.
    first_path = constants.WP_CONFIG_BACKUP_PATHS[0]
    url = f"https://{_HOST}{first_path}"
    http = FakeHttpClient({url: FakeResponse(200, _WP_CONFIG_BODY)})

    n = verify_wp_config_leak(
        engagement_id=eid,
        auth=auth,
        http_client=http,
        scope_hosts=[_HOST],
        graph_store=graph,
        event_store=events,
        secrets_manager=secrets,
    )
    return {"graph": graph, "events": events, "n": n, "eid": eid}


@pytest.fixture()
def js_graph_ctx() -> dict[str, Any]:
    """Set up a JS secret leak that produces at least one credential node."""
    events = InMemoryEventStore()
    auth, eid = _recon_context(events)
    graph = NetworkXGraphStore()
    secrets = SecretsManager()

    page_url = f"https://{_HOST}/"
    bundle_url = f"https://{_HOST}/assets/app.js"
    http = FakeHttpClient(
        {
            page_url: FakeResponse(200, '<script src="/assets/app.js"></script>'),
            bundle_url: FakeResponse(200, 'const k="AKIA1234567890ABCDEF";'),
        }
    )

    n = verify_js_secret_leak(
        engagement_id=eid,
        auth=auth,
        http_client=http,
        scope_targets=[_HOST],
        graph_store=graph,
        event_store=events,
        secrets_manager=secrets,
    )
    return {"graph": graph, "events": events, "n": n, "eid": eid}


# ── T1: wp_config_leak LEADS_TO edges carry T1552.001 ───────────────────────


def test_wp_config_leak_technique_id(wp_graph_ctx: dict[str, Any]) -> None:
    graph: NetworkXGraphStore = wp_graph_ctx["graph"]
    leads_to = graph.edges_by_relationship(RelationshipType.LEADS_TO)
    assert leads_to, "Expected at least one LEADS_TO edge from WP config leak"
    for edge in leads_to:
        assert edge.technique_id == "T1552.001", (
            f"WP LEADS_TO edge {edge.source_id}->{edge.target_id} missing T1552.001"
        )


# ── T2: js_secret_probe LEADS_TO edges carry T1552.001 ─────────────────────


def test_js_secret_probe_technique_id(js_graph_ctx: dict[str, Any]) -> None:
    graph: NetworkXGraphStore = js_graph_ctx["graph"]
    leads_to = graph.edges_by_relationship(RelationshipType.LEADS_TO)
    assert leads_to, "Expected at least one LEADS_TO edge from JS secret probe"
    for edge in leads_to:
        assert edge.technique_id == "T1552.001", (
            f"JS LEADS_TO edge {edge.source_id}->{edge.target_id} missing T1552.001"
        )


# ── T3: credential_assembly LEADS_TO edges carry T1552.001 ─────────────────


def test_credential_assembly_technique_id_paired_and_standalone() -> None:
    """Both paired-login and standalone credential edges get T1552.001."""
    leaked = {"DB_USER": "admin", "DB_PASSWORD": "s3cret", "REDIS_PASSWORD": "r3d1s"}
    nodes, edges = assemble_leaked_credentials(
        leaked,
        host=_HOST,
        vuln_node_id="vuln:test:cred_assembly",
        login_pairs={"database": ("DB_USER", "DB_PASSWORD")},
        username_keys=frozenset({"DB_USER"}),
        secret_keys=frozenset({"DB_PASSWORD", "REDIS_PASSWORD"}),
        service_map={"DB_": "database", "REDIS_": "redis"},
        secrets_manager=None,
        engagement_id="eng-test",
        now_utc="2026-01-01T00:00:00Z",
    )
    assert len(edges) >= 2, "Expected paired + standalone edges"
    for edge in edges:
        assert edge.technique_id == "T1552.001", (
            f"credential_assembly edge {edge.source_id}->{edge.target_id} missing T1552.001"
        )


# ── T4: wp_config_leak persists an asset node ──────────────────────────────


def test_wp_config_leak_asset_node(wp_graph_ctx: dict[str, Any]) -> None:
    graph: NetworkXGraphStore = wp_graph_ctx["graph"]
    assets = graph.nodes_by_type(NodeType.ASSET)
    assert assets, "WP config leak must persist an asset node"
    asset = next(a for a in assets if a.id == f"asset:{_HOST}")
    assert isinstance(asset.properties, AssetProperties)
    assert asset.properties.host == _HOST
    assert "wordpress" in asset.properties.tech_stack


# ── T5: js_secret_probe persists an asset node ─────────────────────────────


def test_js_secret_probe_asset_node(js_graph_ctx: dict[str, Any]) -> None:
    graph: NetworkXGraphStore = js_graph_ctx["graph"]
    assets = graph.nodes_by_type(NodeType.ASSET)
    assert assets, "JS secret probe must persist an asset node"
    asset = next(a for a in assets if a.id == f"asset:{_HOST}")
    assert isinstance(asset.properties, AssetProperties)
    assert asset.properties.host == _HOST
    assert "javascript" in asset.properties.tech_stack


# ── T6: asset→vuln EXPLOITS edge exists for both WP and JS ─────────────────


def test_wp_config_leak_exploits_edge(wp_graph_ctx: dict[str, Any]) -> None:
    graph: NetworkXGraphStore = wp_graph_ctx["graph"]
    exploits = graph.edges_by_relationship(RelationshipType.EXPLOITS)
    assert exploits, "WP config leak must have an EXPLOITS edge from asset to vuln"
    asset_vuln = [e for e in exploits if e.source_id == f"asset:{_HOST}"]
    assert asset_vuln, f"No EXPLOITS edge from asset:{_HOST}"
    assert asset_vuln[0].target_id.startswith("vuln:")


def test_js_secret_probe_exploits_edge(js_graph_ctx: dict[str, Any]) -> None:
    graph: NetworkXGraphStore = js_graph_ctx["graph"]
    exploits = graph.edges_by_relationship(RelationshipType.EXPLOITS)
    assert exploits, "JS secret probe must have an EXPLOITS edge from asset to vuln"
    asset_vuln = [e for e in exploits if e.source_id == f"asset:{_HOST}"]
    assert asset_vuln, f"No EXPLOITS edge from asset:{_HOST}"
    assert asset_vuln[0].target_id.startswith("vuln:")
