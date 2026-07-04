"""FROZEN contract (architect-authored — IDE implements; do NOT edit assertions).

Report-quality fixes surfaced by raw-review of the FP-run Omega report. The FP gate
passed on the METRIC, but the report undersold the payable findings:

  #1 (BUG) Credential-disclosure findings are MITRE-invisible. The vuln->cred LEADS_TO
     edges (credential_assembly.assemble_leaked_credentials + js_secret_probe:388) are
     built with NO technique_id, so Omega's mitre_techniques (collected from edges) shows
     only the Laravel recon technique T1592.002 — a leaked DB credential is presented as
     if the whole engagement were recon. Fix: those credential edges carry
     technique_id="T1552.001" (Unsecured Credentials: Credentials In Files).

  #3 (INCONSISTENCY) Only the Laravel handler persists an ASSET node + asset->vuln edge;
     the WP/JS vectors persist vuln+cred with NO asset node. The graph is incoherent and
     chain-finding cannot start (chains begin at asset nodes). Fix: WP/JS findings hang off
     an asset:{host} node with an asset->vuln edge, mirroring _handle_laravel_debug.

These pin OUTCOMES at Alpha.run_recon (implementation-agnostic — the asset node may be
created in the handler or the vector; the technique in the vector or the shared seam).
Tool selection is stubbed so the test isolates the graph/report shape, not fingerprinting.

NOT pinned here (correct as-is): the absence of a proven exploit CHAIN is right for a
RECON_ONLY engagement (credential not validated -> no access_level node). #2 (Omega
narrative framing of "no attack chains" + surfacing leaked creds) is a narrative-design
change specced separately, not a pass/fail contract.

Authoritative run: Oracle ARM64.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.omega.roaster import Omega
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, RelationshipType
from agent_alpha.security.secrets import SecretsManager

CREDS_IN_FILES = "T1552.001"  # MITRE ATT&CK: Unsecured Credentials — Credentials In Files

_WP_HOST = "wp-lab.invalid"
_SPA_HOST = "spa-lab.invalid"
_WP_CONFIG_BODY = (
    "<?php\n"
    "define('DB_NAME', 'wp_lab');\n"
    "define('DB_USER', 'wpuser');\n"
    "define('DB_PASSWORD', 's3cret');\n"
    "define('DB_HOST', 'localhost');\n"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> FakeResponse:
        self.calls.append(url)
        return self._responses.get(url, FakeResponse(status_code=404, text="Not Found"))


class _StubOrchestrator:
    def __init__(self, tool: str) -> None:
        self._tool = tool

    def decide(self, observation: dict[str, object]) -> SimpleNamespace:
        return SimpleNamespace(
            tool=self._tool, tier="rule", reasoning="stub", cost_usd=0.0, technique_id="T1592.002"
        )


def _alpha_for(host: str, tool: str, responses: dict[str, FakeResponse]) -> Alpha:
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="graph_quality", target=host)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=[host], exclusions=[], db_endpoints=[]),
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=event_store,
        orchestrator=_StubOrchestrator(tool),
        http_client=FakeHttpClient(responses),
        secrets_manager=SecretsManager(),
    )
    alpha.run_recon(rec.engagement_id, f"https://{host}/")
    return alpha


def _wp_alpha() -> Alpha:
    return _alpha_for(
        _WP_HOST,
        "wp_config_probe",
        {
            f"https://{_WP_HOST}/": FakeResponse(200, "<html>wp-content wp-includes</html>"),
            f"https://{_WP_HOST}/wp-config.php.bak": FakeResponse(200, _WP_CONFIG_BODY),
        },
    )


def _spa_alpha() -> Alpha:
    return _alpha_for(
        _SPA_HOST,
        "js_secret_probe",
        {
            f"https://{_SPA_HOST}/": FakeResponse(200, '<script src="/assets/app.js"></script>'),
            f"https://{_SPA_HOST}/assets/app.js": FakeResponse(
                200, 'const k="AKIA1234567890ABCDEF";'
            ),
        },
    )


# ── #1: credential-disclosure edges must carry T1552.001 ─────────────────────────


def test_wp_credential_edge_is_mapped_to_credentials_in_files() -> None:
    alpha = _wp_alpha()
    leads_to = alpha.graph_store.edges_by_relationship(RelationshipType.LEADS_TO)
    assert leads_to, "WP config leak produced no vuln->cred edge."
    assert all(e.technique_id == CREDS_IN_FILES for e in leads_to), (
        f"WP credential edges must map to {CREDS_IN_FILES} (Unsecured Credentials in Files); "
        f"got {[e.technique_id for e in leads_to]!r} — leaked DB creds shown as bare recon."
    )


def test_js_credential_edge_is_mapped_to_credentials_in_files() -> None:
    alpha = _spa_alpha()
    leads_to = alpha.graph_store.edges_by_relationship(RelationshipType.LEADS_TO)
    assert leads_to, "JS secret leak produced no vuln->cred edge."
    assert all(e.technique_id == CREDS_IN_FILES for e in leads_to), (
        f"JS credential edges must map to {CREDS_IN_FILES}; got {[e.technique_id for e in leads_to]!r}."
    )


def test_omega_report_surfaces_credential_disclosure_technique() -> None:
    """The client-facing report must list T1552.001, not only the recon technique."""
    alpha = _wp_alpha()
    report = Omega(alpha.graph_store).generate_report("technical")
    assert CREDS_IN_FILES in report.mitre_techniques, (
        f"Omega report omits {CREDS_IN_FILES}; got {report.mitre_techniques!r}. A leaked "
        "credential must appear as credential-access, not just recon."
    )


# ── #3: WP/JS findings must hang off an asset node (graph coherence) ──────────────
# Tightened: the asset->vuln edge must terminate on a REAL vulnerability node (not a
# dangling id), so an impl cannot pass by wiring asset->anything.


def _assert_asset_wired_to_real_vuln(alpha: Alpha, host: str) -> None:
    graph = alpha.graph_store
    asset_id = f"asset:{host}"

    asset = next((n for n in graph.nodes_by_type(NodeType.ASSET) if n.id == asset_id), None)
    assert asset is not None, (
        f"finding on {host} has no {asset_id} node — only the Laravel path builds an asset "
        "node today (inconsistent graph; chain-finding cannot start)."
    )
    assert getattr(asset.properties, "host", None) == host, (
        f"{asset_id} AssetProperties.host must be {host!r}, got "
        f"{getattr(asset.properties, 'host', None)!r}."
    )

    vuln_ids = {n.id for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    assert vuln_ids, f"finding on {host} produced no vulnerability node to anchor the asset to."

    exploits = graph.edges_by_relationship(RelationshipType.EXPLOITS)
    assert any(e.source_id == asset_id and e.target_id in vuln_ids for e in exploits), (
        f"no EXPLOITS edge from {asset_id} to a real vulnerability node. The asset must anchor "
        "the actual finding, not a dangling reference."
    )


def test_wp_finding_has_asset_node_and_asset_to_vuln_edge() -> None:
    _assert_asset_wired_to_real_vuln(_wp_alpha(), _WP_HOST)


def test_js_finding_has_asset_node_and_asset_to_vuln_edge() -> None:
    _assert_asset_wired_to_real_vuln(_spa_alpha(), _SPA_HOST)
