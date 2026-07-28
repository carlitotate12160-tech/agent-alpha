# WordPress recon-depth battery — fingerprint-keyed playbooks (STACK_CATALOG.md).
#
# Four capabilities deepen the WP stack, each keyed on a body signature via its own
# pure-data playbook and dispatched through Alpha's registry:
#   wp_rest_routes  — DETECT-only route surface (asset property, zero findings)
#   wp_rest_users   — FINDING: username disclosure + USER nodes (cred-reuse feed)
#   woocommerce     — FINDING when body confirms wc/v3; absent = InsufficientData
#   wp_version      — FINDING (low sev) from readme.html + <meta generator>
#
# CARDINAL (anti-#3): a 200 body is NEVER a finding on its own — the finding gate is
# a confirmed BODY SIGNATURE. WordPress soft-404 returns 200 with an HTML body;
# test_soft_404_body_is_not_a_finding pins that the HANDLER (not the playbook) gates.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_wp_recon.py -v

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from types import SimpleNamespace

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AssetProperties, NodeType, VerificationTier
from agent_alpha.graph.persist import merge_asset_node, persist_node
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "wp.example"
_REST_ROOT = f"https://{_HOST}/wp-json/"
_USERS_URL = f"https://{_HOST}/wp-json/wp/v2/users"
_WC_URL = f"https://{_HOST}/wp-json/wc/v3"
_README_URL = f"https://{_HOST}/readme.html"
_SITE_ROOT = f"https://{_HOST}/"
_PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parents[2] / "agent_alpha" / "tools" / "playbooks"


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, FakeResponse] | None = None) -> None:
        self._routes = routes or {}
        self.get_calls: list[str] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.get_calls.append(url)
        return self._routes.get(url, FakeResponse(404, ""))


class _StubProvider:
    model = "stub"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, *args: object, **kwargs: object):
        self.calls += 1
        return type(
            "R",
            (),
            {"text": '{"tool": "generic_http_probe"}', "usage_cost_usd": 0.0, "model": "stub"},
        )()


def _alpha(http: FakeHttpClient, graph: NetworkXGraphStore | None = None) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="wp_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR, phase="recon")
    orchestrator = LLMOrchestrator(engine, _StubProvider())
    alpha = Alpha(
        authorization=auth,
        graph_store=graph or NetworkXGraphStore(),
        event_store=store,
        orchestrator=orchestrator,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    alpha._engagement_id = rec.engagement_id  # direct-handler tests set live run state
    return alpha, rec.engagement_id


def _users_body(*slugs: str) -> str:
    return json.dumps(
        [
            {"id": i + 1, "name": s.title(), "slug": s, "avatar_urls": {"24": "http://a/g"}}
            for i, s in enumerate(slugs)
        ]
    )


def _route_index(route_keys: list[str], namespaces: list[str] | None = None) -> str:
    return json.dumps(
        {
            "name": "Lab",
            "namespaces": namespaces if namespaces is not None else ["wp/v2"],
            "routes": {k: {"namespace": "wp/v2"} for k in route_keys},
        }
    )


# ── 1. REST users disclosure (FINDING + USER nodes) ──────────────────────────


def test_rest_users_disclosure_from_body() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    decision = SimpleNamespace(tool="wp_rest_users")
    alpha._handle_wp_rest_users(
        FakeResponse(200, _users_body("admin", "editor")), decision, _USERS_URL
    )

    assert alpha._findings == 1, "a parseable users array is a username-disclosure finding"
    users = graph.nodes_by_type(NodeType.USER)
    assert {u.properties.username for u in users} == {"admin", "editor"}
    assert len(users) == 2, "each disclosed slug must become a USER node (cred-reuse feed)"
    vulns = {n.id for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    assert f"vuln:{_HOST}:wp_rest_user_disclosure" in vulns


# ── 2. CARDINAL: soft-404 (200 + HTML) is NOT a finding ──────────────────────


def test_soft_404_body_is_not_a_finding() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    html = "<!DOCTYPE html><html><body><h1>Not Found</h1></body></html>"
    decision = SimpleNamespace(tool="wp_rest_users")
    added = alpha._handle_wp_rest_users(FakeResponse(200, html), decision, _USERS_URL)

    assert added == 0
    assert alpha._findings == 0, "a 200 HTML soft-404 must NEVER be a finding (anti-#3)"
    assert graph.nodes_by_type(NodeType.USER) == []
    assert graph.nodes_by_type(NodeType.VULNERABILITY) == []


# ── 3. Route surface = asset property, NOT findings ──────────────────────────


def test_route_surface_is_asset_property_not_findings() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    keys = [f"/wp/v2/thing{i}" for i in range(50)]
    decision = SimpleNamespace(tool="wp_rest_routes")
    alpha._handle_wp_rest_routes(FakeResponse(200, _route_index(keys)), decision, _REST_ROOT)

    assert alpha._findings == 0, "a route surface is reach, never a payable finding"
    assets = graph.nodes_by_type(NodeType.ASSET)
    assert len(assets) == 1
    props = assets[0].properties
    assert set(props.rest_routes) == set(keys)
    assert props.rest_routes_total_count == 50
    assert props.rest_routes_truncated is False
    assert constants.STACK_WP in props.tech_stack


# ── 4. Route surface caps at 200 ─────────────────────────────────────────────


def test_route_surface_caps_at_200() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    keys = [f"/wp/v2/r{i}" for i in range(500)]
    decision = SimpleNamespace(tool="wp_rest_routes")
    alpha._handle_wp_rest_routes(FakeResponse(200, _route_index(keys)), decision, _REST_ROOT)

    props = graph.nodes_by_type(NodeType.ASSET)[0].properties
    assert len(props.rest_routes) == 200, "inventory is capped at WP_REST_ROUTES_CAP"
    assert props.rest_routes_truncated is True
    assert props.rest_routes_total_count == 500
    assert alpha._findings == 0


# ── 5. Only allowlisted routes escalate ──────────────────────────────────────


def test_only_allowlisted_routes_escalate() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    keys = ["/wp/v2/users", "/random-plugin/v1/foo", "/wp/v2/posts"]
    decision = SimpleNamespace(tool="wp_rest_routes")
    alpha._handle_wp_rest_routes(FakeResponse(200, _route_index(keys)), decision, _REST_ROOT)

    assert _USERS_URL in alpha._work_queue, "an allowlisted route must be escalated to the frontier"
    assert not any("random-plugin" in u for u in alpha._work_queue), (
        "a non-allowlisted plugin route must NOT be escalated (anti-#3 over-probe)"
    )


# ── 6. WooCommerce absent = InsufficientData (not error, not finding) ────────


def test_woocommerce_absent_is_insufficient_not_error() -> None:
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    # A /wp-json/ index with wp/v2 only — no wc/* route.
    body = _route_index(["/wp/v2/posts"], namespaces=["wp/v2"])
    decision = SimpleNamespace(tool="woocommerce")
    added = alpha._handle_woocommerce(FakeResponse(200, body), decision, _WC_URL)

    assert added == 0, "no wc/v3 shape → InsufficientData, not a finding"
    assert alpha._findings == 0
    assert graph.nodes_by_type(NodeType.VULNERABILITY) == []


# ── 7. WP version from readme.html + <meta generator> ────────────────────────


def test_wp_version_from_readme_and_meta() -> None:
    meta_body = (
        '<html><head><meta name="generator" content="WordPress 6.5.2">'
        "</head><body>home</body></html>"
    )
    http = FakeHttpClient({_SITE_ROOT: FakeResponse(200, meta_body)})
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(http, graph)

    readme = (
        "<html><body><h1>WordPress</h1>"
        "<p>Semantic Personal Publishing Platform</p>"
        "<p>Version 6.5.2</p></body></html>"
    )
    decision = SimpleNamespace(tool="wp_version")
    alpha._handle_wp_version(FakeResponse(200, readme), decision, _README_URL)

    assert alpha._findings == 1, "a parseable version is a (low-sev) disclosure finding"
    assert _SITE_ROOT in http.get_calls, (
        "the handler must make the 2nd request for <meta generator>"
    )
    vulns = {n.id: n for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    vuln_id = f"vuln:{_HOST}:wp_version_disclosure"
    assert vuln_id in vulns
    assert "6.5.2" in vulns[vuln_id].properties.affected_service


# ── 8. CARDINAL: asset properties survive a WP reprofile (anti-clobber) ──────


def test_asset_props_survive_wp_reprofile() -> None:
    """A WP handler that sets only tech_stack must NOT clobber rest_routes or
    open_ports persisted by an earlier handler on the same asset:{host}.

    This is the cardinal regression test for the CodeRabbit #274 finding:
    ``apply_event("NodeDiscovered")`` REPLACES the node wholesale, so a fresh
    ``AssetProperties(host=..., tech_stack=...)`` silently drops every field it
    did not re-set. ``merge_asset_node`` is the canonical fix.
    """
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(FakeHttpClient(), graph)

    # Phase 1: route discovery sets rest_routes + rest_routes_total_count.
    keys = ["/wp/v2/users", "/wp/v2/posts"]
    decision_routes = SimpleNamespace(tool="wp_rest_routes")
    alpha._handle_wp_rest_routes(FakeResponse(200, _route_index(keys)), decision_routes, _REST_ROOT)

    # Simulate a prior db_service_probe that set open_ports=[3306].
    store = InMemoryEventStore()
    port_node = merge_asset_node(
        graph, _HOST, confidence=0.9, timestamp_utc="2025-01-01T00:00:00Z", open_ports=[3306]
    )
    persist_node(store, graph, alpha._engagement_id, port_node, agent="alpha")

    # Verify preconditions.
    asset = graph.get_node(f"asset:{_HOST}")
    assert asset is not None
    assert isinstance(asset.properties, AssetProperties)
    assert asset.properties.rest_routes == keys
    assert asset.properties.open_ports == [3306]

    # Phase 2: a users finding re-persists asset:{host} with only tech_stack.
    decision_users = SimpleNamespace(tool="wp_rest_users")
    alpha._handle_wp_rest_users(FakeResponse(200, _users_body("admin")), decision_users, _USERS_URL)

    # Cardinal assertion: rest_routes AND open_ports must survive.
    asset_after = graph.get_node(f"asset:{_HOST}")
    assert asset_after is not None
    assert isinstance(asset_after.properties, AssetProperties)
    assert asset_after.properties.rest_routes == keys, (
        "rest_routes must survive a reprofile that did not re-observe them (anti-clobber)"
    )
    assert asset_after.properties.open_ports == [3306], (
        "open_ports must survive a reprofile that did not re-observe them (anti-clobber)"
    )


# ── 9. wp_version corroboration does NOT follow an off-scope 3xx ─────────────


def test_wp_version_corroboration_does_not_follow_offscope_redirect() -> None:
    """A 301 on the site root must NOT be followed; the <meta generator> body
    must NOT be read. The version falls back to the readme signature alone.

    Mirrors the A1 mitigation probe's ``allow_redirects=False`` off-scope guard
    (a1_validation_runner). A 3xx to another host cannot corroborate THIS host's
    version.
    """
    # Root returns 301 (redirect) — body must NOT be parsed for <meta generator>.
    http = FakeHttpClient({_SITE_ROOT: FakeResponse(301, "")})
    graph = NetworkXGraphStore()
    alpha, _ = _alpha(http, graph)

    readme = (
        "<html><body><h1>WordPress</h1>"
        "<p>Semantic Personal Publishing Platform</p>"
        "<p>Version 5.9.1</p></body></html>"
    )
    decision = SimpleNamespace(tool="wp_version")
    alpha._handle_wp_version(FakeResponse(200, readme), decision, _README_URL)

    # Finding is still minted from the readme signature alone.
    assert alpha._findings == 1, "readme version signature alone is still a finding"
    vulns = {n.id: n for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    vuln_id = f"vuln:{_HOST}:wp_version_disclosure"
    assert vuln_id in vulns
    assert "5.9.1" in vulns[vuln_id].properties.affected_service, (
        "version must come from the readme body signature, not the redirected root"
    )


# ── 10. CARDINAL WIRING: WP battery auto-fires on fingerprint ────────────────


def test_wp_battery_autofires_on_fingerprint() -> None:
    """The WP battery must auto-fire through the autonomous recon path when
    the homepage fingerprint matches, WITHOUT hand-seeding /wp-json/ or
    /readme.html.

    Cardinal wiring test (RED before the fix): the 4 WP handlers existed but
    nothing seeded /wp-json/ or /readme.html on the autonomous path, so the
    battery was an island. Now ``wp_fingerprint``'s
    ``frontier_seeds=("/wp-json/", "/readme.html")`` enqueue them through the
    same in-scope guard as every discovery, and the full battery fires e2e.
    """
    routes = {
        _SITE_ROOT: FakeResponse(200, "<html><body>wp-content</body></html>"),
        _REST_ROOT: FakeResponse(200, _route_index(["/wp/v2/users", "/wp/v2/posts"])),
        _README_URL: FakeResponse(
            200,
            "<html><body><h1>WordPress</h1>"
            "<p>Semantic Personal Publishing Platform</p>"
            "<p>Version 6.5</p></body></html>",
        ),
        _USERS_URL: FakeResponse(200, _users_body("admin")),
    }
    http = FakeHttpClient(routes)
    graph = NetworkXGraphStore()
    alpha, eng_id = _alpha(http, graph)

    # Drive the FULL autonomous recon path — no hand-seeding.
    alpha.run_recon(eng_id, _SITE_ROOT)

    # Assert asset.rest_routes is populated (wp_rest_routes auto-fired).
    asset = graph.get_node(f"asset:{_HOST}")
    assert asset is not None
    assert isinstance(asset.properties, AssetProperties)
    assert len(asset.properties.rest_routes) > 0, (
        "wp_rest_routes must auto-fire from the wp_fingerprint seed without hand-seeding"
    )

    # Assert wp_version_disclosure finding is recorded (wp_version auto-fired).
    vulns = {n.id: n for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    vuln_id = f"vuln:{_HOST}:wp_version_disclosure"
    assert vuln_id in vulns, (
        "wp_version must auto-fire from the wp_fingerprint seed without hand-seeding"
    )


# ── 11. REGRESSION: wp_config probe still fires on single-page WP site ───────


def test_wp_config_dist_leak_is_caught_on_single_page() -> None:
    """A WP-unique backup path (/wp-config.php.dist — previously NOT in
    WELL_KNOWN_LEAK_PATHS) leaking DB creds on a single-page WP site must be caught.
    Before the single-source fix, wp_fingerprint (priority 60) shadowed
    wp_config_probe on the homepage and .dist was not universally seeded, so the
    credential was missed. Now BACKUP_FILE_PATHS sources all 9 wp-config paths from
    WP_CONFIG_BACKUP_PATHS (anti-Lyndon #7), so backup_file_probe reaches .dist via
    WELL_KNOWN_LEAK_PATHS and extracts the credential.
    """
    dist_url = f"https://{_HOST}/wp-config.php.dist"
    assert "/wp-config.php.dist" in constants.WELL_KNOWN_LEAK_PATHS  # guard: now covered
    wp_config_body = (
        "<?php\n"
        "define('DB_NAME', 'wp_lab');\n"
        "define('DB_USER', 'wpuser');\n"
        "define('DB_PASSWORD', 'test-fixture-pw');\n"
        "define('DB_HOST', 'localhost');\n"
    )
    routes = {
        _SITE_ROOT: FakeResponse(200, "<html><body>wp-content</body></html>"),
        dist_url: FakeResponse(200, wp_config_body),
    }
    http = FakeHttpClient(routes)
    graph = NetworkXGraphStore()
    alpha, eng_id = _alpha(http, graph)

    alpha.run_recon(eng_id, _SITE_ROOT)

    creds = graph.nodes_by_type(NodeType.CREDENTIAL)
    assert creds, "wp-config.php.dist leak missed — WP-unique backup path not covered"


# ── 12. CARDINAL: patched plugin version is NOT a finding (anti-#3) ──────────


def test_plugin_patched_version_is_not_a_finding() -> None:
    """CARDINAL (anti-#3 + anti-FP): a catalogued plugin at a PATCHED version must
    NOT mint a CVE node. Version gate is the whole guard — presence != vulnerable."""
    body = ('<html><head><link href="/wp-content/plugins/wp-file-manager/'
            'lib/css/ui.css?ver=7.2"></head><body>wp-content</body></html>')
    graph = NetworkXGraphStore()
    alpha, eng_id = _alpha(FakeHttpClient({_SITE_ROOT: FakeResponse(200, body)}), graph)
    alpha.run_recon(eng_id, _SITE_ROOT)
    vulns = [n for n in graph.nodes_by_type(NodeType.VULNERABILITY)
             if getattr(n.properties, "cve_id", None)]
    assert not vulns, "patched plugin version must not be a CVE finding"


# ── 13. Plugin CVE confirmed from asset path (SELF_VERIFIED) ─────────────────


def test_plugin_cve_confirmed_from_asset_path() -> None:
    """Vulnerable plugin asset on the homepage -> CVE VULNERABILITY node, SELF_VERIFIED,
    auto-fired from wp_fingerprint (no hand-dispatch)."""
    body = ('<html><head><script src="/wp-content/plugins/wp-file-manager/'
            'lib/js/app.js?ver=6.0"></script></head><body>wp-content</body></html>')
    graph = NetworkXGraphStore()
    alpha, eng_id = _alpha(FakeHttpClient({_SITE_ROOT: FakeResponse(200, body)}), graph)
    alpha.run_recon(eng_id, _SITE_ROOT)
    vulns = {n.properties.cve_id: n for n in graph.nodes_by_type(NodeType.VULNERABILITY)
             if getattr(n.properties, "cve_id", None)}
    assert "CVE-2020-25213" in vulns
    assert vulns["CVE-2020-25213"].verification == VerificationTier.SELF_VERIFIED
    assert vulns["CVE-2020-25213"].properties.exploit_available is True


# ── 14. Unknown plugin -> no finding ─────────────────────────────────────────


def test_unknown_plugin_no_finding() -> None:
    body = '<html><body>wp-content /wp-content/plugins/some-random/x.js?ver=1.0</body></html>'
    graph = NetworkXGraphStore()
    alpha, eng_id = _alpha(FakeHttpClient({_SITE_ROOT: FakeResponse(200, body)}), graph)
    alpha.run_recon(eng_id, _SITE_ROOT)
    assert not [n for n in graph.nodes_by_type(NodeType.VULNERABILITY)
                if getattr(n.properties, "cve_id", None)]


# ── 15. Plugin version absent -> no CVE claim (anti-#3) ──────────────────────


def test_plugin_version_absent_no_cve_claim() -> None:
    body = '<html><body>wp-content <img src="/wp-content/plugins/wp-file-manager/logo.png"></body></html>'
    graph = NetworkXGraphStore()
    alpha, eng_id = _alpha(FakeHttpClient({_SITE_ROOT: FakeResponse(200, body)}), graph)
    alpha.run_recon(eng_id, _SITE_ROOT)
    assert not [n for n in graph.nodes_by_type(NodeType.VULNERABILITY)
                if getattr(n.properties, "cve_id", None)]
