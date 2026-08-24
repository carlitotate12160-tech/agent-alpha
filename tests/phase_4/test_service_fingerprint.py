"""Universal-by-Design tests for S1 service fingerprinting."""

from pathlib import Path

from agent_alpha.graph.nodes import ServiceProperties
from agent_alpha.recon.service_fingerprint import (
    ProductEvidence,
    extract_service_evidence,
    is_cve_correlation_eligible,
)


def test_universal_by_design_gate_archetype_a() -> None:
    """Archetype A (bernofarm): versions exposed in standard headers."""
    headers = {
        "server": "Apache/2.4.6",
        "x-powered-by": "PHP/7.1.33",
    }
    evidence = extract_service_evidence(headers, [], "")

    assert ProductEvidence("apache", "2.4.6", "server_header", 0.8) in evidence
    assert ProductEvidence("php", "7.1.33", "x_powered_by", 0.8) in evidence


def test_universal_by_design_gate_archetype_b() -> None:
    """Archetype B (niagamas): stripped Server header + non-standard cookie/CSP products."""
    headers = {"server": "nginx"}
    set_cookies = ["metabase.DEVICE=xyz; Path=/"]
    csp = "default-src 'self' metabase.com"

    evidence = extract_service_evidence(headers, set_cookies, csp)

    assert ProductEvidence("nginx", None, "server_header", 0.6) in evidence
    assert ProductEvidence("Metabase", None, "cookie_name", 0.7) in evidence
    assert ProductEvidence("Metabase", None, "csp_domain", 0.7) in evidence


def test_anti_3_cve_correlation_eligibility() -> None:
    """version=None evidence -> SERVICE node minted with version="" AND is excluded from any CVE-correlation-eligible query."""
    # Eligible: has version and confidence > 0
    svc_eligible = ServiceProperties(name="apache", version="2.4.6", confidence=0.8)
    assert is_cve_correlation_eligible(svc_eligible) is True

    # Ineligible: missing version (anti-#3)
    svc_no_version = ServiceProperties(name="metabase", version="", confidence=0.7)
    assert is_cve_correlation_eligible(svc_no_version) is False

    # Ineligible: 0 confidence (sanity)
    svc_no_conf = ServiceProperties(name="apache", version="2.4.6", confidence=0.0)
    assert is_cve_correlation_eligible(svc_no_conf) is False


def test_no_target_hostname_literal_in_source() -> None:
    """Universal-by-Design (CLAUDE.md): the extractor must not overfit to a target.
    DATA maps carry PRODUCT names (Metabase), never TARGET hostnames."""
    src = Path("agent_alpha/recon/service_fingerprint.py").read_text()
    for forbidden in ("niagamas", "bernofarm", "btaskee"):
        assert forbidden not in src.lower()


def test_merge_semantics_corroboration() -> None:
    """Check that corroboration semantics apply (to be tested functionally inside scout's dedup logic,
    but we can at least assert that multiple evidences return)."""
    headers = {"server": "nginx"}
    set_cookies = ["metabase.DEVICE=xyz; Path=/"]
    csp = "default-src 'self' metabase.com"

    evidence = extract_service_evidence(headers, set_cookies, csp)
    # Should yield 2 evidences for Metabase
    meta_ev = [e for e in evidence if e.product == "Metabase"]
    assert len(meta_ev) == 2
    assert meta_ev[0].source == "cookie_name"
    assert meta_ev[1].source == "csp_domain"


def test_scout_run_recon_mints_service_nodes() -> None:
    """Wiring: assert run_recon on archetype_A response persists a SERVICE node via the live path (anti-island)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.agents.alpha.scout import Alpha, Verdict
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    class MockResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "Apache/2.4.6", "x-powered-by": "PHP/7.1.33"}

    mock_http = MagicMock()
    mock_http.get.return_value = MockResponse()

    from types import SimpleNamespace

    mock_orchestrator = MagicMock(spec=["decide", "playbook"])
    mock_orchestrator.playbook.match_all.return_value = []

    # Use SimpleNamespace so cost is a real float, not a Mock
    decision_mock = SimpleNamespace(tool=None, cost_usd=0.0, tier="RULE", reasoning="Test")
    mock_orchestrator.decide.return_value = decision_mock

    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="client_test", target="example.com")
    auth.enable_recon(
        rec.engagement_id, Scope(ip_ranges=[], domains=["example.com"], exclusions=[])
    )

    with (
        patch("agent_alpha.agents.alpha.scout.classify_response", return_value=Verdict.OK),
        patch("agent_alpha.agents.alpha.scout.detect_auth_surface_labels", return_value=[]),
    ):
        scout = Alpha(
            graph_store=graph_store,
            event_store=event_store,
            http_client=mock_http,
            authorization=auth,
            orchestrator=mock_orchestrator,
        )

        # Run the full recon loop on the target URL
        scout.run_recon(rec.engagement_id, "http://example.com/")

    # Verify nodes
    from agent_alpha.graph.nodes import NodeType

    service_nodes = graph_store.nodes_by_type(NodeType.SERVICE)

    # We should have Apache and PHP
    names = {n.properties.name for n in service_nodes}
    assert "apache" in names
    assert "php" in names

    apache_node = next((n for n in service_nodes if n.properties.name == "apache"), None)
    assert apache_node.properties.version == "2.4.6"
    assert apache_node.properties.source == "server_header"


def test_cdn_edge_server_not_minted_as_product() -> None:
    """Universal-by-Design archetype C (Bug 1): a CDN/WAF edge banner (Server: cloudflare)
    identifies the edge, NOT the origin stack — it must yield NO product evidence (junk for S2
    + masks the real origin). Edge posture is owned by AssetProperties (GAP-197), not here."""
    ev = extract_service_evidence(headers={"server": "cloudflare"}, set_cookies=[], csp_header="")
    assert ev == [], f"CDN edge banner must yield no product evidence; got {ev}"


def test_origin_stack_behind_cdn_not_over_suppressed() -> None:
    """The guard must not eat real signal: a genuine origin token in the SAME header survives
    even when a CDN token is also present (a proxy may append both)."""
    ev = extract_service_evidence(
        headers={"server": "cloudflare Apache/2.4.6"}, set_cookies=[], csp_header=""
    )
    products = {e.product for e in ev}
    assert "cloudflare" not in products
    assert "apache" in products


def test_cdn_edge_with_trailing_punctuation_not_minted() -> None:
    """Punctuation after the edge banner (e.g. 'cloudflare,') must be normalized and skipped."""
    ev = extract_service_evidence(headers={"server": "cloudflare,"}, set_cookies=[], csp_header="")
    assert ev == [], f"CDN edge banner with punctuation must yield no product evidence; got {ev}"


def test_cdn_edge_compound_token_not_minted() -> None:
    """Compound tokens like 'cloudflare-nginx' contain an edge identity and must not mint
    a product, even if the full string is not in CDN_IDENTITY_SERVERS exactly."""
    ev = extract_service_evidence(
        headers={"server": "cloudflare-nginx"}, set_cookies=[], csp_header=""
    )
    assert ev == [], f"CDN compound token must yield no product evidence; got {ev}"


# ── §12.67-S1 fingerprint-flank tests ──────────────────────────────


def _make_scout_with_profile(
    graph_store,
    event_store,
    mock_http,
    *,
    allow_origin_discovery: bool = True,
):
    """Shared helper: build an Alpha with an engagement profile that controls
    origin discovery consent (§12.46)."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from agent_alpha.agents.alpha.scout import Alpha, Verdict
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope

    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="client_test", target="example.com")
    auth.enable_recon(
        rec.engagement_id, Scope(ip_ranges=[], domains=["example.com"], exclusions=[])
    )

    mock_orchestrator = MagicMock(spec=["decide", "playbook"])
    mock_orchestrator.playbook.match_all.return_value = []
    decision_mock = SimpleNamespace(tool=None, cost_usd=0.0, tier="RULE", reasoning="Test")
    mock_orchestrator.decide.return_value = decision_mock

    profile = SimpleNamespace(
        allow_origin_discovery=allow_origin_discovery,
        authorized_origins=[],
        allow_evasion=False,
    )
    origin_discovery = MagicMock()

    with (
        patch("agent_alpha.agents.alpha.scout.classify_response", return_value=Verdict.OK),
        patch("agent_alpha.agents.alpha.scout.detect_auth_surface_labels", return_value=[]),
    ):
        scout = Alpha(
            graph_store=graph_store,
            event_store=event_store,
            http_client=mock_http,
            authorization=auth,
            orchestrator=mock_orchestrator,
            engagement_profile=profile,
            origin_discovery=origin_discovery,
        )
    return scout, rec, auth


def test_fingerprint_flank_cf_passthrough_mints_origin_stack() -> None:
    """Archetype A': CF-passthrough 200 → edge Server: cloudflare → 0 CVE-eligible nodes →
    flank resolves origin → origin Server: Apache/2.4.6 + X-Powered-By: PHP/7.1.33 →
    mints apache 2.4.6 + php 7.1.33. (RED before fix: 0 / edge-only.)"""
    from unittest.mock import MagicMock, patch

    from agent_alpha.agents.alpha.scout import Verdict
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType

    class EdgeResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "cloudflare"}

    class OriginResponse:
        status_code = 200
        text = "<html>origin</html>"
        headers = {"server": "Apache/2.4.6", "x-powered-by": "PHP/7.1.33"}

    mock_http = MagicMock()
    mock_http.get.return_value = EdgeResponse()

    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()

    scout, rec, _auth = _make_scout_with_profile(
        graph_store, event_store, mock_http, allow_origin_discovery=True
    )

    with (
        patch("agent_alpha.agents.alpha.scout.classify_response", return_value=Verdict.OK),
        patch("agent_alpha.agents.alpha.scout.detect_auth_surface_labels", return_value=[]),
        patch(
            "agent_alpha.recon.origin_reach.resolve_authorized_origin",
            return_value=["1.2.3.4"],
        ),
        patch(
            "agent_alpha.recon.origin_reach.origin_direct_probe",
            return_value=OriginResponse(),
        ) as mock_odp,
    ):
        scout.run_recon(rec.engagement_id, "https://example.com/")

    # origin_direct_probe was called (flank fired)
    assert mock_odp.called, "fingerprint_flank should have called origin_direct_probe"

    service_nodes = graph_store.nodes_by_type(NodeType.SERVICE)
    names = {n.properties.name for n in service_nodes}
    assert "apache" in names, f"Expected apache in {names}"
    assert "php" in names, f"Expected php in {names}"

    apache_nodes = [n for n in service_nodes if n.properties.name == "apache"]
    assert apache_nodes
    assert apache_nodes[0].properties.version == "2.4.6"

    php_nodes = [n for n in service_nodes if n.properties.name == "php"]
    assert php_nodes
    assert php_nodes[0].properties.version == "7.1.33"


def test_fingerprint_flank_clear_host_no_flank() -> None:
    """Archetype B': clear host with version-bearing Server: Apache/2.4.6 →
    edge extraction yields CVE-eligible nodes → _fingerprint_flank NOT invoked
    (assert no origin_direct_probe call — cost bounded)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.agents.alpha.scout import Verdict
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType

    class ClearResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "Apache/2.4.6", "x-powered-by": "PHP/7.1.33"}

    mock_http = MagicMock()
    mock_http.get.return_value = ClearResponse()

    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()

    scout, rec, _auth = _make_scout_with_profile(
        graph_store, event_store, mock_http, allow_origin_discovery=True
    )

    with (
        patch("agent_alpha.agents.alpha.scout.classify_response", return_value=Verdict.OK),
        patch("agent_alpha.agents.alpha.scout.detect_auth_surface_labels", return_value=[]),
        patch(
            "agent_alpha.recon.origin_reach.origin_direct_probe",
        ) as mock_odp,
    ):
        scout.run_recon(rec.engagement_id, "https://example.com/")

    # origin_direct_probe must NOT be called — edge already version-bearing
    assert not mock_odp.called, (
        "fingerprint_flank should NOT call origin_direct_probe for a clear host"
    )

    service_nodes = graph_store.nodes_by_type(NodeType.SERVICE)
    names = {n.properties.name for n in service_nodes}
    assert "apache" in names
    assert "php" in names


def test_fingerprint_flank_honest_limit_no_origin() -> None:
    """nginx-only edge (version-None, not CVE-eligible) + resolve returns [] →
    flank tried, origin unbound → 0 origin nodes, coverage note emitted, no crash.
    Edge nginx node still persisted (MERGE preserves edge info)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType
    from agent_alpha.recon.origin_reach import fingerprint_flank, is_edge_fronted_host

    class NginxEdgeResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "cloudflare"}

    alpha_mock = MagicMock()
    alpha_mock.graph_store = NetworkXGraphStore()
    alpha_mock._fp_flanked = set()

    # is_edge_fronted_host should detect cloudflare Server header
    assert is_edge_fronted_host(alpha_mock, "example.com", NginxEdgeResponse())

    # fingerprint_flank with no origins → honest coverage note
    with patch(
        "agent_alpha.recon.origin_reach.resolve_authorized_origin",
        return_value=[],
    ):
        result = fingerprint_flank(alpha_mock, "example.com", "https://example.com/")

    assert result == [], f"Expected empty list for unbound origin; got {result}"
    # Coverage note emitted
    alpha_mock._emit.assert_called()
    emit_msg = alpha_mock._emit.call_args[0][1]
    assert "edge-only" in emit_msg
    assert "origin unreachable" in emit_msg


def test_fingerprint_flank_consent_fail_closed() -> None:
    """allow_origin_discovery=False → resolve_authorized_origin returns [] →
    no flank attempted (consent fail-closed §12.46)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.agents.alpha.scout import Verdict
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    class CloudflareResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "cloudflare"}

    mock_http = MagicMock()
    mock_http.get.return_value = CloudflareResponse()

    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()

    scout, rec, _auth = _make_scout_with_profile(
        graph_store, event_store, mock_http, allow_origin_discovery=False
    )

    with (
        patch("agent_alpha.agents.alpha.scout.classify_response", return_value=Verdict.OK),
        patch("agent_alpha.agents.alpha.scout.detect_auth_surface_labels", return_value=[]),
        patch(
            "agent_alpha.recon.origin_reach.resolve_authorized_origin",
            return_value=[],
        ),
        patch(
            "agent_alpha.recon.origin_reach.origin_direct_probe",
        ) as mock_odp,
    ):
        scout.run_recon(rec.engagement_id, "https://example.com/")

    assert not mock_odp.called, "No origin_direct_probe when consent is denied"


def test_fingerprint_flank_bounded_one_per_host() -> None:
    """Two calls to _detect_service_evidence for the same edge-fronted host →
    at most ONE origin_direct_probe call (_fp_flanked guard)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.recon.origin_reach import maybe_fingerprint_flank

    class CloudflareResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "cloudflare"}

    alpha_mock = MagicMock()
    alpha_mock.graph_store = NetworkXGraphStore()
    alpha_mock._fp_flanked = set()

    with (
        patch(
            "agent_alpha.recon.origin_reach.resolve_authorized_origin",
            return_value=["1.2.3.4"],
        ),
        patch(
            "agent_alpha.recon.origin_reach.origin_direct_probe",
            return_value=None,
        ) as mock_odp,
    ):
        # First call — flank fires
        maybe_fingerprint_flank(
            alpha_mock, CloudflareResponse(), "https://example.com/", []
        )
        # Second call — same host, should be blocked by _fp_flanked
        maybe_fingerprint_flank(
            alpha_mock, CloudflareResponse(), "https://example.com/page", []
        )

    assert mock_odp.call_count == 1, (
        f"Expected exactly 1 origin_direct_probe call; got {mock_odp.call_count}"
    )


def test_fingerprint_flank_same_product_collision_version_wins() -> None:
    """Same-product collision: edge nginx (v="") + origin nginx/1.18 (v="1.18") →
    both have id service:example.com:443:nginx → persist_node last-wins semantics
    ensures version="1.18" survives (the whole point: version-bearing for S2).

    Setup: graph has edge_fronted=True (from prior binding), so is_edge_fronted_host
    fires even though Server header is nginx (not a CDN identity)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.agents.alpha.scout import Verdict
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType
    from agent_alpha.graph.persist import merge_asset_node, persist_node

    class NginxEdgeResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "nginx"}  # version-None

    class NginxOriginResponse:
        status_code = 200
        text = "<html>origin</html>"
        headers = {"server": "nginx/1.18.0"}  # version-bearing

    mock_http = MagicMock()
    mock_http.get.return_value = NginxEdgeResponse()

    graph_store = NetworkXGraphStore()
    event_store = InMemoryEventStore()

    # Pre-populate: host is KNOWN edge-fronted (from prior origin-binding proof)
    import datetime

    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
    asset = merge_asset_node(graph_store, "example.com", edge_fronted=True, timestamp_utc=now)
    persist_node(event_store, graph_store, "eng_test", asset, agent="alpha")

    scout, rec, _auth = _make_scout_with_profile(
        graph_store, event_store, mock_http, allow_origin_discovery=True
    )

    with (
        patch("agent_alpha.agents.alpha.scout.classify_response", return_value=Verdict.OK),
        patch("agent_alpha.agents.alpha.scout.detect_auth_surface_labels", return_value=[]),
        patch(
            "agent_alpha.recon.origin_reach.resolve_authorized_origin",
            return_value=["1.2.3.4"],
        ),
        patch(
            "agent_alpha.recon.origin_reach.origin_direct_probe",
            return_value=NginxOriginResponse(),
        ),
    ):
        scout.run_recon(rec.engagement_id, "https://example.com/")

    service_nodes = graph_store.nodes_by_type(NodeType.SERVICE)
    nginx_nodes = [n for n in service_nodes if n.properties.name == "nginx"]

    # Should have exactly 1 nginx node (same id, last-wins)
    assert len(nginx_nodes) == 1, f"Expected 1 nginx node; got {len(nginx_nodes)}"

    # Version MUST be the origin's version-bearing value (last-wins, protected
    # by version-priority guard against subsequent edge re-persistence)
    assert nginx_nodes[0].properties.version == "1.18.0", (
        f"Expected version '1.18.0' (origin wins via last-write); "
        f"got '{nginx_nodes[0].properties.version}'"
    )


