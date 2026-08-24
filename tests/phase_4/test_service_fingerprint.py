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
