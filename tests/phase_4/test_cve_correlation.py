"""§12.67-S2 slice-1: offline advisory CVE correlation."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.nodes import AttackNode, NodeType, ServiceProperties


def _record(
    cve_id: str,
    *,
    kev: bool,
    epss: float,
    max_affected: str = "1.18.0",
) -> dict[str, object]:
    return {
        "corpus_version": constants.CVE_CORPUS_VERSION,
        "product": "nginx",
        "version_range": {"max_affected": max_affected},
        "cve_id": cve_id,
        "cvss": 9.8,
        "cwe": "CWE-787",
        "kev": kev,
        "epss": epss,
        "summary": "Known nginx vulnerability",
        "confirm_probe": None,
    }


def _service_node(version: str) -> AttackNode:
    return AttackNode(
        id="service:example.com:443:nginx",
        type=NodeType.SERVICE,
        properties=ServiceProperties(
            name="nginx",
            version=version,
            port=443,
            protocol="https",
            source="server_header",
            confidence=0.8,
        ),
        confidence=0.8,
    )


def test_correlate_ranks_kev_then_epss() -> None:
    from agent_alpha.recon.cve_correlation import correlate

    corpus = [
        _record("CVE-TEST-HIGH-EPSS", kev=False, epss=0.99),
        _record("CVE-TEST-KEV", kev=True, epss=0.40),
        _record("CVE-TEST-LOW-EPSS", kev=False, epss=0.20),
    ]

    hypotheses = correlate("nginx", "1.18.0", corpus=corpus)

    assert [h.cve_id for h in hypotheses] == [
        "CVE-TEST-KEV",
        "CVE-TEST-HIGH-EPSS",
        "CVE-TEST-LOW-EPSS",
    ]


def test_version_out_of_range_no_hypothesis() -> None:
    from agent_alpha.recon.cve_correlation import correlate

    assert correlate("nginx", "1.18.1", corpus=[_record("CVE-TEST-1", kev=True, epss=0.9)]) == []


def test_concealed_version_no_hypothesis_and_negative_evidence() -> None:
    from agent_alpha.recon.cve_correlation import correlate, dispatch_cve_correlation

    assert correlate("nginx", "", corpus=[_record("CVE-TEST-1", kev=True, epss=0.9)]) == []

    event_store = InMemoryEventStore()
    dispatch_cve_correlation(
        [_service_node("")],
        host="example.com",
        engagement_id="eng_test",
        event_store=event_store,
        corpus=[_record("CVE-TEST-1", kev=True, epss=0.9)],
    )

    events = event_store.get_events("eng_test")
    negatives = [
        event
        for event in events
        if event.event_type == EventType.RECON_TECHNIQUE_ATTEMPTED
        and event.payload.get("outcome") == "concealed"
    ]
    assert len(negatives) == 1
    assert negatives[0].payload["negative_evidence"] == "version CONCEALED, CVE correlation not run"


def test_no_network_in_detection() -> None:
    root = Path("agent_alpha")
    pending = [root / "recon" / "cve_correlation.py"]
    seen: set[Path] = set()
    forbidden = {"httpx", "requests", "curl_cffi"}

    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = {node.module.split(".", 1)[0]}
                if node.module.startswith("agent_alpha."):
                    candidate = Path(*node.module.split(".")).with_suffix(".py")
                    if candidate.exists():
                        pending.append(candidate)
            else:
                continue
            assert not names & forbidden, f"network client imported by detection graph: {names & forbidden}"


def test_corpus_jsonl_loads_and_is_version_pinned() -> None:
    from agent_alpha.recon.cve_correlation import load_corpus

    corpus = load_corpus()

    assert corpus
    assert {record.corpus_version for record in corpus} == {constants.CVE_CORPUS_VERSION}
    assert list(Path("data/cve_corpus").glob("*.jsonl"))


def test_plugin_lookup_api_reads_jsonl_corpus() -> None:
    from agent_alpha.recon.plugin_cve_catalog import lookup

    hit = lookup("wp-file-manager", "6.0")

    assert hit is not None
    assert hit.cve_id == "CVE-2020-25213"
    assert lookup("wp-file-manager", "7.2") is None


def test_run_recon_emits_cve_hypothesis() -> None:
    from agent_alpha.agents.alpha.scout import Alpha, Verdict
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    class MockResponse:
        status_code = 200
        text = "<html>body</html>"
        headers = {"server": "nginx/1.18.0"}

    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()
    authorization = AuthorizationStateMachine(event_store=event_store)
    engagement = authorization.create_engagement(client_id="client_test", target="example.com")
    authorization.enable_recon(
        engagement.engagement_id,
        Scope(ip_ranges=[], domains=["example.com"], exclusions=[]),
    )

    http_client = MagicMock()
    http_client.get.return_value = MockResponse()
    orchestrator = MagicMock(spec=["decide", "playbook"])
    orchestrator.playbook.match_all.return_value = []
    orchestrator.decide.return_value = SimpleNamespace(
        tool=None,
        cost_usd=0.0,
        tier="RULE",
        reasoning="test",
    )

    with (
        patch("agent_alpha.agents.alpha.scout.classify_response", return_value=Verdict.OK),
        patch("agent_alpha.agents.alpha.scout.detect_auth_surface_labels", return_value=[]),
    ):
        Alpha(
            authorization=authorization,
            graph_store=graph_store,
            event_store=event_store,
            orchestrator=orchestrator,
            http_client=http_client,
        ).run_recon(engagement.engagement_id, "https://example.com/")

    hypothesis_events = [
        event
        for event in event_store.get_events(engagement.engagement_id)
        if event.event_type == EventType.CVE_HYPOTHESIS_RAISED
    ]
    assert hypothesis_events
    payload = hypothesis_events[0].payload
    assert payload == {
        "host": "example.com",
        "port": 443,
        "product": "nginx",
        "version": "1.18.0",
        "cve_id": "CVE-2021-23017",
        "cvss": 9.4,
        "kev": True,
        "epss": 0.944,
        "corpus_version": constants.CVE_CORPUS_VERSION,
        "tier": "self_verified",
    }
    assert graph_store.nodes_by_type(NodeType.VULNERABILITY) == []
