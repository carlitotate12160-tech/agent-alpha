"""#4 honesty — WAF-blocked report INCONCLUSIVE contract.

A run with ≥1 WAF_BLOCKED event must NEVER present as a clean "no evidence"
without the INCONCLUSIVE banner. This test ensures both the text narrative
and the HTML report carry the INCONCLUSIVE language when blocked_hosts is
non-empty, and that the generic "No evidence collected." does NOT appear
when the assessment was inconclusive due to WAF blocking.
"""

from __future__ import annotations

from agent_alpha.agents.omega.roaster import Omega, Report
from agent_alpha.conductor.reporting import build_engagement_report
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore


def _make_store_with_waf_blocked(engagement_id: str, host: str) -> InMemoryEventStore:
    """Create an event store with an ENGAGEMENT_CREATED + WAF_BLOCKED event."""
    from agent_alpha.a2a import a2a_pb2

    store = InMemoryEventStore()
    store.append(
        event_type=EventType.ENGAGEMENT_CREATED,
        engagement_id=engagement_id,
        agent="TEST",
        payload={"client_id": "c1", "target": host, "state": a2a_pb2.CREATED},
    )
    store.append(
        event_type=EventType.WAF_BLOCKED,
        engagement_id=engagement_id,
        agent="ALPHA",
        payload={"host": host, "path": "/", "status_code": 403},
    )
    return store


def test_waf_blocked_narrative_has_inconclusive() -> None:
    """Report narrative must contain 'INCONCLUSIVE' when blocked_hosts non-empty."""
    graph_store = NetworkXGraphStore()
    omega = Omega(graph_store)
    report = omega.generate_report(
        style="technical",
        blocked_hosts=("waf-blocked.example.com",),
    )
    assert "INCONCLUSIVE" in report.narrative
    assert "recommend authenticated retest" in report.narrative
    assert "waf-blocked.example.com" in report.narrative


def test_waf_blocked_html_has_inconclusive_banner() -> None:
    """HTML report must contain the INCONCLUSIVE banner when blocked_hosts non-empty."""
    graph_store = NetworkXGraphStore()
    omega = Omega(graph_store)
    report = omega.generate_report(
        style="technical",
        blocked_hosts=("waf-blocked.example.com",),
    )
    html = report.to_html()
    assert "INCONCLUSIVE" in html
    assert "waf-blocked.example.com" in html
    # The banner div must be present
    assert "WAF/bot-protection blocked recon" in html


def test_waf_blocked_html_no_clean_finding() -> None:
    """When evidence is empty AND blocked_hosts non-empty, HTML must NOT show
    'No evidence collected.' — it must show the INCONCLUSIVE message."""
    graph_store = NetworkXGraphStore()
    omega = Omega(graph_store)
    report = omega.generate_report(
        style="technical",
        blocked_hosts=("waf-blocked.example.com",),
    )
    html = report.to_html()
    assert "No evidence collected." not in html, (
        "WAF-blocked report must NOT present as 'No evidence collected.' — "
        "the INCONCLUSIVE banner must replace it (#4 honesty, anti-#3)."
    )
    assert "INCONCLUSIVE" in html


def test_waf_blocked_through_conductor_reporting() -> None:
    """blocked_hosts from WAF_BLOCKED events thread through the Conductor
    reporting path (EngagementMemoryProjector → build_engagement_report → Report)."""
    eid = "eng_waf_test"
    host = "waf-target.example.com"
    store = _make_store_with_waf_blocked(eid, host)
    graph_store = NetworkXGraphStore()

    report = build_engagement_report(graph_store, store, eid, style="technical")

    assert host in report.blocked_hosts
    assert "INCONCLUSIVE" in report.narrative
    html = report.to_html()
    assert "INCONCLUSIVE" in html
    assert "No evidence collected." not in html


def test_clean_report_still_shows_no_evidence() -> None:
    """A clean report with NO WAF blocks should still show 'No evidence collected.'
    (regression guard — don't break the normal case)."""
    graph_store = NetworkXGraphStore()
    omega = Omega(graph_store)
    report = omega.generate_report(style="technical")
    html = report.to_html()
    assert "No evidence collected." in html
    assert "INCONCLUSIVE" not in html
