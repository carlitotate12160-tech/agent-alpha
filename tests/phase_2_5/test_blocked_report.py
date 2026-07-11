# tests/phase_2_5/test_blocked_report.py
"""Contract: R3 slice-1b — the STANDARD engagement report surfaces WAF-blocked hosts
so a blocked host is never silently reported as clean (closes the false-success #3 in
the CLIENT report, not just the trace).

Slice-1 (#R3) made core OBSERVE emit WAF_BLOCKED on ANY recon path; trace.py already
labels it ("waf_blocked"). But the Omega Report has no blocked field, and
build_engagement_report never reads WAF_BLOCKED — so `run_recon_for_engagement`'s
report cannot distinguish "host X was WAF-protected, not assessed" from "host X clean".

Design (mirrors the proven time_to_first_proof_s wiring, NOT a new mechanism):
  EngagementMemoryProjector derives blocked_hosts from WAF_BLOCKED events ->
  build_engagement_report threads it -> Omega.generate_report -> Report.blocked_hosts,
  and the narrative names blocked hosts when present (so it is CONSUMED, not a dead
  field — the R2 lesson). No StopReason.BLOCKED (trace already carries loop-level
  honesty; an unused enum member would be a no-op).

RED at HEAD: Report has no blocked_hosts; EngagementMemoryRecord has no blocked_hosts;
build_engagement_report does not read WAF_BLOCKED.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_blocked_report.py -v
"""

from __future__ import annotations

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.reporting import build_engagement_report
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.memory.engagement import (
    EngagementMemoryProjector,
    InMemoryEngagementMemoryStore,
)

_HOST = "target.example.com"


def _engagement(store: InMemoryEventStore) -> str:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("client_lab", _HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    return rec.engagement_id


def _append_waf_blocked(store: InMemoryEventStore, eng: str, host: str) -> None:
    store.append(
        EventType.WAF_BLOCKED,
        eng,
        "alpha",
        {"host": host, "path": "/", "status_code": 403},
    )


# ---------------------------------------------------------------------------
# B1 — report carries the blocked host
# ---------------------------------------------------------------------------


def test_report_surfaces_blocked_host() -> None:
    store = InMemoryEventStore()
    eng = _engagement(store)
    _append_waf_blocked(store, eng, _HOST)

    report = build_engagement_report(NetworkXGraphStore(), store, eng)

    assert _HOST in tuple(report.blocked_hosts), (
        "a WAF-blocked host is absent from the report — it will be read as 'clean' (#3)"
    )


# ---------------------------------------------------------------------------
# B2 — no WAF_BLOCKED -> no blocked hosts (anti false-positive, direction b)
# ---------------------------------------------------------------------------


def test_report_no_blocked_when_no_waf_events() -> None:
    store = InMemoryEventStore()
    eng = _engagement(store)

    report = build_engagement_report(NetworkXGraphStore(), store, eng)

    assert tuple(report.blocked_hosts) == (), (
        "a clean engagement was reported as blocked (false BLOCKED)"
    )


# ---------------------------------------------------------------------------
# B3 — the blocked host is VISIBLE in the client narrative (consumed, not a dead field)
# ---------------------------------------------------------------------------


def test_blocked_host_is_visible_in_narrative() -> None:
    store = InMemoryEventStore()
    eng = _engagement(store)
    _append_waf_blocked(store, eng, _HOST)

    report = build_engagement_report(NetworkXGraphStore(), store, eng)
    text = report.narrative.lower()

    assert (_HOST in report.narrative) or ("not assessed" in text) or ("blocked" in text), (
        "blocked_hosts is populated but the narrative never mentions it — the client still "
        "cannot tell blocked from clean (a dead structured field; consume it, R2 lesson)"
    )


# ---------------------------------------------------------------------------
# B4 — projector derives blocked_hosts from the event stream (single source)
# ---------------------------------------------------------------------------


def test_projector_derives_blocked_hosts_from_events() -> None:
    store = InMemoryEventStore()
    eng = _engagement(store)
    _append_waf_blocked(store, eng, _HOST)
    _append_waf_blocked(store, eng, _HOST)  # duplicate event -> host listed once

    emr = EngagementMemoryProjector(store, InMemoryEngagementMemoryStore()).project(eng)

    assert tuple(emr.blocked_hosts) == (_HOST,), (
        f"projector must derive a deduped blocked-host set from WAF_BLOCKED events; got {emr.blocked_hosts}"
    )
