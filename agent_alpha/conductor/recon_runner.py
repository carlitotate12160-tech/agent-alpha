# agent_alpha/conductor/recon_runner.py
"""C6a — the recon run pipeline executed inside the Celery worker (Shape B).

Wires the Phase-2 Alpha→Omega flow into the async run path. Celery args are
json-only (C1.7), so the worker cannot receive live dependencies (HttpClient, LLM
provider, graph store) over `.delay()`; they are built HERE, in-process. The two
seams — `build_recon_pipeline` and `resolve_recon_targets` — are module-level so a
hermetic test monkeypatches them to inject the same fakes the synchronous Phase-2
e2e uses (no live target, no LLM). Per-unit fan-out execution (via FanOutDispatcher)
and the live-fire FP<20% gate are C6b.
"""

from __future__ import annotations

import ipaddress
import os
import pathlib
import socket
from dataclasses import dataclass
from typing import Any

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.agents.omega.roaster import Omega, Report
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.config import constants
from agent_alpha.events.store import EventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.llm.routing import resolve_reasoning_provider
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path(__file__).resolve().parent.parent / "tools" / "playbooks"

# Canonical org-specific exclusions (single source of truth, anti-Lyndon #7); the
# structural non-routable classes (loopback / RFC1918 / link-local incl. cloud
# metadata 169.254.169.254 / multicast / reserved / IPv6 ULA + link-local) are
# covered by Python's ``ipaddress`` properties below, not a hand-rolled denylist.
_EXCLUDED_NETWORKS = [ipaddress.ip_network(c) for c in constants.SCOPE_ALWAYS_EXCLUDED]


class BlockedTargetError(ValueError):
    """A recon target resolves to a non-routable / excluded address — refused by the
    SSRF guard (CWE-918). Fail-closed: a host that does not resolve is also blocked,
    so a control-plane worker can never be steered at internal infrastructure (cloud
    metadata, loopback, RFC1918) by tenant-supplied scope. This is platform
    self-protection and holds regardless of what an engagement's scope claims."""


def _resolve_ips(host: str) -> list[str]:
    """Resolve *host* to its IP literals. Seam: tests monkeypatch this to avoid DNS."""
    return [info[4][0] for info in socket.getaddrinfo(host, None)]


def _screen_host(host: str) -> None:
    """Raise BlockedTargetError unless EVERY address *host* resolves to is public.

    Resolution-aware (catches a domain that points at an internal IP), fail-closed
    (no resolution -> blocked). NOTE residual: this validates at resolve time; a
    DNS-rebinding attacker could return a different IP at connect time. The complete
    control pins the connection to the screened IP (HttpClient hardening) and a
    network egress policy on the worker — tracked follow-up, not closed here.
    """
    try:
        ip_strs = _resolve_ips(host)
    except OSError as exc:  # gaierror is an OSError subclass
        raise BlockedTargetError(f"{host!r} does not resolve (fail-closed)") from exc
    if not ip_strs:
        raise BlockedTargetError(f"{host!r} resolved to no addresses (fail-closed)")
    for ip_str in ip_strs:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise BlockedTargetError(
                f"{host!r} resolves to non-routable {ip} — SSRF blocked (CWE-918)"
            )
        for net in _EXCLUDED_NETWORKS:
            if ip in net:
                raise BlockedTargetError(
                    f"{host!r} resolves to excluded network member {ip} ({net})"
                )


class NoTargetsError(ValueError):
    """The engagement's verified scope yielded no scan targets. An empty recon is
    not a silent success (anti-Lyndon #3) — the worker records a failure instead."""


@dataclass(frozen=True)
class ReconPipeline:
    """The live recon agent plus the graph it populates (one per worker run)."""

    alpha: Any
    graph_store: Any


@dataclass(frozen=True)
class ReconRunResult:
    """Opaque run metadata — never findings/report body (C1.8)."""

    node_count: int
    report: Report
    targets_scanned: int


def build_recon_pipeline(
    engagement_id: str,
    tenant_id: str | None,
    auth: AuthorizationStateMachine,
    store: EventStore,
) -> ReconPipeline:
    """Construct a real recon pipeline (Alpha + its own graph) for one worker run.

    Heavy deps are built in-process because Celery args are json-only (C1.7). This
    is exercised for real under C6b live-fire; hermetic tests monkeypatch this seam.
    """
    http_client = HttpClient(engagement_id=engagement_id)
    provider = resolve_reasoning_provider(api_key=os.environ["DEEPSEEK_API_KEY"])
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider)
    graph_store = NetworkXGraphStore()
    alpha = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=store,
        orchestrator=orchestrator,
        http_client=http_client,
    )
    return ReconPipeline(alpha=alpha, graph_store=graph_store)


def resolve_recon_targets(record: Any) -> list[str]:
    """Derive concrete scan URLs from an engagement's VERIFIED scope domains.

    Deterministic + order-preserving. The scope (set behind the auth gate) is the
    only source of targets — never free-form caller input. Empty → NoTargetsError
    (no silent no-op).
    """
    scope = getattr(record, "scope", None)
    domains = [
        d.strip() for d in (list(scope.domains) if scope is not None else []) if d and d.strip()
    ]
    if not domains:
        raise NoTargetsError(
            f"engagement {getattr(record, 'engagement_id', '?')!r} has no in-scope recon targets"
        )
    urls: list[str] = []
    for host in domains:
        _screen_host(host)  # SSRF guard (CWE-918) — raises BlockedTargetError if internal
        urls.append(f"https://{host}")
    return urls


def run_recon_for_engagement(
    engagement_id: str,
    tenant_id: str | None,
    auth: AuthorizationStateMachine,
    store: EventStore,
    record: Any,
) -> ReconRunResult:
    """Scan every in-scope target with Alpha, then produce the Omega report.

    Shape B (single-task): one worker scans all of the engagement's targets in
    sequence and aggregates into ONE graph + the one event stream. Returns opaque
    metadata only; the worker keeps findings/report OUT of the Celery result
    backend (C1.8).
    """
    pipeline = build_recon_pipeline(engagement_id, tenant_id, auth, store)
    targets = resolve_recon_targets(record)
    for url in targets:
        pipeline.alpha.run_recon(engagement_id, url)
    report = Omega(pipeline.graph_store).generate_report(style="technical")
    return ReconRunResult(
        node_count=pipeline.graph_store.node_count(),
        report=report,
        targets_scanned=len(targets),
    )
