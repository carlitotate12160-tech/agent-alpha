# agent_alpha/recon/odoo_dbmanager_probe.py
"""Odoo database-manager exposure recon (RECON_ONLY, passive GET, no creds).

Mirrors the wp_config_probe CONTRACT (not its vector). Odoo's crown-jewel
surface is an internet-exposed ``/web/database/manager`` — it allows unauth
create / duplicate / backup / restore / drop of databases (master-password
gated). At RECON tier we only PROVE the surface is exposed
(``exploit_available=False``); attacking the master password is a later
OFFENSIVE slice (DeepSeek lane), never here.

CLASSIFIER (``classify_odoo_dbmanager``): pure body -> verdict.
VERIFIER (``verify_odoo_dbmanager_exposure``): per in-scope host, tier-gate
(>=RECON, fail-closed) -> scope-gate (is_in_scope, never a co-tenant) ->
https GET -> WAF discriminator (403/429/503 -> WAF_BLOCKED, NOT "clean") ->
classify -> persist. Verify is Claude's gate lane; no offensive payload.
"""

from __future__ import annotations

import datetime
from typing import Any, Protocol, runtime_checkable

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)

# ── Single-source markers for THIS probe (defined once; not a #7 dup) ──────
ODOO_DBMANAGER_PATH = "/web/database/manager"
ODOO_FINGERPRINT_MARKERS: tuple[str, ...] = ("odoo", "/web/static/", "/web/database/")
ODOO_DBMANAGER_ACTION_MARKERS: tuple[str, ...] = (
    "/web/database/create",
    "/web/database/duplicate",
    "/web/database/backup",
    "/web/database/restore",
    "/web/database/drop",
    "master password",
    "manage databases",
)
ODOO_DBMANAGER_MIN_ACTION_MARKERS = 2

# Classifier verdicts.
EXPOSED = "exposed"
PRESENT_LOCKED = "present_locked"
NOT_ODOO = "not_odoo"


def classify_odoo_dbmanager(body: str) -> str:
    """Classify a ``/web/database/manager`` response body.

    - ``exposed``        — Odoo DB manager with live management actions.
    - ``present_locked`` — Odoo, but management disabled (list_db=False / denied).
    - ``not_odoo``       — not an Odoo surface at all.

    Anti-#3: a 200 that is not the LIVE manager is NEVER ``exposed`` — a login
    redirect or a ``list_db=False`` page classifies as ``present_locked``.
    """
    low = body.lower()
    if not any(m in low for m in ODOO_FINGERPRINT_MARKERS):
        return NOT_ODOO
    action_hits = sum(1 for a in ODOO_DBMANAGER_ACTION_MARKERS if a in low)
    if action_hits >= ODOO_DBMANAGER_MIN_ACTION_MARKERS:
        return EXPOSED
    return PRESENT_LOCKED


@runtime_checkable
class HttpClientProtocol(Protocol):
    """Minimal HTTP client interface for recon GET requests."""

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> Any: ...


def verify_odoo_dbmanager_exposure(
    *,
    engagement_id: str,
    auth: Any,  # AuthScopeView: get_state() + is_in_scope()
    http_client: HttpClientProtocol,
    scope_hosts: list[str],
    graph_store: Any,
    event_store: Any,
    timeout_s: float = 10.0,
) -> int:
    """Probe in-scope hosts for an exposed Odoo database manager.

    Returns the number of EXPOSURE vulnerability nodes added.
    """
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    exposures = 0

    for host in scope_hosts:
        if not auth.is_in_scope(engagement_id, host):
            continue

        url = f"https://{host}{ODOO_DBMANAGER_PATH}"
        try:
            resp = http_client.get(url)
        except Exception:
            continue  # network error → skip, not a finding

        status = getattr(resp, "status_code", 0)
        body = getattr(resp, "text", "")

        if status in (403, 429, 503):
            event_store.append(
                EventType.WAF_BLOCKED,
                engagement_id,
                "alpha",
                {"host": host, "path": ODOO_DBMANAGER_PATH, "status_code": status},
            )
            continue  # WAF block is evidence, NOT "clean / not-vulnerable"

        if status != 200:
            continue

        verdict = classify_odoo_dbmanager(body)
        if verdict == NOT_ODOO:
            continue

        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

        asset_node = AttackNode(
            id=f"asset:{host}",
            type=NodeType.ASSET,
            properties=AssetProperties(host=host, tech_stack=["odoo"]),
            confidence=0.85,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        _persist_node(event_store, graph_store, engagement_id, asset_node)

        if verdict != EXPOSED:
            continue  # present_locked → fingerprint only, no exposure finding (anti-#3)

        vuln_node = AttackNode(
            id=f"vuln:{host}:odoo_dbmanager_exposed",
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                affected_service="web",
                exploit_available=False,
            ),
            confidence=0.85,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        _persist_node(event_store, graph_store, engagement_id, vuln_node)

        edge = AttackEdge(
            source_id=asset_node.id,
            target_id=vuln_node.id,
            relationship=RelationshipType.EXPLOITS,
            confidence=0.85,
        )
        _persist_edge(event_store, graph_store, engagement_id, edge)
        exposures += 1

    return exposures


def _persist_node(event_store: Any, graph_store: Any, engagement_id: str, node: AttackNode) -> None:
    payload = node_to_dict(node)
    event_store.append(EventType.NODE_DISCOVERED, engagement_id, "alpha", payload)
    graph_store.apply_event("NodeDiscovered", payload)


def _persist_edge(event_store: Any, graph_store: Any, engagement_id: str, edge: AttackEdge) -> None:
    payload = {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relationship": edge.relationship.value,
        "confidence": edge.confidence,
        "technique_id": edge.technique_id,
    }
    event_store.append(EventType.EDGE_DISCOVERED, engagement_id, "alpha", payload)
    graph_store.apply_event("EdgeDiscovered", payload)
