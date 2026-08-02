# agent_alpha/recon/odoo_dbmanager_probe.py
# RENAME-DEFERRED → odoo_recon.py
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
import json
import uuid
from typing import Any
from urllib.parse import urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.http_client import HttpClientProtocol
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AttackEdge,
    AttackNode,
    NodeType,
    ProofArtifact,
    RelationshipType,
    VerificationTier,
    VulnerabilityProperties,
)
from agent_alpha.graph.persist import merge_asset_node, persist_edge, persist_node
from agent_alpha.recon.response_classifier import Verdict, classify_response

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


def process_odoo_dbmanager_hit(
    *,
    resp: Any,
    url: str,
    engagement_id: str,
    auth: Any,
    graph_store: Any,
    event_store: Any,
) -> int:
    """Process a single Odoo DB manager response without an HTTP client."""
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    host = urlparse(url).hostname
    if not host or not auth.is_in_scope(engagement_id, host):
        return 0

    status = getattr(resp, "status_code", 0)
    body = getattr(resp, "text", "")

    if classify_response(status_code=status, body=body) is Verdict.BLOCKED:
        event_store.append(
            EventType.WAF_BLOCKED,
            engagement_id,
            "alpha",
            {"host": host, "path": ODOO_DBMANAGER_PATH, "status_code": status},
        )
        return 0

    if status != 200:
        return 0

    verdict = classify_odoo_dbmanager(body)
    if verdict == NOT_ODOO:
        return 0

    now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

    # merge_asset_node UNIONs the odoo label and preserves any prior profile
    # (ip / open_ports / rest_routes / ...) instead of clobbering it.
    asset_node = merge_asset_node(
        graph_store,
        host,
        tech_stack_add=["odoo"],
        confidence=0.85,
        timestamp_utc=now_utc,
    )
    persist_node(event_store, graph_store, engagement_id, asset_node, agent="alpha")

    if verdict != EXPOSED:
        return 0

    # Build reproducible evidence from the already-fetched body.
    matched_actions = [a for a in ODOO_DBMANAGER_ACTION_MARKERS if a in body.lower()]
    evidence = (
        f"Odoo /web/database/manager EXPOSED (HTTP 200) at {url}; "
        f"live management actions present: {matched_actions}. "
        f"Create/backup/drop is master-password-gated and UNPROVEN at RECON tier."
    )

    artifact_id = str(uuid.uuid4())
    # GENERAL RULE: a proof-backed finding whose classifier distinguishes a
    # true-positive from a look-alike (here: EXPOSED vs PRESENT_LOCKED — action
    # markers, not bare HTTP 200) constitutes a tool self-report → SELF_VERIFIED.
    # Generalising this to other recon exposure probes (git, backup, actuator) is
    # a fast-follow micro-slice; scope THIS slice to the Odoo probe only.
    vuln_node = AttackNode(
        id=f"vuln:{host}:odoo_dbmanager_exposed",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(
            affected_service="web",
            cvss_score=constants.ODOO_DBMANAGER_EXPOSURE_CVSS,
            exploit_available=False,
        ),
        confidence=0.85,
        proof_artifacts=[
            ProofArtifact(
                artifact_id=artifact_id,
                type="http_response",
                storage_ref=f"engagements/{engagement_id}/proofs/{artifact_id}",
                description=evidence,
                captured_at=now_utc,
                agent="alpha",
                target=url,
            )
        ],
        agent="alpha",
        timestamp_utc=now_utc,
        verification=VerificationTier.SELF_VERIFIED,
    )
    persist_node(event_store, graph_store, engagement_id, vuln_node, agent="alpha")

    edge = AttackEdge(
        source_id=asset_node.id,
        target_id=vuln_node.id,
        relationship=RelationshipType.EXPLOITS,
        confidence=0.85,
    )
    persist_edge(event_store, graph_store, engagement_id, edge, agent="alpha")

    return 1


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

        exposures += process_odoo_dbmanager_hit(
            resp=resp,
            url=url,
            engagement_id=engagement_id,
            auth=auth,
            graph_store=graph_store,
            event_store=event_store,
        )

    return exposures


def parse_odoo_version(payload: dict[str, Any]) -> str | None:
    """Tolerant parser for the Odoo version_info JSON-RPC result.

    Returns the raw server_version (e.g. "12.0-20221012") or None.
    Never raises.
    """
    try:
        val = payload.get("result", {}).get("server_version")
        if isinstance(val, str) and val:
            return val
        return None
    except Exception:
        return None


def verify_odoo_version(
    *,
    http_client: HttpClientProtocol,
    url: str,
    engagement_id: str,
    auth: Any,
    graph_store: Any,
    event_store: Any,
) -> int:
    """Probe for Odoo version disclosure (RECON_ONLY, POST /version_info).

    Mirrors the gate order of verify_odoo_dbmanager_exposure:
    tier-gate -> scope-gate -> POST -> WAF discriminator -> parse.
    Returns 1 if a version is found and minted, 0 otherwise.
    """
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    host = urlparse(url).hostname
    if not host or not auth.is_in_scope(engagement_id, host):
        return 0

    target_url = f"https://{host}{constants.ODOO_VERSION_INFO_PATH}"
    try:
        resp = http_client.post(
            target_url,
            json_body=constants.ODOO_VERSION_JSONRPC_BODY,
            allow_redirects=False,
        )
    except Exception:
        return 0  # network error -> skip, not a finding

    status = getattr(resp, "status_code", 0)
    body = getattr(resp, "text", "")

    if classify_response(status_code=status, body=body) is Verdict.BLOCKED:
        event_store.append(
            EventType.WAF_BLOCKED,
            engagement_id,
            "alpha",
            {"host": host, "path": constants.ODOO_VERSION_INFO_PATH, "status_code": status},
        )
        return 0

    if status != 200:
        return 0

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return 0

    version = parse_odoo_version(payload)
    if not version:
        return 0  # Anti-#3: NO finding minted without actual data

    now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

    # 1. Update the ASSET node with the new version and odoo label
    asset_node = merge_asset_node(
        graph_store,
        host,
        tech_stack_add=["odoo"],
        confidence=0.9,
        timestamp_utc=now_utc,
    )
    persist_node(event_store, graph_store, engagement_id, asset_node, agent="alpha")

    # 2. Mint the VULNERABILITY node (using the EXACT same contract as WP version disclosure)
    vuln_node = AttackNode(
        id=f"vuln:{host}:odoo_version_disclosure",
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(
            affected_service=f"Odoo {version}",
            cvss_score=3.1,
            exploit_available=False,
        ),
        confidence=0.8,
        agent="alpha",
        timestamp_utc=now_utc,
    )
    persist_node(event_store, graph_store, engagement_id, vuln_node, agent="alpha")

    # 3. Connect ASSET -> VULNERABILITY via EXPLOITS edge
    edge = AttackEdge(
        source_id=asset_node.id,
        target_id=vuln_node.id,
        relationship=RelationshipType.EXPLOITS,
        confidence=0.8,
    )
    persist_edge(event_store, graph_store, engagement_id, edge, agent="alpha")

    return 1
