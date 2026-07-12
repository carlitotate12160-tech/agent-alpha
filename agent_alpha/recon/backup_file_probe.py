from __future__ import annotations

import datetime
from typing import Any, Protocol, runtime_checkable

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.config import constants
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
from agent_alpha.recon.response_classifier import Verdict, classify_response
from agent_alpha.security.credential_assembly import assemble_leaked_credentials
from agent_alpha.security.leak_extraction import extract_secrets


@runtime_checkable
class HttpClientProtocol(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> Any: ...


BACKUP_CREDENTIAL_LOGIN_PAIRS: dict[str, tuple[str, str]] = constants.WP_CREDENTIAL_LOGIN_PAIRS
BACKUP_CREDENTIAL_USERNAME_KEYS: frozenset[str] = constants.WP_CREDENTIAL_USERNAME_KEYS
BACKUP_CREDENTIAL_SECRET_KEYS: frozenset[str] = constants.WP_CREDENTIAL_SECRET_KEYS
BACKUP_CREDENTIAL_SERVICE_MAP: dict[str, str] = constants.WP_CREDENTIAL_SERVICE_MAP


def _persist_node(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    node: AttackNode,
) -> None:
    payload = node_to_dict(node)
    event_store.append(
        EventType.NODE_DISCOVERED,
        engagement_id,
        "alpha",
        payload,
    )
    graph_store.apply_event("NodeDiscovered", payload)


def _persist_edge(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    edge: AttackEdge,
) -> None:
    payload = {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relationship": edge.relationship.value,
        "confidence": edge.confidence,
        "technique_id": edge.technique_id,
    }
    event_store.append(
        EventType.EDGE_DISCOVERED,
        engagement_id,
        "alpha",
        payload,
    )
    graph_store.apply_event("EdgeDiscovered", payload)


def _logical_path(path: str) -> str:
    lower = path.lower()
    for suffix in (".bak", ".old", ".save", ".orig", "~"):
        if lower.endswith(suffix):
            return lower[: -len(suffix)]
    return lower


def verify_backup_file(
    *,
    engagement_id: str,
    auth: Any,
    http_client: HttpClientProtocol,
    scope_hosts: list[str],
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any | None = None,
    timeout_s: float = 10.0,
) -> int:
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    creds_added = 0

    for host in scope_hosts:
        if not auth.is_in_scope(engagement_id, host):
            continue

        for path in constants.BACKUP_FILE_PATHS:
            url = f"https://{host}{path}"

            try:
                resp = http_client.get(url)
            except Exception:
                continue

            status = getattr(resp, "status_code", 0)
            body = getattr(resp, "text", "")

            verdict = classify_response(status_code=status, body=body)

            if verdict is Verdict.BLOCKED:
                event_store.append(
                    EventType.WAF_BLOCKED,
                    engagement_id,
                    "alpha",
                    {"host": host, "path": path, "status_code": status},
                )
                continue

            if verdict is not Verdict.OK:
                continue

            logical = _logical_path(path)
            leaked = extract_secrets({logical: body})
            if not leaked:
                continue

            now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

            vuln_node_id = f"vuln:{host}:backup_file_leak"

            vuln_node = AttackNode(
                id=vuln_node_id,
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

            asset_node = AttackNode(
                id=f"asset:{host}",
                type=NodeType.ASSET,
                properties=AssetProperties(
                    host=host,
                    tech_stack=["web"],
                ),
                confidence=0.85,
                agent="alpha",
                timestamp_utc=now_utc,
            )
            _persist_node(event_store, graph_store, engagement_id, asset_node)

            asset_edge = AttackEdge(
                source_id=asset_node.id,
                target_id=vuln_node.id,
                relationship=RelationshipType.EXPLOITS,
                confidence=0.85,
            )
            _persist_edge(event_store, graph_store, engagement_id, asset_edge)

            nodes, edges = assemble_leaked_credentials(
                leaked,
                host=host,
                vuln_node_id=vuln_node_id,
                login_pairs=BACKUP_CREDENTIAL_LOGIN_PAIRS,
                username_keys=BACKUP_CREDENTIAL_USERNAME_KEYS,
                secret_keys=BACKUP_CREDENTIAL_SECRET_KEYS,
                service_map=BACKUP_CREDENTIAL_SERVICE_MAP,
                secrets_manager=secrets_manager,
                engagement_id=engagement_id,
                now_utc=now_utc,
                leak_source="backup_file",
            )

            for node in nodes:
                _persist_node(event_store, graph_store, engagement_id, node)
                creds_added += 1
            for edge in edges:
                _persist_edge(event_store, graph_store, engagement_id, edge)

    return creds_added
