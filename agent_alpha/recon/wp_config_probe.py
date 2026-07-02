# agent_alpha/recon/wp_config_probe.py
"""WordPress wp-config backup leak recon — passive GET of candidate backup paths.

Mirrors ``db_service_probe.py`` in structure: a parse body (IDE/infra lane) +
a verify function (Claude gate).  Runs at RECON_ONLY (passive GET, no creds).

PARSER (``parse_wp_config``): regex-extracts ``define('DB_…', 'value')`` from a
response body.  Returns ``{}`` unless BOTH ``DB_USER`` and ``DB_PASSWORD`` are
found (anti-#3: a random 200 page, Varnish error, or HTML index does not match
``define()`` → no finding).  WP salts (``AUTH_KEY``, ``NONCE_SALT``, …) are
ignored — they are not reusable credentials.

VERIFIER (``verify_wp_config_leak``): for each in-scope host, for each path in
``WP_CONFIG_BACKUP_PATHS``: tier-gate (≥RECON, fail-closed) → scope-gate
(``is_in_scope``, never a co-tenant) → GET → classify → parse → assemble →
persist.  A 403 / challenge / block response is recorded as a ``WAF_BLOCKED``
event (evidence), NEVER silently treated as "clean / not-vulnerable".

The assembled credential feeds the SAME web cred-reuse chain
(HttpFormApplicator) already proven — WP just supplies the credential via a
new leak vector.  No applicator change.
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Protocol, runtime_checkable

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AttackEdge,
    AttackNode,
    NodeType,
    VulnerabilityProperties,
    node_to_dict,
)
from agent_alpha.security.credential_assembly import assemble_leaked_credentials

# Regex for define('DB_KEY', 'value') — case-insensitive, whitespace-tolerant.
_WP_DEFINE_RE = re.compile(
    r"define\s*\(\s*['\"](?P<key>DB_USER|DB_PASSWORD|DB_NAME|DB_HOST)['\"]\s*,\s*['\"](?P<value>[^'\"]*)['\"]\s*\)",
    re.IGNORECASE,
)

# Keys that must BOTH be present for a valid credential leak (anti-#3).
_REQUIRED_KEYS: frozenset[str] = frozenset({"DB_USER", "DB_PASSWORD"})


def parse_wp_config(body: str) -> dict[str, str]:
    """Parse a wp-config.php body for DB credential defines.

    Returns ``{KEY: value}`` for each matched ``define()`` call, or ``{}`` if
    BOTH ``DB_USER`` and ``DB_PASSWORD`` are not found.  Salts and non-DB keys
    are never matched (regex is bounded to DB_* keys).

    This is recon PARSING (like ``parse_db_handshake``) — IDE/infra lane, NOT
    an offensive payload.
    """
    result: dict[str, str] = {}
    for match in _WP_DEFINE_RE.finditer(body):
        key = match.group("key").upper()
        value = match.group("value")
        result[key] = value

    # Anti-#3: no credential unless BOTH username and password are present.
    if not _REQUIRED_KEYS.issubset(result.keys()):
        return {}

    return result


@runtime_checkable
class HttpClientProtocol(Protocol):
    """Minimal HTTP client interface for recon GET requests."""

    def get(self, url: str, *, timeout: float = 10.0) -> Any: ...


def verify_wp_config_leak(
    *,
    engagement_id: str,
    auth: Any,  # AuthScopeView: get_state() + is_in_scope()
    http_client: HttpClientProtocol,
    scope_hosts: list[str],  # in-scope domains from scope.domains
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any | None = None,
    timeout_s: float = 10.0,
) -> int:
    """Probe in-scope hosts for wp-config.php backup files.

    For each host in *scope_hosts* and each path in ``WP_CONFIG_BACKUP_PATHS``:
      1. Tier gate: engagement state >= RECON_ONLY (fail-closed).
      2. Scope gate: ``auth.is_in_scope(engagement_id, host)`` — never a co-tenant.
      3. GET the candidate URL.
      4. Classify: 403/challenge → emit ``WAF_BLOCKED`` event (not clean).
      5. Parse: ``parse_wp_config(body)`` — ``{}`` means no credential.
      6. Assemble: ``assemble_leaked_credentials`` with WP key maps.
      7. Persist nodes + edges to graph_store + event_store.

    Returns the number of CREDENTIAL nodes added.
    """
    # ── Tier gate: fail-closed below RECON_ONLY ────────────────────────────
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    creds_added = 0

    for host in scope_hosts:
        # ── Scope gate: never probe an out-of-scope host ───────────────────
        if not auth.is_in_scope(engagement_id, host):
            continue

        for path in constants.WP_CONFIG_BACKUP_PATHS:
            url = f"https://{host}{path}"

            # ── GET the candidate backup path ──────────────────────────────
            try:
                resp = http_client.get(url)
            except Exception:
                continue  # network error → skip, not a finding

            status = getattr(resp, "status_code", 0)
            body = getattr(resp, "text", "")

            # ── WAF discriminator: 403 / challenge / block ─────────────────
            if status in (403, 429, 503):
                event_store.append(
                    EventType.WAF_BLOCKED,
                    engagement_id,
                    "alpha",
                    {"host": host, "path": path, "status_code": status},
                )
                continue  # WAF block is evidence, NOT "clean / not-vulnerable"

            # ── Non-200 → skip (404, 301, etc.) ────────────────────────────
            if status != 200:
                continue

            # ── Parse: anti-#3 — a 200 page that doesn't parse = no finding ─
            leaked = parse_wp_config(body)
            if not leaked:
                continue

            # ── Assemble credential nodes via shared seam (anti-#6) ────────
            now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

            vuln_node_id = f"vuln:{host}:wp_config_leak"

            # Persist the vulnerability node first.
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

            nodes, edges = assemble_leaked_credentials(
                leaked,
                host=host,
                vuln_node_id=vuln_node_id,
                login_pairs=constants.WP_CREDENTIAL_LOGIN_PAIRS,
                username_keys=constants.WP_CREDENTIAL_USERNAME_KEYS,
                secret_keys=constants.WP_CREDENTIAL_SECRET_KEYS,
                service_map=constants.WP_CREDENTIAL_SERVICE_MAP,
                secrets_manager=secrets_manager,
                engagement_id=engagement_id,
                now_utc=now_utc,
                leak_source="wp_config_backup",
            )

            for node in nodes:
                _persist_node(event_store, graph_store, engagement_id, node)
                creds_added += 1
            for edge in edges:
                _persist_edge(event_store, graph_store, engagement_id, edge)

    return creds_added


def _persist_node(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    node: AttackNode,
) -> None:
    """Persist a node through both event_store and graph_store."""
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
    """Persist an edge through both event_store and graph_store."""
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
