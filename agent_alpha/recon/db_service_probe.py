# agent_alpha/recon/db_service_probe.py
"""Piece 2 — VERIFY an in-scope DB service and write it to the AttackGraph (RECON tier).

THE MISSING WIRING: the Conductor factory resolves a DB target from a SERVICE(mysql)
node + the asset's open_ports, but nothing writes those today (grep-verified: dead
seam, Lyndon #2). This verifier closes it. Driven ONLY by scope.db_endpoints (the SOW
declares the DB host:port), it passively reads the server handshake, and — only when
that handshake PARSES as MySQL/MariaDB (anti-#3: an open port is not proof) — writes a
VERIFIED SERVICE node + joins the port to the DB host's asset. The factory can then bind
the MySqlApplicator; the credential is applied at the OFFENSIVE tier (a separate step).

TIER (decided 2026-07-02): RECON verifies, OFFENSIVE applies. This runs at RECON_ONLY+
against SOW-declared, in-scope endpoints only. It sends NO credential — it reads the
greeting packet a MySQL server emits on connect. Passive recon, not an auth attempt.

LANE:
  * Claude owns: this contract — DbServiceEvidence, the DbHandshakeProbe seam, the
    verify_in_scope_db_services gating (scope + tier + which endpoints, and the graph
    writes). Security-critical, non-offensive.
  * Infra/IDE lane owns the two injected bodies (NOT an offensive payload):
      - DbHandshakeProbe.read_handshake: the raw TCP connect + read of the greeting.
      - parse_db_handshake: decode the greeting → DbServiceEvidence | None.

INVARIANT: never probe an endpoint that is not BOTH in scope_db_endpoints AND passes
auth.is_db_endpoint_in_scope. Never write a SERVICE node for a non-MySQL/closed port.
No new canonical type — reuse ServiceProperties + AssetProperties.open_ports (#6).
"""

from __future__ import annotations

import dataclasses
import datetime
import socket
from typing import Any, Protocol, runtime_checkable

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackNode,
    NodeType,
    ServiceProperties,
    VerificationTier,
)
from agent_alpha.graph.persist import persist_node

# Single source of truth for the DB service labels this verifier recognises (#7).
_DB_SERVICES: frozenset[str] = frozenset({"mysql", "mariadb"})


@dataclasses.dataclass(frozen=True)
class DbServiceEvidence:
    """Proof that a specific host:port speaks MySQL/MariaDB — parsed from the greeting,
    never assumed from the port number (anti-Lyndon #3)."""

    host: str
    port: int
    service: str  # "mysql" | "mariadb"
    server_version: str  # e.g. "8.4.10" — parsed from the handshake, safe proof field


@runtime_checkable
class DbHandshakeProbe(Protocol):
    """Injected transport (infra lane). Open a TCP connection to host:port and return
    the server's initial handshake bytes. MySQL/MariaDB send a greeting packet on
    connect with NO auth — this reads that. MUST raise on a closed/filtered port (do
    not return empty bytes as if success)."""

    def read_handshake(self, *, host: str, port: int, timeout_s: float) -> bytes: ...


def parse_db_handshake(raw: bytes) -> DbServiceEvidence | None:
    """Decode a MySQL/MariaDB v10 greeting → DbServiceEvidence, else None.

    Heuristic discriminator (anti-#3): decides only whether to WRITE a SERVICE node.
    The AUTHORITATIVE proof of "this is really MySQL" is the OFFENSIVE pymysql handshake
    performed later by MySqlApplicator — defense in depth. host/port are filled by the
    caller (the greeting carries neither); returns 'mariadb' when the version contains
    'MariaDB', else 'mysql'.
    """
    if len(raw) < 6:
        return None
    payload_len = int.from_bytes(raw[0:3], "little")
    if payload_len < 5:
        return None
    if raw[3] != 0x00:
        return None
    if raw[4] != 0x0A:
        return None
    nul_pos = raw.find(b"\x00", 5)
    if nul_pos == -1:
        return None
    version_str = raw[5:nul_pos].decode("ascii", errors="replace")
    if not version_str or not any(c.isdigit() for c in version_str):
        return None
    service = "mariadb" if "mariadb" in version_str.lower() else "mysql"
    return DbServiceEvidence(host="", port=0, service=service, server_version=version_str)


def verify_in_scope_db_services(
    *,
    engagement_id: str,
    auth: Any,  # AuthScopeView: get_state() (>= RECON_ONLY) + is_db_endpoint_in_scope()
    scope_db_endpoints: list[str],  # "host:port" list from the SOW — the ONLY probe set
    graph_store: Any,
    event_store: Any,
    probe: DbHandshakeProbe,
    timeout_s: float,
) -> list[DbServiceEvidence]:
    """Verify the SOW-declared DB endpoints and write the confirmed ones to the graph.

    For each "host:port" in scope_db_endpoints:
      1. Require engagement state >= RECON_ONLY (fail-closed: below → skip everything).
      2. Require auth.is_db_endpoint_in_scope(engagement_id, host, port) — else SKIP
         (never probe an endpoint not in the signed SOW scope).
      3. probe.read_handshake(host, port); on raise (closed/filtered) → SKIP.
      4. parse_db_handshake(raw); None (not MySQL/MariaDB) → SKIP (anti-#3).
      5. On a confirmed DbServiceEvidence: write a SERVICE(service, port) node AND
         ensure the DB host's ASSET node exists with `port` in its open_ports (create
         or update the asset — the DB host may differ from the web-app asset). Both
         through event_store + graph_store, mirroring Alpha's persistence.

    Returns the confirmed evidence list (possibly empty — a valid outcome, not an error).
    The offensive step (MySqlApplicator.apply) is NOT called here.
    """
    # ── Tier gate: fail-closed below RECON_ONLY ────────────────────────────
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return []

    results: list[DbServiceEvidence] = []

    for endpoint in scope_db_endpoints:
        # ── Parse "host:port" ──────────────────────────────────────────────
        parts = endpoint.rsplit(":", 1)
        if len(parts) != 2:
            continue
        host, port_str = parts
        try:
            port = int(port_str)
        except ValueError:
            continue

        # ── Scope gate: never probe an out-of-scope endpoint ───────────────
        if not auth.is_db_endpoint_in_scope(engagement_id, host, port):
            continue

        # ── Probe: read the greeting (raise → skip) ────────────────────────
        try:
            raw = probe.read_handshake(host=host, port=port, timeout_s=timeout_s)
        except Exception:
            continue

        # ── Parse: anti-#3 — an open port is not proof of MySQL ────────────
        ev = parse_db_handshake(raw)
        if ev is None:
            continue

        # ── Complete host/port (greeting carries neither) ──────────────────
        ev = dataclasses.replace(ev, host=host, port=port)

        # ── Persist SERVICE + ASSET nodes (mirror scout._persist_node) ─────
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

        service_node = AttackNode(
            id=f"service:{host}:{port}",
            type=NodeType.SERVICE,
            properties=ServiceProperties(
                name=ev.service,
                port=port,
                protocol="tcp",
            ),
            confidence=0.9,
            agent="alpha",
            timestamp_utc=now_utc,
            verification=VerificationTier.SELF_VERIFIED,
        )
        persist_node(event_store, graph_store, engagement_id, service_node, agent="alpha")

        # ── Ensure the DB host's ASSET node has `port` in open_ports ───────
        asset_id = f"asset:{host}"
        existing_asset = graph_store.get_node(asset_id)
        if existing_asset is not None and isinstance(existing_asset.properties, AssetProperties):
            current_ports = list(existing_asset.properties.open_ports)
            if port not in current_ports:
                current_ports.append(port)
            rebuilt_asset = AttackNode(
                id=asset_id,
                type=NodeType.ASSET,
                properties=dataclasses.replace(
                    existing_asset.properties,
                    open_ports=current_ports,
                ),
                confidence=existing_asset.confidence,
                agent=existing_asset.agent,
                timestamp_utc=now_utc,
                verification=existing_asset.verification,
            )
        else:
            rebuilt_asset = AttackNode(
                id=asset_id,
                type=NodeType.ASSET,
                properties=AssetProperties(host=host, open_ports=[port]),
                confidence=0.9,
                agent="alpha",
                timestamp_utc=now_utc,
            )
        persist_node(event_store, graph_store, engagement_id, rebuilt_asset, agent="alpha")

        results.append(ev)

    return results


class SocketDbHandshakeProbe:
    """Concrete DbHandshakeProbe: opens a TCP socket, reads the server's greeting,
    closes, returns the raw bytes. Sends NOTHING — read only. Raises on connect/
    timeout/refused (does not swallow)."""

    def read_handshake(self, *, host: str, port: int, timeout_s: float) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_s)
            sock.connect((host, port))
            return sock.recv(1024)
