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
from typing import Any, Protocol, runtime_checkable

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
    """Decode a MySQL/MariaDB greeting packet → DbServiceEvidence, or None if `raw` 
    is not a recognisable MySQL/MariaDB handshake (anti-#3 — a bare open port that
    is not a DB, e.g. an SSH banner, returns None → no SERVICE node written).

    MySQL v10 greeting layout (infra/IDE lane fills this): 4-byte packet header, then
    protocol_version byte (0x0a for v10), then a NUL-terminated server_version string
    (MariaDB advertises a version containing 'MariaDB'). host/port are supplied by the
    caller (the greeting carries neither). Returns service='mariadb' when the version
    string contains 'MariaDB', else 'mysql'.
    """
    raise NotImplementedError(
        "parse_db_handshake body is the infra/IDE lane — see the layout in the docstring."
    )


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
    raise NotImplementedError(
        "verify_in_scope_db_services gating+writes — IDE lane against the RED test; "
        "Claude owns this contract, the RED test pins the behaviour."
    )
