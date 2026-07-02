## Piece 2 — DB service discovery (Step 3d)

Closes the dead seam: the Conductor factory resolves a DB target from a SERVICE(mysql) node + the asset's open_ports, but nothing writes those today. This verifier — driven ONLY by the SOW's scope.db_endpoints, at RECON tier — passively reads a DB server's greeting packet and, only when it PARSES as MySQL/MariaDB, writes a VERIFIED SERVICE node + joins the port to the DB host's asset.

### What was implemented

3 bodies in `agent_alpha/recon/db_service_probe.py`:

1. **`parse_db_handshake(raw: bytes) -> DbServiceEvidence | None`** — Decodes MySQL v10 greeting (4-byte header, protocol byte 0x0a, NUL-terminated version string). Returns `mariadb` if version contains "MariaDB" (case-insensitive), else `mysql`. Returns `None` for SSH banners, truncated packets, empty, or any non-MySQL greeting (anti-#3).

2. **`verify_in_scope_db_services(...)`** — Exact gating order per endpoint:
   - (a) Tier gate: below RECON_ONLY → return `[]` immediately (fail-closed)
   - (b) Parse `host:port`, check `is_db_endpoint_in_scope` → skip if false (never probe)
   - (c) `probe.read_handshake` → skip on any exception
   - (d) `parse_db_handshake` → skip if `None` (anti-#3)
   - (e) Complete host/port, persist SERVICE node (`verified=True`, `confidence=0.9`) + rebuild/create ASSET node with `port` in `open_ports` — both via `event_store.append(NODE_DISCOVERED)` + `graph_store.apply_event("NodeDiscovered")` (mirrors `scout._persist_node`)
   - (f) Return evidence list

3. **`SocketDbHandshakeProbe`** — Opens TCP socket with timeout, reads up to 1024 bytes of server greeting, closes, returns raw bytes. Sends nothing. Raises on connect/timeout/refused.

Also created `agent_alpha/recon/__init__.py` (empty — package was missing).

### Test results (local, Windows)

- **7 passed** for `test_db_service_probe.py` + `test_db_chain_field_prove.py`
- **509 passed, 33 skipped** (full suite, zero regressions)
- **ruff check**: clean
- **ruff format**: clean
- **mypy**: clean

### Review gate (Natanael's standing rule)

Before merge, Claude must:
1. Raw-review + trace each body against T1-T5 and invariants
2. Unit-test `parse_db_handshake` standalone against crafted bytes
3. Confirm Oracle full-suite + make check output

### Test contract

- T1: verified MySQL -> SERVICE+open_ports+factory binds mysql (consumption, anti-#2)
- T2: non-mysql banner -> no node (anti-#3)
- T3: closed -> skip
- T4: out-of-scope -> NEVER probed
- T5: below RECON -> fail-closed
- `test_db_chain_field_prove.py` T2: end-to-end reachable
