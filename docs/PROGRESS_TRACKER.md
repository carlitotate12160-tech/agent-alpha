# Agent-Alpha — Progress Tracker

**Dokumen ini selalu diperbarui setelah setiap task selesai.** Berisi penjelasan lengkap tentang kemajuan proyek, modul yang ditambahkan, efeknya terhadap agent, behavior sistem, dan flow dengan contoh.

---

## Status Proyek

| Phase | Status | Progress | Target |
|-------|--------|----------|--------|
| Phase 0 | ✅ COMPLETED | 7/7 komponen selesai | 7 komponen |
| Phase 1 | ✅ COMPLETED | 5/5 komponen selesai | 5 komponen |
| Phase 2 | ✅ COMPLETED | 12/12 komponen selesai | 12 komponen |
| Phase 3 | 🟦 IN PROGRESS | C1–C3 of C1–C8 done (Oracle-green) | C1–C8 |
| Phase 4 | ⬜ NOT STARTED | 0% | - |
| Phase 5 | ⬜ NOT STARTED | 0% | - |
| Phase 6 | ⬜ NOT STARTED | 0% | - |

---

> **Source-of-truth note (2026-06-22).** The authoritative Phase-3 (Orchestrator
> hardening) step list + exit criteria is **`docs/PHASE_3_TEST_CONTRACT.md`** (C1–C8).
> The "C1 — Phase 0 Extension" numbering BELOW is an older, narrower breakdown and uses
> DIFFERENT labels (e.g. tracker C1.0 = "Celery skeleton" / C1.7 = "Emergency stop" vs
> contract C1.0 = "event-source auth state" / C1.7 = "json-only"). Do NOT cross-reference
> the two by number. Reality as of 2026-06-22: contract **C1, C2, C3 GREEN on Oracle**;
> next = C4 (real revoker ≤5s). See also the Pre-Beta Gate (rate-limit, observability) in
> the contract.

---

## C1 — Run Status & Idempotency (Phase 0 Extension)

**Tujuan C1:** Menambahkan run status tracking dan idempotency untuk engagement execution. Ini memungkinkan user memantau status run engagement dan memastikan task tidak di-dispatch secara redundant.

### C1 Checklist

- ✅ **C1.0** — Celery task skeleton (run_engagement_task)
- ✅ **C1.1** — Authorization gate enforcement (refusal when not authorized)
- ✅ **C1.2** — Status queryable via GET /run-status
- ✅ **C1.3** — Idempotent dispatch, re-runnable after completion
- ✅ **C1.4** — Failure handling and recording (ENGAGEMENT_RUN_FAILED)
- ✅ **C1.5** — Timeout recording (SoftTimeLimitExceeded)
- ✅ **C1.6** — Tenant-aware worker reconstruction
- ✅ **C1.7** — Emergency stop execution
- ✅ **C1.8** — Opaque return value (no sensitive data)

---

## Komponen yang Sudah Dibuat (C1)

### C1.0 - Celery Task Skeleton (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Celery task skeleton untuk engagement execution. Task ini di-dispatch oleh FastAPI endpoint dan dijalankan oleh Celery worker.

#### Efek terhadap Agent
- Agent task dijalankan secara asynchronous di background
- User bisa query status run tanpa blocking
- Task bisa di-retry jika transient error terjadi

#### Behavior Sistem
- `run_engagement_task(engagement_id, tenant_id)` — main task function
- Worker reconstructs auth state dari EventStore
- Authorization gate enforcement (refusal jika tidak authorized)
- Emits ENGAGEMENT_RUN_STARTED jika authorized
- Emits ENGAGEMENT_RUN_REFUSED jika tidak authorized
- Returns status "started" atau "refused"

#### Contoh Flow
```
1. User POST /engagements/{id}/run
2. FastAPI dispatch run_engagement_task.delay(engagement_id, tenant_id)
3. Celery worker picks up task
4. Worker reconstructs auth state dari EventStore
5. Worker cek can_agent_proceed(ALPHA)
6. Jika True → emit ENGAGEMENT_RUN_STARTED → return "started"
7. Jika False → emit ENGAGEMENT_RUN_REFUSED → return "refused"
```

---

### C1.1 - Authorization Gate Enforcement (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Authorization gate enforcement di dalam Celery task. Worker memastikan hanya agent yang authorized bisa menjalankan task.

#### Efek terhadap Agent
- Agent tidak bisa menjalankan task tanpa izin
- Refusal event dicatat untuk audit
- Tenant ownership enforced

#### Behavior Sistem
- Worker reconstructs EngagementRecord dari EventStore
- Cek state machine (CREATED, RECON_ONLY, ACTIVE_APPROVED, OFFENSIVE_APPROVED)
- Cek can_agent_proceed(agent_type)
- Jika tidak authorized → emit ENGAGEMENT_RUN_REFUSED → return "refused"
- Jika authorized → lanjut ke task body

#### Contoh Flow
```
1. Task di-dispatch untuk engagement di state CREATED
2. Worker reconstructs EngagementRecord
3. Worker cek can_agent_proceed(ALPHA) → False
4. Worker emit ENGAGEMENT_RUN_REFUSED
5. Worker return "refused"
```

---

### C1.2 - Status Queryable via GET /run-status (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
GET endpoint untuk query status run engagement. User bisa memantau progress task secara real-time.

#### Efek terhadap Agent
- User bisa query status tanpa blocking
- Status visible via projection dari event log
- Tenant ownership enforced

#### Behavior Sistem
- `GET /engagements/{id}/run-status` — endpoint
- `project_run_status(events)` — pure projection function
- Status literals: "queued", "running", "done", "failed", "refused", "none"
- Returns: engagement_id, status, task_id, updated_at
- Tenant ownership check (404 jika cross-tenant)

#### Contoh Flow
```
1. User GET /engagements/{id}/run-status
2. FastAPI cek tenant ownership
3. FastAPI project_run_status(store.get_events(engagement_id))
4. Return: {"engagement_id": "eng_123", "status": "running", "task_id": "abc", "updated_at": "..."}
```

---

### C1.3 - Idempotent Dispatch, Re-runnable After Completion (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Idempotent dispatch untuk mencegah redundant task dispatch. Jika task sudah queued/running, return existing task_id. Jika task done/failed/refused, accept new dispatch.

#### Efek terhadap Agent
- User tidak perlu khawatir double-click
- Task tidak di-dispatch redundant
- Re-runnable setelah completion (terminal status)

#### Behavior Sistem
- Cek run status sebelum dispatch
- Jika "queued" atau "running" → return 200 dengan existing task_id
- Jika "done", "failed", atau "refused" → accept new dispatch (202)
- Emit ENGAGEMENT_RUN_QUEUED dengan task_id

#### Contoh Flow
```
1. User POST /engagements/{id}/run → task queued
2. User POST lagi (double-click) → return 200 dengan existing task_id
3. Task selesai → status "done"
4. User POST lagi → accept new dispatch (202) dengan new task_id
```

---

### C1.4 - Failure Handling and Recording (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Generic failure handling untuk task execution. Jika task body raise exception, catch dan emit ENGAGEMENT_RUN_FAILED.

#### Efek terhadap Agent
- Failure tidak hilang (recorded di event log)
- Task return "failed" status
- Failure visible via projection

#### Behavior Sistem
- Try-catch di task body
- Jika exception → emit ENGAGEMENT_RUN_FAILED dengan reason
- Return "failed" status
- Tidak re-raise (failure captured, not lost)

#### Contoh Flow
```
1. Task body raise RuntimeError("simulated failure")
2. Task catch exception
3. Task emit ENGAGEMENT_RUN_FAILED dengan reason "simulated failure"
4. Task return {"engagement_id": "eng_123", "status": "failed"}
```

---

### C1.5 - Timeout Recording (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Timeout handling untuk Celery task. Jika SoftTimeLimitExceeded di-raise, catch dan record sebagai failure dengan "timeout" reason.

#### Efek terhadap Agent
- Timeout tidak hilang (recorded di event log)
- Task return "failed" status
- Timeout visible via projection

#### Behavior Sistem
- Catch SoftTimeLimitExceeded
- Emit ENGAGEMENT_RUN_FAILED dengan reason "timeout"
- Return "failed" status

#### Contoh Flow
```
1. Task melebihi soft time limit
2. Celery raise SoftTimeLimitExceeded
3. Task catch exception
4. Task emit ENGAGEMENT_RUN_FAILED dengan reason "timeout"
5. Task return {"engagement_id": "eng_123", "status": "failed"}
```

---

### C1.6 - Tenant-Aware Worker Reconstruction (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Worker reconstructs tenant-specific event store dari StoreProvider. Setiap tenant memiliki isolated event store.

#### Efek terhadap Agent
- Tenant isolation enforced di worker level
- Worker tidak bisa cross-tenant access
- Multi-tenant support

#### Behavior Sistem
- Task menerima tenant_id parameter
- Worker calls store_provider.for_tenant(tenant_id)
- Tenant-specific event store digunakan
- Cross-tenant access diblok

#### Contoh Flow
```
1. Task di-dispatch dengan tenant_id="tenant_a"
2. Worker calls store_provider.for_tenant("tenant_a")
3. Worker gunakan tenant_a event store
4. Worker tidak bisa access tenant_b data
```

---

### C1.7 - Emergency Stop Execution (`agent_alpha/conductor/emergency.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Emergency stop handler untuk kill switch tunggal. Force state ke EMERGENCY_STOP dan revoke semua Celery tasks.

#### Efek terhadap Agent
- Semua agent diblokir setelah emergency stop
- Task yang sedang berjalan di-revoke
- Audit event dicatat

#### Behavior Sistem
- `execute(engagement_id, reason, issued_by)` — main function
- Force state ke EMERGENCY_STOP
- Revoke semua Celery tasks (Phase 0: mock)
- Emit audit event
- Return EmergencyStopResult dengan elapsed time

#### Contoh Flow
```
1. Operator trigger emergency stop
2. EmergencyStopHandler.execute("eng_123", "Anomali", "operator_1")
3. State forced ke EMERGENCY_STOP
4. Tasks revoked
5. Event emitted
6. Return result dengan elapsed time
```

---

### C1.8 - Opaque Return Value (`agent_alpha/conductor/main.py`)

**Tanggal:** 2026-06-22
**Status:** ✅ Selesai

#### Apa ini?
Task return value hanya berisi engagement_id dan status. Tidak ada sensitive data (findings, creds, payload, target, client_id).

#### Efek terhadap Agent
- Sensitive data tidak bocor lewat task return
- Return value aman untuk logging
- Audit trail tetap lengkap di event log

#### Behavior Sistem
- Task return: {"engagement_id": "eng_123", "status": "started"}
- Tidak ada sensitive keys di return value
- Sensitive data hanya di event log (encrypted jika perlu)

#### Contoh Flow
```
1. Task selesai
2. Task return {"engagement_id": "eng_123", "status": "started"}
3. User tidak melihat findings, creds, payload, dll.
4. Sensitive data tetap di event log
```

---

## Phase 0 — Fondasi Sistem

**Tujuan Phase 0:** Membangun komponen-komponen kritis yang menjadi fondasi sebelum sistem bisa berjalan. Tanpa komponen ini, agent tidak bisa beroperasi dengan aman.

### Komponen Phase 0 Checklist

- ✅ **A2A Contract** — Protokol komunikasi antar agent
- ✅ **Authorization State Machine** — Otorisasi engagement
- ✅ **Event Store** — Audit trail append-only
- ✅ **Secrets Vault** — Penyimpanan kredensial terenkripsi
- ✅ **Policy Enforcer** — Enforcement Rules of Engagement
- ✅ **Emergency Stop** — Kill switch tunggal
- ✅ **Conductor Skeleton** — FastAPI + Celery app

---

## Komponen yang Sudah Dibuat

### 1. A2A Contract (`proto/a2a.proto`)

**Tanggal:** Sebelum sesi ini  
**Status:** ✅ Selesai

#### Apa ini?
Protokol komunikasi antar agent menggunakan gRPC/protobuf. Ini adalah "bahasa" yang semua agent gunakan untuk berkomunikasi.

#### Efek terhadap Agent
- Semua agent (Alpha, Beta, Gamma, Delta, Epsilon, Omega) berkomunikasi lewat schema ini
- Tidak ada teks bebas antar agent — semua terstruktur
- Memastikan konsistensi data antar agent

#### Behavior Sistem
- Agent mengirim pesan dengan format: `A2AMessage`
- Setiap pesan berisi: engagement_id, from_agent, to_agent, message_type, timestamp, payload, confidence
- Contoh pesan: Alpha mengirim handoff ke Beta setelah selesai reconnaissance

#### Contoh Flow
```
1. Alpha (SCOUT) selesai reconnaissance
2. Alpha kirim A2AMessage ke Conductor:
   - message_type: HANDOFF_READY
   - from_agent: ALPHA
   - to_agent: CONDUCTOR
   - payload: HandoffPayload (findings, proof_artifacts)
3. Conductor validasi dan authorize
4. Conductor kirim A2AMessage ke Beta (STRIKE):
   - message_type: HANDOFF_READY
   - from_agent: CONDUCTOR
   - to_agent: BETA
   - payload: HandoffPayload (dari Alpha)
5. Beta mulai eksekusi serangan
```

---

### 2. Authorization State Machine (`agent_alpha/conductor/authorization.py`)

**Tanggal:** Sebelum sesi ini  
**Status:** ✅ Selesai

#### Apa ini?
Mesin state yang mengontrol otorisasi engagement. Hanya Conductor yang boleh baca/tulis state ini (Rule 9).

#### Efek terhadap Agent
- Agent TIDAK bisa menjalankan aksi tanpa izin dari state machine
- Setiap agent harus memanggil `can_agent_proceed()` sebelum aksi
- Jika state tidak mengizinkan, agent diblokir

#### Behavior Sistem
State transitions:
```
CREATED → RECON_ONLY → ACTIVE_APPROVED → OFFENSIVE_APPROVED → EMERGENCY_STOP
```

- **CREATED**: Engagement baru, belum ada izin
- **RECON_ONLY**: Hanya Alpha (SCOUT) boleh reconnaissance
- **ACTIVE_APPROVED**: Beta, Gamma, Delta, Epsilon boleh beroperasi (non-offensive)
- **OFFENSIVE_APPROVED**: Semua agent boleh beroperasi termasuk offensive
- **EMERGENCY_STOP**: SEMUA agent diblokir, tidak ada yang boleh proceed

#### Contoh Flow
```
1. Engagement dibuat → state: CREATED
2. Conductor enable RECON_ONLY → state: RECON_ONLY
3. Alpha (SCOUT) panggil can_agent_proceed(ALPHA) → True (boleh recon)
4. Alpha selesai reconnaissance
5. Conductor enable ACTIVE_APPROVED → state: ACTIVE_APPROVED
6. Beta (STRIKE) panggil can_agent_proceed(BETA) → True (boleh strike)
7. Gamma (ANCHOR) panggil can_agent_proceed(GAMMA) → False (belum offensive)
8. Conductor enable OFFENSIVE_APPROVED → state: OFFENSIVE_APPROVED
9. Gamma (ANCHOR) panggil can_agent_proceed(GAMMA) → True (boleh persistence)
10. Emergency stop triggered → state: EMERGENCY_STOP
11. Semua agent panggil can_agent_proceed() → False (semua diblokir)
```

---

### 3. Event Store (`agent_alpha/events/store.py`)

**Tanggal:** Sebelum sesi ini  
**Status:** ✅ Selesai

#### Apa ini?
Penyimpanan event *append-only* — setiap aksi agent dicatat sebagai event yang tidak bisa dihapus atau dimodifikasi.

#### Efek terhadap Agent
- Setiap aksi agent mencatat event ke Event Store
- Agent tidak perlu khawatir tentang audit — Conductor yang mencatat
- Event menjadi sumber kebenaran tunggal (single source of truth)

#### Behavior Sistem
- Event berisi: event_id, event_type, engagement_id, agent, timestamp, payload, sequence_number
- Sequence number monotonic (1, 2, 3, ...) per engagement
- Tidak ada gap yang diizinkan (kecuali di-override)
- Phase 0: in-memory (Phase 1: PostgreSQL)

#### Contoh Flow
```
1. Alpha (SCOUT) melakukan port scan
2. Conductor append event:
   - event_type: "PortScanCompleted"
   - engagement_id: "eng_123"
   - agent: "ALPHA"
   - payload: {"ports": [22, 80, 443], "host": "192.168.1.1"}
   - sequence_number: 1
3. Beta (STRIKE) melakukan exploit
4. Conductor append event:
   - event_type: "ExploitAttempted"
   - engagement_id: "eng_123"
   - agent: "BETA"
   - payload: {"technique": "T1190", "target": "192.168.1.1:22"}
   - sequence_number: 2
5. Auditor replay event untuk engagement:
   - get_events("eng_123") → [event_1, event_2, ...]
   - Urut berdasarkan sequence_number
   - Lihat timeline lengkap semua aksi
```

---

### 4. Secrets Vault (`agent_alpha/security/secrets.py`)

**Tanggal:** Sesi ini (selesai)  
**Status:** ✅ Selesai

#### Apa ini?
Penyimpanan kredensial terenkripsi (password, API key, token) menggunakan Fernet symmetric encryption. Kredensial TIDAK PERNAH muncul di plaintext di log/event.

#### Efek terhadap Agent
- Agent menyimpan kredensial lewat SecretsManager
- Agent hanya bisa retrieve kredensial yang dimiliki
- Log agent otomatis di-scrub (sensitive data dihapus)

#### Behavior Sistem
- `store(label, value, engagement_id)` → menyimpan terenkripsi
- `retrieve(secret_id)` → mengembalikan plaintext
- `delete(secret_id)` → menghapus (diizinkan untuk secrets)
- `list_labels(engagement_id)` → hanya label, tidak ada nilai
- LogScrubber: menghapus password, token, Bearer dari log

#### Contoh Flow
```
1. Alpha (SCOUT) mendapatkan password database target
2. Alpha panggil secrets_manager.store("db_password", "supersecret123", "eng_123")
3. SecretsManager mengenkripsi dan menyimpan:
   - secret_id: "secret_a1b2c3d4"
   - label: "db_password"
   - encrypted_value: <bytes terenkripsi>
   - engagement_id: "eng_123"
4. Alpha log: "Connecting to database with password=supersecret123"
5. LogScrubber otomatis mengubah menjadi:
   - "Connecting to database with [REDACTED]"
6. Beta (STRIKE) butuh password:
   - secrets_manager.retrieve("secret_a1b2c3d4") → "supersecret123"
7. Audit event hanya berisi encrypted_value, bukan plaintext
```

---

### 5. Policy Enforcer (`agent_alpha/conductor/policy.py`)

**Tanggal:** Sesi ini (selesai)  
**Status:** ✅ Selesai

#### Apa ini?
Enforcement layer untuk Rules of Engagement (RoE). Membaca `policy.yaml` dan menegakkan aturan sebelum agent melakukan aksi.

#### Efek terhadap Agent
- Conductor memanggil PolicyEnforcer sebelum authorize aksi agent
- Agent tidak bisa melakukan teknik yang dilarang
- Agent tidak bisa menyerang network yang di-exclude
- Agent tidak bisa menggunakan LLM provider yang dilarang

#### Behavior Sistem
- `check_technique(mitre_id)` → cek apakah teknik dilarang
- `check_scope(target)` → cek apakah target di-exclude
- `get_opsec_profile(profile_name)` → ambil konfigurasi OPSEC
- `is_provider_allowed_for_payload(provider)` → cek provider LLM
- `requires_human_approval(transition_to)` → cek butuh approval manusia

#### Contoh Flow
```
1. Beta (STRIKE) ingin melakukan DoS (T1498)
2. Conductor panggil policy.check_technique("T1498")
3. PolicyEnforcer kembalikan PolicyViolation:
   - rule: "excluded_technique"
   - detail: "Destructive — never allowed"
   - mitre_id: "T1498"
4. Conductor tolak aksi Beta
5. Beta (STRIKE) ingin scan 169.254.1.1 (link-local)
6. Conductor panggil policy.check_scope("169.254.1.1")
7. PolicyEnforcer kembalikan PolicyViolation:
   - rule: "excluded_network"
   - detail: "Target 169.254.1.1 is in excluded network 169.254.0.0/16"
8. Conductor tolak aksi Beta
9. Beta (STRIKE) ingin scan 192.168.1.1
10. Conductor panggil policy.check_scope("192.168.1.1")
11. PolicyEnforcer kembalikan None (allowed)
12. Conductor izinkan aksi Beta
```

---

### 6. Emergency Stop (`agent_alpha/conductor/emergency.py`)

**Tanggal:** Sesi ini (baru dibuat user)  
**Status:** ✅ Selesai (perlu test)

#### Apa ini?
Tombol "kill switch" tunggal untuk menghentikan SEMUA agent secara paksa. Ketika triggered, semua agent diblokir dan semua task Celery di-revoke.

#### Efek terhadap Agent
- Agent tidak bisa proceed setelah emergency stop
- Task yang sedang berjalan di-revoke (dibatalkan)
- Agent harus berhenti segera ketika state EMERGENCY_STOP

#### Behavior Sistem
- `execute(engagement_id, reason, issued_by)` → jalankan emergency stop
- Langkah-langkah:
  1. Force state ke EMERGENCY_STOP
  2. Revoke semua task Celery (Phase 0: mock)
  3. Emit audit event
  4. Hitung elapsed time
  5. Warn jika melebihi timeout (5 detik)
- `is_stopped(engagement_id)` → cek apakah engagement di-stopped
- **Best-effort**: TIDAK PERNAH raise exception

#### Contoh Flow
```
1. Engagement berjalan dengan state OFFENSIVE_APPROVED
2. Operator mendeteksi anomali berbahaya
3. Operator panggil emergency_stop.execute("eng_123", "Anomali terdeteksi", "operator_1")
4. EmergencyStopHandler:
   a. Panggil auth.emergency_stop("eng_123", "Anomali terdeteksi")
   b. State berubah ke EMERGENCY_STOP
   c. Revoke semua task Celery (Phase 0: 0 task)
   d. Emit event "EmergencyStopExecuted"
   e. Hitung elapsed time: 120ms
5. Kembalikan EmergencyStopResult:
   - engagement_id: "eng_123"
   - success: True
   - tasks_revoked: 0
   - elapsed_ms: 120.0
   - reason: "Anomali terdeteksi"
   - timestamp_utc: "2026-06-16T09:30:00Z"
6. Alpha (SCOUT) panggil can_agent_proceed(ALPHA) → False
7. Beta (STRIKE) panggil can_agent_proceed(BETA) → False
8. Semua agent berhenti
```

---

## Flow Sistem Lengkap (Phase 0)

### Normal Operation Flow
```
1. Engagement dibuat → state: CREATED
2. Conductor enable RECON_ONLY → state: RECON_ONLY
3. Alpha (SCOUT) panggil can_agent_proceed(ALPHA) → True
4. Alpha melakukan reconnaissance
5. Alpha selesai, kirim handoff ke Conductor
6. Conductor validasi dengan PolicyEnforcer:
   - check_technique() → OK
   - check_scope() → OK
7. Conductor emit event ke EventStore
8. Conductor enable ACTIVE_APPROVED → state: ACTIVE_APPROVED
9. Beta (STRIKE) panggil can_agent_proceed(BETA) → True
10. Beta melakukan exploit
11. Beta butuh kredensial → retrieve dari SecretsVault
12. Beta log aktivitas → LogScrubber menghapus sensitive data
13. Conductor emit event ke EventStore
14. Engagement selesai → state: EMERGENCY_STOP (cleanup)
```

### Emergency Stop Flow
```
1. Engagement berjalan → state: OFFENSIVE_APPROVED
2. Operator trigger emergency stop
3. EmergencyStopHandler.execute():
   a. Force state ke EMERGENCY_STOP
   b. Revoke semua task Celery
   c. Emit event
4. Semua agent diblokir
5. Audit trail lengkap di EventStore
```

---

## Phase 1 — Attack Graph & Knowledge Representation

**Tujuan Phase 1:** Membangun sistem representasi knowledge graph untuk attack surface dan path reasoning. Graph ini menjadi dasar untuk cognitive loop agent.

### Komponen Phase 1 Checklist

- ✅ **GraphStore Protocol** — Interface abstrak read-model untuk graph engine
- ✅ **NetworkXGraphStore** — Implementasi konkret NetworkX untuk Phase 0-3
- ✅ **EngagementMemory** — Event-sourced projection untuk post-engagement learning/audit
- ✅ **SessionMemory** — Volatile live state store untuk active engagement (Redis-backed)
- ✅ **IntelligenceBase** — Cross-engagement learning queries (K3, K15-K20)

---

## Komponen yang Sudah Dibuat (Phase 1)

### 7. GraphStore Protocol (`agent_alpha/graph/store.py`)

**Tanggal:** 2026-06-17  
**Status:** ✅ Selesai

#### Apa ini?
Interface abstrak (Protocol) untuk read-model graph. Memungkinkan swapping graph engine (NetworkX → Memgraph/Neo4j) tanpa mengubah consumer code.

#### Efek terhadap Agent
- Cognitive Loop hanya bergantung pada GraphStore, bukan implementasi spesifik
- Event-sourced: graph adalah projection dari event log (event log adalah single source of truth)
- Tidak ada method save/persist/commit — hanya apply_event untuk mutasi

#### Behavior Sistem
- `apply_event(event_type, payload)` — satu-satunya write path
- `get_node`, `get_edge`, `all_nodes`, `all_edges` — query methods
- `nodes_by_type`, `edges_by_relationship` — filtering
- `neighbors`, `find_paths` — graph traversal
- `clear` — reset untuk rebuild
- `rebuild_from_events(store, events)` — helper function generic

#### Contoh Flow
```
1. Event log berisi: NodeDiscovered, EdgeDiscovered, NodeVerified
2. rebuild_from_events(store, events):
   a. store.clear()
   b. apply_event(NodeDiscovered) → tambah node
   c. apply_event(EdgeDiscovered) → tambah edge
   d. apply_event(NodeVerified) → update verified=True
3. Graph siap untuk query cognitive loop
```

---

### 8. NetworkXGraphStore (`agent_alpha/graph/networkx_store.py`)

**Tanggal:** 2026-06-17
**Status:** ✅ Selesai

#### Apa ini?
Implementasi konkret GraphStore menggunakan NetworkX DiGraph. Ini satu-satunya file yang boleh import networkx.

#### Efek terhadap Agent
- Agent bisa reasoning tentang attack surface dan attack paths
- Graph query: neighbors, find_paths, filtering by type/relationship
- Event-driven: graph dibangun dari event log

#### Behavior Sistem
- Directed graph (nx.DiGraph) untuk relationship yang berarah
- Node/Edge disimpan di attribute "data" (tidak unpack fields)
- Event handlers:
  - NodeDiscovered → add_node dengan AttackNode
  - EdgeDiscovered → add_edge dengan AttackEdge
  - NodeVerified → dataclasses.replace(verified=True)
- Unknown event types → no-op (forward-compatible)

#### Contoh Flow
```
1. Alpha (SCOUT) menemukan asset 10.0.0.1
2. Event: NodeDiscovered (id="asset1", type=ASSET, properties={...})
3. NetworkXGraphStore.apply_event() → add_node("asset1", data=AttackNode)
4. Alpha menemukan vulnerability CVE-2024-1234 di asset
5. Event: EdgeDiscovered (source="asset1", target="vuln1", relationship=EXPLOITS)
6. NetworkXGraphStore.apply_event() → add_edge("asset1", "vuln1", data=AttackEdge)
7. Cognitive loop query: find_paths("asset1", "credential1") → [asset1 → vuln1 → credential1]
```

---

### 9. EngagementMemory (`agent_alpha/memory/engagement.py`)

**Tanggal:** 2026-06-17
**Status:** ✅ Selesai

#### Apa ini?
Event-sourced projection untuk post-engagement learning dan audit. EngagementMemory adalah read-model yang dibangun murni dari event log — tidak pernah ditulis langsung.

#### Efek terhadap Agent
- Agent tidak perlu khawatir tentang learning/audit — Conductor yang memproses
- EngagementMemoryRecord frozen (immutable) — hanya dibaca, tidak dimutasi
- Source of truth adalah event log, bukan EngagementMemory

#### Behavior Sistem
- `EngagementMemoryProjector.project(engagement_id)` — replay event log dan derive record
- Fields: confirmed_exploits, failed_attempts, time_to_exploit_per_phase, tool_success_rates, proof_artifacts, scratchpad_snapshot
- Event handlers:
  - EXPLOIT_CONFIRMED → append ke confirmed_exploits
  - EXPLOIT_FAILED → append ke failed_attempts
  - PROOF_ARTIFACT_RECORDED → append ke proof_artifacts
  - SCRATCHPAD_SNAPSHOTTED → update scratchpad_snapshot (latest wins)
- `verify_projection()` — consistency check untuk drift detection

#### Contoh Flow
```
1. Engagement selesai dengan 10 events
2. EngagementMemoryProjector.project("eng_123"):
   a. get_events("eng_123") → [event_1, ..., event_10]
   b. Process setiap event → derive fields
   c. upsert EngagementMemoryRecord
3. Record berisi:
   - confirmed_exploits: [CVE-2024-0001, CVE-2024-0002]
   - failed_attempts: [CVE-2024-0003]
   - scratchpad_snapshot: {"notes": "engagement complete"}
4. Auditor query EngagementMemory untuk learning
```

---

### 10. SessionMemory (`agent_alpha/memory/session.py`)

**Tanggal:** 2026-06-17
**Status:** ✅ Selesai

#### Apa ini?
Volatile live state store untuk active engagement. SessionMemory adalah genuinely volatile (Redis-backed), bukan event-sourced — source of truth adalah dirinya sendiri selama engagement berjalan.

#### Efek terhadap Agent
- Agent read/write SessionMemory langsung selama Cognitive Loop
- SessionRecord mutable — di-update in-place (ORIENT/PLAN steps)
- Scratchpad untuk temporary notes antar cognitive loop iteration
- Jika Redis hilang mid-engagement, live progress hilang — tapi durable facts (AttackGraph, confirmed exploits) TIDAK hilang (sudah dipromote ke event log)

#### Behavior Sistem
- `SessionStore` Protocol + `InMemorySessionStore` test double
- Fields: engagement_id, target_scope, active_agent, current_phase, current_phase_iteration, authorization, scratchpad, ttl_seconds
- Methods:
  - `get()` / `set()` — basic CRUD
  - `update_scratchpad()` — convenience untuk high-frequency write path
  - `delete()` — idempotent removal
  - `exists()` — boolean check
  - `snapshot_scratchpad_event()` — return tuple untuk Conductor append ke EventStore (deep copy untuk mencegah payload drift)
- Tidak ada EventStore dependency — checkpointing adalah Conductor's job

#### Contoh Flow
```
1. Engagement dimulai → SessionRecord dibuat
2. Alpha (SCOUT) ORIENT step:
   a. get("eng_123") → SessionRecord
   b. update_scratchpad("eng_123", {"phase": "RECON", "notes": "port scan complete"})
3. Conductor checkpoint:
   a. snapshot_scratchpad_event("eng_123") → (SCRATCHPAD_SNAPSHOTTED, scratchpad_copy)
   b. EventStore.append(...) → durably append ke event log
4. Beta (STRIKE) PLAN step:
   a. get("eng_123") → SessionRecord
   b. update_scratchpad("eng_123", {"phase": "EXPLOIT", "target": "10.0.0.1"})
5. Engagement selesai → delete("eng_123")
```

---

### 11. IntelligenceBase (`agent_alpha/memory/intelligence.py`)

**Tanggal:** 2026-06-18
**Status:** ✅ Selesai

#### Apa ini?
Cross-engagement learning query interface (K3, K15-K20). Layer query untuk belajar dari engagement sebelumnya — tool reliability, false positive rates, scan strategies, credential patterns.

#### Efek terhadap Agent
- Agent bisa query "apa yang berhasil untuk target mirip?" sebelum memilih tool
- Agent bisa melihat reliability score tool sebelum menggunakannya
- Cognitive loop menggunakan IntelligenceBase untuk ORIENT/PLAN decisions
- Phase 1: semua methods return `InsufficientData` (belum ada data cross-engagement)
- Phase 2+: mulai return real scores setelah `tool_success_rates` populated

#### Behavior Sistem
- `IntelligenceBase` Protocol + `RecordBackedIntelligenceBase` implementation
- Methods:
  - `what_worked_for_similar_targets(tech_stack, target_type)` → strategy recommendation
  - `credential_patterns(industry, region)` → credential pattern lookup
  - `false_positive_rate(tool, target_type)` → FP rate untuk tool
  - `tool_reliability(tool, conditions)` → reliability score (Wilson lower-bound)
- Backend: Option A — no dedicated storage, query over `list[EngagementMemoryRecord]`
- Anti-Lyndon #3: explicit `InsufficientData` type, bukan silent 0.0
- Wilson lower-bound formula (K20) untuk statistical correction pada small samples

#### Contoh Flow (Phase 2+)
```
1. Conductor load semua EngagementMemoryRecord dari database
2. RecordBackedIntelligenceBase dibuat dengan records tersebut
3. Beta (STOUT) ORIENT step:
   a. what_worked_for_similar_targets(["laravel", "mysql"], "webapp")
   b. Return: ScanStrategy(recommended_tool_order=["nuclei", "httpx"], ...)
4. Beta PLAN step:
   a. tool_reliability("nuclei", {})
   b. Return: ToolReliabilityScore(success_rate=0.85, samples=12)
5. Beta memilih nuclei karena reliability tinggi
6. Beta execute exploit
```

#### Contoh Flow (Phase 1 Reality)
```
1. Conductor load EngagementMemoryRecord (semua tool_success_rates = {})
2. RecordBackedIntelligenceBase dibuat
3. Beta (STRIKE) ORIENT step:
   a. what_worked_for_similar_targets(["laravel", "mysql"], "webapp")
   b. Return: InsufficientData(reason="no tech_stack field on record")
4. Beta PLAN step:
   a. tool_reliability("nuclei", {})
   b. Return: InsufficientData(reason="no tool_success_rates recorded")
5. Beta fallback ke default tool selection (hardcoded logic)
```

---

## Phase 2 — Cognitive Loop & Agent Implementation

**Tujuan Phase 2:** Membangun cognitive loop dan implementasi agent pertama (Alpha SCOUT) dengan LLM reasoning dan decision ladder.

### Komponen Phase 2 Checklist

- ✅ **DeepSeekProvider** — LLM provider untuk reasoning/payload
- ✅ **PlaybookEngine** — RULE tier decision making (deterministic)
- ✅ **LLMOrchestrator** — Routing ke RULE/SINGLE_LLM/CONSENSUS
- ✅ **ToolRegistry** — Registry untuk tool yang tersedia
- ✅ **BoundedAutonomy + run_cognitive_loop** — Cognitive loop dengan stop conditions
- ✅ **Alpha SCOUT** — Reconnaissance agent pertama
- ✅ **Omega ROASTER** — Report generation agent
- ✅ **HttpClient** — Production httpx-backed HTTP client
- ✅ **Inner Monologue** — Real-time reasoning stream ke USER channel
- ✅ **RLS Guard** — Fail-closed guard untuk Postgres RLS enforcement
- ✅ **create_app_role.sql** — SQL script untuk least-privilege role
- ✅ **RLS Isolation Tests** — Integration tests dengan raw SQL verification
- ✅ **Python 3.12 + Dependencies** — Upgrade Python dan tambah pytest/protobuf

---

## Komponen yang Sudah Dibuat (Phase 2)

### 12. DeepSeekProvider (`agent_alpha/llm/providers/deepseek.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
LLM provider untuk DeepSeek API (reasoning model deepseek-v4-pro). Menyediakan interface untuk inference dengan cost tracking dan error handling.

#### Efek terhadap Agent
- Agent bisa melakukan LLM reasoning untuk decision making
- Cost tracking untuk budget enforcement
- Error handling untuk truncation (max_tokens too small)
- Timeout enforcement untuk network reliability

#### Behavior Sistem
- `list_models()` — fetch available models from DeepSeek API
- `complete(messages, max_tokens)` — single inference round-trip
- Returns `CompletionResult(text, usage_cost_usd, model)`
- Raises `CompletionTruncatedError` jika max_tokens terlalu kecil
- Warning untuk unpriced models
- Timeout 30.0 detik untuk semua HTTP requests

#### Contoh Flow
```
1. LLMOrchestrator memanggil DeepSeekProvider.complete()
2. HTTP request ke api.deepseek.com/v1/chat/completions
3. Response berisi choices[0].message.content
4. Cost dihitung dari prompt_tokens + completion_tokens
5. Return CompletionResult dengan text dan cost
```

---

### 13. PlaybookEngine (`agent_alpha/tools/playbook.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Deterministic RULE tier decision engine. Membaca YAML playbooks dan mengembalikan tool decision tanpa LLM. Ini adalah tier pertama dari decision ladder.

#### Efek terhadap Agent
- Agent bisa mengetahui tool yang harus digunakan untuk observation tertentu
- Tidak ada LLM call untuk known patterns (lebih cepat dan lebih murah)
- Escalation ke LLM hanya jika playbook tidak match

#### Behavior Sistem
- `from_directory(path)` — load semua *.yaml playbooks dari directory
- `match(observation)` — cari playbook yang match observation
- Indicators: body_contains, body_regex
- Logical OR untuk any_indicator
- Stable sorted order (deterministic)
- Returns `PlaybookDecision(tool, tier, technique_id, cost_usd)` atau None

#### Contoh Flow
```
1. Alpha SCOUT mengamati Laravel debug page
2. Observation: {"body": "Whoops...Illuminate\\...", "headers": {...}}
3. PlaybookEngine.match() mengecek laravel_debug.yaml
4. body_contains "Whoops" → match
5. Return PlaybookDecision(tool="laravel_debug_probe", tier="rule", technique_id="T1592.002")
6. Alpha execute laravel_debug_probe
```

---

### 14. LLMOrchestrator (`agent_alpha/llm/orchestrator.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Orchestrator untuk LLM decision routing. Mengimplementasikan decision ladder: RULE → SINGLE_LLM → CONSENSUS.

#### Efek terhadap Agent
- Agent mendapatkan tool decision yang optimal
- Cost optimization (RULE tier gratis, SINGLE_LLM murah, CONSENSUS mahal)
- Fallback jika tier gagal

#### Behavior Sistem
- `decide(observation)` — main decision method
- Priority: PlaybookEngine (RULE) → LLM (SINGLE_LLM) → Consensus (CONSENSUS)
- Returns `Decision(tool, tier, technique_id, cost_usd)`
- Cost tracking per decision

#### Contoh Flow
```
1. Alpha SCOUT panggil orchestrator.decide(observation)
2. Cek PlaybookEngine.match() → match
3. Return RULE tier decision (cost_usd=0.0)
4. Jika tidak match → panggil LLM provider
5. Parse JSON response untuk tool selection
6. Return SINGLE_LLM tier decision (cost_usd>0.0)
```

---

### 15. ToolRegistry (`agent_alpha/tools/registry.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Registry untuk tool yang tersedia di sistem. Menyediakan lookup tool metadata dan validation.

#### Efek terhadap Agent
- Agent bisa mengetahui tool yang tersedia
- Validation untuk tool calls
- Metadata untuk tool (description, tier, technique_id)

#### Behavior Sistem
- `get_tool(tool_name)` — ambil tool metadata
- `list_tools()` — list semua tool yang tersedia
- `is_tool_available(tool_name)` — cek availability

#### Contoh Flow
```
1. LLMOrchestrator memilih tool "laravel_debug_probe"
2. ToolRegistry.get_tool("laravel_debug_probe")
3. Return tool metadata
4. Agent execute tool
```

---

### 16. BoundedAutonomy + run_cognitive_loop (`agent_alpha/agents/base.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Cognitive loop implementation dengan bounded autonomy. Agent menjalankan loop OBSERVE → ORIENT → PLAN → ACT → VERIFY → PERSIST dengan stop conditions.

#### Efek terhadap Agent
- Agent memiliki autonomy terbatas (tidak berjalan tanpa batas)
- Stop conditions: no_progress_threshold, max_iterations
- Deterministic behavior (tidak infinite loop)

#### Behavior Sistem
- `BoundedAutonomy` — policy untuk stop conditions
- `run_cognitive_loop(agent, policy)` — main loop driver
- Loop: agent.step() → check stop conditions → continue or stop
- Stop jika: no_progress_threshold tercapai atau max_iterations tercapai

#### Contoh Flow
```
1. Alpha SCOUT panggil run_cognitive_loop(self, policy)
2. Loop:
   a. agent.step() → OBSERVE → ORIENT → PLAN → ACT → VERIFY → PERSIST
   b. check stop conditions
   c. jika tidak tercapai → continue
   d. jika tercapai → stop
3. Return outcome
```

---

### 17. Alpha SCOUT (`agent_alpha/agents/alpha/scout.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Reconnaissance agent pertama. Alpha bertugas melakukan reconnaissance pada target dan menemukan vulnerabilities.

#### Efek terhadap Agent
- Alpha melakukan reconnaissance (port scan, subdomain enumeration, tech detection)
- Alpha menulis findings ke AttackGraph dan EventStore
- Alpha handoff ke Beta setelah reconnaissance selesai

#### Behavior Sistem
- `run_recon(engagement_id, target_url)` — main entry point
- Authorization gate: cek can_agent_proceed(ALPHA)
- Scope gate: cek is_in_scope(target_host)
- Cognitive loop: OBSERVE → ORIENT → PLAN → ACT → VERIFY → PERSIST
- Tool handlers: laravel_debug_probe, generic_http_probe
- Handoff ke Conductor setelah selesai

#### Contoh Flow
```
1. Conductor panggil Alpha.run_recon(engagement_id, target_url)
2. Authorization gate: can_agent_proceed(ALPHA) → True
3. Scope gate: is_in_scope(target_host) → True
4. Cognitive loop:
   a. OBSERVE: HTTP GET ke target_url
   b. ORIENT: orchestrator.decide(observation)
   c. PLAN: tool selection
   d. ACT: execute tool
   e. VERIFY: check result
   f. PERSIST: write ke AttackGraph dan EventStore
5. Stop conditions tercapai
6. Handoff ke Conductor
```

---

### 18. Omega ROASTER (`agent_alpha/agents/omega/roaster.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Report generation agent. Omega bertugas membuat report dari findings yang dikumpulkan oleh agent lain.

#### Efek terhadap Agent
- Omega menghasilkan executive report dan technical report
- Omega mengorganisir proof artifacts
- Omega menulis narrative dari attack path

#### Behavior Sistem
- `generate_report(engagement_id)` — main entry point
- Query AttackGraph untuk findings
- Generate narrative dari attack path
- Generate executive summary
- Attach proof artifacts

#### Contoh Flow
```
1. Conductor panggil Omega.generate_report(engagement_id)
2. Omega query AttackGraph untuk findings
3. Omega generate narrative dari attack path
4. Omega generate executive summary
5. Omega attach proof artifacts
6. Omega return report
```

---

### 19. HttpClient (`agent_alpha/agents/http_client.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Production httpx-backed HTTP client untuk Alpha reconnaissance. Menggantikan FakeHttpClient di production.

#### Efek terhadap Agent
- Alpha bisa melakukan HTTP request ke real target
- User-Agent identification untuk blue team
- Timeout enforcement untuk reliability
- Transport injection untuk testing

#### Behavior Sistem
- `HttpClient(engagement_id, timeout, transport)` — constructor
- `get(url)` — HTTP GET request
- Returns `HttpResponse(status_code, text, headers, url)`
- User-Agent: "Agent-Alpha-Recon/{engagement_id}"
- Timeout: 30.0 detik (default)

#### Contoh Flow
```
1. Alpha SCOUT panggil HttpClient.get(target_url)
2. httpx.Client dengan timeout dan headers
3. HTTP GET ke target_url
4. Return HttpResponse
5. Alpha process response
```

---

### 20. Inner Monologue (`agent_alpha/agents/monologue.py`)

**Tanggal:** 2026-06-19  
**Status:** ✅ Selesai

#### Apa ini?
Real-time reasoning stream ke USER channel. Agent mengirim ThoughtFrame per cognitive-loop phase (OBSERVE, ORIENT, ACT, PERSIST) untuk memberikan visibility ke user tentang decision-making process.

#### Efek terhadap Agent
- Agent memiliki transparency dalam decision-making
- User bisa melihat reasoning real-time (RULE tier: playbook rationale, SINGLE_LLM tier: DeepSeek reasoning_content)
- Backward compatible: tanpa sink menggunakan NullMonologueSink (no-op)
- A2A messages tetap structured JSON (tidak terkontaminasi reasoning text)

#### Behavior Sistem
- `ThoughtFrame` dataclass: engagement_id, agent, phase, message, timestamp_utc, reasoning
- `MonologueSink` Protocol: duck-typed emit(frame) method
- `NullMonologueSink`: default no-op sink untuk backward compatibility
- `CollectingMonologueSink`: in-memory sink untuk testing/replay
- Alpha emits frames di setiap cognitive-loop phase:
  - OBSERVE: HTTP fetch result
  - ORIENT: tool selection dengan reasoning (playbook rationale atau LLM reasoning_content)
  - ACT: tool execution
  - PERSIST: graph persistence result
- Reasoning chain: DeepSeek reasoning_content → LLMOrchestrator → PlaybookDecision → Alpha monologue

#### Contoh Flow
```
1. Alpha SCOUT panggil orchestrator.decide(observation)
2. PlaybookEngine.match() → match (RULE tier)
3. PlaybookDecision berisi reasoning: "Laravel APP_DEBUG=true detected"
4. Alpha._emit("ORIENT", "Selected tool 'laravel_debug_probe' via the rule tier", reasoning="Laravel APP_DEBUG=true detected")
5. MonologueSink.emit(ThoughtFrame(...))
6. User melihat frame real-time via WebSocket
```

---

### 21. RLS Guard (`agent_alpha/storage/rls_guard.py`)

**Tanggal:** 2026-06-20
**Status:** ✅ Selesai

#### Apa ini?
Fail-closed guard yang mencegah Postgres stores beroperasi jika DSN role bisa bypass Row-Level Security (superuser atau BYPASSRLS). Ini memastikan tenant isolation benar-benar enforced oleh database, bukan hanya secara aplikasi.

#### Efek terhadap Agent
- Postgres stores (EventStore, EngagementMemory) menolak inisialisasi jika role bisa bypass RLS
- Mencegah silent RLS bypass di mana tenant isolation terlihat bekerja tapi sebenarnya inert
- Error message yang jelas jika role tidak aman

#### Behavior Sistem
- `RlsNotEnforcedError` — exception yang di-raise jika role bisa bypass RLS
- `assert_role_cannot_bypass_rls(connect)` — main guard function
- SQL query: `SELECT current_user, current_setting('is_superuser'), (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user)`
- Raises error jika `is_superuser='on'` atau `rolbypassrls=True`
- Dipanggil di akhir `PostgresEventStore.__init__` dan `PostgresEngagementMemoryStore.__init__`

#### Contoh Flow
```
1. Aplikasi mencoba inisialisasi PostgresEventStore dengan superuser DSN
2. assert_role_cannot_bypass_rls() dijalankan
3. SQL query menemukan is_superuser='on'
4. RlsNotEnforcedError di-raise dengan message:
   "Postgres role 'agent_alpha' can bypass Row-Level Security (is_superuser='on', rolbypassrls=False).
    Tenant isolation is NOT enforced by the database.
    Use a dedicated NOSUPERUSER NOBYPASSRLS role for the app DSN."
5. Aplikasi fail-closed (tidak berjalan dengan tenant isolation yang inert)
```

---

### 22. create_app_role.sql (`infra/create_app_role.sql`)

**Tanggal:** 2026-06-20
**Status:** ✅ Selesai

#### Apa ini?
SQL script untuk membuat least-privilege role `agent_alpha_app` yang tidak bisa bypass RLS. Script ini menyerahkan ownership tabel P2 ke role tersebut agar FORCE ROW LEVEL SECURITY benar-benar meng-constrain role tersebut.

#### Efek terhadap Agent
- Menyediakan role yang aman untuk aplikasi DSN
- Memastikan RLS enforcement berfungsi dengan benar
- Role memiliki permission yang cukup untuk operasi runtime tapi tidak bisa bypass RLS

#### Behavior Sistem
- Membuat role `agent_alpha_app` dengan `NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`
- Grant CONNECT pada database dan USAGE/CREATE pada schema public
- Transfer ownership tabel `agent_events` dan `engagement_memory` ke role tersebut
- Transfer ownership function `agent_alpha_events_append_only()` ke role tersebut
- Idempotent: bisa dijalankan berulang kali tanpa error
- Verification query untuk mengecek role tidak bisa bypass RLS

#### Contoh Flow
```
1. Jalankan script sebagai superuser:
   psql "postgresql://agent_alpha:<superpw>@127.0.0.1:15432/agent_alpha" -f create_app_role.sql
2. Script membuat role agent_alpha_app dengan password yang ditentukan
3. Script grant permission yang diperlukan
4. Script transfer ownership tabel dan function
5. Verification query menunjukkan:
   rolname: agent_alpha_app
   is_superuser: f
   can_bypass_rls: f
6. Update AGENT_ALPHA_PG_DSN untuk menggunakan role baru
```

---

### 23. RLS Isolation Tests (`tests/integration/test_rls_isolation.py`)

**Tanggal:** 2026-06-20
**Status:** ✅ Selesai

#### Apa ini?
Integration tests yang memverifikasi Row-Level Security berfungsi dengan benar untuk multi-tenant isolation. Tests ini menggunakan raw SQL queries untuk memastikan database itu sendiri yang menegakkan isolation, bukan hanya aplikasi layer.

#### Efek terhadap Agent
- Memberikan confidence bahwa tenant isolation berfungsi dengan benar
- Mendeteksi jika RLS configuration salah atau role bisa bypass
- Guard untuk mencegah silent RLS bypass di production

#### Behavior Sistem
- Tests menggunakan raw SQL tanpa tenant_id predicates
- Memverifikasi bahwa cross-tenant access diblok oleh database
- Tests untuk both app-layer isolation (WHERE tenant_id) dan RLS-layer isolation
- Guard untuk memastikan DSN role tidak bisa bypass RLS
- Tests dijalankan sebagai agent_alpha_app role (bukan superuser)

#### Contoh Flow
```
1. Test setup: buat dua tenant (tenant_a, tenant_b)
2. Insert data untuk tenant_a
3. Test raw SQL query tanpa WHERE tenant_id clause:
   SELECT * FROM engagement_memory WHERE engagement_id = 'test_engagement'
4. Jika RLS berfungsi: query hanya mengembalikan data tenant_a
5. Jika RLS tidak berfungsi: query mengembalikan semua data (cross-tenant leak)
6. Test assert bahwa query hanya mengembalikan data tenant_a
7. Test guard: cek bahwa role tidak bisa bypass RLS
```

---

### 24. Python 3.12 + Dependencies Upgrade

**Tanggal:** 2026-06-20
**Status:** ✅ Selesai

#### Apa ini?
Upgrade Python environment di Oracle dari versi lama ke Python 3.12, dan tambah dependencies yang diperlukan untuk testing dan gRPC/protobuf support.

#### Efek terhadap Agent
- Python 3.12 menyediakan fitur modern (better asyncio, type hints, performance)
- pytest untuk integration testing
- protobuf dan grpcio untuk A2A gRPC communication
- Konsistensi environment antara development dan production

#### Behavior Sistem
- Python 3.12 diinstall di Oracle ARM64
- Virtual environment dibuat ulang dengan Python 3.12
- Dependencies ditambahkan ke pyproject.toml:
  - pytest (testing framework)
  - protobuf (protobuf support)
  - grpcio (gRPC support)
- Semua dependencies diinstall di venv
- Integration tests bisa dijalankan dengan pytest

#### Contoh Flow
```
1. Install Python 3.12 di Oracle
2. python3.12 -m venv .venv
3. .venv/bin/pip install --upgrade pip
4. .venv/bin/pip install -e . (install project dependencies)
5. .venv/bin/pip install pytest protobuf grpcio
6. .venv/bin/python3 -m pytest tests/integration/test_rls_isolation.py -v
7. Tests pass dengan Python 3.12
```

---

## Komponen yang Belum Dibuat (Phase 0)

### Conductor Skeleton (FastAPI + Celery app)
**Status:** ⬜ BELUM  
**Priority:** TINGGI (komponen terakhir Phase 0)

#### Apa ini?
Skeleton FastAPI untuk Conductor service dan Celery untuk task queue agent.

#### Efek terhadap Agent
- Agent mengirim request ke FastAPI endpoint
- Agent menerima task dari Celery queue
- Agent bisa beroperasi secara distributed

#### Behavior Sistem (rencana)
- FastAPI endpoints:
  - POST /engagement → buat engagement baru
  - POST /engagement/{id}/transition → transition state
  - POST /engagement/{id}/emergency → trigger emergency stop
  - POST /engagement/{id}/sow → upload SOW file
- Celery tasks:
  - task_recon → Alpha reconnaissance
  - task_strike → Beta exploit
  - task_anchor → Gamma persistence
  - dll.

---

## Testing Strategy

### Test Coverage
- **PROTECTED tests** (6 test) — kontrak protobuf, tidak boleh dimodifikasi
- **Phase 0 tests** (159 test) — uji semua komponen Phase 0 + C1 run status & idempotency
- **Phase 1 tests** (85 test) — uji GraphStore, NetworkXGraphStore, EngagementMemory, SessionMemory, IntelligenceBase
- **Phase 2 tests** (13 test) — uji DeepSeekProvider, PlaybookEngine, LLMOrchestrator, ToolRegistry, Alpha SCOUT, Omega ROASTER, HttpClient, Inner Monologue
- Total: 263 test, semua passing

### Aturan Penting (Rule 10)
Semua test **HARUS** dijalankan di Oracle ARM64 (server remote), bukan di Windows lokal.

### Command Verifikasi
```bash
# Di Oracle ARM64:
ssh -i "<path-to-ssh-key>" ubuntu@<oracle-arm-host>
cd ~/agent-alpha
git pull origin main
make quality
```

`make quality` menjalankan:
- `ruff` (linting + formatting)
- `mypy` (type checking strict)
- `pytest` (semua test)

---

## Next Steps

### Immediate (Sesi ini)
1. Buat test untuk `emergency.py` (`test_emergency.py`)
2. Verifikasi di Oracle ARM64
3. Update progress tracker ini

### Short-term (Phase 0 completion)
1. Buat Conductor skeleton (FastAPI + Celery)
2. Buat SOW upload endpoint
3. Wire semua komponen bersama
4. Verifikasi Phase 0 exit criteria

### Long-term (Phase 1+)
1. PostgreSQL backend untuk EventStore
2. HashiCorp Vault untuk SecretsVault
3. Real Celery task revocation
4. Agent implementation (Alpha, Beta, Gamma, dll.)

---

## Apa Jenis Agent Ini?

### Agent-Alpha: Autonomous Red-Team Platform

Agent-Alpha adalah **platform red-team otomatis** dengan multi-agent architecture untuk full kill chain penetration testing. Bukan single agent, tapi sistem koordinasi 6 specialized agents yang bekerja bersama.

### Agent Hierarchy

```
Conductor (Orchestrator)
├── Alpha   (SCOUT / Reconnaissance)
├── Beta    (STRIKE / Initial Access)
├── Gamma   (ANCHOR / Exploitation)
├── Delta   (HUNTER / Post-Exploitation)
├── Epsilon (SCOUT-HUNTER / Lateral Movement)
└── Omega   (ROASTER / Reporting)
```

### Agent Types & Responsibilities

| Agent | Level | Fungsi Utama | Output |
|-------|-------|--------------|--------|
| **Alpha (SCOUT)** | Level 1 | Reconnaissance, port scan, subdomain enumeration | Attack surface map, asset inventory |
| **Beta (STRIKE)** | Level 2 | Initial access, credential spray, phishing | Valid credentials, foothold |
| **Gamma (ANCHOR)** | Level 3 | Exploitation, persistence, privilege escalation | Shell access, elevated privileges |
| **Delta (HUNTER)** | Level 4 | Post-exploitation, lateral movement, data exfiltration | Crown jewel access, sensitive data |
| **Epsilon (SCOUT-HUNTER)** | Level 5 | Hybrid recon + lateral movement | Pivot chains, internal network map |
| **Omega (ROASTER)** | Level 6 | Report generation, narrative, proof artifacts | Executive report, technical report |

### Cognitive Loop (Setiap Agent)

Setiap agent menjalankan cognitive loop yang sama:

```
OBSERVE  → Baca AttackGraph + outcome history
ORIENT   → Klasifikasi situasi, hypothesis (LLM)
PLAN     → Pilih aksi + alternative (consensus untuk critical)
ACT      → Eksekusi via gRPC tool call (Go execution engine)
VERIFY   → Konfirmasi result + tag outcome + save proof artifact
PERSIST  → Tulis node/edge ke AttackGraph (durable state)
```

### Stop Conditions (Bounded Autonomy)

Agent tidak berjalan tanpa batas — ada stop conditions:

- `max_iterations_per_agent` — maksimal loop per phase
- `time_budget_per_engagement` — batas waktu total
- `cost_budget` — batas LLM token cap
- `no_progress_detection` — N consecutive loops tanpa graph node baru

### Authorization Gates

Agent tidak bisa berjalan sembarangan — ada authorization state machine:

```
CREATED → RECON_ONLY → ACTIVE_APPROVED → OFFENSIVE_APPROVED → EMERGENCY_STOP
```

- **RECON_ONLY**: Hanya Alpha boleh reconnaissance
- **ACTIVE_APPROVED**: Beta, Gamma, Delta, Epsilon boleh (non-offensive)
- **OFFENSIVE_APPROVED**: Semua agent boleh (termasuk offensive)
- **EMERGENCY_STOP**: SEMUA agent diblokir (kill switch)

### Learning & Memory

Agent belajar dari engagement sebelumnya:

- **EngagementMemory** — Post-engagement learning (event-sourced)
- **SessionMemory** — Live state selama engagement (volatile)
- **IntelligenceBase** — Cross-engagement queries (tool reliability, strategies)
- **AttackGraph** — Knowledge graph untuk attack path reasoning

### Hybrid Architecture

- **Python (asyncio)** — Reasoning, memory, orchestration, cognitive loop
- **Go (goroutines)** — Execution (network-heavy: port scan, exploit)
- **gRPC** — IPC antara Python dan Go
- **Celery + Redis** — Task queue, multi-tenant orchestration

### Business Goal

Target: Authorized red team SaaS untuk Indonesia/SE Asia market
- Level 6 = full exfiltration dengan proof artifacts
- Multi-tenant (dedicated queue per engagement)
- Priority queue (paid tier gets higher priority)

### Key Principles

1. **Prove exploitability, not just vulnerability existence** — Fokus pada proof-of-concept
2. **Authorized engagement only** — SOW upload, blast radius calculation
3. **Audit trail append-only** — Semua aksi dicatat di EventStore
4. **Emergency stop** — Kill switch tunggal untuk semua agent
5. **No silent success** — Explicit result types, bukan truthiness checks

---

## Arsitektur Agent — Hybrid Python (asyncio) + Go (goroutines)

### Overview
Agent-Alpha menggunakan **hybrid architecture** — bukan framework khusus, tapi kombinasi Python dan Go dengan concurrency masing-masing.

| Komponen | Bahasa | Concurrency | Tujuan |
|----------|--------|-------------|--------|
| **Conductor** | Python | asyncio | Orchestration, authorization, cognitive loop |
| **Alpha/Beta/Gamma/Delta/Epsilon (reasoning)** | Python | asyncio | Cognitive loop, planning, decision-making |
| **Alpha/Beta/Gamma/Delta/Epsilon (execution)** | Go | goroutines | Port scan, exploit, credential spray (network-heavy) |
| **IPC** | gRPC | - | Python ↔ Go communication |
| **Orchestration** | Celery + Redis | - | Task queue, multi-tenant |

### Python (asyncio) — Reasoning, Memory, Orchestration

**Komponen Python:**
- **Conductor** — Authorization, state machine, handoff validation
- **Cognitive Loop** — OBSERVE → ORIENT → PLAN → ACT → PERSIST
- **Memory** — SessionMemory, EngagementMemory, IntelligenceBase, UserMemory
- **AttackGraph** — NetworkX (graph reasoning)
- **LLM Orchestrator** — Routing ke DeepSeek/Mimo

**Kenapa asyncio?**
- Non-blocking I/O untuk database (PostgreSQL, Redis)
- Concurrent LLM calls (DeepSeek, Mimo)
- Concurrent gRPC calls ke Go agents
- Python 3.12 native asyncio support

### Go (goroutines) — Execution (Network-Heavy)

**Komponen Go:**
- **Alpha (SCOUT)** — Port scan, subdomain enumeration, tech detection
- **Beta (STRIKE)** — Credential spray, browser automation
- **Gamma (ANCHOR)** — Exploit execution, persistence
- **Delta (HUNTER)** — Post-exploitation, lateral movement
- **Epsilon (SCOUT-HUNTER)** — Hybrid reconnaissance + lateral movement

**Kenapa Go?**
- **Goroutines 3-5x lebih cepat** dari asyncio untuk network-heavy tasks
- **Single binary deployable** — tidak perlu interpreter di compromised host
- **Stealth** — tidak ada "python script" signature
- **Low-level network control** — raw sockets, custom protocols

### IPC: gRPC (Python ↔ Go)

**gRPC Protocol:**
```protobuf
service ConductorService {
    rpc RequestAuthTransition(AuthTransitionRequest) returns (AuthTransitionResponse);
    rpc EmergencyStop(EmergencyStopRequest) returns (AuthTransitionResponse);
    rpc GetEngagementState(EngagementStateRequest) returns (EngagementStateResponse);
}
```

**Kenapa gRPC?**
- Type-safe (protobuf)
- Fast (binary protocol)
- Streaming support
- Bidirectional communication

### Orchestration: Celery + Redis

**Celery Task Queue:**
```python
@app.task
def task_recon(engagement_id: str, target: str):
    alpha = AlphaAgent()
    alpha.run_reconnaissance(target)
```

**Kenapa Celery?**
- Non-blocking — user bisa chat "status?" sambil task berjalan
- Multi-tenant — dedicated queue per engagement
- Priority queue — paid tier gets higher priority
- Rate limiting — per-tenant rate limit

---

## Kenapa Tidak Menggunakan C/C++?

### Kelebihan C/C++ (Theoretical)
- **Performance** — C/C++ lebih cepat dari Go untuk raw computation
- **Memory control** — Manual memory management (bisa lebih efisien)
- **Legacy ecosystem** — Banyak tools/security tools dalam C/C++

### Kenapa Tidak Dipilih Agent-Alpha?

| Aspek | C/C++ | Go | Keputusan |
|-------|-------|-----|-----------|
| **Concurrency** | Manual (pthreads, complex) | Goroutines (simple, 3-5x asyncio) | **Go** |
| **Memory safety** | Manual (segfault, buffer overflow) | Garbage collected (safe) | **Go** |
| **Development speed** | Lambat (manual memory, boilerplate) | Cepat (GC, simple syntax) | **Go** |
| **Deployment** | Dynamic libraries, dependency hell | Single binary, zero deps | **Go** |
| **Stealth** | Tergantung compiler | No "python script" signature | **Go** |
| **Network I/O** | Manual (epoll, kqueue) | Goroutines (built-in) | **Go** |
| **Cross-platform** | Complex (platform-specific code) | Simple (cross-compile) | **Go** |
| **Security** | Buffer overflow, memory leaks | Memory safe | **Go** |

### Alasan Utama: Go Lebih Cocok untuk Agent-Alpha

1. **Concurrency sederhana** — Goroutines vs manual pthreads di C/C++
2. **Memory safety** — Garbage collected vs manual memory management
3. **Single binary deployable** — Tidak perlu interpreter/library di compromised host
4. **Development speed** — Go lebih cepat develop daripada C/C++
5. **Network I/O built-in** — Goroutines untuk concurrent network operations
6. **Cross-platform** — Go cross-compile lebih mudah daripada C/C++

### Alasan Utama: Python Tetap Diperlukan untuk Reasoning

1. **LLM ecosystem** — Python adalah bahasa utama untuk LLM integration
2. **AI/ML libraries** — NetworkX, pgvector, PostgreSQL drivers semua Python-first
3. **Cognitive loop** — Asyncio cocok untuk non-blocking I/O (database, LLM calls)
4. **Development speed** — Python lebih cepat untuk logic/algorithm
5. **Ecosystem** — FastAPI, Celery, Redis semua Python-first

### Hybrid Architecture adalah Trade-off Optimal

- **Python** untuk reasoning, memory, orchestration (AI/ML ecosystem)
- **Go** untuk execution (network-heavy, single binary deployable)
- **Tidak C/C++** karena concurrency complexity dan memory safety risk

---

## Glossary

- **A2A**: Agent-to-Agent communication
- **RoE**: Rules of Engagement (aturan operasi)
- **SOW**: Statement of Work (dokumen scope engagement)
- **OPSEC**: Operational Security (keamanan operasional)
- **MITRE ATT&CK**: Framework teknik serangan siber
- **Celery**: Distributed task queue untuk Python
- **FastAPI**: Web framework modern untuk Python
- **gRPC**: RPC framework berbasis protobuf
- **Fernet**: Symmetric encryption untuk Python
- **Append-only**: Hanya bisa menambah, tidak bisa menghapus/mengubah
- **asyncio**: Async I/O library untuk Python
- **goroutines**: Lightweight threads di Go
- **gRPC**: RPC framework berbasis protobuf
- **NetworkX**: Graph library untuk Python

---

**Dokumen ini diperbarui terakhir:** 2026-06-22
**Phase saat ini:** Phase 2 (COMPLETED)
**Progress:** Phase 0 completed (7/7), Phase 1 completed (5/5), Phase 2 completed (12/12), C1 completed (9/9)
**Total tests:** 263 passing
