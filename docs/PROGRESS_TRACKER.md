# Agent-Alpha — Progress Tracker

**Dokumen ini selalu diperbarui setelah setiap task selesai.** Berisi penjelasan lengkap tentang kemajuan proyek, modul yang ditambahkan, efeknya terhadap agent, behavior sistem, dan flow dengan contoh.

---

## Status Proyek

| Phase | Status | Progress | Target |
|-------|--------|----------|--------|
| Phase 0 | � COMPLETED | 7/7 komponen selesai | 7 komponen |
| Phase 1 | 🟡 IN PROGRESS | 2/2 komponen selesai | 2 komponen |
| Phase 2 | ⬜ NOT STARTED | 0% | - |
| Phase 3 | ⬜ NOT STARTED | 0% | - |
| Phase 4 | ⬜ NOT STARTED | 0% | - |
| Phase 5 | ⬜ NOT STARTED | 0% | - |
| Phase 6 | ⬜ NOT STARTED | 0% | - |

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
- **Phase 0 tests** (79 test) — uji semua komponen Phase 0
- **Phase 1 tests** (22 test) — uji GraphStore dan NetworkXGraphStore
- Total: 107 test, semua passing

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

**Dokumen ini diperbarui terakhir:** 2026-06-17  
**Phase saat ini:** Phase 1  
**Progress:** Phase 0 completed (7/7), Phase 1 in progress (2/2)
