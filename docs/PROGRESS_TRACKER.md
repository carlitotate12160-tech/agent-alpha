# Agent-Alpha — Progress Tracker

**Ringkasan kemajuan proyek Agent-Alpha.**

---

## Status Proyek

| Phase | Status | Progress | Target |
|-------|--------|----------|--------|
| Phase 0 | ✅ COMPLETED | 7/7 komponen selesai | 7 komponen |
| Phase 1 | ✅ COMPLETED | 5/5 komponen selesai | 5 komponen |
| Phase 2 | ✅ COMPLETED | 12/12 komponen selesai | 12 komponen |
| Phase 3 | 🟦 IN PROGRESS | C1–C6a of C1–C8 done (Oracle-green) | C1–C8 |
| Phase 4 | ⬜ NOT STARTED | 0% | - |
| Phase 5 | ⬜ NOT STARTED | 0% | - |
| Phase 6 | ⬜ NOT STARTED | 0% | - |

---

> **Phase 3 Contract:** Lihat `docs/PHASE_3_TEST_CONTRACT.md` untuk authoritative step list (C1–C8). Status: C1, C2, C3, C4, C5, C6a GREEN on Oracle. Next: C6b (fan-out execution + live-fire FP<20%).

---

## Ringkasan Komponen per Phase

### Phase 0 — Fondasi Sistem (7/7 selesai)
- **A2A Contract** — Protokol gRPC/protobuf untuk komunikasi antar agent
- **Authorization State Machine** — State machine untuk otorisasi engagement (CREATED → RECON_ONLY → ACTIVE_APPROVED → OFFENSIVE_APPROVED → EMERGENCY_STOP)
- **Event Store** — Audit trail append-only untuk semua aksi agent
- **Secrets Vault** — Penyimpanan kredensial terenkripsi dengan Fernet
- **Policy Enforcer** — Enforcement Rules of Engagement dari policy.yaml
- **Emergency Stop** — Kill switch tunggal untuk menghentikan semua agent
- **Conductor Skeleton** — FastAPI + Celery app untuk task execution

### Phase 1 — Attack Graph & Knowledge Representation (5/5 selesai)
- **GraphStore Protocol** — Interface abstrak untuk graph engine (NetworkX → Memgraph/Neo4j)
- **NetworkXGraphStore** — Implementasi NetworkX untuk attack graph
- **EngagementMemory** — Event-sourced projection untuk post-engagement learning/audit
- **SessionMemory** — Volatile Redis-backed store untuk live state engagement
- **IntelligenceBase** — Cross-engagement learning queries (tool reliability, FP rates, strategies)

### Phase 2 — Cognitive Loop & Agent Implementation (12/12 selesai)
- **DeepSeekProvider** — LLM provider untuk reasoning/payload generation
- **PlaybookEngine** — Deterministic RULE tier decision engine dari YAML playbooks
- **LLMOrchestrator** — Routing ke RULE/SINGLE_LLM/CONSENSUS decision ladder
- **ToolRegistry** — Registry untuk tool yang tersedia
- **BoundedAutonomy + run_cognitive_loop** — Cognitive loop dengan stop conditions
- **Alpha SCOUT** — Reconnaissance agent pertama
- **Omega ROASTER** — Report generation agent
- **HttpClient** — Production httpx-backed HTTP client
- **Inner Monologue** — Real-time reasoning stream ke USER channel
- **RLS Guard** — Fail-closed guard untuk Postgres RLS enforcement
- **create_app_role.sql** — SQL script untuk least-privilege role
- **RLS Isolation Tests** — Integration tests dengan raw SQL verification
- **Python 3.12 + Dependencies** — Upgrade Python dan tambah pytest/protobuf

### Phase 3 — Orchestrator Hardening (C1–C6a selesai)
- **C1** — Event-sourced auth state reconstruction (Oracle-green)
- **C2** — Emergency revoker ≤5s (Oracle-green)
- **C3** — Fan-out interface (Oracle-green)
- **C4** — Real emergency revoker (Oracle-green)
- **C5** — Async kill chain Shape B + SSRF guard (Oracle-green)
- **C6a** — Phase 0 test stubs (Oracle-green)
- **C6b** — Per-unit fan-out execution + live-fire FP<20% (PENDING)
- **C7** — No regression + CI (PENDING)
- **C8** — Anti-Lyndon gates (PENDING)

### Phase 3 Additional Components
- **ADR §12.16: Tool Layer Contracts** — Template protocol untuk build/verify methods (MERGED)
- **RateLimiter + HttpClient RoE Enforcement** — Rate limiting dan RoE enforcement (MERGED)
- **Laravel Finding Template** — Template untuk Laravel debug exposure detection (MERGED)
- **Laravel Template Wiring** — Integration template ke scout.py dengan Laravel-specific redaction (MERGED)

---

## Detail Komponen Penting

### A2A Contract (`proto/a2a.proto`)
Protokol gRPC/protobuf untuk komunikasi antar agent. Semua agent (Alpha, Beta, Gamma, Delta, Epsilon, Omega) berkomunikasi lewat schema ini untuk memastikan konsistensi data.

### Authorization State Machine (`agent_alpha/conductor/authorization.py`)
Mesin state untuk otorisasi engagement. State transitions: CREATED → RECON_ONLY → ACTIVE_APPROVED → OFFENSIVE_APPROVED → EMERGENCY_STOP. Hanya Conductor yang boleh baca/tulis state ini.

### Event Store (`agent_alpha/events/store.py`)
Penyimpanan event append-only untuk audit trail. Setiap aksi agent dicatat sebagai event yang tidak bisa dihapus atau dimodifikasi. Event menjadi single source of truth.

### Secrets Vault (`agent_alpha/security/secrets.py`)
Penyimpanan kredensial terenkripsi dengan Fernet. Kredensial tidak pernah muncul di plaintext di log/event. LogScrubber otomatis menghapus sensitive data dari log.

### Policy Enforcer (`agent_alpha/conductor/policy.py`)
Enforcement Rules of Engagement dari policy.yaml. Mencegah agent melakukan teknik yang dilarang, menyerang network yang di-exclude, atau menggunakan LLM provider yang dilarang.

### Emergency Stop (`agent_alpha/conductor/emergency.py`)
Kill switch tunggal untuk menghentikan semua agent. Force state ke EMERGENCY_STOP dan revoke semua Celery tasks. Best-effort implementation (tidak pernah raise exception).

### GraphStore Protocol (`agent_alpha/graph/store.py`)
Interface abstrak untuk graph engine. Memungkinkan swapping NetworkX → Memgraph/Neo4j tanpa mengubah consumer code. Event-sourced: graph adalah projection dari event log.

### NetworkXGraphStore (`agent_alpha/graph/networkx_store.py`)
Implementasi NetworkX untuk attack graph. Directed graph untuk relationship yang berarah. Event handlers untuk NodeDiscovered, EdgeDiscovered, NodeVerified.

### EngagementMemory (`agent_alpha/memory/engagement.py`)
Event-sourced projection untuk post-engagement learning/audit. EngagementMemoryRecord frozen (immutable). Source of truth adalah event log, bukan EngagementMemory.

### SessionMemory (`agent_alpha/memory/session.py`)
Volatile Redis-backed store untuk live state engagement. SessionRecord mutable untuk high-frequency write path. Source of truth adalah dirinya sendiri selama engagement berjalan.

### IntelligenceBase (`agent_alpha/memory/intelligence.py`)
Cross-engagement learning queries. Methods: what_worked_for_similar_targets, credential_patterns, false_positive_rate, tool_reliability. Phase 1: return InsufficientData (belum ada data cross-engagement).

### DeepSeekProvider (`agent_alpha/llm/providers/deepseek.py`)
LLM provider untuk DeepSeek API. Menyediakan interface untuk inference dengan cost tracking dan error handling. Timeout 30.0 detik untuk semua HTTP requests.

### PlaybookEngine (`agent_alpha/tools/playbook.py`)
Deterministic RULE tier decision engine. Membaca YAML playbooks dan mengembalikan tool decision tanpa LLM. Indicators: body_contains, body_regex.

### LLMOrchestrator (`agent_alpha/llm/orchestrator.py`)
Orchestrator untuk LLM decision routing. Decision ladder: RULE → SINGLE_LLM → CONSENSUS. Cost optimization (RULE tier gratis, SINGLE_LLM murah, CONSENSUS mahal).

### Alpha SCOUT (`agent_alpha/agents/alpha/scout.py`)
Reconnaissance agent pertama. Melakukan reconnaissance (port scan, subdomain enumeration, tech detection) dan menulis findings ke AttackGraph dan EventStore. Handoff ke Beta setelah selesai.

### Laravel Finding Template (`agent_alpha/tools/templates/cms/laravel_finding.py`)
Template untuk Laravel debug exposure detection. RECON_ONLY probing dengan proof-based verification. Laravel-specific redaction untuk APP_KEY dan env keys.

### Laravel Env Redaction (`agent_alpha/security/laravel_env.py`)
Single source of truth untuk parsing + redacting Laravel debug-page env leaks. Regex untuk <td>KEY</td><td>VALUE</td> table form.

---

## Flow Sistem Lengkap

### Normal Operation Flow
1. Engagement dibuat → state: CREATED
2. Conductor enable RECON_ONLY → state: RECON_ONLY
3. Alpha SCOUT panggil can_agent_proceed(ALPHA) → True
4. Alpha melakukan reconnaissance dengan cognitive loop
5. Alpha selesai, kirim handoff ke Conductor
6. Conductor validasi dengan PolicyEnforcer
7. Conductor emit event ke EventStore
8. Conductor enable ACTIVE_APPROVED → state: ACTIVE_APPROVED
9. Beta STRIKE panggil can_agent_proceed(BETA) → True
10. Beta melakukan exploit
11. Engagement selesai → state: EMERGENCY_STOP (cleanup)

### Emergency Stop Flow
1. Engagement berjalan → state: OFFENSIVE_APPROVED
2. Operator trigger emergency stop
3. EmergencyStopHandler.execute(): force state ke EMERGENCY_STOP, revoke tasks, emit event
4. Semua agent diblokir
5. Audit trail lengkap di EventStore

---

## Testing Strategy

### Unit Tests
- Phase 0: Authorization, EventStore, SecretsVault, PolicyEnforcer, EmergencyStop
- Phase 1: GraphStore, EngagementMemory, SessionMemory, IntelligenceBase
- Phase 2: DeepSeekProvider, PlaybookEngine, LLMOrchestrator, Alpha SCOUT
- Phase 3: Laravel template, Laravel redaction, Template wiring

### Integration Tests
- Redis SessionStore (skip jika Redis tidak tersedia)
- PostgreSQL EngagementMemory (skip jika PG tidak tersedia)
- PostgreSQL EventStore (skip jika PG tidak tersedia)
- RLS Guard (raw SQL verification)

### Oracle ARM64 Testing
- Full test suite dijalankan di Oracle ARM64 untuk final validation
- Phase 3 contract (C1–C8) harus GREEN di Oracle sebelum merge

---

## Next Steps

### Phase 3 Remaining
- **C6b** — Per-unit fan-out execution + live-fire FP<20%
- **C7** — No regression + CI
- **C8** — Anti-Lyndon gates

### Future Phases
- **Phase 4** — Beta STRKE, Gamma ANCHOR, Delta PERSIST, Epsilon CLEAN
- **Phase 5** — Multi-engagement orchestration
- **Phase 6** — IntelligenceBase dengan pgvector untuk embeddings

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
