# Agent-Alpha — Progress Tracker

**Ringkasan kemajuan proyek Agent-Alpha.**

---

## Status Proyek

| Phase | Status | Progress | Target |
|-------|--------|----------|--------|
| Phase 0 | ✅ COMPLETED | 7/7 komponen selesai | 7 komponen |
| Phase 1 | ✅ COMPLETED | 5/5 komponen selesai | 5 komponen |
| Phase 2 | ✅ COMPLETED | 12/12 komponen selesai | 12 komponen |
| Phase 3 | 🟦 IN PROGRESS | C1–C6a + Cred-Reuse Chain + Applicator Seam + CI Hardening + DB Chain Field-Proven + FP-Validation PASS done | C1–C8 |
| Phase 4 | ⬜ NOT STARTED | 0% | - |
| Phase 5 | ⬜ NOT STARTED | 0% | - |
| Phase 6 | ⬜ NOT STARTED | 0% | - |

---

> **Phase 3 Contract:** Lihat `docs/PHASE_3_TEST_CONTRACT.md` untuk authoritative step list (C1–C8). Status: C1, C2, C3, C4, C5, C6a GREEN on Oracle. Cred-Reuse Chain live-fire CHAIN PROVEN on Oracle. CredentialApplicator seam extracted (PR #63). CI hardened dengan 7 gate (PR #64, #65). DB Chain field-proven CHAIN PROVEN on Oracle ARM64 lawan real MySQL 8.4 (commit `73203b6`). Credential-pairing fix + safety guard landed. **FP-Validation RUN: TP=3, FP=0, FN=0, TN=3, PASS (FP rate 0.0000 < 0.2000)** on Oracle ARM64 dengan 6 DuckDNS lab targets. Next: C6b (fan-out execution), C7 (no regression + CI), C8 (anti-Lyndon gates).

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
- **EngagementMemory** — Event-sourced projection untuk post-engagement learning/audit (dengan time_to_first_proof_s dan time_to_first_exploit_s metrics)
- **SessionMemory** — Volatile Redis-backed store untuk live state engagement
- **IntelligenceBase** — Cross-engagement learning queries (tool reliability, FP rates, strategies)

### Phase 2 — Cognitive Loop & Agent Implementation (12/12 selesai)
- **DeepSeekProvider** — LLM provider untuk reasoning/payload generation
- **PlaybookEngine** — Deterministic RULE tier decision engine dari YAML playbooks
- **LLMOrchestrator** — Routing ke RULE/SINGLE_LLM/CONSENSUS decision ladder
- **ToolRegistry** — Registry untuk tool yang tersedia
- **BoundedAutonomy + run_cognitive_loop** — Cognitive loop dengan stop conditions
- **Alpha SCOUT** — Reconnaissance agent pertama
- **Omega ROASTER** — Report generation agent (dengan time-to-proof headline di PDF)
- **HttpClient** — Production httpx-backed HTTP client
- **Inner Monologue** — Real-time reasoning stream ke USER channel
- **RLS Guard** — Fail-closed guard untuk Postgres RLS enforcement
- **create_app_role.sql** — SQL script untuk least-privilege role
- **RLS Isolation Tests** — Integration tests dengan raw SQL verification
- **Python 3.12 + Dependencies** — Upgrade Python dan tambah pytest/protobuf

### Phase 3 — Orchestrator Hardening + Cred-Reuse Chain + CI Hardening + DB Chain Field-Proven (C1–C6a + Chain + Seam + CI + DB Field-Prove done)
- **C1** — Event-sourced auth state reconstruction (Oracle-green)
- **C2** — Emergency revoker ≤5s (Oracle-green)
- **C3** — Fan-out interface (Oracle-green)
- **C4** — Real emergency revoker (Oracle-green)
- **C5** — Async kill chain Shape B + SSRF guard (Oracle-green)
- **C6a** — Phase 0 test stubs (Oracle-green)
- **Cred-Reuse Chain** — Alpha harvest+vault → Beta cred_reuse → access → ENABLES edge (CHAIN PROVEN on Oracle, PR #57)
- **Header Case Fix** — Normalize HttpClient response headers to lowercase (PR #58, bug fix)
- **CredentialApplicator Seam** — Extract HTTP form login dari cred_reuse.run ke HttpFormApplicator (PR #63)
- **CI: Coverage + Audit** — pytest-cov 80% threshold + pip-audit + fix make test target (PR #64)
- **CI: SAST + Lint + Random** — bandit SAST + T20 no-print + C90 complexity + pytest-randomly (PR #65)
- **Credential Pairing Fix** — Alpha assemble satu paired login node dari DB_USERNAME + DB_PASSWORD yang co-located (commit `9bc848d`, additive variant)
- **Safety Guard (anti-#10)** — MySqlApplicator refuse empty-username DB auth, zero auth packet ke wire (commit `2651e6b`)
- **DB Chain Field-Prove** — CHAIN PROVEN: True, db_root, critical — lawan real MySQL 8.4 di Oracle ARM64 (commit `73203b6`)
- **Mock Laravel Debug Page** — HTTP server mock untuk field-prove (commit `b380413`)
- **FP-Validation Run** — Live-fire FP-validation dengan 6 lab targets (3 vuln + 3 hardened) via DuckDNS + Caddy HTTPS. Scorecard: TP=3, FP=0, FN=0, TN=3, FP rate=0.0000, Verdict=PASS (commit `3b025c4`)
- **Campaign Vector Scope Fix** — `_handle_wp_config_probe` dan `_handle_js_secret_probe` hanya scan current target host (`urlparse(url).hostname`), bukan semua scope hosts. Hapus `_get_scope_hosts()`. Mencegah cross-contamination FP (commit sebelumnya)
- **Playbook Priority Field** — Tambah `priority` field ke `PlaybookRule` (lower=checked first). `laravel_debug` = priority 10, lainnya default 100. Fix FN: Laravel debug page (1.1MB) mengandung `<div id="app">` yang match `js_secret` playbook sebelum `laravel_debug` (alphabetical sort j < l) (commit `3b025c4`)
- **Caddyfile.fp** — Caddy reverse proxy dengan DuckDNS DNS-01 ACME untuk 6 lab subdomains. WP proxy ke HTTPS upstream nginx:8443 dengan `tls_insecure_skip_verify`
- **Engagement YAML** — `fp_validation_engagement.yaml` dengan 6 DuckDNS targets, Laravel vuln+hardened pakai `/trigger-error` untuk TN yang bermakna
- **Lab Guard Allowlist** — 6 DuckDNS subdomains ditambahkan ke `LAB_TARGET_ALLOWLIST` di `lab_guard.py`
- **Graph Quality: T1552.001 on credential edges** — `credential_assembly.py` dan `js_secret_probe.py` LEADS_TO edges sekarang carry `technique_id="T1552.001"` (Unsecured Credentials in Files). Omega report menampilkan T1552.001 + T1592.002 (commit `127269f`)
- **Graph Quality: Asset nodes for WP/JS** — `wp_config_probe.py` dan `js_secret_probe.py` sekarang persist ASSET node + EXPLOITS edge (asset→vuln), mirroring `_handle_laravel_debug`. Graph coherent: 3 asset nodes, 3 exploits edges, chain-finding bisa mulai (commit `127269f`)
- **Scope.validate() fix** — Allow `ip_ranges=[]` ketika `domains` terisi. Domain-only engagement (DuckDNS lab) valid tanpa hardcode IP (commit `9558d78`)
- **Graph Quality FROZEN test contract** — 5 tests di `test_alpha_graph_quality.py`: T1552.001 on WP/JS credential edges, Omega report surfaces T1552.001, asset node + asset→vuln edge for WP/JS (commit `9558d78`)
- **C6b** — Per-unit fan-out execution + live-fire FP<20% (PENDING)
- **C7** — No regression + CI (PENDING)
- **C8** — Anti-Lyndon gates (PENDING)

### Phase 3 Additional Components
- **ADR §12.16: Tool Layer Contracts** — Template protocol untuk build/verify methods (MERGED)
- **RateLimiter + HttpClient RoE Enforcement** — Rate limiting dan RoE enforcement (MERGED)
- **Laravel Finding Template** — Template untuk Laravel debug exposure detection (MERGED)
- **Laravel Template Wiring** — Integration template ke scout.py dengan Laravel-specific redaction (MERGED)
- **CredReuseTool** — Tool untuk reuse vaulted credentials dari Alpha recon (MERGED, PR #55)
- **Alpha Vaulting** — Alpha harvest leaked credentials → SecretsManager vault (MERGED, PR #55)
- **Beta Ranked Tool Selection** — Beta memilih CredReuseTool/DefaultCredsTool via applies_to() ranking (MERGED, PR #55)
- **Chain Runner** — Single-process Alpha→Beta chain live-fire runner dengan shared SecretsManager (MERGED, PR #57)
- **Chain Edge Verification** — Test memastikan ENABLES edge berasal dari Alpha's vaulted credential, bukan Beta-minted default (MERGED, PR #57)
- **Header Case Normalization** — Fix HttpClient response headers ke lowercase untuk match real httpx behavior (MERGED, PR #58)
- **CredentialApplicator Seam** — Protocol + HttpFormApplicator + select_applicator() untuk service-agnostic credential application (MERGED, PR #63)
- **CI Coverage Gate** — pytest-cov dengan 80% threshold, coverage 84% (MERGED, PR #64)
- **CI Dependency Audit** — pip-audit untuk CVE check pada installed packages (MERGED, PR #64)
- **CI SAST Scan** — bandit -ll -ii untuk security scan medium+ severity (MERGED, PR #65)
- **CI T20 No-Print** — ruff T20 mencegah print() di production code, live_fire CLI exempt (MERGED, PR #65)
- **CI C90 Complexity** — ruff mccabe max-complexity=20 untuk gate god-function (MERGED, PR #65)
- **CI Random Test Order** — pytest-randomly untuk tangkap test order-dependency bug (MERGED, PR #65)
- **Credential Pairing Fix** — Alpha assemble paired login node dari co-located DB_USERNAME + DB_PASSWORD; DB_USERNAME tidak di-emit standalone (anti-#3); DB_PASSWORD tetap standalone untuk web chain compat (MERGED, commit `9bc848d`)
- **Safety Guard (anti-#10)** — MySqlApplicator.apply() refuse empty-username sebelum connect(); _SpyConnector membuktikan zero wire packet (MERGED, commit `2651e6b`)
- **DB Chain Field-Prove** — Real MySQL 8.4 di Docker Oracle ARM64; mock Laravel debug page leak DB_USERNAME+DB_PASSWORD; CHAIN PROVEN: True, db_root, critical (MERGED, commit `73203b6`)
- **Mock Laravel Debug Page** — HTTP server mock yang serve /trigger-error (leak env vars) + /login untuk field-prove (MERGED, commit `b380413`)
- **Time-to-Proof Metrics (Phase 1)** — EngagementMemoryRecord dengan time_to_first_proof_s dan time_to_first_exploit_s; _build_record track first timestamps dari ENGAGEMENT_CREATED, PROOF_ARTIFACT_RECORDED, EXPLOIT_CONFIRMED (MERGED, commit `ae43d8a`)
- **Time-to-Proof Headline (Phase 2)** — Omega Report dengan format_duration formatter, time_to_proof_headline method, dan PDF headline section (MERGED, commit `19836ed`)
- **FP-Validation Run** — Live-fire validation dengan 6 lab targets (WP vuln/hardened, Laravel vuln/hardened, SPA vuln/hardened) via DuckDNS + Caddy HTTPS reverse proxy. Scorecard: TP=3, FP=0, FN=0, TN=3, FP rate=0.0000, Verdict=PASS (commit `3b025c4`)
- **Campaign Vector Scope Fix** — scout.py: `_handle_wp_config_probe` dan `_handle_js_secret_probe` hanya scan `[urlparse(url).hostname]` (current target), bukan `_get_scope_hosts()` (all scope). Mencegah hardened target dapat finding dari vulnerable sibling (cross-contamination FP)
- **Playbook Priority Field** — `PlaybookRule.priority` (lower=first). `laravel_debug.yaml` priority=10. Fix FN: Laravel debug page berisi `<div id="app">` yang match `js_secret` playbook (alphabetical j < l) sebelum `laravel_debug` bisa match (commit `3b025c4`)
- **Caddyfile.fp (HTTPS Proxy)** — Caddy dengan DuckDNS DNS-01 ACME plugin untuk 6 subdomains. WP reverse proxy ke nginx:8443 HTTPS dengan `tls_insecure_skip_verify`. SPA serve static files. Laravel reverse proxy ke HTTP backend
- **Lab Guard DuckDNS Allowlist** — 6 DuckDNS subdomains (wp-vuln, wp-hardened, spa-vuln, spa-hardened, laravel-vuln, laravel-hardened `.agentalpha.duckdns.org`) ditambahkan ke `LAB_TARGET_ALLOWLIST`

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

### CredentialApplicator Seam (`agent_alpha/tools/internal/access/applicator.py`)
**Bahasa sederhana:** Ini adalah "colokan universal" untuk pakai kredensial ke berbagai jenis service.

Bayangkan cred_reuse.run sebelumnya seperti orang yang hanya tahu cara login ke website (HTTP form). Kalau mau login ke database (MySQL), harus nambah kode baru di tempat yang sama — bikin function jadi rumit dan gede (god-function).

CredentialApplicator memisahkan "kredensial mana yang mau dipakai" (tugas cred_reuse) dari "cara pakai kredensial ke service tertentu" (tugas applicator). Jadi:
- `HttpFormApplicator` — tahu cara login ke website (POST username+password)
- Nanti `MySqlApplicator` — tahu cara login ke database
- `select_applicator()` — milih applicator yang cocok berdasarkan jenis service

`AuthResult` menyimpan hasil login tanpa menyimpan password asli (anti-leak).

### CI Quality Gates (7 total)
**Bahasa sederhana:** Ini adalah "penjaga gerbang" sebelum kode boleh masuk ke main branch.

| Gate | Bahasa sederhana |
|---|---|
| **ruff check** | Cek kode tidak ada typo, import yang nggak dipakai, `print()` yang nyangkut di production, dan function yang terlalu rumit (god-function) |
| **ruff format** | Cek indentasi dan style konsisten |
| **mypy strict** | Cek tipe data benar (misal: tidak kirim string ke function yang butuh integer) |
| **pip-audit** | Cek apakah dependency (library pihak ketiga) punya celah keamanan (CVE) |
| **bandit** | Scan kode untuk pola berbahaya (hardcoded password, SQL injection, weak crypto) |
| **pytest --cov** | Jalankan semua test + cek minimal 80% kode tercakup test |
| **GitGuardian** | Scan apakah ada secret (password, API key) yang tidak sengaja di-commit |

**pytest-randomly**: Test dijalankan dengan urutan acak setiap kali — kalau ada test yang hanya pass karena "kebetulan urutannya pas", akan ketahuan.

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
- Phase 3: Laravel template, Laravel redaction, Template wiring, CredReuseTool, Alpha vaulting, Beta ranked tool selection, Chain runner, Header case fix

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
- Phase 3 tests (43+ test) — uji CredReuseTool, Alpha vaulting, Beta strike, chain runner, default creds, session token redaction, credential pairing (7 test), mysql safety guard (1 test), alpha vector dispatch (9 test), playbook vector reachability (4 test)
- Total: 587 passed, 23 skipped (random order, coverage 84%)

### Aturan Penting (Rule 10)
Semua test **HARUS** dijalankan di Oracle ARM64 (server remote), bukan di Windows lokal.

### Command Verifikasi
```bash
# Di Oracle ARM64:
ssh -i "<path-to-ssh-key>" ubuntu@<oracle-arm-host>
cd ~/agent-alpha
git pull origin main
.venv/bin/pip install -e .
.venv/bin/pip install pytest-cov pytest-randomly bandit

# Full regression + coverage
.venv/bin/pytest tests/ -q --cov=agent_alpha --cov-fail-under=80

# Lint + typecheck
make check

# SAST security scan
.venv/bin/bandit -r agent_alpha/ -ll -ii -x agent_alpha/a2a

# Live-fire chain runner
.venv/bin/python3 -m agent_alpha.live_fire.chain_runner engagements/chain_lab.yaml
```

**CI gates (7 total):**
- `ruff check` — linting + T20 no-print + C90 complexity
- `ruff format --check` — style consistency
- `mypy strict` — type safety
- `pip-audit` — dependency CVE check
- `bandit -ll -ii` — SAST security scan (medium+ fail)
- `pytest --cov` — tests + coverage 80% threshold
- `GitGuardian` — secret scanning

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

**Dokumen ini diperbarui terakhir:** 2026-07-04
**Phase saat ini:** Phase 3 (IN PROGRESS — FP-Validation PASS + DB Chain Field-Proven + Credential Pairing + Safety Guard + CI 7-gate + Time-to-Proof Metrics)
**Progress:** Phase 0 completed (7/7), Phase 1 completed (5/5), Phase 2 completed (12/12), Phase 3 C1–C6a + Cred-Reuse Chain + Applicator Seam + CI Hardening + DB Chain Field-Proven + Time-to-Proof Metrics + FP-Validation PASS done
**Total tests:** 587 passed, 23 skipped (random order, coverage 84%)
**Field-Prove:** DB Chain CHAIN PROVEN: True (db_root, critical) lawan real MySQL 8.4 di Oracle ARM64
**FP-Validation:** TP=3, FP=0, FN=0, TN=3, FP rate=0.0000, Verdict=PASS — 6 lab targets (WP/Laravel/SPA × vuln/hardened) via DuckDNS + Caddy HTTPS di Oracle ARM64. MITRE: T1552.001 + T1592.002. Graph: 3 asset nodes, 3 vuln nodes, 3 credential nodes, 3 EXPLOITS edges, 3 LEADS_TO edges
**Time-to-Proof:** EngagementMemory metrics (time_to_first_proof_s, time_to_first_exploit_s) + Omega PDF headline (format_duration) implemented
