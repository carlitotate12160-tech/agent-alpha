-- Runs once on first Postgres init (docker-entrypoint-initdb.d).
-- pgvector extension reserved for the Phase 6 IntelligenceBase (embeddings).
-- Harmless now; the P2 event store + engagement memory tables do not need it.
-- The application schema (event store table, append-only constraint, tenant_id
-- + Row-Level Security per decision D0.3) is created by the app's migrations,
-- NOT here — keep provisioning (engine) separate from schema (app-owned).
CREATE EXTENSION IF NOT EXISTS vector;
