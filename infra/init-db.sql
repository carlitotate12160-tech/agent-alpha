-- Runs once on first Postgres init (docker-entrypoint-initdb.d).
-- pgvector extension reserved for the Phase 6 IntelligenceBase (embeddings).
-- Harmless now; the P2 event store + engagement memory tables do not need it.
-- The application schema (event store table, append-only constraint, tenant_id
-- + Row-Level Security per decision D0.3) is created by the app's migrations,
-- NOT here — keep provisioning (engine) separate from schema (app-owned).
CREATE EXTENSION IF NOT EXISTS vector;
-- Create least-privilege role for the application (NOSUPERUSER NOBYPASSRLS)
-- This ensures Row-Level Security is enforced at the database level.
-- The default POSTGRES_USER is a superuser and bypasses RLS even with FORCE.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_alpha_app') THEN
    CREATE ROLE agent_alpha_app WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE LOGIN PASSWORD 'natanael12160';
    GRANT CONNECT ON DATABASE agent_alpha TO agent_alpha_app;
    GRANT ALL ON SCHEMA public TO agent_alpha_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO agent_alpha_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO agent_alpha_app;
  END IF;
END $$;
