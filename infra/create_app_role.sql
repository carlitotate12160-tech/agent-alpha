-- infra/create_app_role.sql
-- =====================================================================
-- Closes the RLS-bypass vuln: the app/CI DSN was a SUPERUSER, and superusers
-- bypass Row-Level Security even with FORCE -> tenant isolation was INERT.
--
-- This creates a least-privilege runtime role and hands it ownership of the P2
-- tables, so FORCE ROW LEVEL SECURITY actually constrains it. After running
-- this, repoint AGENT_ALPHA_PG_DSN at agent_alpha_app (NOT the superuser).
--
-- RUN ONCE, as the current superuser, against the agent_alpha database:
--   psql "postgresql://agent_alpha:<superpw>@127.0.0.1:15432/agent_alpha" \
--        -v app_pw="'choose_a_strong_unique_password'" \
--        -f create_app_role.sql
--
-- Provisioning (DDL, this script, as superuser) is intentionally separate from
-- runtime (DML, as agent_alpha_app). Keep the superuser for migrations only.
-- =====================================================================

\if :{?app_pw}
\else
  \set app_pw '''CHANGE_ME_strong_unique'''
\endif

-- 1. Least-privilege runtime role (idempotent).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_alpha_app') THEN
        EXECUTE format(
            'CREATE ROLE agent_alpha_app LOGIN PASSWORD %s '
            'NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE',
            :app_pw
        );
    ELSE
        EXECUTE format('ALTER ROLE agent_alpha_app PASSWORD %s', :app_pw);
        ALTER ROLE agent_alpha_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;

-- 2. Connect + schema privileges. CREATE on schema is needed only for the
--    first-run path where the store auto-creates its tables.
GRANT CONNECT ON DATABASE agent_alpha TO agent_alpha_app;
GRANT USAGE, CREATE ON SCHEMA public TO agent_alpha_app;

-- 3. Hand ownership of existing P2 objects to the runtime role, so:
--      - FORCE ROW LEVEL SECURITY subjects it (owner is exempt UNLESS FORCE),
--      - it can still run the idempotent _ensure_schema (ALTER TABLE / CREATE
--        POLICY / CREATE OR REPLACE FUNCTION all require ownership).
ALTER TABLE IF EXISTS agent_events       OWNER TO agent_alpha_app;
ALTER TABLE IF EXISTS engagement_memory  OWNER TO agent_alpha_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'agent_alpha_events_append_only') THEN
        ALTER FUNCTION agent_alpha_events_append_only() OWNER TO agent_alpha_app;
    END IF;
END
$$;

-- 4. Prove it: this role must NOT be able to bypass RLS.
SELECT
    rolname,
    rolsuper      AS is_superuser,
    rolbypassrls  AS can_bypass_rls
FROM pg_roles
WHERE rolname = 'agent_alpha_app';
-- Expected: is_superuser = f, can_bypass_rls = f
