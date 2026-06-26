# Agent-Alpha Infra — P2 stateful backends (Track A)

Local Redis + Postgres for durable persistence (P2). Stand these up on the
Oracle box so the P2 adapters + the restart→replay integration test run against
**real** backends, not in-memory fakes.

## Bring up

```bash
cd infra
cp .env.example .env
#  edit infra/.env — set strong POSTGRES_PASSWORD and REDIS_PASSWORD
docker compose up -d
docker compose ps        # postgres + redis both "healthy"
```

## Verify

```bash
# Postgres reachable + pgvector present:
docker compose exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT extname FROM pg_extension;"
# Redis reachable (auth):
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" ping     # -> PONG
```

Connection (for the app adapters, wired next):
- Postgres: `127.0.0.1:5432`, db/user/password from `infra/.env`
- Redis:    `127.0.0.1:6379`, password from `infra/.env`

## Security

- Both ports bind to **127.0.0.1 only** — never expose to the network.
- `infra/.env` holds secrets and **must be gitignored** (add `infra/.env` to
  `.gitignore`). Only `.env.example` is committed.
- Redis requires a password (`--requirepass`); Postgres requires its password.
- Data persists in named volumes (`pgdata`, `redisdata`) so a `docker compose
  restart` keeps state — which is exactly what the P2 restart→replay test checks.

## What this is NOT

This only provisions the engines. The schema — the append-only event table, the
immutability constraint, `tenant_id` + Postgres Row-Level Security (decision
D0.3) — is created by the application's adapters/migrations (next P2 step, authored
in-repo), keeping engine provisioning separate from app-owned schema.

## Teardown

```bash
docker compose down            # keep data
docker compose down -v         # also wipe pgdata + redisdata (fresh start)
```
