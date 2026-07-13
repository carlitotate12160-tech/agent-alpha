#!/usr/bin/env bash
# Quantum Laboratoris deployment script — Oracle ARM64.
# Usage: ./deploy_quantum.sh
#
# Prerequisites:
#   - Docker + docker compose installed on Oracle
#   - .env created (DEEPSEEK_API_KEY, AGENT_ALPHA_PG_DSN, REDIS_URL)
#   - infra/.env created from infra/.env.example with strong passwords
#   - Python 3.12 venv at .venv312/

set -euo pipefail

echo "=== Agent-Alpha — Quantum Laboratoris Deployment (Oracle ARM64) ==="

# 1. Start infra (PostgreSQL + Redis)
echo -e "\n[1/4] Starting infra (PostgreSQL + Redis)..."
docker compose -f infra/docker-compose.yml --env-file infra/.env up -d
sleep 5

# Verify containers
PG_STATUS=$(docker inspect --format='{{.State.Health.Status}}' agent-alpha-infra-postgres-1 2>/dev/null || echo "starting")
REDIS_STATUS=$(docker inspect --format='{{.State.Health.Status}}' agent-alpha-infra-redis-1 2>/dev/null || echo "starting")
if [ "$PG_STATUS" != "healthy" ]; then
    echo "  Waiting for PostgreSQL..."
    sleep 10
    PG_STATUS=$(docker inspect --format='{{.State.Health.Status}}' agent-alpha-infra-postgres-1 2>/dev/null || echo "unknown")
fi
echo "  PostgreSQL: $PG_STATUS"
echo "  Redis:      $REDIS_STATUS"

# 2. Load environment variables
echo -e "\n[2/4] Loading environment..."
if [ -f .env ]; then
    set -a
    source .env
    set +a
    echo "  DEEPSEEK_API_KEY = (set)"
    echo "  AGENT_ALPHA_PG_DSN = (set)"
    echo "  REDIS_URL = (set)"
else
    echo "  .env not found — create it from .env.example"
    exit 1
fi

# 3. Database schema
echo -e "\n[3/4] Database schema..."
echo "  Schema is applied by app adapters on first connect (no manual migration needed)"

# 4. Start Conductor API
echo -e "\n[4/4] Starting Conductor API (FastAPI)..."
echo "  API:  http://127.0.0.1:8000"
echo "  Docs: http://127.0.0.1:8000/docs"
echo ""
echo "=== Quantum Laboratoris Engagement Flow ==="
echo "  1. POST /engagements   {client_id: 'client_quantum_labs', target: 'quantum-laboratories.com'}"
echo "  2. POST /{id}/recon     {ip_ranges: [...], domains: ['quantum-laboratories.com'], exclusions: []}"
echo "  3. POST /{id}/sow       (upload SOW PDF)"
echo "  4. POST /{id}/run       (start Alpha -> Beta -> Omega)"
echo ""
echo "  Engagement config: engagements/quantum_laboratories.yaml"
echo ""

# Start uvicorn
export PYTHONPATH="."
exec .venv312/bin/python3 -m uvicorn agent_alpha.conductor.main:app --host 127.0.0.1 --port 8000
