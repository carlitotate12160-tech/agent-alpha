#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export AGENT_ALPHA_JWT_SECRET=agent-alpha-jwt-secret-2026-secure-32chars-min
export AGENT_ALPHA_REDIS_URL='redis://:natanael12160@127.0.0.1:6379/0'
export AGENT_ALPHA_PG_DSN='postgresql://agent_alpha:natanael12160@127.0.0.1:5432/agent_alpha'
export AGENT_ALPHA_VAULT_KEY='eQXmkGZCFioJt-us7idUkfw7ZayZzUdWX14iYPDGvuU='
BASE="http://127.0.0.1:8080"

TOKEN=$(.venv312/bin/python3 /tmp/gen_jwt.py)
echo "JWT: ${TOKEN:0:20}..."

# laravel-vuln.agentalpha.duckdns.org resolves to 168.110.192.62 (public IP)
# Caddy proxies it to 127.0.0.1:9081 (Laravel vuln container)

echo ""
echo "=== 1. Create engagement (DuckDNS lab target) ==="
RESP=$(curl -s -X POST "$BASE/engagements" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"client_id": "lab_api_test", "target": "laravel-vuln.agentalpha.duckdns.org"}')
echo "$RESP"
ENG_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['engagement_id'])")
echo "Engagement ID: $ENG_ID"

echo ""
echo "=== 2. Enable recon ==="
curl -s -X POST "$BASE/engagements/$ENG_ID/recon" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ip_ranges": ["168.110.192.62/32"], "domains": ["laravel-vuln.agentalpha.duckdns.org"], "exclusions": []}'
echo ""

echo ""
echo "=== 3. Enable active ==="
.venv312/bin/python3 -c "
from agent_alpha.config.stores import StoreProvider
from agent_alpha.conductor.authorization import AuthorizationStateMachine
store = StoreProvider().for_tenant('tenant_lab')
auth = AuthorizationStateMachine(event_store=store)
auth.enable_active('$ENG_ID')
record = auth.get_record('$ENG_ID')
print(f'State: {record.state} (ACTIVE_APPROVED=2)')
"

echo ""
echo "=== 4. Dispatch run ==="
curl -s -X POST "$BASE/engagements/$ENG_ID/run" \
  -H "Authorization: Bearer $TOKEN"
echo ""

echo ""
echo "=== 5. Wait 30s for Alpha+Beta+Omega ==="
sleep 30

echo "=== 6. Status ==="
curl -s "$BASE/engagements/$ENG_ID/run-status" \
  -H "Authorization: Bearer $TOKEN"
echo ""

echo ""
echo "=== 7. Trace ==="
curl -s "$BASE/engagements/$ENG_ID/trace" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>&1 | head -80
echo ""

echo ""
echo "=== 8. Celery log (last 40) ==="
tail -40 /tmp/celery.log
echo ""
echo "Engagement ID: $ENG_ID"
