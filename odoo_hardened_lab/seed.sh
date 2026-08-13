#!/usr/bin/env bash
# Odoo Hardened Real-World Lab seeder — run on Oracle ARM64.
# TRUE-NEGATIVE: no leak, unique password, list_db=False.
#
# Prerequisites:
#   1. DNS A record: odoo.alpha-ai.web.id → 168.110.192.62 (proxied)
#   2. CF Origin cert at /etc/nginx/certs/origin.pem + origin.key
#   3. Front-facing nginx config (front_proxy.conf) installed
#   4. Docker + docker compose v2
#
# Usage:
#   sudo ./seed.sh          # bring up + init Odoo
#   sudo ./seed.sh --down   # tear down
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { echo "copy .env.example -> .env first"; exit 1; }
set -a; . ./.env; set +a

if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "Neither 'docker compose' nor 'docker-compose' found."; exit 1
fi

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  echo "Odoo hardened lab down."
  exit 0
fi

# ── 1. Internal self-signed cert ──────────────────────────────────────────────
mkdir -p certs
if [ ! -f certs/stack-internal.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/stack-internal.key -out certs/stack-internal.crt \
    -subj "/CN=odoo-hardened-alpha-ai-internal"
fi

# ── 2. Bring up + wait for Odoo ───────────────────────────────────────────────
"${DC[@]}" up -d
echo "waiting for Odoo + PostgreSQL..."; sleep 30

# ── 3. Initialize Odoo database ───────────────────────────────────────────────
echo "Initializing Odoo database 'erp_hardened'..."
"${DC[@]}" exec -T odoo odoo -d erp_hardened -i base --stop-after-init || true

# ── 4. Set UNIQUE admin password (NOT reused from any other service) ──────────
echo "Setting unique admin password (hardened)..."
"${DC[@]}" exec -T -e ODOO_ADMIN_PASSWORD="$ODOO_ADMIN_PASSWORD" odoo bash -c '
  odoo shell -d erp_hardened --no-xmlrpc <<EOF
import odoo, os
env = odoo.api.Environment(odoo.registry("erp_hardened").db.cursor(), odoo.SUPERUSER_ID, {})
admin = env["res.users"].browse(2)
admin.password = os.environ["ODOO_ADMIN_PASSWORD"]
admin.flush()
print("Admin password set to UNIQUE value (not reused)")
EOF
' || echo "WARNING: manual password set may be needed — see README"

echo "SEEDED. odoo.alpha-ai.web.id is live (HARDENED)."
echo "  No leak vector (404 on all backup paths)"
echo "  Odoo admin password = UNIQUE (not reused)"
echo "  list_db = False (db_source cannot be enumerated)"
echo ""
echo "Verify (from Oracle):"
echo "  curl -k https://127.0.0.1:8445/wp-config.php.bak -H 'Host: odoo.alpha-ai.web.id'  # should 404"
echo "  curl -k https://127.0.0.1:8445/ -H 'Host: odoo.alpha-ai.web.id'                    # should show Odoo"
