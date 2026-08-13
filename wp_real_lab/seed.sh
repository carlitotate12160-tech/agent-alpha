#!/usr/bin/env bash
# WP Real-World Lab seeder — run on Oracle ARM64 (168.110.192.62).
# Deploys WordPress + MariaDB behind CF for wp.alpha-ai.web.id.
#
# Prerequisites:
#   1. DNS A record: wp.alpha-ai.web.id → 168.110.192.62 (proxied, orange cloud)
#   2. CF Origin cert installed at /etc/nginx/certs/origin.pem + origin.key
#   3. Front-facing nginx config (front_proxy.conf) included in main nginx
#   4. Docker + docker compose v2 installed
#
# Usage:
#   sudo ./seed.sh          # bring up + seed
#   sudo ./seed.sh --down   # tear down
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "Neither 'docker compose' nor 'docker-compose' found. Install one first."; exit 1
fi

[ -f .env ] || { echo "copy .env.example -> .env first"; exit 1; }
set -a; . ./.env; set +a

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  echo "WP real lab down."
  exit 0
fi

# ── 1. Internal self-signed cert (front proxy → this stack, localhost only) ───
mkdir -p certs exposed/vuln
if [ ! -f certs/stack-internal.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/stack-internal.key -out certs/stack-internal.crt \
    -subj "/CN=wp-alpha-ai-internal"
fi

# ── 2. Bring up + wait for WordPress ──────────────────────────────────────────
"${DC[@]}" up -d
echo "waiting for WordPress..."; sleep 25

# ── 3. WP-CLI install — admin password == leaked DB password (cred-reuse) ─────
WP="${DC[*]} exec -T wpcli wp --allow-root --path=/var/www/html"
$WP core install --url="https://wp.alpha-ai.web.id" --title="Alpha-AI WP Lab" \
    --admin_user="$LEAKED_WP_ADMIN" --admin_password="$LEAKED_DB_PASSWORD" \
    --admin_email="lab@alpha-ai.web.id" --skip-email
# admin password == DB password → the payable password-reuse finding

# ── 4. Exposed wp-config.php.bak (leak vector) ────────────────────────────────
cat > exposed/vuln/wp-config.php.bak <<EOF
<?php
/** Backup remnant left in web root */
define( 'DB_NAME', '$MARIADB_DATABASE' );
define( 'DB_USER', '$MARIADB_USER' );
define( 'DB_PASSWORD', '$LEAKED_DB_PASSWORD' );
define( 'DB_HOST', 'localhost' );
\$table_prefix = 'wp_';
EOF

echo "SEEDED. wp.alpha-ai.web.id is live."
echo "  Leak vector: https://wp.alpha-ai.web.id/wp-config.php.bak"
echo "  Access vector: wp-login.php with $LEAKED_WP_ADMIN / <LEAKED_DB_PASSWORD>"
echo ""
echo "Verify (from Oracle):"
echo "  curl -k https://127.0.0.1:8443/wp-config.php.bak -H 'Host: wp.alpha-ai.web.id'"
echo "Verify (through CF, from external):"
echo "  curl https://wp.alpha-ai.web.id/wp-config.php.bak"
