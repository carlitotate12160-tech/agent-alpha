#!/usr/bin/env bash
# Laravel Real-World Lab seeder — run on Oracle ARM64.
# Deploys real Laravel 10 with APP_DEBUG=true for laravel.alpha-ai.web.id.
#
# Prerequisites:
#   1. DNS A record: laravel.alpha-ai.web.id → 168.110.192.62 (proxied)
#   2. CF Origin cert at /etc/nginx/certs/origin.pem + origin.key
#   3. Front-facing nginx config (front_proxy.conf) installed
#   4. Docker + docker compose v2
#
# Usage:
#   sudo ./seed.sh          # build + up + install Laravel
#   sudo ./seed.sh --down   # tear down
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "Neither 'docker compose' nor 'docker-compose' found."; exit 1
fi

[ -f .env ] || { echo "copy .env.example -> .env first"; exit 1; }
set -a; . ./.env; set +a

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  echo "Laravel real lab down."
  exit 0
fi

# ── 1. Internal self-signed cert ──────────────────────────────────────────────
mkdir -p certs
if [ ! -f certs/stack-internal.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/stack-internal.key -out certs/stack-internal.crt \
    -subj "/CN=laravel-alpha-ai-internal"
fi

# ── 2. Build + bring up ───────────────────────────────────────────────────────
echo "Building Laravel image (this takes a few minutes on first run)..."
"${DC[@]}" build laravel
"${DC[@]}" up -d
echo "waiting for MySQL..."; sleep 15

# ── 3. Install Laravel inside the container ───────────────────────────────────
echo "Installing Laravel 10 via composer..."
"${DC[@]}" exec -T laravel bash -c '
  if [ ! -f /var/www/html/artisan ]; then
    cd /var/www/html
    composer create-project laravel/laravel:^10.0 . --no-interaction \
      --ignore-platform-reqs --no-security-blocking
  fi
'

# ── 4. Configure .env inside the container ────────────────────────────────────
echo "Configuring Laravel .env..."
"${DC[@]}" exec -T laravel bash -c "
  cd /var/www/html
  sed -i 's/APP_DEBUG=false/APP_DEBUG=true/' .env
  sed -i 's/DB_CONNECTION=.*/DB_CONNECTION=mysql/' .env
  sed -i 's/DB_HOST=.*/DB_HOST=mysql/' .env
  sed -i 's/DB_DATABASE=.*/DB_DATABASE=${DB_DATABASE}/' .env
  sed -i 's/DB_USERNAME=.*/DB_USERNAME=${DB_USER}/' .env
  sed -i 's/DB_PASSWORD=.*/DB_PASSWORD=${DB_PASSWORD}/' .env
  php artisan key:generate
  php artisan config:clear
"

# ── 5. Create trigger-error route (leak vector) ───────────────────────────────
echo "Creating trigger-error route..."
"${DC[@]}" exec -T laravel bash -c '
  cd /var/www/html
  cat > routes/web.php <<'"'"'ROUTE'"'"'
<?php
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::get("/", function () {
    return view("welcome");
});

Route::get("/trigger-error", function () {
    try {
        DB::connection()->getPdo();
        throw new \Exception("Test error for Laravel debug page");
    } catch (\Exception $e) {
        throw $e;
    }
});
ROUTE
'

# ── 6. Set permissions ────────────────────────────────────────────────────────
"${DC[@]}" exec -T laravel bash -c '
  cd /var/www/html
  chown -R www-data:www-data storage bootstrap/cache
  chmod -R 775 storage bootstrap/cache
'

echo "SEEDED. laravel.alpha-ai.web.id is live."
echo "  Leak vector: https://laravel.alpha-ai.web.id/trigger-error"
echo "  Expected: 500 Whoops debug page with DB_USERNAME + DB_PASSWORD"
echo ""
echo "Verify (from Oracle):"
echo "  curl -k https://127.0.0.1:8444/trigger-error -H 'Host: laravel.alpha-ai.web.id'"
echo "Verify (through CF):"
echo "  curl https://laravel.alpha-ai.web.id/trigger-error"
