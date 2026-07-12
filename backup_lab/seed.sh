#!/usr/bin/env bash
# Backup-file exposure field-prove lab seeder — run on Oracle ARM64 (self-owned).
#   sudo ./seed.sh          # bring up + seed
#   sudo ./seed.sh --down   # tear down + revert /etc/hosts
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
else echo "need docker compose"; exit 1; fi

HOSTS=(vuln.backup.lab hardened.backup.lab)
MARK="# agent-alpha-backup-lab"

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  sudo sed -i "/$MARK/d" /etc/hosts
  rm -rf sites certs || true
  echo "lab down; /etc/hosts reverted."; exit 0
fi

# 1. /etc/hosts
for h in "${HOSTS[@]}"; do
  grep -q "127.0.0.1 $h $MARK" /etc/hosts || echo "127.0.0.1 $h $MARK" | sudo tee -a /etc/hosts >/dev/null
done

# 2. self-signed lab CA + wildcard cert; emit a trust bundle for httpx (SSL_CERT_FILE)
mkdir -p certs
if [ ! -f certs/backup-lab.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/ca.key -out certs/ca.crt -subj "/CN=Agent-Alpha Backup Lab CA"
  openssl req -newkey rsa:2048 -nodes -keyout certs/backup-lab.key -out certs/backup-lab.csr \
    -subj "/CN=*.backup.lab"
  printf "subjectAltName=DNS:*.backup.lab,DNS:vuln.backup.lab,DNS:hardened.backup.lab" > certs/san.ext
  openssl x509 -req -in certs/backup-lab.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out certs/backup-lab.crt -days 365 -extfile certs/san.ext
  cat certs/backup-lab.crt certs/ca.crt > certs/backup-lab-bundle.crt
fi

# 3. Docroots. Both apps ship a benign index; ONLY vuln leaks the backup files.
mkdir -p sites/vuln sites/hardened
echo "<html><body>backup lab app</body></html>" > sites/vuln/index.html
echo "<html><body>backup lab app</body></html>" > sites/hardened/index.html

# Plant leaked backup config in vuln (exposed .env.bak + database.yml.bak).
cat > sites/vuln/.env.bak <<'ENV'
APP_ENV=production
APP_KEY=base64:labkeyonly
DB_CONNECTION=mysql
DB_HOST=db.internal
DB_DATABASE=app_prod
DB_USER=appuser
DB_PASSWORD=SuperSecretPassword123
ENV

mkdir -p sites/vuln/config
cat > sites/vuln/config/database.yml.bak <<'YML'
production:
  adapter: postgresql
  host: db.internal
  database: app_prod
  username: appuser
  password: SuperSecretPassword123
YML

# hardened: NO backup files planted (true-negative). Nothing to remove.

# 4. Bring up Nginx
"${DC[@]}" up -d

echo "Lab up."
echo "Verify vuln .env.bak     : curl -k https://vuln.backup.lab/.env.bak"
echo "Verify vuln db.yml.bak   : curl -k https://vuln.backup.lab/config/database.yml.bak"
echo "Verify hardened .env.bak : curl -k https://hardened.backup.lab/.env.bak   (should be 404)"
echo "Export for the runner    : export SSL_CERT_FILE=\$(pwd)/certs/backup-lab-bundle.crt"
