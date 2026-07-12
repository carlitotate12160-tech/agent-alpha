#!/usr/bin/env bash
# Git Exposure field-prove lab seeder — run on Oracle ARM64 (self-owned).
#   sudo ./seed.sh          # bring up + seed
#   sudo ./seed.sh --down   # tear down + revert /etc/hosts
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
else echo "need docker compose"; exit 1; fi

HOSTS=(vuln.git.lab hardened.git.lab)
MARK="# agent-alpha-git-lab"

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  sudo sed -i "/$MARK/d" /etc/hosts
  rm -rf sites/vuln/.git sites/vuln/config sites/hardened/.git sites/hardened/config certs || true
  echo "lab down; /etc/hosts reverted."; exit 0
fi

# 1. /etc/hosts
for h in "${HOSTS[@]}"; do
  grep -q "127.0.0.1 $h $MARK" /etc/hosts || echo "127.0.0.1 $h $MARK" | sudo tee -a /etc/hosts >/dev/null
done

# 2. self-signed lab CA + wildcard cert; emit a trust bundle for httpx (SSL_CERT_FILE)
mkdir -p certs
if [ ! -f certs/git-lab.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/ca.key -out certs/ca.crt -subj "/CN=Agent-Alpha Git Lab CA"
  openssl req -newkey rsa:2048 -nodes -keyout certs/git-lab.key -out certs/git-lab.csr \
    -subj "/CN=*.git.lab"
  printf "subjectAltName=DNS:*.git.lab,DNS:vuln.git.lab,DNS:hardened.git.lab" > certs/san.ext
  openssl x509 -req -in certs/git-lab.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out certs/git-lab.crt -days 365 -extfile certs/san.ext
  cat certs/git-lab.crt certs/ca.crt > certs/git-lab-bundle.crt
fi

# 3. Create docroots and plant the vulnerable .git repository
mkdir -p sites/vuln/config sites/hardened/config

# Plant DB credential in vuln (exposed .git)
echo "host: localhost" > sites/vuln/config/database.yml
echo "username: db_user" >> sites/vuln/config/database.yml
echo "password: SuperSecretPassword123" >> sites/vuln/config/database.yml
echo "database: app_prod" >> sites/vuln/config/database.yml

(cd sites/vuln && git init && git add config/database.yml && git config user.name "Lab Admin" && git config user.email "admin@git.lab" && git commit -m "Initial commit with DB config")

# Ensure hardened has no .git directory, just the files
echo "host: localhost" > sites/hardened/config/database.yml
echo "username: db_user" >> sites/hardened/config/database.yml
echo "password: SuperSecretPassword123" >> sites/hardened/config/database.yml
echo "database: app_prod" >> sites/hardened/config/database.yml
rm -rf sites/hardened/.git

# 4. Bring up Nginx
"${DC[@]}" up -d

echo "Lab up."
echo "Verify vuln: curl -k https://vuln.git.lab/config/database.yml"
echo "Verify vuln .git: curl -k https://vuln.git.lab/.git/config"
echo "Verify hardened .git: curl -k https://hardened.git.lab/.git/config (should be 404)"
echo "Export for the runner: export SSL_CERT_FILE=\$(pwd)/certs/git-lab-bundle.crt"
