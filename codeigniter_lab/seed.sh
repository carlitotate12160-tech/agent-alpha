#!/usr/bin/env bash
# CodeIgniter config leak field-prove lab seeder — run on Oracle ARM64 (self-owned).
#   sudo ./seed.sh          # bring up + seed
#   sudo ./seed.sh --down   # tear down + revert /etc/hosts
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
else echo "need docker compose"; exit 1; fi

HOSTS=(vuln.codeigniter.lab hardened.codeigniter.lab)
MARK="# agent-alpha-codeigniter-lab"

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  sudo sed -i "/$MARK/d" /etc/hosts
  rm -rf certs || true
  echo "lab down; /etc/hosts reverted."; exit 0
fi

# 1. /etc/hosts
for h in "${HOSTS[@]}"; do
  grep -q "127.0.0.1 $h $MARK" /etc/hosts || echo "127.0.0.1 $h $MARK" | sudo tee -a /etc/hosts >/dev/null
done

# 2. lab docroots must be present (tracked in git)
if [ ! -f "sites/vuln/index.html" ] || [ ! -f "sites/vuln/application/config/database.php" ]; then
    echo "sites/ docroots missing — run from the codeigniter_lab/ directory after git checkout"
    exit 1
fi

# 3. self-signed lab CA + wildcard cert
mkdir -p certs
if [ ! -f certs/codeigniter-lab.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/ca.key -out certs/ca.crt -subj "/CN=Agent-Alpha CodeIgniter Lab CA"
  openssl req -newkey rsa:2048 -nodes -keyout certs/codeigniter-lab.key -out certs/codeigniter-lab.csr \
    -subj "/CN=*.codeigniter.lab"
  printf "subjectAltName=DNS:*.codeigniter.lab,DNS:vuln.codeigniter.lab,DNS:hardened.codeigniter.lab" > certs/san.ext
  openssl x509 -req -in certs/codeigniter-lab.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out certs/codeigniter-lab.crt -days 365 -extfile certs/san.ext
  cat certs/codeigniter-lab.crt certs/ca.crt > certs/codeigniter-lab-bundle.crt
fi

# 4. Bring up Nginx
"${DC[@]}" up -d

echo "Lab up."
echo "Verify vuln root          : curl -k --resolve vuln.codeigniter.lab:8444:127.0.0.1 https://vuln.codeigniter.lab:8444/"
echo "Verify vuln database.php  : curl -k --resolve vuln.codeigniter.lab:8444:127.0.0.1 https://vuln.codeigniter.lab:8444/application/config/database.php"
echo "Verify hardened root      : curl -k --resolve hardened.codeigniter.lab:8444:127.0.0.1 https://hardened.codeigniter.lab:8444/"
echo "Export for the runner     : export SSL_CERT_FILE=\$(pwd)/certs/codeigniter-lab-bundle.crt"
