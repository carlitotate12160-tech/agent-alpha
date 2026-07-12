#!/usr/bin/env bash
# Actuator exposure field-prove lab seeder — run on Oracle ARM64 (self-owned).
#   sudo ./seed.sh          # bring up + seed
#   sudo ./seed.sh --down   # tear down + revert /etc/hosts
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
else echo "need docker compose"; exit 1
fi

HOSTS=(vuln.actuator.lab hardened.actuator.lab)
MARK="# agent-alpha-actuator-lab"

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  sudo sed -i "/$MARK/d" /etc/hosts
  rm -rf sites certs || true
  echo "lab down; /etc/hosts reverted."; exit 0
fi

for h in "${HOSTS[@]}"; do
  grep -q "127.0.0.1 $h $MARK" /etc/hosts || echo "127.0.0.1 $h $MARK" | sudo tee -a /etc/hosts >/dev/null
done

mkdir -p certs
if [ ! -f certs/actuator-lab.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/ca.key -out certs/ca.crt -subj "/CN=Agent-Alpha Actuator Lab CA"
  openssl req -newkey rsa:2048 -nodes -keyout certs/actuator-lab.key -out certs/actuator-lab.csr \
    -subj "/CN=*.actuator.lab"
  printf "subjectAltName=DNS:*.actuator.lab,DNS:vuln.actuator.lab,DNS:hardened.actuator.lab" > certs/san.ext
  openssl x509 -req -in certs/actuator-lab.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out certs/actuator-lab.crt -days 365 -extfile certs/san.ext
  cat certs/actuator-lab.crt certs/ca.crt > certs/actuator-lab-bundle.crt
fi

# docroots: both serve /actuator/env; ONLY vuln is unmasked.
mkdir -p sites/vuln/actuator sites/hardened/actuator
echo '{"status":"UP"}' > sites/vuln/index.html
echo '{"status":"UP"}' > sites/hardened/index.html

cat > sites/vuln/actuator/env <<'JSON'
{
  "activeProfiles": ["prod"],
  "propertySources": [
    {"name": "systemProperties", "properties": {"java.version": {"value": "17"}}},
    {"name": "applicationConfig: [classpath:/application.yml]", "properties": {
      "spring.datasource.username": {"value": "appuser"},
      "spring.datasource.password": {"value": "SuperSecretPassword123"},
      "spring.datasource.url": {"value": "jdbc:postgresql://db.internal:5432/app_prod"}
    }}
  ]
}
JSON

# hardened: same endpoint, values MASKED (Spring default) → true-negative.
cat > sites/hardened/actuator/env <<'JSON'
{
  "activeProfiles": ["prod"],
  "propertySources": [
    {"name": "applicationConfig: [classpath:/application.yml]", "properties": {
      "spring.datasource.username": {"value": "******"},
      "spring.datasource.password": {"value": "******"}
    }}
  ]
}
JSON

"${DC[@]}" up -d
echo "Lab up."
echo "Verify vuln     : curl -k https://vuln.actuator.lab/actuator/env"
echo "Verify hardened : curl -k https://hardened.actuator.lab/actuator/env  (values ******)"
echo "Export for runner: export SSL_CERT_FILE=\$(pwd)/certs/actuator-lab-bundle.crt"
