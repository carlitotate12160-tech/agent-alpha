#!/usr/bin/env bash
# Odoo field-prove lab seeder — run on Oracle ARM64 (self-owned). 
#   sudo ./seed.sh          # bring up + seed
#   sudo ./seed.sh --down   # tear down + revert /etc/hosts
# NOTE: the Odoo db-init + admin-password steps (marked ⚠) are the parts most
# likely to need on-box adjustment for the exact Odoo image tag. Validate output.
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
else echo "need docker compose"; exit 1; fi

HOSTS=(vuln.odoo.lab hardened.odoo.lab)
MARK="# agent-alpha-odoo-lab"
[ -f .env ] || { echo "copy .env.example -> .env first"; exit 1; }
set -a; . ./.env; set +a

if [ "${1:-}" = "--down" ]; then
  "${DC[@]}" down -v || true
  sudo sed -i "/$MARK/d" /etc/hosts
  echo "lab down; /etc/hosts reverted."; exit 0
fi

# 1. /etc/hosts
for h in "${HOSTS[@]}"; do
  grep -q "127.0.0.1 $h $MARK" /etc/hosts || echo "127.0.0.1 $h $MARK" | sudo tee -a /etc/hosts >/dev/null
done

# 2. self-signed lab CA + wildcard cert; emit a trust bundle for httpx (SSL_CERT_FILE)
mkdir -p certs
if [ ! -f certs/odoo-lab.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/ca.key -out certs/ca.crt -subj "/CN=Agent-Alpha Odoo Lab CA"
  openssl req -newkey rsa:2048 -nodes -keyout certs/odoo-lab.key -out certs/odoo-lab.csr \
    -subj "/CN=*.odoo.lab"
  printf "subjectAltName=DNS:*.odoo.lab,DNS:vuln.odoo.lab,DNS:hardened.odoo.lab" > certs/san.ext
  openssl x509 -req -in certs/odoo-lab.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out certs/odoo-lab.crt -days 365 -extfile certs/san.ext
  cat certs/odoo-lab.crt certs/ca.crt > certs/odoo-lab-bundle.crt
fi

# 3. write the SHARED reused password into the bait (crux of the reuse scenario)
sed -i "s|__SET_TO_ODOO_ADMIN_PW_IN_SEED__|${ODOO_ADMIN_PASSWORD}|" exposed/vuln/wp-config.php.bak

# 4. bring up
"${DC[@]}" up -d

# ⚠ 5. init an Odoo database 'erp' (list_db on → db.list() returns it → enumerated)
echo "waiting for postgres…"; sleep 8
"${DC[@]}" exec -T odoo odoo -d erp -i base --stop-after-init --without-demo=all || \
  echo "⚠ odoo db-init returned nonzero — inspect; may already exist."

# ⚠ 6. set the admin (uid 2) password to the SHARED pw so the reused cred authenticates
"${DC[@]}" exec -T odoo bash -lc "odoo shell -d erp --no-http <<'PY'
u = env['res.users'].browse(2)
u.password = '${ODOO_ADMIN_PASSWORD}'
env.cr.commit()
print('admin login=%s uid=%s pw set' % (u.login, u.id))
PY" || echo "⚠ admin-pw step needs adjustment for this Odoo tag — set uid 2 password to ODOO_ADMIN_PASSWORD manually."

echo "Lab up. Verify:  curl -k https://vuln.odoo.lab/wp-config.php.bak   (should show DB_PASSWORD=${ODOO_ADMIN_PASSWORD})"
echo "Verify db.list:  curl -k -H 'Content-Type: text/xml' --data '<?xml version=\"1.0\"?><methodCall><methodName>list</methodName><params/></methodCall>' https://vuln.odoo.lab/xmlrpc/2/db"
echo "Export for the runner:  export SSL_CERT_FILE=\$(pwd)/certs/odoo-lab-bundle.crt"
