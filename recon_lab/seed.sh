#!/usr/bin/env bash
# recon_lab seed — self-signed cert for *.recon.lab + .env.bak leak fixture + /etc/hosts reminder.
# The .env.bak with real credentials is generated HERE (lab machine only, never committed).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
if [ ! -f certs/recon-lab.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout certs/recon-lab.key -out certs/recon-lab.crt \
    -subj "/CN=recon.lab" \
    -addext "subjectAltName=DNS:apex.recon.lab,DNS:late.recon.lab,DNS:waf.recon.lab,DNS:decoy.recon.lab,DNS:dead.recon.lab,DNS:hardened.recon.lab"
  echo "generated certs/recon-lab.crt"
fi
# Generate the leak fixture with real-looking credentials (lab-only).
# The actual credentials live in generate_leak.sh which is gitignored.
if [ -f generate_leak.sh ]; then
  bash generate_leak.sh
  echo "generated exposed/late/.env.bak (lab fixture)"
else
  echo "WARNING: generate_leak.sh not found — exposed/late/.env.bak still has placeholders."
  echo "         Create it with: cp generate_leak.sh.example generate_leak.sh && edit"
fi
cat <<'HOSTS'
Add to /etc/hosts (all resolve to loopback; SNI selects the vhost):
127.0.0.1  apex.recon.lab late.recon.lab waf.recon.lab decoy.recon.lab dead.recon.lab hardened.recon.lab
HOSTS
