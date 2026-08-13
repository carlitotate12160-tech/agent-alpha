# Odoo Hardened Real-World Lab

TRUE-NEGATIVE lab for the Odoo cred-reuse chain. Deployed at
`odoo.alpha-ai.web.id` (Cloudflare-proxied, Oracle ARM64).

## What makes this "hardened" (the chain MUST fail)

1. **No leak vector** — nginx returns 404 for all backup/config paths
   (`/wp-config*`, `/.env`, `/.git`, `/backup`, `*.bak`)
2. **Unique admin password** — NOT reused from WP or any other service
3. **`list_db = False`** — `db_source` cannot be "enumerated" (the chain
   gate only chains enumerated access; a guessed db never counts as proven)

If the agent reports "chain proven" on this target → FALSE POSITIVE (anti-#3).

## Deploy

```bash
cd odoo_hardened_lab
sudo ./seed.sh
```

## Verify (from Oracle)

```bash
# No leak vector — all backup paths 404:
curl -k https://127.0.0.1:8445/wp-config.php.bak -H 'Host: odoo.alpha-ai.web.id'
# Expected: 404

# Odoo is live:
curl -k https://127.0.0.1:8445/ -H 'Host: odoo.alpha-ai.web.id'
# Expected: Odoo login page

# list_db = False — XML-RPC db.list should fail or return empty:
curl -k -H 'Content-Type: text/xml' \
  --data '<?xml version="1.0"?><methodCall><methodName>list</methodName><params/></methodCall>' \
  https://127.0.0.1:8445/xmlrpc/2/db -H 'Host: odoo.alpha-ai.web.id'
# Expected: fault or empty (NOT a db name)
```
