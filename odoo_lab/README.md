# Odoo field-prove lab (slice 1d-0)

Self-owned lab that proves the **cross-service credential-reuse chain** for Odoo:
a leaked config exposes `admin/<pw>`; the same `<pw>` is reused as the Odoo login;
Agent-Alpha harvests the leak and reuses it over XML-RPC to get a `uid`.

This is **1d-0 (the lab)**. The chain runner that consumes it is **1d-1** (next slice).

## Why this shape (decisions locked)

- **Chain = cross-service reuse**, composition-only (Phase-4 charter). No new Odoo leak
  probe: the leak is harvested by the existing `wp_config_probe` (it GETs
  `/wp-config.php.bak`, parses `DB_USER`/`DB_PASSWORD`, and — via
  `credential_assembly` login-branch — mints a CREDENTIAL node **with a username**).
- **Why not js_secret leak?** `js_secret_probe` mints creds with `username=""` (API-key
  style) — Odoo `authenticate()` needs a real login, so a JS-key leak cannot feed this
  chain. Only a login-credential leak works. (Traced, see `[[odoo-1d-chain]]` memory.)
- **`list_db = True`** in `odoo.conf` is mandatory: it makes XML-RPC `db.list()` return
  the real db name → `OdooAccessTool` records `db_source="enumerated"`. The 1d chain gate
  only chains **enumerated** access; a guessed db is never "proven".

## Topology (one IP, Host-header vhosts, self-signed CA)

```
127.0.0.1:443 ── nginx ─┬─ vuln.odoo.lab      ── GET /wp-config.php.bak → BAIT (leak)
                        │                       └ /  and /xmlrpc/2/*    → Odoo (access)
                        └─ hardened.odoo.lab   ── no bait exposed        → Odoo
                                    (true-negative: no leak → chain must FAIL)
   odoo:17.0  ←→  postgres:16     (single backend; the vhost difference is only the bait)
```

Ground truth (`ground-truth.yaml`): `vuln` → `chain_proven: true`, `db_source: enumerated`,
`access_level: admin`; `hardened` → `chain_proven: false`, `leak_creds_added: 0`.

## Files

| File | Role |
|------|------|
| `docker-compose.yml` | nginx + odoo:17 + postgres:16 |
| `odoo.conf` | `list_db = True` (enumerated), master pw from `.env` |
| `nginx.conf` | serves the bait on vuln + proxies `/xmlrpc/2/*` to Odoo |
| `exposed/vuln/wp-config.php.bak` | the leak bait (DB_USER=admin, DB_PASSWORD=shared) |
| `ground_truth.yaml` | expected per-host chain outcome |
| `odoo_lab_engagement.yaml` | scope (127.0.0.1/32 + 2 domains) |
| `seed.sh` | /etc/hosts + certs + up + Odoo db-init + admin-pw set |
| `.env.example` | the SHARED reused pw + Odoo master pw (copy → `.env`, gitignored) |
| `lab_guard_allowlist.patch.txt` | add the 2 lab hosts to `lab_guard.py` (fail-closed) |

## Stand-up (on your self-owned Oracle box — NOT verifiable in my sandbox)

```bash
cd odoo_lab
cp .env.example .env      # set ODOO_ADMIN_PASSWORD (the reused pw) + ODOO_MASTER_PASSWORD
sudo ./seed.sh            # /etc/hosts, certs, compose up, Odoo db 'erp', admin pw
```

### ⚠ Validation boundary (be honest — this part is NOT sealed)
Everything here is **draft infra I could not run** (no Docker/Odoo in my sandbox; anti-#9 —
only your Oracle run is valid). The two steps most likely to need adjustment for the exact
`odoo:17.0` tag are marked `⚠` in `seed.sh`:
1. `odoo -d erp -i base --stop-after-init` (db creation),
2. setting **uid 2** admin password to `$ODOO_ADMIN_PASSWORD` via `odoo shell`.

**Verify the lab is correct before 1d-1** (these are the ground-truth checks):
```bash
# leak vector serves the bait with the reused pw:
curl -k https://vuln.odoo.lab/wp-config.php.bak        # DB_PASSWORD must equal your pw
# access vector enumerates the db (db_source=enumerated):
curl -k -H 'Content-Type: text/xml' \
  --data '<?xml version="1.0"?><methodCall><methodName>list</methodName><params/></methodCall>' \
  https://vuln.odoo.lab/xmlrpc/2/db                     # must contain <string>erp</string>
export SSL_CERT_FILE=$(pwd)/certs/odoo-lab-bundle.crt   # so httpx trusts the lab CA
```
Then apply the `lab_guard.py` allowlist addition (`lab_guard_allowlist.patch.txt`).

## What 1d-1 will do (next slice — not in this delivery)

`live_fire/odoo_chain_runner.py` (mirror `db_chain_runner.py`/`wp_chain_runner.py`):
run `wp_config_probe` on `vuln.odoo.lab` → CREDENTIAL(admin/pw) → `OdooAccessTool` reused
path → `authenticate('erp','admin',pw)` → uid. `chain_proven` is honest only when
`credential_source=="reused"` **and** `db_source=="enumerated"`. Lab-only guard enforced.
Unit test (fake HTTP) first, then field-prove on this lab.

**Bundled with 1d-1** (noted, not done here): a tiny `odoo_access` fix to SKIP `username==""`
credentials in the reused-path (they can never authenticate — just waste budget/add noise).
