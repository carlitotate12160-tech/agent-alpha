# Stack Catalog — fingerprint-keyed recon depth

> **Rule of record (anti maju-mundur).** Recon depth lives in the **playbook
> catalog**, keyed on stack **fingerprint** — never per client, never a second
> "stack manifest" object (that is Lyndon #6/#7; see `tools/registry.py` docstring).
> "Battery for stack X" = the SET of playbooks whose `match` fires on X's
> fingerprint. To make a stack deeper you ADD fingerprint-keyed playbooks; you do
> not add a manifest. Every entry is general (fires on *any* host of that stack).
>
> **DETECT vs FINDING (anti Lyndon #3).** A fingerprint / route inventory / API
> surface is DETECT-only: it persists an ASSET node/property and MAY seed the
> frontier, but never increments `self._findings`. A FINDING requires a confirmed
> body signature (status code alone is never enough — WordPress soft-404 returns
> 200 with an HTML body; see niagamas field notes).
>
> Precedent to mirror for DETECT-only surface: `scout._handle_surface_discovery`.
> Precedent for a body-confirmed finding: `wp_config` DB-cred leak path.

---

## WordPress (`STACK_WP = "wp"`)

Fingerprint: `wp-content` / `wp-includes` body marker, `meta generator=WordPress`.

| Capability | Playbook | Signal | DETECT/FINDING | Status |
|---|---|---|---|---|
| wp-config backup exposure | `wp_config.yaml` | backup path → DB creds in body | FINDING (creds) | built |
| REST user enumeration | `wp_rest_users.yaml` | `/wp-json/wp/v2/users` -> id+slug JSON | FINDING (username disclosure -> cred-reuse feed) | **slice** |
| REST route surface | `wp_rest_routes.yaml` | `/wp-json/` route index | DETECT (asset `rest_routes`, capped) | **slice** |
| WooCommerce enum | `woocommerce.yaml` | `/wp-json/wc/v3/*`, Store API | FINDING (order/PII/config leak) when body confirms | **slice** |
| Version disclosure | `wp_version.yaml` | `readme.html`, `<meta generator>` | FINDING (low sev) | **slice** |
| xmlrpc abuse | `wp_xmlrpc.yaml` | `/xmlrpc.php` pingback/system.multicall | FINDING (brute amplification) | menu (defer) |
| Author enum | `wp_author.yaml` | `/?author=1` -> slug redirect | FINDING (username disclosure) | menu (defer) |
| Plugin/theme enum | `wp_plugins.yaml` | `/wp-content/plugins/<x>/…` + version -> CVE map | FINDING (versioned CVE) | menu (defer) |

Slice boundary (agreed): the four marked **slice** only. Deferred rows go OUT of the
build — documented here as menu, NOT half-scaffolded in code.

`rest_routes` escalation is filtered by `constants.WP_REST_INTERESTING_ROUTES` (SSOT):
only allowlisted routes trigger a follow-up probe; the rest sit inert on the asset.

---

## Laravel (menu only — not this slice)

Fingerprint: `laravel_session` cookie, `X-Powered-By`, Ignition error page markers.

| Capability | Signal | DETECT/FINDING |
|---|---|---|
| Debug mode / Ignition | `APP_DEBUG` stack trace page | FINDING (info leak; RCE if Ignition CVE) |
| `.env` exposure | `/.env` -> `APP_KEY=`, DB creds | FINDING (creds) |
| Telescope exposure | `/telescope/requests` reachable | FINDING (request/PII leak) |
| Horizon exposure | `/horizon` dashboard reachable | FINDING (queue/infra leak) |
| APP_KEY leak -> decrypt | leaked `APP_KEY` | FINDING (session forgery — Gamma-gated) |

## Odoo (menu only — not this slice)

Fingerprint: `odoo` / `web/login` markers, `odoo_fingerprint.yaml` already present.

| Capability | Signal | DETECT/FINDING | Status |
|---|---|---|---|
| Fingerprint | login/version markers | DETECT | built (`odoo_fingerprint.yaml`) |
| DB manager exposure | `/web/database/manager` reachable | FINDING (DB enumerate/create) | built (`odoo_dbmanager.yaml`) |
| XML-RPC auth surface | `/xmlrpc/2/common` | DETECT/FINDING | menu |
| Version -> CVE map | version banner | FINDING | menu |
| Default credentials | admin/admin on discovered DB | FINDING (access) | menu |

---

## Adding a stack later (the repeatable recipe)

1. Add a fingerprint match (body/header) that yields the stack label into
   `AssetProperties.tech_stack` via `merge_tech_stack` (single merge site).
2. For each capability, add ONE pure-data playbook under `tools/playbooks/`
   (`match` -> `action{tool,tier,technique_id,rationale}`), keyed on the stack
   fingerprint. No code in the yaml.
3. Add the handler in `scout.py`, register it in `_dispatch_registry`, register
   the capability in the capability registry (`capability_for_tool`).
4. RED test first in the stack's single `test_<stack>_recon.py` — the cardinal
   assertion must FAIL before the handler exists.
5. Register wiring-debt in `tests/governance/test_wiring_gate.py` until the
   autonomous path (`run_recon`) actually dispatches it — RUNNER-SEAL != WIRED.
6. Prove on a self-owned lab host e2e (fingerprint -> full battery auto-fires),
   Oracle ARM64 only.
