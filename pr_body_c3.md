## Summary

Implements C3: auth-event tenant routing through synchronous API path.

## C3 - Auth-Event Tenant Routing

**GAP (C1.0 regression):** The worker (`run_engagement_task`) was made tenant-aware in C1.6, but the synchronous API routes (create / recon / sow / run / stop / state) still operate through the module-global `auth`, which is bound to the single default `event_store`.

**Functional break for real tenants:**
- `create_engagement` writes ENGAGEMENT_CREATED + state events to the DEFAULT store
- The worker reads the engagement from the TENANT store → finds nothing → refuses a legitimately-authorized run with "not_found"

## Implementation

- `agent_alpha/conductor/main.py`:
  - Add `auth_for(tenant_id)` function for tenant-aware auth routing
  - Add `emergency_for(tenant_id)` function for tenant-aware emergency handler
  - Remove global `auth` and `emergency` variables
  - Update all API routes to use `auth_for()`:
    - `create_engagement`
    - `enable_recon`
    - `upload_sow`
    - `run_engagement`
    - `get_run_status`
    - `emergency_stop` (with `emergency_for()`)
    - `get_state`

- `tests/phase_0/test_auth_tenant_routing.py` — 4 contract tests:
  - `test_create_routes_lifecycle_events_to_tenant_store` — ENGAGEMENT_CREATED lands in tenant store
  - `test_recon_transition_also_lands_in_tenant_store` — state transitions stay in tenant store
  - `test_second_tenant_cannot_see_first_tenants_events` — tenant isolation
  - `test_worker_finds_engagement_created_via_api` — end-to-end consistency (worker finds API-created engagement)

## Contract

**Behavior asserted:**
- Lifecycle events land in the tenant store
- Default store stays empty
- Worker finds the record created via API
- Tenant isolation enforced

**Single source of truth:** `auth_for(tenant_id)` used by every route, so one tenant == one store.

## Tests

- 4/4 tests passing
- All hermetic (in-memory backend, no DB)
- Exercises full lifecycle end-to-end

## Fix

Closes the C1.0 split-brain where the API wrote auth events to the default store while the worker read the tenant store. Now both API and worker use the same tenant-aware routing.
