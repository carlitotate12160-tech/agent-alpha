# Add RateLimiter + HttpClient RoE Rate-Limit Enforcement

## Summary

Implements RoE (Rules-of-Engagement) rate-limit enforcement at the HTTP egress chokepoint. Previously, `policy.yaml` declared `rate_limiting_enabled` + per-OPSEC-profile `rate_limit_rps` but nothing enforced it — recon fired requests as fast as the network allowed (anti-Lyndon #2: declared-not-wired). This is the enforcement: a blocking min-interval limiter at the single HTTP egress chokepoint (`HttpClient.get`).

## Changes

### Added Files

- **agent_alpha/agents/rate_limiter.py**
  - `RateLimiter` class with blocking min-interval rate limiting
  - DELAYS, never DROPS — no request is silently discarded (anti-Lyndon #3)
  - Injectable clock + sleep → fully deterministic tests (no real wall-clock waiting)
  - Thread-safe — Celery workers may share a client across threads
  - First request is immediate; subsequent requests spaced by >= 1/rps

- **tests/phase_2/test_rate_limiter.py**
  - Deterministic tests via injected clock (no real wall-clock waiting)
  - Tests: first request immediate, successive requests spaced, no wait when enough time passed
  - Tests: delays never drops, invalid RPS rejected
  - Tests: HttpClient acquires slot before each request, default limiter uses constant

### Modified Files

- **agent_alpha/agents/http_client.py**
  - Added import for `RateLimiter`
  - Added `rate_limit_rps` and `rate_limiter` parameters to `__init__`
  - Added `_rate_limiter` initialization with default from constants
  - Added `self._rate_limiter.acquire()` call in `get()` method before egress

- **agent_alpha/config/constants.py**
  - Added `DEFAULT_RATE_LIMIT_RPS` to `__all__`
  - Added constant definition (2.0 rps = quiet OPSEC profile)
  - Single source for code-level default (anti-Lyndon #7)

## Design Decisions

### DELAYS, never DROPS
- `acquire()` blocks until the next slot, so no request is silently discarded
- Throughput is bounded, requests are not lost
- Addresses anti-Lyndon #3 (no silent failures)

### Injectable Clock + Sleep
- Fully deterministic tests (no real wall-clock waiting)
- Clock advances ONLY when limiter sleeps, modelling real time
- Proves limiter DELAYS and honours >= 1/rps spacing

### Thread-Safe
- Celery workers may share a client across threads
- Uses threading.Lock to protect `_next_allowed` state

### Default Rate Limit
- Safe RoE default = policy.yaml "quiet" OPSEC profile (2 rps)
- Per-engagement OPSEC profile selection (normal=10/loud=50) will override via ctor when that feature lands
- Single source for code-level default (anti-Lyndon #7)

## Testing

Run on Oracle ARM64:
```bash
.venv/bin/pytest tests/phase_2/test_rate_limiter.py -v
```

## Checklist

- [x] RateLimiter implementation
- [x] Deterministic tests with injected clock
- [x] HttpClient integration
- [x] Constants single source of truth
- [x] Anti-Lyndon #2 addressed (declared-not-wired)
- [x] Anti-Lyndon #3 addressed (delays never drops)
- [x] Anti-Lyndon #7 addressed (single source constant)
