# RECON Condition Catalog

> **Mirror** of the detection constants in `agent_alpha/recon/response_classifier.py`.
> The source of truth is the Python module (anti-Lyndon #7). This file is
> documentation only — if the two disagree, the code wins.

## Verdict.CHALLENGE (ADR §12.27 D1)

A CDN/WAF interstitial page served at HTTP 200 (or any status) is a challenge,
not real content. Without detection it reads as `OK` → token burn in the LLM
tier (Bug #18/#19).

**PRECISION-CRITICAL:** `CHALLENGE` requires a **body marker**. Headers may
corroborate but MUST NOT alone produce `CHALLENGE` — a legit 200 behind
`Server: cloudflare` stays `OK`.

### CHALLENGE_STRONG_MARKERS

Lowercase-compared. A body containing any of these is a CDN/WAF interstitial
**regardless of headers** — these are CDN-internal tokens that never appear
in legitimate page text (CodeRabbit #188).

| Marker | CDN/WAF |
|---|---|
| `cf-browser-verification` | Cloudflare |
| `challenge-platform` | Cloudflare |
| `_cf_chl_opt` | Cloudflare |
| `sucuri_cloudproxy` | Sucuri |

### CHALLENGE_WEAK_MARKERS

Lowercase-compared. A body containing any of these **requires** a
corroborating `CHALLENGE_HEADER_HINT` to produce `CHALLENGE` — these are
natural-language / brand-name strings that appear in legitimate pages
(CodeRabbit #188).

| Marker | CDN/WAF |
|---|---|
| `just a moment` | Cloudflare |
| `checking your browser` | Cloudflare / Sucuri |
| `incapsula` | Incapsula |
| `imperva` | Imperva |
| `access denied` | Akamai |
| `reference #` | Akamai |

### CHALLENGE_HEADER_HINTS

Corroborating only — never the sole trigger for `CHALLENGE`.

Each entry is `(header_name_lower, value_substr_lower)` where `""` means
header presence is enough.

| Header | Value substring | CDN/WAF |
|---|---|---|
| `server` | `cloudflare` | Cloudflare |
| `cf-ray` | *(presence)* | Cloudflare |
| `x-sucuri-id` | *(presence)* | Sucuri |
| `x-iinfo` | *(presence)* | Incapsula |
| `server` | `akamaighost` | Akamai |

### Precedence

```text
transport_error → BLOCKED(403/429/503) → EMPTY → CHALLENGE(body marker) → NOT_FOUND(404/410) → UNSUPPORTED_MEDIA_TYPE(415) → OK
```

`CHALLENGE` sits after `EMPTY` (so an empty body can't match) and before
`NOT_FOUND`/`UNSUPPORTED_MEDIA_TYPE`/`OK` (so a challenge body at 404 or 415
is still caught as a challenge, not misclassified).

## Condition Taxonomy (D3 Single-Source)

| Condition | Observed Signature | Expected Verdict | Fixture | Guarding Test |
|---|---|---|---|---|
| `cf_challenge` | Body contains Cloudflare/WAF interstitial marker | `Verdict.CHALLENGE` | `cf_challenge_body.txt` | `test_cf_challenge_no_llm.py::test_cf_challenge_200_never_burns_llm_tokens` |
| `identical_body` | Exact SHA-256 match of a previously seen `Verdict.OK` body | Short-circuit (No Tier Run) | `test_identical_body_dedup.py` inline bodies | `test_identical_body_dedup.py::test_identical_ok_body_is_analyzed_once` |
