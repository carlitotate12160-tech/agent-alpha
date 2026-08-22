# agent_alpha/recon/response_classifier.py
"""ONE canonical response classifier for the recon layer (R3 slice-1).

Every recon path — the core OBSERVE loop in ``scout.step`` and the individual
probes (``js_secret_probe``, ``odoo_dbmanager_probe``) — routes its HTTP
responses through :func:`classify_response` so the WAF/CF block rule has a
SINGLE source of truth (anti-Lyndon #7) and a block is never silently dressed
as "clean" (anti-Lyndon #3).

A 200 with a real body is ``OK`` and is NEVER ``BLOCKED``, even if the body
happens to contain the word "forbidden". Only the block status codes
(403 / 429 / 503) carry the ``BLOCKED`` verdict. The one exception is a CDN/WAF
interstitial page (Cloudflare "Just a moment…", Sucuri, Incapsula, Akamai)
served at HTTP 200: the body-marker-gated ``CHALLENGE`` verdict catches it
before it can reach ``OK`` and burn LLM tokens (ADR §12.27 D1, Bug #18/#19).

PURE: no I/O, no logging, no side effects — a plain function of its arguments.
"""

from __future__ import annotations

import enum
import re


class Verdict(enum.StrEnum):
    """The canonical classification of a fetched recon response."""

    OK = "ok"
    EMPTY = "empty"
    NOT_FOUND = "not_found"
    TRANSPORT_FAIL = "transport_fail"
    BLOCKED = "blocked"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    CHALLENGE = "challenge"


# --- CHALLENGE detection (ADR §12.27 D1) --------------------------------------
#
# A CDN/WAF interstitial page (Cloudflare "Just a moment...", Sucuri, Incapsula,
# Akamai) served at HTTP 200 is a challenge, not real content.  Without detection
# it reads as OK → token burn in the LLM tier (Bug #18/#19).
#
# SINGLE source of truth (anti-#7): the constants below are the only place these
# patterns live. docs/RECON_CONDITION_CATALOG.md mirrors them as documentation.
#
# PRECISION-CRITICAL: a CHALLENGE verdict requires a BODY marker. Headers may
# corroborate but MUST NOT alone produce CHALLENGE — a legit 200 behind
# Server: cloudflare stays OK (the FP landmine).
#
# R2 tiering (CodeRabbit #3/#4): markers are split into STRONG (body alone
# suffices) and WEAK (need a corroborating header hint).  This prevents
# "access denied" / "reference #" in legitimate article text from false-
# triggering CHALLENGE (the reflection / self-DoS landmine).

# STRONG body markers — lowercase-compared. A body containing any of these is a
# CDN/WAF interstitial regardless of headers.  These are CDN-internal tokens
# that never appear in legitimate page text (CodeRabbit #188).
#
# NOTE: ``challenge-platform`` is NOT here — CF injects that string into ALL
# proxied sites via its analytics/beacon script, so it false-positives on
# legitimate content.  It is handled separately with a body-size guard below.
CHALLENGE_STRONG_MARKERS: frozenset[str] = frozenset(
    {
        "cf-browser-verification",
        "_cf_chl_opt",
        "sucuri_cloudproxy",
    }
)

# ``challenge-platform`` is a CF-internal script path that appears in both
# interstitial challenge pages AND legitimate CF-proxied sites (CF injects
# it via its analytics/beacon script).  Only treat it as a strong marker
# when the body is small enough to be an interstitial page.  Real content
# pages are typically > 5 KB; CF interstitial pages are typically < 5 KB.
_CHALLENGE_PLATFORM_MARKER = "challenge-platform"
_CHALLENGE_MAX_INTERSTITIAL_BODY = 5000

# WEAK body markers — require a corroborating :data:`CHALLENGE_HEADER_HINT`.
# These are natural-language / brand-name strings ("just a moment",
# "checking your browser", "incapsula", "imperva", "access denied",
# "reference #") that appear in legitimate pages; they only produce CHALLENGE
# when a vendor header is present (CodeRabbit #188).
CHALLENGE_WEAK_MARKERS: frozenset[str] = frozenset(
    {
        "just a moment",
        "checking your browser",
        "incapsula",
        "imperva",
        "access denied",
        "reference #",
    }
)

# Header hints — corroborating ONLY. Presence of any hint RAISES confidence but
# NEVER alone produces CHALLENGE.  Each entry is (header_name_lower,
# value_substr_lower) where "" means "header presence is enough".
# A name ending in "*" is a prefix match (e.g. "x-akamai-*").
CHALLENGE_HEADER_HINTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("server", "cloudflare"),
        ("cf-ray", ""),
        ("x-sucuri-id", ""),
        ("x-iinfo", ""),
        ("server", "akamaighost"),
        ("x-akamai-*", ""),
    }
)

# Volatile headers that MUST NOT enter the body-dedup hash key (Bug #20).
# Hashing these would defeat dedup entirely — every request has a different
# CF-Ray / Date / Set-Cookie.  scout.py imports this for its dedup whitelist.
VOLATILE_HEADERS: frozenset[str] = frozenset(
    {"cf-ray", "date", "set-cookie", "age", "x-request-id"}
)

# Block status codes: WAF/CF/rate-limit/challenge signals. Recorded as evidence
# (WAF_BLOCKED), never as "clean / not vulnerable".
_BLOCK_STATUS_CODES: frozenset[int] = frozenset({403, 429, 503})

# Missing-path status. A 404 WITH a body would otherwise read as OK and get
# escalated to the LLM tier (pure token burn on a path that is not there — F2).
# Checked AFTER the empty check so a 404 with an empty body stays EMPTY (zero
# behaviour change); only a 404 that carries a body becomes NOT_FOUND.
_NOT_FOUND_STATUS_CODES: frozenset[int] = frozenset({404, 410})

# Content-negotiation rejection (Bug #10). Observed from Cloudways/WP origins
# when the client sends no Accept header — the ORIGIN's error page, not a
# WAF/CDN block, so it must NEVER become BLOCKED (that would mis-record a
# content-negotiation quirk as WAF_BLOCKED evidence — corrupts the audit
# trail, see graph/persist.py's provenance argument for the same principle).
# It also must never fall through to OK: the body is the origin's generic
# error page, not the target's real content, and matching a playbook rule
# against it is exactly the false-positive pattern Bug #2/#14 already show
# (page-wide markers hit inside an unrelated error page).
_UNSUPPORTED_MEDIA_TYPE_STATUS_CODES: frozenset[int] = frozenset({415})


# --- Reload-shell cost-gate hint (ADR §12.41) ---------------------------------
#
# A cheap, safe boolean hint for the reach layer — NOT a Verdict.  This hint
# lets ``scout._classify_host_reach`` decide whether to spend one browser
# probe.  No delay parsing, no int(), no counting.
# Byte (not character) threshold — use _body_size_bytes() for comparisons.
RELOAD_SHELL_MAX_BYTES = 15000


def _body_size_bytes(body: str) -> int:
    """Return the UTF-8 byte size of *body*.

    HTTP response sizes are byte counts; ``len(str)`` counts Unicode code
    points. Non-ASCII content can be many bytes per code point, so use the
    encoded byte length for size thresholds named in bytes.
    """
    return len(body.encode("utf-8"))


def is_reload_shell(body: str) -> bool:
    """Return True if *body* looks like a thin reload/refresh shell.

    This is a COST-GATE hint for the reach layer only — never a verdict.
    A small body with a ``location.reload()`` or ``<meta http-equiv="refresh">``
    signal is *suspicious* and may warrant a browser probe.
    """
    b = body.lower()
    return _body_size_bytes(body) < RELOAD_SHELL_MAX_BYTES and (
        "location.reload(" in b or 'http-equiv="refresh"' in b or "http-equiv='refresh'" in b
    )


# --- Reload-interstitial detection (CF soft-200) -----------------------------
#
# Cloudflare can serve a soft-200 interstitial ("One moment, please...") whose
# primary behavior is an automatic ``setTimeout`` + ``location.reload()`` or a
# short ``<meta http-equiv="refresh">``.  It carries NO CDN-internal token
# (no ``cf-browser-verification``, no ``_cf_chl_opt``) so the STRONG markers
# miss it.  This STRUCTURAL detector catches it without adding any natural-
# language phrase to CHALLENGE_STRONG_MARKERS (CodeRabbit #188 principle).
#
# Conservative: requires BOTH a reload signal AND the absence of substantive
# anchor content.  A legitimate page that uses meta-refresh or setTimeout but
# carries real content (anchors, articles) stays OK.
_RELOAD_INTERSTITIAL_MAX_ANCHORS = 3
_RELOAD_INTERSTITIAL_MAX_META_REFRESH_DELAY = 5  # seconds

_META_REFRESH_RE: re.Pattern[str] = re.compile(
    r'<meta\s+http-equiv=["\']?refresh["\']?\s+content=["\']?(\d+)\s*;',
    re.IGNORECASE,
)


def _is_reload_interstitial(body: str) -> bool:
    """Return True if the body's primary behavior is an automatic reload/redirect
    AND it lacks real content.

    Detects CDN/WAF soft-200 interstitial pages (e.g. Cloudflare "One moment,
    please...") that use ``setTimeout`` + ``location.reload()`` or a short
    ``<meta http-equiv="refresh">`` to redirect the browser, while serving no
    substantive content to a non-browser client.

    Conservative: requires BOTH a reload signal AND the absence of substantive
    anchor content (fewer than N ``<a`` tags AND no ``<article`` marker). A
    legitimate page that happens to use meta-refresh or setTimeout but carries
    real content stays OK.

    SIZE GATE (field-confirmed on a 200 catch-all SPA target): a genuine soft-200
    reload interstitial ("One moment, please...") is SMALL. A large body is
    application content that merely SHIPS a reload signal (SPA bundles routinely
    inline setTimeout/location.reload). Without this gate a large 200 catch-all
    SPA shell (field-observed example: ~361 KB) false-CHALLENGEs, which
    short-circuits scout.py's soft-404 catch-all suppression (the CHALLENGE branch
    returns _handle_waf_block BEFORE _is_soft404 runs) and makes recon never
    converge. Mirror is_reload_shell's size gate — single source
    RELOAD_SHELL_MAX_BYTES (anti-#7).
    """
    if _body_size_bytes(body) >= RELOAD_SHELL_MAX_BYTES:
        return False

    body_lower = body.lower()

    has_js_reload = "settimeout" in body_lower and "location.reload(" in body_lower

    has_meta_refresh = False
    for m in _META_REFRESH_RE.finditer(body):
        delay = int(m.group(1))
        if delay <= _RELOAD_INTERSTITIAL_MAX_META_REFRESH_DELAY:
            has_meta_refresh = True
            break

    if not has_js_reload and not has_meta_refresh:
        return False

    anchor_count = body_lower.count("<a ")
    has_article = "<article" in body_lower

    return anchor_count < _RELOAD_INTERSTITIAL_MAX_ANCHORS and not has_article


def _is_challenge(body: str, headers: dict[str, str] | None) -> bool:
    """Return True if body matches CHALLENGE rules.

    Rule: CHALLENGE iff (any STRONG body marker) OR (``challenge-platform``
    present AND body is small enough to be an interstitial) OR (any WEAK body
    marker AND any header hint present).  ``headers=None`` is treated as no
    headers — weak markers alone never trigger CHALLENGE.
    """
    body_lower = body.lower()
    if any(marker in body_lower for marker in CHALLENGE_STRONG_MARKERS):
        return True
    # challenge-platform: only strong for small (interstitial) bodies.
    # CF injects this string into all proxied sites; a large body with this
    # marker is real content, not a challenge page.
    if _CHALLENGE_PLATFORM_MARKER in body_lower and len(body) < _CHALLENGE_MAX_INTERSTITIAL_BODY:
        return True
    if _is_reload_interstitial(body):
        return True
    if any(marker in body_lower for marker in CHALLENGE_WEAK_MARKERS):
        return _has_challenge_header_hint(headers)
    return False


def _has_challenge_header_hint(headers: dict[str, str] | None) -> bool:
    """Return True if *headers* contain any :data:`CHALLENGE_HEADER_HINT`.

    Corroborating only — never used as the sole trigger for CHALLENGE.
    """
    if not headers:
        return False
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for name, substr in CHALLENGE_HEADER_HINTS:
        if name.endswith("*"):
            prefix = name[:-1]
            if any(
                k.startswith(prefix) and (not substr or substr in v)
                for k, v in headers_lower.items()
            ):
                return True
        else:
            if name in headers_lower and (not substr or substr in headers_lower[name]):
                return True
    return False


def classify_response(
    *,
    status_code: int,
    body: str,
    headers: dict[str, str] | None = None,
    transport_error: bool = False,
) -> Verdict:
    """Classify a fetched recon response into a single :class:`Verdict`.

    Precedence (most-decisive first):
      1. ``transport_error`` (host down, DNS, connect/read timeout) -> ``TRANSPORT_FAIL``.
      2. status in (403, 429, 503) -> ``BLOCKED`` (a block is evidence, not "clean").
      3. empty / whitespace-only body -> ``EMPTY`` (reachable but non-analyzable).
      4. body contains a :data:`CHALLENGE_STRONG_MARKER` -> ``CHALLENGE``, or
         body contains a :data:`CHALLENGE_WEAK_MARKER` AND a
         :data:`CHALLENGE_HEADER_HINT` is present -> ``CHALLENGE`` (a CDN/WAF
         interstitial at any status incl. 200; non-analyzable — no LLM, no
         frontier, no asset, but a WAF/CF audit event IS recorded). Headers may
         corroborate but NEVER alone produce CHALLENGE (a legit 200 behind
         Server: cloudflare stays OK).
      5. status in (404, 410) WITH a body -> ``NOT_FOUND`` (missing path; the
         RULE tier may still look — a debug/error page can leak on a 404 — but it
         is NEVER escalated to the LLM, unlike ``OK`` (F2 token-burn guard).
      6. status == 415 WITH a body -> ``UNSUPPORTED_MEDIA_TYPE`` (Bug #10 — an
         origin content-negotiation rejection, e.g. Cloudways/WP without an
         Accept header. NOT a WAF block, NOT the target's real content — never
         escalated to the LLM AND never given to the RULE tier, unlike NOT_FOUND,
         because the body is the origin's generic error page and matching a
         playbook rule against it reproduces Bug #2/#14's page-wide-marker
         false-positive pattern).
      7. otherwise -> ``OK``.

    Backward-compatible: omitting ``headers`` reproduces today's verdicts
    byte-for-byte (the CHALLENGE check is body-marker-gated and only fires on
    bodies containing a CDN/WAF interstitial marker — a case that was previously
    a false-OK / token burn, now correctly caught).

    PURE: no I/O, no logging, no side effects — a plain function of its arguments.
    """
    if transport_error:
        return Verdict.TRANSPORT_FAIL
    if status_code in _BLOCK_STATUS_CODES:
        return Verdict.BLOCKED
    if not body or not body.strip():
        return Verdict.EMPTY
    if _is_challenge(body, headers):
        return Verdict.CHALLENGE
    if status_code in _NOT_FOUND_STATUS_CODES:
        return Verdict.NOT_FOUND
    if status_code in _UNSUPPORTED_MEDIA_TYPE_STATUS_CODES:
        return Verdict.UNSUPPORTED_MEDIA_TYPE
    return Verdict.OK


def is_json_response(content_type: str, body: str) -> bool:
    """True iff the response is JSON-shaped.

    A lying/absent Content-Type is tolerated by also inspecting the body's
    first non-space byte, so a WAF/reach path that strips the header does
    not misclassify a real JSON index as HTML.
    """
    if "json" in content_type.lower():
        return True
    return body.lstrip()[:1] in ("{", "[")
