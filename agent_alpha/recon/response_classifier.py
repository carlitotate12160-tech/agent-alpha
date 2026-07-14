# agent_alpha/recon/response_classifier.py
"""ONE canonical response classifier for the recon layer (R3 slice-1).

Every recon path — the core OBSERVE loop in ``scout.step`` and the individual
probes (``js_secret_probe``, ``odoo_dbmanager_probe``) — routes its HTTP
responses through :func:`classify_response` so the WAF/CF block rule has a
SINGLE source of truth (anti-Lyndon #7) and a block is never silently dressed
as "clean" (anti-Lyndon #3).

The verdict is deliberately conservative and status-only in slice-1: a 200 with
a real body is ``OK`` and is NEVER ``BLOCKED``, even if the body happens to
contain the word "forbidden". Only the block status codes (403 / 429 / 503)
carry the ``BLOCKED`` verdict.

PURE: no I/O, no logging, no side effects — a plain function of its arguments.
"""

from __future__ import annotations

import enum


class Verdict(enum.StrEnum):
    """The canonical classification of a fetched recon response."""

    OK = "ok"
    EMPTY = "empty"
    NOT_FOUND = "not_found"
    TRANSPORT_FAIL = "transport_fail"
    BLOCKED = "blocked"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"


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


def classify_response(
    *,
    status_code: int,
    body: str,
    transport_error: bool = False,
) -> Verdict:
    """Classify a fetched recon response into a single :class:`Verdict`.

    Precedence (most-decisive first):
      1. ``transport_error`` (host down, DNS, connect/read timeout) -> ``TRANSPORT_FAIL``.
      2. status in (403, 429, 503) -> ``BLOCKED`` (a block is evidence, not "clean").
      3. empty / whitespace-only body -> ``EMPTY`` (reachable but non-analyzable).
      4. status in (404, 410) WITH a body -> ``NOT_FOUND`` (missing path; the
         RULE tier may still look — a debug/error page can leak on a 404 — but it
         is NEVER escalated to the LLM, unlike ``OK`` (F2 token-burn guard).
      5. status == 415 WITH a body -> ``UNSUPPORTED_MEDIA_TYPE`` (Bug #10 — an
         origin content-negotiation rejection, e.g. Cloudways/WP without an
         Accept header. NOT a WAF block, NOT the target's real content — never
         escalated to the LLM AND never given to the RULE tier, unlike NOT_FOUND,
         because the body is the origin's generic error page and matching a
         playbook rule against it reproduces Bug #2/#14's page-wide-marker
         false-positive pattern).
      6. otherwise -> ``OK``.

    Conservative by design: a 200 with a real body is ``OK`` and is never
    ``BLOCKED`` — only the status code carries the block verdict in slice-1.
    """
    if transport_error:
        return Verdict.TRANSPORT_FAIL
    if status_code in _BLOCK_STATUS_CODES:
        return Verdict.BLOCKED
    if not body or not body.strip():
        return Verdict.EMPTY
    if status_code in _NOT_FOUND_STATUS_CODES:
        return Verdict.NOT_FOUND
    if status_code in _UNSUPPORTED_MEDIA_TYPE_STATUS_CODES:
        return Verdict.UNSUPPORTED_MEDIA_TYPE
    return Verdict.OK
