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
    TRANSPORT_FAIL = "transport_fail"
    BLOCKED = "blocked"


# Block status codes: WAF/CF/rate-limit/challenge signals. Recorded as evidence
# (WAF_BLOCKED), never as "clean / not vulnerable".
_BLOCK_STATUS_CODES: frozenset[int] = frozenset({403, 429, 503})


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
      4. otherwise -> ``OK``.

    Conservative by design: a 200 with a real body is ``OK`` and is never
    ``BLOCKED`` — only the status code carries the block verdict in slice-1.
    """
    if transport_error:
        return Verdict.TRANSPORT_FAIL
    if status_code in _BLOCK_STATUS_CODES:
        return Verdict.BLOCKED
    if not body or not body.strip():
        return Verdict.EMPTY
    return Verdict.OK
