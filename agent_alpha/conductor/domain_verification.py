# agent_alpha/conductor/domain_verification.py
# Phase A1 — DNS-TXT domain ownership verification.
#
# Design:
#   Before authorizing targets in an EngagementProfile, the Conductor verifies
#   that the client controls each target domain by querying a DNS-TXT record
#   for an expected ownership token.  The match is EXACT (full string equality
#   after stripping surrounding quotes and whitespace) — NO substring acceptance
#   (#3 fix, anti-CWE-284).
#
#   _normalise_target strips trailing dots (#7 fix) so evil.com. cannot bypass
#   the guardrail.

from __future__ import annotations

from typing import Protocol, runtime_checkable


# ── Exceptions ────────────────────────────────────────────────


class DomainOwnershipError(RuntimeError):
    """Raised when domain ownership verification fails."""


# ── DNS resolver protocol (injectable seam) ───────────────────


@runtime_checkable
class DNSResolver(Protocol):
    """Injectable DNS resolver for TXT record lookups.

    Fail-loud default: if no resolver is injected, ``verify_domain_ownership``
    raises — ownership is NEVER silently assumed.
    """

    def resolve_txt(self, domain: str) -> list[str]:
        """Return all TXT record values for *domain*."""
        ...


# ── Target normalisation ─────────────────────────────────────


def _normalise_target(raw: str) -> str:
    """Normalise a target hostname.

    - Strips surrounding whitespace.
    - Lowercases.
    - Strips trailing dot (#7 fix: ``evil.com.`` → ``evil.com``).

    Normalise BEFORE ownership verification and BEFORE storing in
    ``verified_targets`` / ``scope_targets`` (#5 fix).
    """
    return raw.strip().lower().rstrip(".")


# ── Domain ownership verification ────────────────────────────


def verify_domain_ownership(
    domain: str,
    expected_token: str,
    resolver: DNSResolver | None,
) -> str:
    """Verify ownership of *domain* via DNS-TXT record.

    Returns the **normalised** domain on success.

    Raises :class:`DomainOwnershipError` on:
      - No resolver injected (fail-loud — ownership NEVER silently assumed).
      - Token not found in any TXT record.
      - TXT record contains the token as a substring but not an exact match
        (#3 fix: no substring acceptance).

    Each TXT record value is stripped of surrounding quotes and whitespace
    before comparison.  The comparison is full-string ``==`` — NEVER ``in``.
    """
    if resolver is None:
        raise DomainOwnershipError(
            "no DNS resolver injected — domain ownership cannot be verified "
            "(fail-loud: ownership is NEVER silently assumed)"
        )

    normalised = _normalise_target(domain)
    token = expected_token.strip()

    try:
        txt_records = resolver.resolve_txt(normalised)
    except Exception as exc:
        raise DomainOwnershipError(
            f"DNS-TXT lookup failed for {normalised!r}: {exc}"
        ) from exc

    for record in txt_records:
        # Strip surrounding quotes and whitespace from each TXT value.
        cleaned = record.strip().strip('"').strip("'").strip()
        # EXACT full-string equality — NOT substring (#3 fix).
        if cleaned == token:
            return normalised

    raise DomainOwnershipError(
        f"ownership token not found in DNS-TXT records for {normalised!r} "
        f"(checked {len(txt_records)} record(s), exact match required)"
    )
