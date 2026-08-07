# agent_alpha/conductor/domain_verification.py
# Phase 6 — §12.36 domain ownership verification via DNS-TXT.
#
# A target may enter scope_targets ONLY if ownership is proven. This is the
# authorization proof — SEPARATE from the consent checklist. The consent
# checklist records what the client agreed to; DNS-TXT proves they actually
# control the domain.
#
# Reuses the DNS-TXT mechanism from lab_guard (anti-#6: no duplicate checker).
# The lab_guard ownership_proof strings ("dns-txt:token=value") are the same
# format used here for production targets.
#
# Fail-closed: if the dns_resolver is not provided, raises — ownership can
# NEVER be silently assumed.

from __future__ import annotations

from typing import Protocol


class DomainOwnershipError(RuntimeError):
    """Raised when domain ownership verification fails."""


class DNSResolver(Protocol):
    """Injectable DNS resolver seam for TXT record lookups.

    Production: wraps dnspython or socket.getaddrinfo-based lookup.
    Tests: a stub that returns canned TXT records.

    The seam ensures ownership is NEVER silently assumed — a real DNS
    lookup must occur, or a test stub must explicitly provide the record.
    """

    def resolve_txt(self, domain: str) -> list[str]:
        """Return all TXT record values for *domain*.

        Returns an empty list if no TXT records exist or the domain
        does not resolve. Never raises on DNS failures (returns []).
        """
        ...  # pragma: no cover


class _FailLoudResolver:
    """Default resolver that raises if no real resolver was injected.

    This ensures ownership can NEVER be silently assumed — callers MUST
    inject a real DNSResolver (or a test stub).
    """

    def resolve_txt(self, domain: str) -> list[str]:
        raise DomainOwnershipError(
            f"no DNS resolver injected — cannot verify ownership of {domain!r}. "
            f"Inject a DNSResolver (production: DnspythonResolver, tests: stub)."
        )


class DnspythonResolver:
    """Production DNS-TXT resolver backed by dnspython.

    Returns all TXT record values for a domain. On any DNS failure
    (NXDOMAIN, timeout, SERVFAIL) returns an empty list — fail-closed
    at the CALLER level (verify_domain_ownership returns False when no
    matching TXT record is found).
    """

    def resolve_txt(self, domain: str) -> list[str]:
        import dns.resolver

        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
            return [b"".join(r.strings).decode() for r in answers]
        except Exception:  # noqa: BLE001 — any DNS error = no records
            return []

    # §12.48 slice-3: passive DNS enrichment records. Fail-open ([] on any DNS
    # error) — enrichment is recon signal, NEVER a security gate, so a missing
    # record must degrade gracefully, not block the engagement (unlike ownership
    # TXT which is fail-closed at the caller). These live on the ONE production
    # resolver (anti-#6: no second DNS resolver type); the ownership DNSResolver
    # Protocol stays TXT-only so its fail-closed stubs are untouched.

    def resolve_mx(self, domain: str) -> list[str]:
        import dns.resolver

        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
            return sorted(str(r.exchange).rstrip(".").lower() for r in answers)
        except Exception:  # noqa: BLE001 — any DNS error = no records (fail-open)
            return []

    def resolve_ns(self, domain: str) -> list[str]:
        import dns.resolver

        try:
            answers = dns.resolver.resolve(domain, "NS", lifetime=5.0)
            return sorted(str(r.target).rstrip(".").lower() for r in answers)
        except Exception:  # noqa: BLE001 — any DNS error = no records (fail-open)
            return []


def _parse_expected_token(expected_token: str) -> str:
    """Parse a DNS-TXT ownership token string.

    Accepts formats:
      - "dns-txt:agent-alpha=verified"  → "agent-alpha=verified"
      - "agent-alpha=verified"          → "agent-alpha=verified"
    """
    token = expected_token.strip()
    if token.startswith("dns-txt:"):
        token = token[len("dns-txt:") :]
    return token


def _normalise_target(raw: str) -> str:
    """Strip whitespace, lowercase, and strip trailing dot (anti-SSR/trailing-dot)."""
    return raw.strip().lower().rstrip(".")


def verify_domain_ownership(
    domain: str,
    expected_token: str,
    dns_resolver: DNSResolver | None = None,
) -> bool:
    """Verify that *domain* has a DNS-TXT record matching *expected_token*.

    The token format is ``dns-txt:key=value`` (or bare ``key=value``).
    The function queries TXT records for *domain* and checks if any
    record value contains the expected token string.

    Fail-closed: if *dns_resolver* is None, raises DomainOwnershipError.
    Returns True only if a matching TXT record is found.

    Parameters
    ----------
    domain : str
        The domain to verify (e.g. "example.com").
    expected_token : str
        The expected DNS-TXT token (e.g. "dns-txt:agent-alpha=abc123").
    dns_resolver : DNSResolver | None
        Injectable DNS resolver. MUST be provided — None raises.

    Returns
    -------
    bool
        True if ownership is proven, False if no matching TXT record.

    Raises
    ------
    DomainOwnershipError
        If no DNS resolver is injected (fail-loud).
    """
    if dns_resolver is None:
        # Use the fail-loud resolver — it will raise.
        dns_resolver = _FailLoudResolver()

    token = _parse_expected_token(expected_token)
    if not token:
        raise DomainOwnershipError(f"empty ownership token for {domain!r} — cannot verify")

    txt_records = dns_resolver.resolve_txt(domain)

    # Check if any TXT record exactly matches the expected token.
    for record in txt_records:
        clean_record = record.strip(" \t\"'")
        if clean_record == token:
            return True

    return False
