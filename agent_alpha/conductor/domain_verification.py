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


def _parse_expected_token(expected_token: str) -> str:
    """Parse a DNS-TXT ownership token string.

    Accepts formats:
      - "dns-txt:agent-alpha=verified"  → "agent-alpha=verified"
      - "agent-alpha=verified"          → "agent-alpha=verified"
    """
    token = expected_token.strip()
    if token.startswith("dns-txt:"):
        token = token[len("dns-txt:"):]
    return token


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
        The domain to verify (e.g. "quantum-laboratories.com").
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
        raise DomainOwnershipError(
            f"empty ownership token for {domain!r} — cannot verify"
        )

    txt_records = dns_resolver.resolve_txt(domain)

    # Check if any TXT record contains the expected token.
    for record in txt_records:
        if token in record:
            return True

    return False
