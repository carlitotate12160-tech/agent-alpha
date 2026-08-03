# agent_alpha/recon/origin_binding.py
# §12.46 — Token-only origin-binding verification.
#
# Pure, deterministic verifier: proves that an origin IP serves the OWNED
# fronted_host by fetching a per-engagement ownership token IP-direct with
# a Host header.  A co-tenant CANNOT serve the client's token → binding
# proven iff the token body echoes.
#
# Token-only this slice (no cert-SAN corroboration — deferred).
# Fail-closed: any error / mismatch → False.

from __future__ import annotations

from agent_alpha.recon.net_guard import is_internal_ip
from agent_alpha.recon.reach_transport import origin_direct_fetch

WELL_KNOWN_TOKEN_PATH = "/.well-known/agent-alpha-{token}.txt"


def verify_origin_binding(
    *,
    origin_ip: str,
    fronted_host: str,
    ownership_token: str,
) -> bool:
    """P2 (§12.46): prove ``origin_ip`` serves the OWNED ``fronted_host``
    by fetching the per-engagement ownership token IP-direct with a Host
    header.

    A co-tenant cannot serve the client's token → binding proven iff the
    token body echoes.  Token-only (no cert read); cert-SAN corroboration
    is a later slice.

    Rejects internal/metadata IPs BEFORE connecting (SSRF guard, CWE-918) —
    candidates come from DNS and are untrusted.

    Fail-closed: any error / mismatch → False.
    """
    if not origin_ip or not fronted_host or not ownership_token:
        return False

    if is_internal_ip(origin_ip):
        return False

    path = WELL_KNOWN_TOKEN_PATH.format(token=ownership_token)
    try:
        result = origin_direct_fetch(fronted_host, origin_ip, path)
    except RuntimeError:
        return False

    if result.status_code != 200:
        return False

    return ownership_token in (result.body or "")
