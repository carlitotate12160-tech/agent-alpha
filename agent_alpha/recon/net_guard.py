# agent_alpha/recon/net_guard.py
"""SSRF destination guard (CWE-918) — single-source IP routability classifier.

Blocks loopback, RFC1918, link-local (incl. cloud metadata 169.254.169.254),
multicast, reserved, unspecified, and org-excluded networks. Reused by
conductor.recon_runner._screen_host (host-resolve path) and
recon.origin_binding.verify_origin_binding (raw-IP path). Anti-#6/#7."""

from __future__ import annotations

import ipaddress

from agent_alpha.config import constants

_EXCLUDED_NETWORKS = [ipaddress.ip_network(c) for c in constants.SCOPE_ALWAYS_EXCLUDED]


def is_internal_ip(ip_str: str) -> bool:
    """True iff *ip_str* is a non-routable / internal / excluded destination.

    Fail-closed: an unparseable literal is treated as internal (blocked)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    return any(ip in net for net in _EXCLUDED_NETWORKS)
