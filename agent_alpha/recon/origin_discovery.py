"""Origin-discovery seam — A1 Slice B.

Defines the ``OriginDiscovery`` protocol that downstream slices depend on.
A lab stand-in injects a fixed list; production = real source (CT / Shodan /
DNS-history → IPs).

Candidate ≠ authorization: every candidate MUST still pass
``assert_origin_authorized`` before use (enforced in Slice C).

No network I/O in this module — pure seam interface.
"""

from __future__ import annotations

from typing import Protocol


class OriginDiscovery(Protocol):
    """Seam for discovering candidate origin IPs behind a fronted host."""

    def candidates(self, fronted_host: str) -> list[str]:
        """Return candidate origin IPs/hostnames for *fronted_host*.

        Sources in production: Certificate Transparency logs, Shodan,
        DNS history, etc.  In tests a stub injects a fixed list.
        """
        ...  # pragma: no cover


class StaticOriginDiscovery:
    """Fixed-list ``OriginDiscovery`` — lab/config stand-in for real
    CT/Shodan/DNS-history discovery (e.g. A1 field-prove).

    Authorization is NOT granted here: a returned candidate is only ACTED on
    if it is also in the signed ``EngagementProfile.authorized_origins``
    (Slice C, C9). This class merely stands in for the discovery step.
    """

    def __init__(self, candidates: list[str]) -> None:
        self._candidates = list(candidates)

    def candidates(self, fronted_host: str) -> list[str]:  # noqa: ARG002 (fixed lab list)
        return list(self._candidates)
