# agent_alpha/conductor/engagement_profile.py
# Phase A1 — EngagementProfile: immutable, signed engagement metadata.
#
# Design (anti-#6 / event-sourcing):
#   Profiles are SUPERSEDED, never edited.  Each profile is serialised to
#   canonical JSON and SHA-256 hashed; any field change (including
#   authorized_origins) invalidates the signature.
#
#   authorized_origins is a frozenset embedded in the hash — a tampered
#   profile fails verify().

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from agent_alpha.live_fire.lab_guard import LAB_TARGET_ALLOWLIST

# ── Exceptions ────────────────────────────────────────────────


class OriginNotAuthorizedError(RuntimeError):
    """Raised when an origin-direct request is refused by the gate."""


# ── EngagementProfile ─────────────────────────────────────────


@dataclass(frozen=True)
class EngagementProfile:
    """Immutable, signed engagement metadata.

    ``canonical_json`` deterministically serialises every field; ``sha256``
    is the hex digest of that JSON.  Together they form the integrity
    envelope — any mutation (including adding/removing authorized_origins)
    changes the hash and fails ``verify()``.

    Profiles are superseded, never edited (event-sourcing §8o-1).
    """

    engagement_id: str
    client_id: str
    targets: frozenset[str] = frozenset()
    authorized_origins: frozenset[str] = frozenset()  # origin IPs client consented to hit direct

    # ── Signature helpers ─────────────────────────────────────

    def canonical_json(self) -> str:
        """Deterministic JSON representation — sorted keys, no whitespace."""
        payload = {
            "engagement_id": self.engagement_id,
            "client_id": self.client_id,
            "targets": sorted(self.targets),
            "authorized_origins": sorted(self.authorized_origins),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def sha256(self) -> str:
        """Hex digest of ``canonical_json``."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    def verify(self, expected_hash: str) -> bool:
        """Return True iff sha256() matches *expected_hash*."""
        return self.sha256() == expected_hash


# ── Origin-authorization gate (fail-closed) ───────────────────


def assert_origin_authorized(
    origin_ip: str,
    fronted_host: str,
    profile: EngagementProfile,
    lab_allowlist: frozenset[str] = LAB_TARGET_ALLOWLIST,
) -> None:
    """Fail-closed.  Origin-direct bypasses the client's WAF, so it is allowed
    ONLY when the origin IP is in the SIGNED authorized_origins AND the fronted
    host is a proven-owned target.  Distinct from lab_guard bare-IP refusal:
    an explicit, consented, auditable technique.

    Raises
    ------
    OriginNotAuthorizedError
        When the fronted host is not in the lab allowlist, or the origin IP
        is not in the profile's signed ``authorized_origins`.
    """
    if fronted_host not in lab_allowlist:
        raise OriginNotAuthorizedError(f"fronted host {fronted_host!r} not a proven-owned target")
    if origin_ip not in profile.authorized_origins:
        raise OriginNotAuthorizedError(
            f"origin {origin_ip!r} not in signed authorized_origins — hitting a client "
            f"origin bypasses their WAF; requires front-loaded consent (§12.36)."
        )
