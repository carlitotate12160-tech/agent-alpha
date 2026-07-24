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
from typing import Any

from agent_alpha.live_fire.lab_guard import LAB_TARGET_ALLOWLIST

# ── Exceptions ────────────────────────────────────────────────


class OriginNotAuthorizedError(RuntimeError):
    """Raised when an origin-direct request is refused by the gate."""


class ProfileSignatureError(RuntimeError):
    """Raised when an EngagementProfile's SHA-256 signature does not match.

    Distinct from ``OriginNotAuthorizedError`` (gate authz refusal): this is an
    integrity failure — the profile JSON was tampered with or corrupted after
    signing. The profile cannot be trusted at all, whereas an authz refusal
    simply means a *valid* profile does not authorize a given origin.
    """


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
    allow_evasion: bool = False  # client consented to browser_solve / evasion techniques

    # ── Signature helpers ─────────────────────────────────────

    def canonical_json(self) -> str:
        """Deterministic JSON representation — sorted keys, no whitespace."""
        payload = {
            "engagement_id": self.engagement_id,
            "client_id": self.client_id,
            "targets": sorted(self.targets),
            "authorized_origins": sorted(self.authorized_origins),
            "allow_evasion": self.allow_evasion,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def sha256(self) -> str:
        """Hex digest of ``canonical_json``."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    def verify(self, expected_hash: str) -> bool:
        """Return True iff sha256() matches *expected_hash*."""
        return self.sha256() == expected_hash


# ── Signed-profile serialisation / loader ─────────────────────


def dump_signed_profile(profile: EngagementProfile) -> dict[str, Any]:
    """Serialise *profile* to a signed envelope dict.

    Returns ``{"profile": {...}, "sha256": "<hex>"}``.  Callers persist this
    with ``json.dump`` — the resulting file is what ``--profile`` consumes.

    This is the symmetric writer for ``load_signed_profile`` — a loader with
    no writer is half-wired (anti-#2).
    """
    return {
        "profile": {
            "engagement_id": profile.engagement_id,
            "client_id": profile.client_id,
            "targets": sorted(profile.targets),
            "authorized_origins": sorted(profile.authorized_origins),
            "allow_evasion": profile.allow_evasion,
        },
        "sha256": profile.sha256(),
    }


def load_signed_profile(path: str) -> EngagementProfile:
    """Load and verify a signed EngagementProfile from *path*.

    Format: ``{"profile": {engagement_id, client_id, targets[],
    authorized_origins[]}, "sha256": "<hex>"}``.

    Raises ``ProfileSignatureError`` when the recorded sha256 does not match
    the profile's ``canonical_json`` — indicating the file was tampered with
    or corrupted after signing.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    profile_data = data["profile"]
    profile = EngagementProfile(
        engagement_id=profile_data["engagement_id"],
        client_id=profile_data["client_id"],
        targets=frozenset(profile_data.get("targets", [])),
        authorized_origins=frozenset(profile_data.get("authorized_origins", [])),
        allow_evasion=bool(profile_data.get("allow_evasion", False)),
    )

    if not profile.verify(data["sha256"]):
        raise ProfileSignatureError(
            "engagement profile signature mismatch — tampered or corrupt consent"
        )

    return profile


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
