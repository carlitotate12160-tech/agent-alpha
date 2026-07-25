# agent_alpha/conductor/engagement_profile.py
# Phase A1 — EngagementProfile: immutable, keyed-HMAC signed engagement metadata.
#
# Design (anti-#6 / event-sourcing):
#   Profiles are SUPERSEDED, never edited.  Each profile is serialised to
#   canonical JSON and HMAC-SHA-256 signed with a server-held secret key;
#   any field change (including authorized_origins, consent, authorization_level)
#   invalidates the signature.
#
#   Integrity is KEYED — an attacker without the key cannot forge a valid
#   envelope.  The old unkeyed SHA-256 path is REMOVED (CWE-347 fix).
#   Legacy envelopes carrying a "sha256" field are REJECTED fail-closed.

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
from typing import Any

from agent_alpha.live_fire.lab_guard import LAB_TARGET_ALLOWLIST

# ── Exceptions ────────────────────────────────────────────────


class OriginNotAuthorizedError(RuntimeError):
    """Raised when an origin-direct request is refused by the gate."""


class ProfileSignatureError(RuntimeError):
    """Raised when an EngagementProfile's HMAC signature does not match,
    or the envelope is malformed (missing ``hmac``, legacy ``sha256`` present).

    Distinct from ``OriginNotAuthorizedError`` (gate authz refusal): this is an
    integrity failure — the profile JSON was tampered with or corrupted after
    signing. The profile cannot be trusted at all, whereas an authz refusal
    simply means a *valid* profile does not authorize a given origin.
    """


class ProfileSigningKeyError(RuntimeError):
    """Raised when the HMAC signing key is absent or invalid."""


# ── ConsentRecord ─────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class ConsentRecord:
    """Immutable record of human-verified consent for elevated authorization.

    ``accepted_items`` enumerates the specific capabilities / scope items the
    human signer consented to.  ``signed_by`` and ``signed_at`` provide
    audit provenance.  All fields are embedded in the profile's
    ``canonical_json`` so any mutation invalidates the HMAC.
    """

    accepted_items: frozenset[str]
    signed_by: str
    signed_at: str


# ── EngagementProfile ─────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class EngagementProfile:
    """Immutable, HMAC-signed engagement metadata.

    ``canonical_json`` deterministically serialises every field; ``sign(key)``
    produces the HMAC-SHA-256 hex digest of that JSON.  Together they form
    the integrity envelope — any mutation (including adding/removing
    authorized_origins, changing authorization_level, or altering consent)
    changes the HMAC and fails ``verify_sig()``.

    Profiles are superseded, never edited (event-sourcing §8o-1).

    The old unkeyed ``sha256()`` / ``verify()`` methods are REMOVED.
    Use ``sign(key)`` and ``verify_sig(sig, key)`` exclusively.
    """

    engagement_id: str
    client_id: str
    targets: frozenset[str] = frozenset()
    authorized_origins: frozenset[str] = frozenset()  # origin IPs client consented to hit direct
    allow_evasion: bool = False  # client consented to browser_solve / evasion techniques
    # ── New fields (§12.36 consent gate + integrity hardening) ──
    authorization_level: str = "RECON_ONLY"
    scope_targets: frozenset[str] = frozenset()
    opsec_stealth: bool = False
    consent: ConsentRecord | None = None

    # ── Signature helpers ─────────────────────────────────────

    def canonical_json(self) -> str:
        """Deterministic JSON representation — sorted keys, no whitespace."""
        consent_payload = None
        if self.consent is not None:
            consent_payload = {
                "accepted_items": sorted(self.consent.accepted_items),
                "signed_by": self.consent.signed_by,
                "signed_at": self.consent.signed_at,
            }
        payload = {
            "engagement_id": self.engagement_id,
            "client_id": self.client_id,
            "targets": sorted(self.targets),
            "authorized_origins": sorted(self.authorized_origins),
            "allow_evasion": self.allow_evasion,
            "authorization_level": self.authorization_level,
            "scope_targets": sorted(self.scope_targets),
            "opsec_stealth": self.opsec_stealth,
            "consent": consent_payload,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def sign(self, key: bytes) -> str:
        """HMAC-SHA-256 hex digest of ``canonical_json``, keyed by *key*."""
        return hmac.new(key, self.canonical_json().encode(), hashlib.sha256).hexdigest()

    def verify_sig(self, sig: str, key: bytes) -> bool:
        """Return True iff *sig* matches ``sign(key)`` (constant-time compare)."""
        return hmac.compare_digest(self.sign(key), sig)


# ── Signed-profile serialisation / loader ─────────────────────


def dump_signed_profile(profile: EngagementProfile, *, key: bytes) -> dict[str, Any]:
    """Serialise *profile* to a keyed-HMAC signed envelope dict.

    Returns ``{"profile": {...}, "hmac": "<hex>"}``.  Callers persist this
    with ``json.dump`` — the resulting file is what ``--profile`` consumes.

    This is the symmetric writer for ``load_signed_profile`` — a loader with
    no writer is half-wired (anti-#2).

    The old ``sha256`` field is NEVER emitted.  Legacy envelopes are rejected
    by ``load_signed_profile`` (fail-closed).
    """
    consent_data = None
    if profile.consent is not None:
        consent_data = {
            "accepted_items": sorted(profile.consent.accepted_items),
            "signed_by": profile.consent.signed_by,
            "signed_at": profile.consent.signed_at,
        }
    return {
        "profile": {
            "engagement_id": profile.engagement_id,
            "client_id": profile.client_id,
            "targets": sorted(profile.targets),
            "authorized_origins": sorted(profile.authorized_origins),
            "allow_evasion": profile.allow_evasion,
            "authorization_level": profile.authorization_level,
            "scope_targets": sorted(profile.scope_targets),
            "opsec_stealth": profile.opsec_stealth,
            "consent": consent_data,
        },
        "hmac": profile.sign(key),
    }


def load_signed_profile(path: str, *, key: bytes) -> EngagementProfile:
    """Load and verify a keyed-HMAC signed EngagementProfile from *path*.

    Format: ``{"profile": {...}, "hmac": "<hex>"}``.

    Fail-closed rejection:
      - Missing ``hmac`` field → ``ProfileSignatureError``.
      - Legacy ``sha256`` field present → ``ProfileSignatureError``
        (unkeyed envelopes are NEVER silently accepted).
      - HMAC mismatch → ``ProfileSignatureError``.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    # ── Fail-closed: reject legacy unkeyed envelopes ──────────
    if "sha256" in data:
        raise ProfileSignatureError(
            "legacy unkeyed sha256 envelope rejected — re-sign with "
            "HMAC-SHA-256 via scripts/sign_profile.py"
        )
    if "hmac" not in data:
        raise ProfileSignatureError(
            "envelope missing 'hmac' field — not a signed profile"
        )

    profile_data = data["profile"]

    # Reconstruct ConsentRecord if present.
    consent = None
    consent_data = profile_data.get("consent")
    if consent_data is not None:
        consent = ConsentRecord(
            accepted_items=frozenset(consent_data.get("accepted_items", [])),
            signed_by=consent_data["signed_by"],
            signed_at=consent_data["signed_at"],
        )

    profile = EngagementProfile(
        engagement_id=profile_data["engagement_id"],
        client_id=profile_data["client_id"],
        targets=frozenset(profile_data.get("targets", [])),
        authorized_origins=frozenset(profile_data.get("authorized_origins", [])),
        allow_evasion=bool(profile_data.get("allow_evasion", False)),
        authorization_level=profile_data.get("authorization_level", "RECON_ONLY"),
        scope_targets=frozenset(profile_data.get("scope_targets", [])),
        opsec_stealth=bool(profile_data.get("opsec_stealth", False)),
        consent=consent,
    )

    if not profile.verify_sig(data["hmac"], key):
        raise ProfileSignatureError(
            "engagement profile HMAC mismatch — tampered or corrupt consent"
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
        is not in the profile's signed ``authorized_origins``.
    """
    if fronted_host not in lab_allowlist:
        raise OriginNotAuthorizedError(f"fronted host {fronted_host!r} not a proven-owned target")
    if origin_ip not in profile.authorized_origins:
        raise OriginNotAuthorizedError(
            f"origin {origin_ip!r} not in signed authorized_origins — hitting a client "
            f"origin bypasses their WAF; requires front-loaded consent (§12.36)."
        )
