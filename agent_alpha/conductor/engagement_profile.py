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
from dataclasses import dataclass, field
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


class TargetNotInScopeError(RuntimeError):
    """Raised when a target is not in the signed scope_targets."""


class CapabilityNotAuthorizedError(RuntimeError):
    """Raised when a capability is not authorized by the signed profile."""


class AuthorizationLevelError(RuntimeError):
    """Raised when the agent tier requires a higher authorization level."""


class GuardrailError(RuntimeError):
    """Raised when a target is blocked by the hard guardrail regardless of consent."""


# ── ConsentRecord ─────────────────────────────────────────────


@dataclass(frozen=True)
class ConsentRecord:
    """Immutable record of accepted consent checklist items.

    Embedded in ``EngagementProfile.canonical_json`` so any change to the
    consent record invalidates the profile signature.
    """

    accepted_items: frozenset[str] = frozenset()
    signed_by: str = ""
    signed_at: str = ""  # ISO-8601 UTC

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_items": sorted(self.accepted_items),
            "signed_by": self.signed_by,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConsentRecord:
        return cls(
            accepted_items=frozenset(data.get("accepted_items", [])),
            signed_by=data.get("signed_by", ""),
            signed_at=data.get("signed_at", ""),
        )


# ── Target guardrail (defense-in-depth ABOVE consent) ─────────

# Hard-blocked TLDs — ALWAYS refused, even with signed consent + ownership.
_GUARDBRAIL_TLDS: frozenset[str] = frozenset({
    ".gov", ".mil", ".edu", ".int",
})

# Well-known big-tech / cloud / financial domains — ALWAYS refused.
_GUARDBRAIL_DOMAINS: frozenset[str] = frozenset({
    "google.com", "amazon.com", "microsoft.com", "apple.com",
    "facebook.com", "meta.com", "twitter.com", "x.com",
    "netflix.com", "cloudflare.com", "aws.amazon.com",
    "github.com", "linkedin.com", "instagram.com",
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com",
    "oracle.com", "ibm.com", "intel.com", "cisco.com",
})


def _normalise_target(target: str) -> str:
    """Strip to bare lowercase hostname for guardrail checks."""
    host = target.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def assert_not_guardrailed(target: str) -> None:
    """Fail-closed. ALWAYS block government/military/education/big-tech targets
    regardless of consent, ownership, or signed profile. Defense-in-depth ABOVE
    consent — these targets are never authorized for pentest by Agent-Alpha.
    """
    host = _normalise_target(target)
    if not host:
        raise GuardrailError(f"empty/invalid target: {target!r}")

    for tld in _GUARDBRAIL_TLDS:
        if host.endswith(tld):
            raise GuardrailError(
                f"target {host!r} is in a guarded TLD ({tld}) — "
                f"government/military/education/international targets are ALWAYS blocked."
            )

    # Check exact match and subdomain match against blocked domains.
    for blocked in _GUARDBRAIL_DOMAINS:
        if host == blocked or host.endswith("." + blocked):
            raise GuardrailError(
                f"target {host!r} is a well-known big-tech/cloud/financial domain "
                f"({blocked}) — ALWAYS blocked regardless of consent."
            )


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
    allow_evasion: bool = False  # §12.36: client consented to browser_solve / evasion techniques

    # ── §12.36 production authorization fields ────────────────
    scope_targets: frozenset[str] = frozenset()  # authorized domains/IPs for this engagement
    scope_mode: str = "single"  # "single" | "multi"
    allow_subdomain_enum: bool = False
    opsec_stealth: bool = False
    include_root: bool = False
    authorization_level: str = "RECON_ONLY"  # RECON_ONLY | ACTIVE_APPROVED | OFFENSIVE_APPROVED
    consent: ConsentRecord = field(default_factory=ConsentRecord)

    # ── Signature helpers ─────────────────────────────────────

    def canonical_json(self) -> str:
        """Deterministic JSON representation — sorted keys, no whitespace.

        Every field is embedded so any mutation invalidates the signature.
        """
        payload = {
            "engagement_id": self.engagement_id,
            "client_id": self.client_id,
            "targets": sorted(self.targets),
            "authorized_origins": sorted(self.authorized_origins),
            "allow_evasion": self.allow_evasion,
            "scope_targets": sorted(self.scope_targets),
            "scope_mode": self.scope_mode,
            "allow_subdomain_enum": self.allow_subdomain_enum,
            "opsec_stealth": self.opsec_stealth,
            "include_root": self.include_root,
            "authorization_level": self.authorization_level,
            "consent": self.consent.to_dict(),
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
            "scope_targets": sorted(profile.scope_targets),
            "scope_mode": profile.scope_mode,
            "allow_subdomain_enum": profile.allow_subdomain_enum,
            "opsec_stealth": profile.opsec_stealth,
            "include_root": profile.include_root,
            "authorization_level": profile.authorization_level,
            "consent": profile.consent.to_dict(),
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
    consent_data = profile_data.get("consent", {})
    profile = EngagementProfile(
        engagement_id=profile_data["engagement_id"],
        client_id=profile_data["client_id"],
        targets=frozenset(profile_data.get("targets", [])),
        authorized_origins=frozenset(profile_data.get("authorized_origins", [])),
        allow_evasion=bool(profile_data.get("allow_evasion", False)),
        scope_targets=frozenset(profile_data.get("scope_targets", [])),
        scope_mode=profile_data.get("scope_mode", "single"),
        allow_subdomain_enum=bool(profile_data.get("allow_subdomain_enum", False)),
        opsec_stealth=bool(profile_data.get("opsec_stealth", False)),
        include_root=bool(profile_data.get("include_root", False)),
        authorization_level=profile_data.get("authorization_level", "RECON_ONLY"),
        consent=ConsentRecord.from_dict(consent_data) if consent_data else ConsentRecord(),
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
    host is a proven-owned target (lab allowlist OR signed scope_targets).
    Distinct from lab_guard bare-IP refusal: an explicit, consented, auditable
    technique.

    For signed engagements (§12.36), the fronted host may be in
    ``profile.scope_targets`` instead of the lab allowlist — this is the
    production path. Lab allowlist remains for field-prove harnesses.

    Raises
    ------
    OriginNotAuthorizedError
        When the fronted host is not in the lab allowlist AND not in signed
        scope_targets, or the origin IP is not in the profile's signed
        ``authorized_origins``.
    GuardrailError
        When the fronted host is blocked by the hard guardrail.
    """
    assert_not_guardrailed(fronted_host)

    in_lab = fronted_host in lab_allowlist
    in_scope = fronted_host in profile.scope_targets

    if not in_lab and not in_scope:
        raise OriginNotAuthorizedError(
            f"fronted host {fronted_host!r} not a proven-owned target "
            f"(not in lab allowlist and not in signed scope_targets)"
        )
    if origin_ip not in profile.authorized_origins:
        raise OriginNotAuthorizedError(
            f"origin {origin_ip!r} not in signed authorized_origins — hitting a client "
            f"origin bypasses their WAF; requires front-loaded consent (§12.36)."
        )


# ── Enforcement gates (§12.36 — fail-closed) ──────────────────


def assert_target_in_scope(target: str, profile: EngagementProfile) -> None:
    """Fail-closed. Target must be in signed scope_targets AND profile
    signature must be valid (caller should verify hash separately).

    Also checks the hard guardrail — guardrail violations override consent.

    Raises TargetNotInScopeError if target not in scope_targets.
    Raises GuardrailError if target is in a guarded TLD/domain.
    """
    assert_not_guardrailed(target)
    host = _normalise_target(target)
    if host not in profile.scope_targets:
        raise TargetNotInScopeError(
            f"target {host!r} not in signed scope_targets "
            f"(scope={sorted(profile.scope_targets)})"
        )


# Capability flags that map to profile fields.
_CAPABILITY_FIELDS: dict[str, str] = {
    "evasion": "allow_evasion",
    "origin_direct": "allow_evasion",  # origin-direct requires evasion consent
    "subdomain_enum": "allow_subdomain_enum",
    "stealth": "opsec_stealth",
    "include_root": "include_root",
}


def assert_capability_authorized(capability: str, profile: EngagementProfile) -> None:
    """Fail-closed. The named capability must be authorized by the signed
    profile.

    Raises CapabilityNotAuthorizedError if the capability flag is not set.
    """
    field_name = _CAPABILITY_FIELDS.get(capability)
    if field_name is None:
        raise CapabilityNotAuthorizedError(
            f"unknown capability {capability!r} — not in {_CAPABILITY_FIELDS}"
        )
    authorized = getattr(profile, field_name, False)
    if not authorized:
        raise CapabilityNotAuthorizedError(
            f"capability {capability!r} not authorized by signed profile "
            f"({field_name}=False). Requires front-loaded consent (§12.36)."
        )


# Authorization level ladder — maps agent tiers to minimum required level.
_LEVEL_RANK: dict[str, int] = {
    "RECON_ONLY": 1,
    "ACTIVE_APPROVED": 2,
    "OFFENSIVE_APPROVED": 3,
}

_AGENT_TIER_MIN_LEVEL: dict[str, str] = {
    "ALPHA": "RECON_ONLY",
    "OMEGA": "RECON_ONLY",
    "BETA": "ACTIVE_APPROVED",
    "GAMMA": "OFFENSIVE_APPROVED",
    "DELTA": "OFFENSIVE_APPROVED",
    "EPSILON": "OFFENSIVE_APPROVED",
}


def assert_authorization_level(agent_tier: str, profile: EngagementProfile) -> None:
    """Fail-closed. The agent tier requires a minimum authorization level.

    Raises AuthorizationLevelError if the profile's authorization_level is
    below the tier's minimum.
    """
    required = _AGENT_TIER_MIN_LEVEL.get(agent_tier)
    if required is None:
        raise AuthorizationLevelError(
            f"unknown agent tier {agent_tier!r} — not in {_AGENT_TIER_MIN_LEVEL}"
        )
    profile_level = _LEVEL_RANK.get(profile.authorization_level, 0)
    required_level = _LEVEL_RANK.get(required, 0)
    if profile_level < required_level:
        raise AuthorizationLevelError(
            f"agent tier {agent_tier!r} requires {required} "
            f"(rank {required_level}), profile has {profile.authorization_level} "
            f"(rank {profile_level})."
        )
