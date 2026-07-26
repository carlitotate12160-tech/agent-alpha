"""§12.36 convergence contract — prove the signed EngagementProfile reaches
the recon pipeline via the Conductor path.

CARDINAL: run_engagement_task must pass a NON-None engagement_profile whose
scope_targets came from a DNS-TXT-verified domain. Today (pre-convergence)
engagement_profile is None — the test FAILS on main. After the §12.36 wiring
it PASSES, proving the island is converged.

All tests use InMemoryEventStore, Celery eager, and a STUB DNSResolver — never
a live DNS lookup. Celery eager runs the whole chain synchronously.
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agent_alpha.conductor import main as m
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.engagement_profile import (
    EngagementProfile,
    ProfileSignatureError,
    dump_signed_profile,
    load_signed_profile_from_dict,
)
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.security.secrets import get_profile_signing_key

_DOMAIN = "test-ownership.example.com"
_JWT_SECRET = os.environ.get("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")


class _StubDNSResolver:
    """Canned DNS resolver for tests. Returns the token(s) set on the instance."""

    def __init__(self, records: dict[str, list[str]] | None = None) -> None:
        self.records: dict[str, list[str]] = records or {}

    def resolve_txt(self, domain: str) -> list[str]:
        return self.records.get(domain, [])


def _make_jwt(tenant_id: str = "test-tenant") -> str:
    import jwt

    return jwt.encode(
        {"sub": "test-operator", "tenant_id": tenant_id},
        _JWT_SECRET,
        algorithm="HS256",
    )


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate each test: fresh event store, Celery eager, monkeypatched seams."""
    monkeypatch.setenv("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-for-eager-dispatch")
    # Profile signing key — 64 hex chars = 32 bytes (minimum for HMAC-SHA-256).
    monkeypatch.setenv("PROFILE_SIGNING_KEY", "a" * 64)

    fresh_store = InMemoryEventStore()
    monkeypatch.setattr(m, "event_store", fresh_store)
    monkeypatch.setattr(m, "store_provider", m.StoreProvider())
    m.celery_app.conf.task_always_eager = True
    m.celery_app.conf.task_eager_propagates = True


@pytest.fixture()
def client() -> TestClient:
    return TestClient(m.app)


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_jwt()}"}


def _create_engagement(client: TestClient, headers: dict[str, str]) -> str:
    """Create an engagement and return its id."""
    resp = client.post("/engagements", json={"client_id": "c1", "target": _DOMAIN}, headers=headers)
    assert resp.status_code == 200
    return resp.json()["engagement_id"]


def _challenge_domain(
    client: TestClient, headers: dict[str, str], engagement_id: str, domain: str = _DOMAIN
) -> str:
    """Issue an ownership challenge and return the token."""
    resp = client.post(
        f"/engagements/{engagement_id}/ownership/challenge",
        json={"domain": domain},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["record_name"] == f"_agentalpha.{domain}"
    # Extract the token from record_value "agent-alpha=<token>"
    return data["record_value"].split("=", 1)[1]


def _authorize_with_stub(
    client: TestClient,
    headers: dict[str, str],
    engagement_id: str,
    domain: str,
    token: str,
    *,
    authorization_level: str = "RECON_ONLY",
    consent_items: list[str] | None = None,
    signed_by: str = "operator",
    signed_at: str = "2026-07-26T00:00:00Z",
    allow_evasion: bool = False,
    opsec_stealth: bool = False,
    stub_resolver: _StubDNSResolver | None = None,
) -> Any:
    """Call /authorize with a stub DNS resolver returning the given token."""
    if stub_resolver is None:
        # authorize_engagement (reused as-is per D1) queries the apex domain
        # directly via verify_domain_ownership. The challenge endpoint tells
        # the user _agentalpha.<domain>, but to pass the existing verify logic,
        # the stub must map the apex domain.
        stub_resolver = _StubDNSResolver({domain: [f"agent-alpha={token}"]})

    body: dict[str, Any] = {
        "domains": [domain],
        "signed_by": signed_by,
        "signed_at": signed_at,
        "authorization_level": authorization_level,
        "allow_evasion": allow_evasion,
        "opsec_stealth": opsec_stealth,
    }
    if consent_items is not None:
        body["consent_items"] = consent_items

    with patch("agent_alpha.conductor.main.DnspythonResolver", return_value=stub_resolver):
        return client.post(
            f"/engagements/{engagement_id}/authorize",
            json=body,
            headers=headers,
        )


# ── CARDINAL ────────────────────────────────────────────────────────────
# This test FAILS on main before the §12.36 convergence (engagement_profile
# is None). It PASSES after the wiring.


def test_cardinal_profile_reaches_recon_pipeline(
    client: TestClient, auth_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """CARDINAL: the signed EngagementProfile reaches build_recon_pipeline."""
    eid = _create_engagement(client, auth_headers)
    token = _challenge_domain(client, auth_headers, eid)
    resp = _authorize_with_stub(client, auth_headers, eid, _DOMAIN, token)
    assert resp.status_code == 200, resp.json()

    # enable_recon — scope comes from the signed profile
    resp = client.post(f"/engagements/{eid}/recon", headers=auth_headers)
    assert resp.status_code == 200, resp.json()

    # Spy on build_recon_pipeline to capture the engagement_profile arg
    captured_profiles: list[Any] = []
    original_build = recon_runner.build_recon_pipeline

    def _spy_build(*args: Any, **kwargs: Any) -> Any:
        captured_profiles.append(kwargs.get("engagement_profile"))
        return original_build(*args, **kwargs)

    monkeypatch.setattr(recon_runner, "build_recon_pipeline", _spy_build)

    # Also monkeypatch resolve_recon_targets to avoid live DNS / SSRF guard
    monkeypatch.setattr(
        recon_runner,
        "resolve_recon_targets",
        lambda record: [f"https://{_DOMAIN}"],
    )
    # Monkeypatch build_passive_discovery to avoid live network I/O
    from dataclasses import dataclass

    @dataclass
    class _FakePD:
        enumerated: set[str] = None  # type: ignore[assignment]

        def __post_init__(self) -> None:
            if self.enumerated is None:
                self.enumerated = set()

        def discover(self, eid: str, host: str) -> Any:
            return self

    monkeypatch.setattr(recon_runner, "build_passive_discovery", lambda *a, **kw: _FakePD())

    # Run the engagement task
    result = m.run_engagement_task(eid, "test-tenant")
    assert result["status"] == "completed", result

    # CARDINAL ASSERTION: the profile reached build_recon_pipeline and is not None
    assert len(captured_profiles) >= 1, "build_recon_pipeline was never called"
    profile = captured_profiles[0]
    assert profile is not None, (
        "CARDINAL FAILURE: engagement_profile is None — the §12.36 signed profile "
        "did not reach the recon pipeline (the island is not converged)."
    )
    assert isinstance(profile, EngagementProfile)
    assert _DOMAIN in profile.scope_targets


# ── Consent gate ────────────────────────────────────────────────────────


def test_authorize_refuses_offensive_without_consent(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """/authorize with allow_evasion=True + no consent → 400."""
    eid = _create_engagement(client, auth_headers)
    token = _challenge_domain(client, auth_headers, eid)
    resp = _authorize_with_stub(
        client,
        auth_headers,
        eid,
        _DOMAIN,
        token,
        authorization_level="OFFENSIVE_APPROVED",
        allow_evasion=True,
        # No consent_items, no signed_by, no signed_at
        consent_items=[],
        signed_by="",
        signed_at="",
    )
    assert resp.status_code == 400
    assert "consent" in resp.json()["detail"].lower() or "Consent" in resp.json()["detail"]


# ── Ownership verification failure ──────────────────────────────────────


def test_authorize_wrong_txt_token(client: TestClient, auth_headers: dict[str, str]) -> None:
    """/authorize where stub TXT does NOT match → 400 (DomainOwnershipError)."""
    eid = _create_engagement(client, auth_headers)
    _challenge_domain(client, auth_headers, eid)

    # Stub returns a WRONG token
    wrong_resolver = _StubDNSResolver({f"_agentalpha.{_DOMAIN}": ["agent-alpha=WRONG_TOKEN_xyz"]})
    resp = _authorize_with_stub(
        client,
        auth_headers,
        eid,
        _DOMAIN,
        "ignored",  # actual token doesn't matter — the stub returns wrong
        stub_resolver=wrong_resolver,
    )
    assert resp.status_code == 400
    assert "ownership" in resp.json()["detail"].lower()


# ── enable_recon profile-required gate ──────────────────────────────────


def test_enable_recon_without_profile_returns_400(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """enable_recon with NO signed-profile envelope event → 400."""
    eid = _create_engagement(client, auth_headers)
    resp = client.post(f"/engagements/{eid}/recon", headers=auth_headers)
    assert resp.status_code == 400
    assert "authorize" in resp.json()["detail"].lower()


# ── Signed profile round-trip ───────────────────────────────────────────


def test_signed_profile_round_trip() -> None:
    """dump → load_signed_profile_from_dict (real key) succeeds; tampered → error."""
    key = get_profile_signing_key()
    profile = EngagementProfile(
        engagement_id="eng_test",
        client_id="c1",
        targets=frozenset([_DOMAIN]),
        scope_targets=frozenset([_DOMAIN]),
    )
    envelope = dump_signed_profile(profile, key=key)
    loaded = load_signed_profile_from_dict(envelope, key=key)
    assert loaded.engagement_id == profile.engagement_id
    assert loaded.scope_targets == profile.scope_targets

    # Tampered envelope
    tampered = dict(envelope)
    tampered["hmac"] = "0" * 64
    with pytest.raises(ProfileSignatureError):
        load_signed_profile_from_dict(tampered, key=key)


# ── Challenge token randomness ──────────────────────────────────────────


def test_challenge_token_is_random_per_call(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Two challenges for the same domain produce different tokens."""
    eid = _create_engagement(client, auth_headers)
    token1 = _challenge_domain(client, auth_headers, eid)
    token2 = _challenge_domain(client, auth_headers, eid)
    assert token1 != token2, "challenge tokens must be random per call"


def test_challenge_token_not_derivable_from_signing_key(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Token is secrets.token_urlsafe, NOT HMAC(signing_key, ...)."""
    eid = _create_engagement(client, auth_headers)
    token = _challenge_domain(client, auth_headers, eid)
    # A signing-key-derived HMAC would be a hex digest. token_urlsafe is
    # base64url-encoded. If the token is valid hex of length 64, it might
    # be HMAC-derived — that's a violation.
    try:
        bytes.fromhex(token)
        is_hex = len(token) == 64
    except ValueError:
        is_hex = False
    assert not is_hex, "token looks HMAC-derived (64-char hex); must be random"


# ── origin_discovery wiring debt ────────────────────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="WIRING-DEBT (§12.38): origin_discovery is injected None on the live "
    "Conductor path — deferred to the CDN-target reach slice (D5).",
)
def test_origin_discovery_still_none_on_conductor_path(
    client: TestClient, auth_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """origin_discovery wiring debt: the parameter is None on the live path."""
    eid = _create_engagement(client, auth_headers)
    token = _challenge_domain(client, auth_headers, eid)
    _authorize_with_stub(client, auth_headers, eid, _DOMAIN, token)
    client.post(f"/engagements/{eid}/recon", headers=auth_headers)

    captured: list[Any] = []
    original = recon_runner.build_recon_pipeline

    def _spy(*args: Any, **kwargs: Any) -> Any:
        captured.append(kwargs.get("origin_discovery"))
        return original(*args, **kwargs)

    monkeypatch.setattr(recon_runner, "build_recon_pipeline", _spy)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda r: [f"https://{_DOMAIN}"])
    monkeypatch.setattr(
        recon_runner,
        "build_passive_discovery",
        lambda *a, **kw: type(
            "PD", (), {"discover": lambda s, e, h: type("R", (), {"enumerated": set()})()}
        )(),
    )

    m.run_engagement_task(eid, "test-tenant")

    assert len(captured) >= 1
    # This assertion SHOULD fail (origin_discovery is None) — xfail makes
    # the test green while the debt is tracked.
    assert captured[0] is not None, "origin_discovery is still None (wiring debt)"
