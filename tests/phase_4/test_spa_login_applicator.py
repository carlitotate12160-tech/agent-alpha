"""Slice-B: SpaLoginApplicator test contract (T1–T7, all cardinal).

Fake http_client pattern mirrors the codebase norm: a dataclass-backed stub that
returns controlled responses without touching the network.

T1  login → valid JWT; replay protected_url → 200 authed body ≠ baseline
      ⇒ AuthResult(success=True, access_level in {"user","admin"}).  [cross_verified]
T2  login → valid JWT; replay protected_url → 401
      ⇒ success=False.  ← ANTI-#3 CARDINAL (token presence must NOT imply access).
T3  login → 200 JSON error body, no token ⇒ success=False.
T4  no login endpoint harvested ⇒ factory constructs NO SpaLoginApplicator (fail-closed).
T5  AuthResult never contains the raw token/secret (assert absent from all proof fields).
T6  required_auth == "ACTIVE_APPROVED"; not bound below ACTIVE_APPROVED (tier gate).
T7  spa-login-form ∈ STRIKABLE_AUTH_LABELS (entry-selection now targets SPA logins).
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_alpha.conductor.applicator_factory import (
    _first_non_login_api_endpoint,
    beta_web_applicators,
)
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.recon.auth_surface import SPA_LOGIN_FORM, STRIKABLE_AUTH_LABELS
from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.spa_login_applicator import SpaLoginApplicator

_HOST = "app.example.com"
_LOGIN_URL = f"https://{_HOST}/api/auth/login"
_PROTECTED_URL = f"https://{_HOST}/api/me"
_SECRET = "super-secret-password-that-must-not-leak"
_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123signature_AAAAAAA"  # JWT-shaped
_BUDGET = ResourceBudget(max_requests=10, max_seconds=30.0, max_cost_usd=1.0)


# ── Fake HTTP response ────────────────────────────────────────────────────────


@dataclasses.dataclass
class FakeResponse:
    status_code: int
    _text: str
    headers: dict[str, str] = dataclasses.field(default_factory=dict)

    @property
    def text(self) -> str:
        return self._text

    def json(self) -> Any:
        return json.loads(self._text)


# ── Fake HTTP client (call-sequence controlled) ───────────────────────────────


class FakeHttpClient:
    """Minimal stub that returns canned responses in call order."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._queue = list(responses)
        self._calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self._calls.append(("GET", url, kwargs))
        return self._queue.pop(0)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self._calls.append(("POST", url, kwargs))
        return self._queue.pop(0)


# ── T1: cross_verified success ───────────────────────────────────────────────


def test_t1_cross_verified_success() -> None:
    """Login → valid JWT → Bearer replay non-401 + body ≠ baseline ⇒ success=True."""
    login_json = json.dumps({"access_token": _TOKEN})
    authed_body = '{"id":1,"email":"user@example.com","role":"user"}'
    baseline_body = '{"error":"Unauthorized"}'

    http = FakeHttpClient(
        [
            # 1. baseline GET of protected_url (unauthenticated)
            FakeResponse(401, baseline_body),
            # 2. POST with email/password body shape → 200 + JWT
            FakeResponse(200, login_json),
            # 3. Bearer replay → 200 + authed body
            FakeResponse(200, authed_body),
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="user@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is True
    assert result.access_level in {"user", "admin"}
    assert result.service == "spa"


def test_t1_admin_marker_detected() -> None:
    """Admin marker in authed body → access_level == "admin"."""
    login_json = json.dumps({"token": _TOKEN})
    authed_body = '{"id":1,"role":"administrator","is_superuser":true}'
    baseline_body = '{"error":"Unauthorized"}'

    http = FakeHttpClient(
        [
            FakeResponse(401, baseline_body),
            FakeResponse(200, login_json),
            FakeResponse(200, authed_body),
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="admin@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is True
    assert result.access_level == "admin"


# ── T2: ANTI-#3 CARDINAL — token presence does NOT imply access ──────────────


def test_t2_valid_jwt_but_replay_401_means_failure() -> None:
    """Token extracted from login response; Bearer replay → 401 ⇒ success=False.

    CARDINAL TEST: success must depend on cross-verification, NOT token presence.
    """
    login_json = json.dumps({"access_token": _TOKEN})

    http = FakeHttpClient(
        [
            # baseline
            FakeResponse(200, '{"public":"data"}'),
            # login → 200 + valid JWT
            FakeResponse(200, login_json),
            # Bearer replay → 401 (token accepted by login but rejected by API)
            FakeResponse(401, '{"error":"expired token"}'),
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="user@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is False
    assert "401" in result.error


def test_t2_valid_jwt_but_replay_403_means_failure() -> None:
    """Bearer replay → 403 ⇒ success=False (forbidden = rejected token)."""
    login_json = json.dumps({"jwt": _TOKEN})

    http = FakeHttpClient(
        [
            FakeResponse(200, '{"public":"data"}'),
            FakeResponse(200, login_json),
            FakeResponse(403, '{"error":"forbidden"}'),
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="user@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is False
    assert "403" in result.error


# ── T3: 200 JSON response but no JWT ⇒ failure ───────────────────────────────


def test_t3_login_200_no_token_field() -> None:
    """200 response with no recognised token key → success=False."""
    login_json = json.dumps({"message": "ok", "user_id": 42})

    http = FakeHttpClient(
        [
            FakeResponse(401, '{"error":"Unauthorized"}'),
            FakeResponse(200, login_json),
            # username/password fallback also no token
            FakeResponse(200, login_json),
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="user@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is False
    assert "no JWT" in result.error


def test_t3_login_returns_non_jwt_shaped_token() -> None:
    """Token field present but value is NOT JWT-shaped (not a.b.c) → failure."""
    login_json = json.dumps({"token": "opaque-token-not-a-jwt"})

    http = FakeHttpClient(
        [
            FakeResponse(401, '{"error":"Unauthorized"}'),
            FakeResponse(200, login_json),
            FakeResponse(200, login_json),
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="user@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is False


# ── T4: no login endpoint → factory builds NO SpaLoginApplicator ─────────────


def test_t4_factory_no_spa_applicator_when_no_login_endpoint() -> None:
    """Fail-closed: if the event store has no harvested api_endpoint for the host,
    beta_web_applicators must NOT return a SpaLoginApplicator.
    """
    store = InMemoryEventStore()
    # Seed only product/non-login endpoints — no login path
    store.append(
        EventType.NODE_DISCOVERED,
        "e",
        "alpha",
        {"type": "api_endpoint", "host": _HOST, "endpoint": "/api/products"},
    )

    events = store.get_events("e")
    roster = beta_web_applicators(MagicMock(), events=events, host=_HOST)

    spa_applicators = [a for a in roster if isinstance(a, SpaLoginApplicator)]
    assert spa_applicators == [], (
        "SpaLoginApplicator must NOT be constructed when no login endpoint is harvested"
    )


def test_t4_factory_adds_spa_applicator_when_login_endpoint_harvested() -> None:
    """Positive: when a login api_endpoint IS harvested, factory adds SpaLoginApplicator."""
    store = InMemoryEventStore()
    store.append(
        EventType.NODE_DISCOVERED,
        "e",
        "alpha",
        {"type": "api_endpoint", "host": _HOST, "endpoint": "/api/auth/login"},
    )

    events = store.get_events("e")
    roster = beta_web_applicators(MagicMock(), events=events, host=_HOST)

    spa_applicators = [a for a in roster if isinstance(a, SpaLoginApplicator)]
    assert len(spa_applicators) == 1


def test_t4_factory_no_events_no_spa_applicator() -> None:
    """No events passed (events=None) → no SpaLoginApplicator (backward compat)."""
    roster = beta_web_applicators(MagicMock())
    spa_applicators = [a for a in roster if isinstance(a, SpaLoginApplicator)]
    assert spa_applicators == []


# ── T5: AuthResult NEVER contains raw token or raw secret ────────────────────


def test_t5_auth_result_never_contains_raw_secret_or_token() -> None:
    """proof_request and proof_response must be clean of the raw secret AND raw token."""
    login_json = json.dumps({"access_token": _TOKEN})
    authed_body = '{"id":1,"email":"user@example.com"}'
    baseline_body = '{"error":"Unauthorized"}'

    http = FakeHttpClient(
        [
            FakeResponse(401, baseline_body),
            FakeResponse(200, login_json),
            FakeResponse(200, authed_body),
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="user@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is True

    # Serialize all proof fields to string and scan for secret/token presence
    proof_str = str(result.proof_request) + str(result.proof_response)

    assert _SECRET not in proof_str, (
        f"Raw secret leaked into proof fields: {proof_str!r}"
    )
    assert _TOKEN not in proof_str, (
        f"Raw JWT token leaked into proof fields: {proof_str!r}"
    )

    # Confirm proof fields contain only safe metadata
    assert "data_keys" in result.proof_request or "method" in result.proof_request
    assert "bearer_header_name" in result.proof_response


# ── T6: required_auth == "ACTIVE_APPROVED"; tier gate blocks RECON_ONLY ──────


def test_t6_required_auth_is_active_approved() -> None:
    """SpaLoginApplicator.required_auth MUST be ACTIVE_APPROVED."""
    applicator = SpaLoginApplicator(http_client=MagicMock(), protected_url=None)
    assert applicator.required_auth == "ACTIVE_APPROVED"


def test_t6_tier_gate_blocks_below_active_approved() -> None:
    """The tier gate in build_applicators_for_engagement must exclude SpaLoginApplicator
    when state is RECON_ONLY (not yet ACTIVE_APPROVED).
    """
    from agent_alpha.a2a import a2a_pb2
    from agent_alpha.conductor.applicator_factory import _tier_satisfied

    # RECON_ONLY rank — must NOT satisfy ACTIVE_APPROVED requirement
    recon_only_state = a2a_pb2.RECON_ONLY
    assert _tier_satisfied("ACTIVE_APPROVED", recon_only_state) is False

    # ACTIVE_APPROVED rank — MUST satisfy ACTIVE_APPROVED requirement
    active_state = a2a_pb2.ACTIVE_APPROVED
    assert _tier_satisfied("ACTIVE_APPROVED", active_state) is True


# ── T7: SPA_LOGIN_FORM in STRIKABLE_AUTH_LABELS ──────────────────────────────


def test_t7_spa_login_form_in_strikable_auth_labels() -> None:
    """SPA_LOGIN_FORM must now be in STRIKABLE_AUTH_LABELS so entry-selection routes
    SPA-host strikes to Beta.
    """
    assert SPA_LOGIN_FORM in STRIKABLE_AUTH_LABELS, (
        f"SPA_LOGIN_FORM ({SPA_LOGIN_FORM!r}) is NOT in STRIKABLE_AUTH_LABELS. "
        f"Current set: {STRIKABLE_AUTH_LABELS}"
    )


# ── Additional edge cases ─────────────────────────────────────────────────────


def test_baseline_matches_authed_body_is_failure() -> None:
    """If cross-verify response == unauthenticated baseline → not real access."""
    login_json = json.dumps({"access_token": _TOKEN})
    body = '{"public":"same-body-for-everyone"}'

    http = FakeHttpClient(
        [
            FakeResponse(200, body),   # baseline
            FakeResponse(200, login_json),  # login → JWT
            FakeResponse(200, body),   # replay → SAME body as baseline
        ]
    )

    applicator = SpaLoginApplicator(http_client=http, protected_url=_PROTECTED_URL)
    result = applicator.apply(
        username="user@example.com", secret=_SECRET, target=_LOGIN_URL, budget=_BUDGET
    )

    assert result.success is False
    assert "baseline" in result.error


def test_applies_to_http_creds_on_https_target() -> None:
    """applies_to: http cred on https target → True."""
    applicator = SpaLoginApplicator(http_client=MagicMock(), protected_url=None)
    assert applicator.applies_to("http", "https://api.example.com/login") is True
    assert applicator.applies_to("https", "https://api.example.com/login") is True
    assert applicator.applies_to("", "https://api.example.com/login") is True


def test_applies_to_rejects_non_http_target() -> None:
    """applies_to: mysql cred or non-http target → False."""
    applicator = SpaLoginApplicator(http_client=MagicMock(), protected_url=None)
    assert applicator.applies_to("mysql", "mysql://db.example.com:3306") is False
    assert applicator.applies_to("http", "mysql://db.example.com:3306") is False
