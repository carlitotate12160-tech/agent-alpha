"""Front-door contract tests — authenticated tenant binding (gate 2a).

TEST-FIRST: these are written before GPT-5.1 finishes the front-door, so they
WILL be red until it lands. That is intentional (anti-Lyndon #2 — test before
code). They assert BEHAVIOUR at the HTTP boundary (status codes + isolation),
NOT internal symbol names, so the implementation is free to name its classes
however it likes — only the contract is fixed.

────────────────────────────────────────────────────────────────────────────
CONTRACT ASSUMPTIONS — align these with the implementation if it chose
differently (the BEHAVIOUR below is the real contract, these are the knobs):
  * Auth = `Authorization: Bearer <JWT>`, HS256, secret from env
    AGENT_ALPHA_JWT_SECRET, tenant identity in the `tenant_id` claim.
  * If the impl picked a different alg/claim/lib, change `_token()` only.
No DB required: this exercises the API perimeter (auth + ownership), which is
separable from the DB RLS layer already proven in test_rls_isolation.py.
────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import uuid

import pytest

# Secret must be set BEFORE the app imports its config. If the impl reads the
# key elsewhere (SecretsManager), point this at the same source.
# ≥32 chars to avoid InsecureKeyLengthWarning for HS256 (RFC 7518 §3.2).
os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-at-least-32-bytes!!")

jwt = pytest.importorskip("jwt")  # PyJWT; align if impl uses another lib
fastapi_testclient = pytest.importorskip("fastapi.testclient")

from fastapi.testclient import TestClient  # noqa: E402

from agent_alpha.conductor.main import app  # noqa: E402

_SECRET = os.environ["AGENT_ALPHA_JWT_SECRET"]
client = TestClient(app)


def _token(tenant_id: str, sub: str = "tester") -> str:
    return jwt.encode({"tenant_id": tenant_id, "sub": sub}, _SECRET, algorithm="HS256")


def _auth(tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(tenant_id)}"}


def _new_engagement(tenant_id: str) -> str:
    r = client.post(
        "/engagements",
        json={"client_id": "label-only", "target": "10.0.0.0/24"},
        headers=_auth(tenant_id),
    )
    assert r.status_code == 200, r.text
    return r.json()["engagement_id"]


def _tenant() -> str:
    return "t_" + uuid.uuid4().hex[:8]


# ── 1. AuthN: no/invalid token is rejected; /health stays open ────────


def test_health_is_open() -> None:
    assert client.get("/health").status_code == 200


def test_engagement_endpoints_require_a_token() -> None:
    r = client.post("/engagements", json={"client_id": "x", "target": "10.0.0.0/24"})
    assert r.status_code == 401


def test_invalid_token_rejected() -> None:
    r = client.post(
        "/engagements",
        json={"client_id": "x", "target": "10.0.0.0/24"},
        headers={"Authorization": "Bearer not-a-real-jwt"},
    )
    assert r.status_code == 401


def test_token_without_tenant_claim_rejected() -> None:
    bad = jwt.encode({"sub": "tester"}, _SECRET, algorithm="HS256")  # no tenant_id
    r = client.post(
        "/engagements",
        json={"client_id": "x", "target": "10.0.0.0/24"},
        headers={"Authorization": f"Bearer {bad}"},
    )
    assert r.status_code == 401


# ── 2. Tenant binding: tenant comes ONLY from the verified token ──────


def test_tenant_comes_from_token_not_body() -> None:
    """A request body claiming client_id of another tenant must NOT change the
    tenant the engagement is bound to — tenant is the token claim, full stop."""
    tenant_a = _tenant()
    r = client.post(
        "/engagements",
        json={"client_id": "pretend-to-be-someone-else", "target": "10.0.0.0/24"},
        headers=_auth(tenant_a),
    )
    assert r.status_code == 200, r.text
    eng = r.json()["engagement_id"]
    # The owner (token tenant_a) can read it; nobody else can (see test 3).
    assert client.get(f"/engagements/{eng}/state", headers=_auth(tenant_a)).status_code == 200


# ── 3. Ownership: cross-tenant access returns 404 (never leaks) ───────


def test_cross_tenant_access_returns_404() -> None:
    tenant_a, tenant_b = _tenant(), _tenant()
    eng = _new_engagement(tenant_a)

    # Tenant A sees its own engagement.
    assert client.get(f"/engagements/{eng}/state", headers=_auth(tenant_a)).status_code == 200

    # Tenant B must NOT see it — 404, not 403 (do not leak existence).
    assert client.get(f"/engagements/{eng}/state", headers=_auth(tenant_b)).status_code == 404


def test_cross_tenant_mutation_returns_404() -> None:
    tenant_a, tenant_b = _tenant(), _tenant()
    eng = _new_engagement(tenant_a)

    # Tenant B tries to drive recon on A's engagement -> 404.
    r = client.post(
        f"/engagements/{eng}/recon",
        json={"ip_ranges": ["10.0.0.0/24"], "domains": [], "exclusions": []},
        headers=_auth(tenant_b),
    )
    assert r.status_code == 404


def test_cross_tenant_sow_upload_returns_404() -> None:
    """Tenant B must not upload a SOW against tenant A's engagement.

    Critical going forward: SOW upload is the gate to OFFENSIVE_APPROVED — an
    unguarded /sow lets one tenant escalate another tenant's engagement.
    """
    tenant_a, tenant_b = _tenant(), _tenant()
    eng = _new_engagement(tenant_a)

    r = client.post(
        f"/engagements/{eng}/sow",
        files={"file": ("sow.pdf", b"%PDF-1.4 fake sow", "application/pdf")},
        headers=_auth(tenant_b),
    )
    assert r.status_code == 404, r.text


def test_owner_sow_upload_allowed() -> None:
    """Guard: the ownership check must NOT break legitimate same-tenant access."""
    tenant_a = _tenant()
    eng = _new_engagement(tenant_a)

    r = client.post(
        f"/engagements/{eng}/sow",
        files={"file": ("sow.pdf", b"%PDF-1.4 fake sow", "application/pdf")},
        headers=_auth(tenant_a),
    )
    assert r.status_code == 200, r.text


def test_cross_tenant_emergency_stop_returns_404() -> None:
    """Tenant B must not emergency-stop tenant A's engagement.

    /stop revokes tasks + mutates engagement state; cross-tenant access is a
    live abuse (DoS / tampering). The ownership check MUST reject (404) BEFORE
    emergency.execute runs.
    """
    tenant_a, tenant_b = _tenant(), _tenant()
    eng = _new_engagement(tenant_a)

    r = client.post(
        f"/engagements/{eng}/stop",
        json={"reason": "unauthorized-stop", "issued_by": "tenant-b"},
        headers=_auth(tenant_b),
    )
    assert r.status_code == 404, r.text


def test_stop_and_sow_still_require_a_token() -> None:
    """Both routes must also reject unauthenticated access (router-level auth)."""
    tenant_a = _tenant()
    eng = _new_engagement(tenant_a)

    assert (
        client.post(
            f"/engagements/{eng}/sow",
            files={"file": ("s.pdf", b"x", "application/pdf")},
        ).status_code
        == 401
    )
    assert (
        client.post(
            f"/engagements/{eng}/stop",
            json={"reason": "x", "issued_by": "y"},
        ).status_code
        == 401
    )
