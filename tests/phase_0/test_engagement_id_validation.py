"""Test that engagement_id path param is boundary-validated.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_engagement_id_validation.py -v
"""

import os

import pytest
from fastapi.testclient import TestClient

from agent_alpha.conductor.main import app

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")

jwt = pytest.importorskip("jwt")


def _token(tenant_id: str, sub: str = "tester") -> str:
    return jwt.encode(
        {"tenant_id": tenant_id, "sub": sub},
        os.environ["AGENT_ALPHA_JWT_SECRET"],
        algorithm="HS256",
    )


def _auth(tenant_id: str = "test-tenant") -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(tenant_id)}"}


def test_engagement_id_validation_valid_passes() -> None:
    client = TestClient(app)

    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
        headers=_auth(),
    )
    assert create_resp.status_code == 200
    engagement_id = create_resp.json()["engagement_id"]

    response = client.get(f"/engagements/{engagement_id}/state", headers=_auth())
    assert response.status_code == 200


@pytest.mark.parametrize(
    "bad_id",
    [
        "eng_abc%0Ainjected",
        "../x",
        "eng_ZZZ",
        "eng_123",  # wait, {4,} requires at least 4 hex chars. 123 is 3.
        "eng_xyz!",
    ],
)
def test_engagement_id_validation_invalid_returns_404(bad_id: str) -> None:
    client = TestClient(app)

    response = client.get(f"/engagements/{bad_id}/state", headers=_auth())
    assert response.status_code == 404

    response = client.post(
        f"/engagements/{bad_id}/stop",
        json={"reason": "abort", "issued_by": "operator"},
        headers=_auth(),
    )
    assert response.status_code == 404
