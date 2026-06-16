"""Phase 0 — FastAPI + Celery skeleton test contract.

10 tests covering all endpoints: health, engagement creation, recon enablement,
SOW upload, emergency stop, state queries, and error handling. Celery broker
is mocked (no real Redis needed).

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_0/test_conductor_main.py -v
"""

from io import BytesIO

from fastapi.testclient import TestClient

from agent_alpha.conductor.main import app


def test_health_returns_ok() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}


def test_create_engagement_returns_engagement_id() -> None:
    client = TestClient(app)
    response = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "engagement_id" in data
    assert data["engagement_id"].startswith("eng_")
    assert "state" in data


def test_enable_recon_with_valid_scope() -> None:
    client = TestClient(app)
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    engagement_id = create_resp.json()["engagement_id"]

    response = client.post(
        f"/engagements/{engagement_id}/recon",
        json={
            "ip_ranges": ["10.0.0.0/24"],
            "domains": ["example.com"],
            "exclusions": ["10.0.0.5"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["engagement_id"] == engagement_id
    assert "state" in data


def test_enable_recon_with_invalid_cidr_returns_400() -> None:
    client = TestClient(app)
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    engagement_id = create_resp.json()["engagement_id"]

    response = client.post(
        f"/engagements/{engagement_id}/recon",
        json={
            "ip_ranges": ["invalid-cidr"],
            "domains": ["example.com"],
            "exclusions": [],
        },
    )
    assert response.status_code == 400


def test_upload_sow_with_valid_pdf_returns_hash() -> None:
    client = TestClient(app)
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    engagement_id = create_resp.json()["engagement_id"]

    pdf_content = b"%PDF-1.4\n%fake pdf content"
    file = BytesIO(pdf_content)
    file.name = "sow.pdf"

    response = client.post(
        f"/engagements/{engagement_id}/sow",
        files={"file": (file.name, file, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["engagement_id"] == engagement_id
    assert "sow_hash" in data
    assert len(data["sow_hash"]) == 64  # sha256 hex


def test_upload_sow_exceeding_size_limit_returns_400() -> None:
    client = TestClient(app)
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    engagement_id = create_resp.json()["engagement_id"]

    # 51MB exceeds 50MB limit
    large_content = b"x" * (51 * 1024 * 1024)
    file = BytesIO(large_content)
    file.name = "sow.pdf"

    response = client.post(
        f"/engagements/{engagement_id}/sow",
        files={"file": (file.name, file, "application/pdf")},
    )
    assert response.status_code == 400


def test_emergency_stop_returns_success() -> None:
    client = TestClient(app)
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    engagement_id = create_resp.json()["engagement_id"]

    response = client.post(
        f"/engagements/{engagement_id}/stop",
        json={"reason": "abort", "issued_by": "operator"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["engagement_id"] == engagement_id
    assert data["success"] is True
    assert "tasks_revoked" in data
    assert "elapsed_ms" in data


def test_get_state_returns_state_field() -> None:
    client = TestClient(app)
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    engagement_id = create_resp.json()["engagement_id"]

    response = client.get(f"/engagements/{engagement_id}/state")
    assert response.status_code == 200
    data = response.json()
    assert data["engagement_id"] == engagement_id
    assert "state" in data
    assert "state_value" in data


def test_get_state_nonexistent_returns_404() -> None:
    client = TestClient(app)
    response = client.get("/engagements/eng_does_not_exist/state")
    assert response.status_code == 404


def test_emergency_stop_then_state_returns_emergency_stop() -> None:
    client = TestClient(app)
    create_resp = client.post(
        "/engagements",
        json={"client_id": "client_a", "target": "10.0.0.0/24"},
    )
    engagement_id = create_resp.json()["engagement_id"]

    client.post(
        f"/engagements/{engagement_id}/stop",
        json={"reason": "abort", "issued_by": "operator"},
    )

    response = client.get(f"/engagements/{engagement_id}/state")
    assert response.status_code == 200
    data = response.json()
    assert data["state"] == "EMERGENCY_STOP"
