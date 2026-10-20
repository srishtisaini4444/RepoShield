
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_valid_scan_request():
    response = client.post(
        "/api/v1/scans",
        json={
            "package_name": "express",
            "version": "4.21.2",
        },
    )

    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "validated"
    assert body["target"]["package_name"] == "express"
    assert body["target"]["version"] == "4.21.2"


def test_invalid_package_name_is_rejected():
    response = client.post(
        "/api/v1/scans",
        json={
            "package_name": "Express Package",
            "version": "4.21.2",
        },
    )

    assert response.status_code == 422


def test_unexpected_field_is_rejected():
    response = client.post(
        "/api/v1/scans",
        json={
            "package_name": "express",
            "version": "4.21.2",
            "execute_script": True,
        },
    )

    assert response.status_code == 422


def test_missing_package_name_is_rejected():
    response = client.post(
        "/api/v1/scans",
        json={"version": "4.21.2"},
    )

    assert response.status_code == 422
