
import httpx
import pytest
from fastapi.testclient import TestClient

from app.integrations.npm_client import (
    NpmPackageNotFound,
    NpmRegistryError,
)
from app.main import app


client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_osv_lookup(monkeypatch):
    def fake_query(self, package_name, version):
        return []

    monkeypatch.setattr(
        "app.main.OsvClient.query_vulnerabilities",
        fake_query,
    )



def test_valid_scan_request(monkeypatch):
    def mock_metadata(self, package_name):
        return {
            "name": "express",
            "latest_version": "5.3.0",
            "description": "Web framework",
        }

    monkeypatch.setattr(
        "app.main.NpmRegistryClient.get_package_metadata",
        mock_metadata,
    )

    response = client.post(
        "/api/v1/scans",
        json={"package_name": "express"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["target"]["package_name"] == "express"
    assert data["target"]["resolved_version"] == "5.3.0"
    assert data["target"]["requested_version"] is None
    assert data["metadata"]["description"] == "Web framework"
    assert data["checks"][0]["status"] == "completed"
    assert data["findings"] == []


def test_invalid_package_name_is_rejected():
    response = client.post(
        "/api/v1/scans",
        json={"package_name": "Express Package"},
    )

    assert response.status_code == 422


def test_unexpected_field_is_rejected():
    response = client.post(
        "/api/v1/scans",
        json={
            "package_name": "express",
            "execute_script": True,
        },
    )

    assert response.status_code == 422


def test_missing_package_name_is_rejected():
    response = client.post("/api/v1/scans", json={})

    assert response.status_code == 422


def test_missing_npm_package_returns_404(monkeypatch):
    def mock_metadata(self, package_name):
        raise NpmPackageNotFound("Package not found")

    monkeypatch.setattr(
        "app.main.NpmRegistryClient.get_package_metadata",
        mock_metadata,
    )

    response = client.post(
        "/api/v1/scans",
        json={"package_name": "missing-package"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_registry_failure_returns_502(monkeypatch):
    def mock_metadata(self, package_name):
        raise NpmRegistryError("Registry unavailable")

    monkeypatch.setattr(
        "app.main.NpmRegistryClient.get_package_metadata",
        mock_metadata,
    )

    response = client.post(
        "/api/v1/scans",
        json={"package_name": "express"},
    )

    assert response.status_code == 502
    assert "lookup failed" in response.json()["detail"].lower()



def test_requested_version_is_retrieved(monkeypatch):
    def mock_metadata(self, package_name, version):
        assert package_name == "express"
        assert version == "4.18.2"

        return {
            "name": "express",
            "version": "4.18.2",
            "description": "Web framework",
        }

    monkeypatch.setattr(
        "app.main.NpmRegistryClient.get_package_version_metadata",
        mock_metadata,
    )

    response = client.post(
        "/api/v1/scans",
        json={
            "package_name": "express",
            "version": "4.18.2",
        },
    )

    assert response.status_code == 200

    data = response.json()
    assert data["target"]["requested_version"] == "4.18.2"
    assert data["target"]["resolved_version"] == "4.18.2"



def test_registry_error_does_not_expose_internal_message(monkeypatch):
    def mock_metadata(self, package_name):
        raise NpmRegistryError("Internal connection details")

    monkeypatch.setattr(
        "app.main.NpmRegistryClient.get_package_metadata",
        mock_metadata,
    )

    response = client.post(
        "/api/v1/scans",
        json={"package_name": "express"},
    )

    assert response.status_code == 502
    assert "Internal connection details" not in response.text

    
def test_scan_returns_osv_vulnerability_findings(monkeypatch):
    def mock_metadata(self, package_name):
        return {
            "name": "express",
            "latest_version": "5.3.0",
            "description": "Web framework",
        }

    def mock_vulnerabilities(self, package_name, version):
        assert package_name == "express"
        assert version == "5.3.0"

        return [
            {
                "id": "GHSA-example-1234",
                "summary": "Example vulnerability",
                "modified": "2026-01-01T00:00:00Z",
            }
        ]

    monkeypatch.setattr(
        "app.main.NpmRegistryClient.get_package_metadata",
        mock_metadata,
    )
    monkeypatch.setattr(
        "app.main.OsvClient.query_vulnerabilities",
        mock_vulnerabilities,
    )

    response = client.post(
        "/api/v1/scans",
        json={"package_name": "express"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "completed"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "GHSA-example-1234"
    assert data["findings"][0]["source"] == "OSV"
    assert data["checks"][1]["status"] == "completed"


def test_scan_marks_osv_failure_as_incomplete(monkeypatch):
    def mock_metadata(self, package_name):
        return {
            "name": "express",
            "latest_version": "5.3.0",
            "description": "Web framework",
        }

    def mock_osv_failure(self, package_name, version):
        from app.integrations.osv_client import OsvClientError

        raise OsvClientError("Simulated OSV failure")

    monkeypatch.setattr(
        "app.main.NpmRegistryClient.get_package_metadata",
        mock_metadata,
    )
    monkeypatch.setattr(
        "app.main.OsvClient.query_vulnerabilities",
        mock_osv_failure,
    )

    response = client.post(
        "/api/v1/scans",
        json={"package_name": "express"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "partial"
    assert data["checks"][1]["check_id"] == "osv_vulnerabilities"
    assert data["checks"][1]["status"] == "incomplete"
    assert data["findings"] == []

