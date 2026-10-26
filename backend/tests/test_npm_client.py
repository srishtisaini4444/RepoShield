
import httpx
import pytest

from app.integrations.npm_client import (
    NpmPackageNotFound,
    NpmRegistryClient,
    NpmRegistryError,
)


def test_successful_metadata_lookup(monkeypatch):
    def mock_get(url, **kwargs):
        return httpx.Response(
            200,
            json={
                "name": "express",
                "description": "Web framework",
                "dist-tags": {"latest": "5.3.0"},
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        mock_get,
    )

    result = NpmRegistryClient().get_package_metadata("express")

    assert result == {
        "name": "express",
        "latest_version": "5.3.0",
        "description": "Web framework",
    }


def test_missing_package(monkeypatch):
    def mock_get(url, **kwargs):
        return httpx.Response(
            404,
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        mock_get,
    )

    with pytest.raises(NpmPackageNotFound):
        NpmRegistryClient().get_package_metadata("missing-package")


def test_timeout_is_reported(monkeypatch):
    def mock_get(url, **kwargs):
        request = httpx.Request("GET", url)
        raise httpx.ReadTimeout("Request timed out", request=request)

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        mock_get,
    )

    with pytest.raises(NpmRegistryError, match="timed out"):
        NpmRegistryClient().get_package_metadata("express")


def test_invalid_json_is_rejected(monkeypatch):
    def mock_get(url, **kwargs):
        return httpx.Response(
            200,
            text="not valid JSON",
            headers={"Content-Type": "application/json"},
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        mock_get,
    )

    with pytest.raises(NpmRegistryError, match="invalid JSON"):
        NpmRegistryClient().get_package_metadata("express")

        
def test_exact_version_lookup(monkeypatch):
    def mock_get(url, **kwargs):
        assert url.endswith("/express/4.18.2")
        return httpx.Response(
            200,
            json={
                "name": "express",
                "version": "4.18.2",
                "description": "Web framework",
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        mock_get,
    )

    result = NpmRegistryClient().get_package_version_metadata(
        "express",
        "4.18.2",
    )

    assert result == {
        "name": "express",
        "version": "4.18.2",
        "description": "Web framework",
    }


def test_exact_version_not_found(monkeypatch):
    def mock_get(url, **kwargs):
        return httpx.Response(
            404,
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        mock_get,
    )

    with pytest.raises(NpmPackageNotFound):
        NpmRegistryClient().get_package_version_metadata(
            "express",
            "0.0.0-nonexistent",
        )


def test_exact_version_mismatch_is_rejected(monkeypatch):
    def mock_get(url, **kwargs):
        return httpx.Response(
            200,
            json={
                "name": "express",
                "version": "5.3.0",
                "description": "Web framework",
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        mock_get,
    )

    with pytest.raises(NpmRegistryError, match="version did not match"):
        NpmRegistryClient().get_package_version_metadata(
            "express",
            "4.18.2",
        )

