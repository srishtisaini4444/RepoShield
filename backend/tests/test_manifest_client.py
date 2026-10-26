import httpx
import pytest

from app.integrations.npm_client import (
    NpmPackageNotFound,
    NpmRegistryClient,
    NpmRegistryError,
)


def test_manifest_retrieval(monkeypatch):
    def fake_get(url, **kwargs):
        assert "express" in url
        assert "5.1.0" in url

        return httpx.Response(
            200,
            json={
                "name": "express",
                "version": "5.1.0",
                "scripts": {
                    "postinstall": "node setup.js"
                },
                "dependencies": {
                    "accepts": "^2.0.0"
                },
                "devDependencies": {},
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        fake_get,
    )

    client = NpmRegistryClient()
    result = client.get_package_manifest("express", "5.1.0")

    assert result["name"] == "express"
    assert result["version"] == "5.1.0"
    assert result["scripts"]["postinstall"] == "node setup.js"
    assert result["dependencies"]["accepts"] == "^2.0.0"


def test_manifest_rejects_missing_package(monkeypatch):
    def fake_get(url, **kwargs):
        return httpx.Response(
            404,
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        fake_get,
    )

    client = NpmRegistryClient()

    with pytest.raises(NpmPackageNotFound):
        client.get_package_manifest("missing-package", "1.0.0")


def test_manifest_rejects_mismatched_version(monkeypatch):
    def fake_get(url, **kwargs):
        return httpx.Response(
            200,
            json={
                "name": "express",
                "version": "9.9.9",
                "scripts": {},
                "dependencies": {},
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(
        "app.integrations.npm_client.httpx.get",
        fake_get,
    )

    client = NpmRegistryClient()

    with pytest.raises(NpmRegistryError):
        client.get_package_manifest("express", "5.1.0")
