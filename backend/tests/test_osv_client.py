
import httpx
import pytest

from app.integrations.osv_client import (
    OsvClient,
    OsvClientError,
)


def test_successful_vulnerability_lookup(monkeypatch):
    def mock_post(url, **kwargs):
        assert kwargs["json"] == {
            "package": {
                "name": "express",
                "ecosystem": "npm",
            },
            "version": "4.18.2",
        }

        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "GHSA-example-1234",
                        "summary": "Example vulnerability",
                        "modified": "2026-01-01T00:00:00Z",
                    }
                ]
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(
        "app.integrations.osv_client.httpx.post",
        mock_post,
    )

    result = OsvClient().query_vulnerabilities(
        "express",
        "4.18.2",
    )

    assert len(result) == 1
    assert result[0]["id"] == "GHSA-example-1234"
    assert result[0]["summary"] == "Example vulnerability"


def test_no_vulnerabilities_returns_empty_list(monkeypatch):
    def mock_post(url, **kwargs):
        return httpx.Response(
            200,
            json={},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(
        "app.integrations.osv_client.httpx.post",
        mock_post,
    )

    result = OsvClient().query_vulnerabilities(
        "express",
        "5.3.0",
    )

    assert result == []


def test_osv_timeout_is_reported(monkeypatch):
    def mock_post(url, **kwargs):
        request = httpx.Request("POST", url)
        raise httpx.ReadTimeout(
            "Request timed out",
            request=request,
        )

    monkeypatch.setattr(
        "app.integrations.osv_client.httpx.post",
        mock_post,
    )

    with pytest.raises(OsvClientError, match="timed out"):
        OsvClient().query_vulnerabilities(
            "express",
            "4.18.2",
        )


def test_invalid_vulnerability_list_is_rejected(monkeypatch):
    def mock_post(url, **kwargs):
        return httpx.Response(
            200,
            json={"vulns": "not-a-list"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(
        "app.integrations.osv_client.httpx.post",
        mock_post,
    )

    with pytest.raises(
        OsvClientError,
        match="invalid vulnerability list",
    ):
        OsvClient().query_vulnerabilities(
            "express",
            "4.18.2",
        )
