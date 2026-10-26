
import httpx


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvClientError(Exception):
    """Raised when the OSV vulnerability lookup fails."""


class OsvClient:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def query_vulnerabilities(
        self,
        package_name: str,
        version: str,
    ) -> list[dict]:
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": "npm",
            },
            "version": version,
        }

        try:
            response = httpx.post(
                OSV_QUERY_URL,
                json=payload,
                timeout=self.timeout,
                follow_redirects=False,
            )
        except httpx.TimeoutException as exc:
            raise OsvClientError(
                "The OSV request timed out."
            ) from exc
        except httpx.RequestError as exc:
            raise OsvClientError(
                "Could not connect to the OSV vulnerability database."
            ) from exc

        if response.status_code != 200:
            raise OsvClientError(
                f"OSV returned HTTP {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise OsvClientError(
                "OSV returned invalid JSON."
            ) from exc

        if not isinstance(data, dict):
            raise OsvClientError(
                "OSV returned an unexpected response format."
            )

        vulnerabilities = data.get("vulns", [])

        if not isinstance(vulnerabilities, list):
            raise OsvClientError(
                "OSV returned an invalid vulnerability list."
            )

        results = []

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise OsvClientError(
                    "OSV returned an invalid vulnerability record."
                )

            vulnerability_id = vulnerability.get("id")

            if not isinstance(vulnerability_id, str) or not vulnerability_id:
                raise OsvClientError(
                    "An OSV vulnerability record is missing its ID."
                )

            summary = vulnerability.get("summary")
            if not isinstance(summary, str):
                summary = ""

            
            details = vulnerability.get("details")
            if not isinstance(details, str):
                details = ""

            severity_data = vulnerability.get("severity", [])
            if not isinstance(severity_data, list):
                severity_data = []

            references_data = vulnerability.get("references", [])
            if not isinstance(references_data, list):
                references_data = []

            references = [
                item["url"]
                for item in references_data
                if isinstance(item, dict)
                and isinstance(item.get("url"), str)
                and item["url"].startswith(("https://", "http://"))
            ]

            affected_data = vulnerability.get("affected", [])
            if not isinstance(affected_data, list):
                affected_data = []

            results.append({
                "id": vulnerability_id,
                "summary": summary,
                "details": details,
                "modified": vulnerability.get("modified"),
                "severity": severity_data,
                "references": references,
                "affected": affected_data,
            })


        return results
