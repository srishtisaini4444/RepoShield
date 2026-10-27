from fastapi import FastAPI, HTTPException
from cvss import CVSS3, CVSS4
from fastapi.middleware.cors import CORSMiddleware

from app.integrations.npm_client import (
    NpmPackageNotFound,
    NpmRegistryClient,
    NpmRegistryError,
)
from app.integrations.osv_client import OsvClient, OsvClientError
from app.rules.static_rules import analyze_package_json
from app.schemas.scan import ScanRequest


app = FastAPI(
    title="RepoShield API",
    description="Explainable npm package security risk assessment.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://reposhield.onrender.com",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_osv_severity(vulnerability: dict) -> str:
    """Determine the highest recognized severity from OSV CVSS metadata."""

    severity_order = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    detected_severities = []
    severity_data = vulnerability.get("severity", [])

    if isinstance(severity_data, list):
        for item in severity_data:
            if not isinstance(item, dict):
                continue

            vector = item.get("score")
            vector_type = item.get("type", "")

            if not isinstance(vector, str):
                continue

            try:
                if vector_type == "CVSS_V4" or vector.startswith("CVSS:4.0/"):
                    parser = CVSS4(vector)

                elif vector_type.startswith("CVSS_V3") or vector.startswith(
                    ("CVSS:3.0/", "CVSS:3.1/")
                ):
                    parser = CVSS3(vector)

                else:
                    continue

                severity = parser.severities()[0].lower()

                if severity in severity_order:
                    detected_severities.append(severity)

            except Exception:
                # Ignore malformed or unsupported vectors.
                continue

    # Fall back to an explicit database severity when available.
    if not detected_severities:
        for affected_item in vulnerability.get("affected", []):
            if not isinstance(affected_item, dict):
                continue

            database_specific = affected_item.get("database_specific", {})

            if not isinstance(database_specific, dict):
                continue

            severity = database_specific.get("severity")

            if isinstance(severity, str):
                severity = severity.lower()

                if severity in severity_order:
                    detected_severities.append(severity)

    if not detected_severities:
        return "unknown"

    return max(
        detected_severities,
        key=lambda severity: severity_order[severity],
    )


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/api/v1/scans")
def scan_package(request: ScanRequest):
    npm_client = NpmRegistryClient()

    # Resolve the package and requested version.
    try:
        if request.version:
            metadata = npm_client.get_package_version_metadata(
                request.package_name,
                request.version,
            )
            package_version = metadata["version"]
        else:
            metadata = npm_client.get_package_metadata(
                request.package_name
            )
            package_version = metadata["latest_version"]

    except NpmPackageNotFound:
        raise HTTPException(
            status_code=404,
            detail="The requested npm package or version was not found.",
        )

    except NpmRegistryError:
        raise HTTPException(
            status_code=502,
            detail=(
                "Package lookup failed because the npm Registry "
                "could not complete the request."
            ),
        )

    target = {
        "package_name": request.package_name,
        "requested_version": request.version,
        "resolved_version": package_version,
    }

    findings = []
    checks = []

    # Static package configuration analysis.
    try:
        manifest = npm_client.get_package_manifest(
            request.package_name,
            package_version,
        )

        rule_findings = analyze_package_json(manifest)

        for finding in rule_findings:
            findings.append(
                {
                    "id": finding["rule_id"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "description": finding["description"],
                    "evidence": finding["evidence"],
                    "recommendation": finding["recommendation"],
                    "source": "static_rules",
                }
            )

        checks.append(
            {
                "check_id": "static_rules",
                "status": "completed",
                "message": "Package configuration analysis completed.",
            }
        )

    except (NpmPackageNotFound, NpmRegistryError):
        checks.append(
            {
                "check_id": "static_rules",
                "status": "incomplete",
                "message": (
                    "The package manifest could not be retrieved, "
                    "so static analysis was incomplete."
                ),
            }
        )

    # Known vulnerability lookup through OSV.
    try:
        osv_client = OsvClient()

        vulnerabilities = osv_client.query_vulnerabilities(
            request.package_name,
            package_version,
        )

        for vulnerability in vulnerabilities:
            advisory_id = vulnerability.get("id", "OSV-UNKNOWN")

            findings.append(
                {
                    "id": advisory_id,
                    "title": vulnerability.get(
                        "summary",
                        "Known vulnerability",
                    ),
                    "severity": get_osv_severity(vulnerability),
                    "description": vulnerability.get(
                        "details",
                        "A vulnerability record was returned by OSV.",
                    ),
                    "evidence": {
                        "source": "OSV",
                        "advisory_id": advisory_id,
                        "severity_data": vulnerability.get(
                            "severity",
                            [],
                        ),
                        "affected": vulnerability.get(
                            "affected",
                            [],
                        ),
                        "references": vulnerability.get(
                            "references",
                            [],
                        ),
                    },
                    "recommendation": (
                        "Review the advisory and verify its "
                        "affected-version range before deciding "
                        "on remediation."
                    ),
                    "source": "OSV",
                }
            )

        checks.append(
            {
                "check_id": "osv_vulnerabilities",
                "status": "completed",
                "message": (
                    f"OSV returned {len(vulnerabilities)} "
                    "vulnerability record(s)."
                ),
            }
        )

    except OsvClientError:
        checks.append(
            {
                "check_id": "osv_vulnerabilities",
                "status": "incomplete",
                "message": (
                    "The OSV vulnerability lookup could not complete. "
                    "The package's vulnerability status is unknown."
                ),
            }
        )

    # Determine whether all checks completed.
    scan_status = (
        "partial"
        if any(check["status"] != "completed" for check in checks)
        else "completed"
    )

    # Calculate the overall risk level from recognized findings.
    severities = {
        finding.get("severity")
        for finding in findings
    }

    if "critical" in severities:
        risk_level = "critical"
    elif "high" in severities:
        risk_level = "high"
    elif "medium" in severities:
        risk_level = "medium"
    elif "low" in severities:
        risk_level = "low"
    elif findings:
        risk_level = "unknown"
    else:
        risk_level = "no_findings"

    return {
        "target": target,
        "metadata": {
            "name": metadata.get(
                "name",
                request.package_name,
            ),
            "description": metadata.get("description", ""),
        },
        "package": {
            "name": request.package_name,
            "version": package_version,
            "description": metadata.get("description", ""),
        },
        "status": scan_status,
        "risk_level": risk_level,
        "findings_count": len(findings),
        "findings": findings,
        "checks": checks,
        "limitations": [
            "No findings does not guarantee that a package is safe.",
            (
                "Static rules identify risk indicators, "
                "not confirmed malicious behavior."
            ),
            (
                "OSV advisories should be checked against "
                "their affected-version ranges."
            ),
            "Dependency lockfile analysis is not currently implemented.",
        ],
    }