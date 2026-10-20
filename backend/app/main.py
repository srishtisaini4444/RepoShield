
from fastapi import FastAPI

from app.schemas.scan import ScanRequest


app = FastAPI(
    title="RepoShield API",
    description="Software supply-chain risk analysis API",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "RepoShield API",
    }


@app.post("/api/v1/scans")
def create_scan_request(request: ScanRequest):
    return {
        "status": "validated",
        "message": (
            "Input validation succeeded. "
            "Package scanning is not implemented yet."
        ),
        "target": {
            "ecosystem": "npm",
            "package_name": request.package_name,
            "version": request.version,
        },
    }

