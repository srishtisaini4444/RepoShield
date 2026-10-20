
from fastapi import FastAPI

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
