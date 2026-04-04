"""
SecOps Fix Engine API — automated remediation for SecOps scanner findings.

Endpoints:
  POST /api/v1/secops-fix/remediate           — trigger remediation for a scan
  GET  /api/v1/secops-fix/remediate/{scan_id} — get remediation status
  GET  /api/v1/secops-fix/findings/{scan_id}  — list findings for a scan
  GET  /api/v1/secops-fix/findings/{scan_id}/summary
  GET  /api/v1/health/live                    — liveness probe
  GET  /api/v1/health/ready                   — readiness probe
  GET  /api/v1/health                         — full health
"""

import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from routers.remediation import router as remediation_router
from routers.findings import router as findings_router
from routers.health import router as health_router
from core.rule_loader import rule_loader

logger = logging.getLogger("secops_fix")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

app = FastAPI(
    title="SecOps Fix Engine API",
    description=(
        "Automated remediation engine — fetches SecOps scanner findings from DB, "
        "matches each finding to a fix rule (3-layer: exact/CWE/regex), "
        "generates fix suggestions, and patches the source repo in a new branch."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(remediation_router, prefix="/api/v1/secops-fix/remediate", tags=["Remediation"])
app.include_router(findings_router,    prefix="/api/v1/secops-fix/findings",   tags=["Findings"])
app.include_router(health_router,      prefix="/api/v1/health",                tags=["Health"])


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    count = rule_loader.load()
    logger.info(f"SecOps Fix Engine started — {count} rules loaded")


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "SecOps Fix Engine",
        "version": "1.0.0",
        "rules_loaded": rule_loader.total,
        "status": "operational",
        "endpoints": {
            "remediate":  "/api/v1/secops-fix/remediate",
            "findings":   "/api/v1/secops-fix/findings/{secops_scan_id}",
            "health":     "/api/v1/health",
            "docs":       "/docs",
        },
    }


@app.get("/health")
async def legacy_health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rules_loaded": rule_loader.total,
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SECOPS_FIX_PORT", "8006"))
    uvicorn.run(app, host="0.0.0.0", port=port)
