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

from routers.remediation import router as remediation_router
from routers.findings import router as findings_router
from routers.health import router as health_router
from db.db_config import close_pool

logger = logging.getLogger("secops_fix")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

app = FastAPI(
    title="SecOps Fix Engine API",
    description=(
        "Automated remediation engine — fetches SecOps scanner findings from DB, "
        "pulls rule metadata from secops_rule_metadata (single source of truth), "
        "calls Mistral AI with full code context to generate precise fixes, "
        "and commits the patched code to a new branch in the source repo."
    ),
    version="2.0.0",
)

# CORS — restrict in production via ALLOWED_ORIGINS env var
_allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(remediation_router, prefix="/api/v1/secops-fix/remediate", tags=["Remediation"])
app.include_router(findings_router,    prefix="/api/v1/secops-fix/findings",   tags=["Findings"])
app.include_router(health_router,      prefix="/api/v1/health",                tags=["Health"])


# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    ai_enabled = bool(os.getenv("MISTRAL_API_KEY", "").strip())
    logger.info(
        f"SecOps Fix Engine started — "
        f"rules source: secops_rule_metadata (DB) — "
        f"AI fix: {'enabled (Mistral)' if ai_enabled else 'disabled (set MISTRAL_API_KEY)'}"
    )


@app.on_event("shutdown")
async def _shutdown():
    close_pool()
    logger.info("SecOps Fix Engine shutdown complete")


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "SecOps Fix Engine",
        "version": "2.0.0",
        "rules_source": "secops_rule_metadata table (same DB as SAST scanner)",
        "ai_fix": bool(os.getenv("MISTRAL_API_KEY", "").strip()),
        "status": "operational",
        "endpoints": {
            "remediate": "/api/v1/secops-fix/remediate",
            "findings":  "/api/v1/secops-fix/findings/{secops_scan_id}",
            "health":    "/api/v1/health",
            "docs":      "/docs",
        },
    }


@app.get("/health")
async def legacy_health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rules_source": "secops_rule_metadata (DB)",
        "ai_fix_enabled": bool(os.getenv("MISTRAL_API_KEY", "").strip()),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SECOPS_FIX_PORT", "8006"))
    uvicorn.run(app, host="0.0.0.0", port=port)
