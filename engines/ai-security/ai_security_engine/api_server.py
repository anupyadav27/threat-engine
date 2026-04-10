"""
FastAPI server for AI Security Engine.

Provides endpoints for AI/ML security posture queries and scan triggering.
Port: 8032
"""

import os
import sys
import logging

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from engine_common.logger import setup_logger
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.orchestration import get_orchestration_metadata
from engine_common.job_creator import create_engine_job

logger = setup_logger(__name__, engine_name="engine-ai-security")

# -- Scanner Job config -------------------------------------------------------
SCANNER_IMAGE = os.getenv("AI_SECURITY_SCANNER_IMAGE", "yadavanup84/engine-ai-security:v-std-cols")
SCANNER_CPU_REQUEST = os.getenv("SCANNER_CPU_REQUEST", "100m")
SCANNER_MEM_REQUEST = os.getenv("SCANNER_MEM_REQUEST", "512Mi")
SCANNER_CPU_LIMIT = os.getenv("SCANNER_CPU_LIMIT", "250m")
SCANNER_MEM_LIMIT = os.getenv("SCANNER_MEM_LIMIT", "1Gi")

app = FastAPI(
    title="AI Security Engine API",
    description="AI/ML Security Posture Management — model security, endpoint security, data pipeline, AI governance, prompt security, access control",
    version="1.0.0",
)
configure_telemetry("engine-ai-security", app)

app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="engine-ai-security")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
from .api.ui_data_router import router as ui_data_router
app.include_router(ui_data_router)


# -- Request Models -----------------------------------------------------------

class ScanRequest(BaseModel):
    """Request body for triggering an AI security scan."""

    csp: str = Field(..., description="Cloud service provider (aws, azure, gcp)")
    scan_run_id: Optional[str] = Field(None, description="Pipeline scan_run_id")
    tenant_id: str = Field(default="default-tenant", description="Tenant ID")


# -- Health Checks ------------------------------------------------------------

@app.get("/api/v1/health/live")
async def liveness():
    """Kubernetes liveness probe."""
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
async def readiness():
    """Kubernetes readiness probe."""
    return {"status": "ok"}


@app.get("/api/v1/health")
async def health():
    """Full health check with database connectivity status."""
    import psycopg2
    try:
        conn = psycopg2.connect(
            host=os.getenv("AI_SECURITY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("AI_SECURITY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("AI_SECURITY_DB_NAME", "threat_engine_ai_security"),
            user=os.getenv("AI_SECURITY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("AI_SECURITY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            connect_timeout=5,
        )
        conn.close()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "degraded", "database": str(e)}


# -- Scan Trigger -------------------------------------------------------------

@app.post("/api/v1/ai-security/scan")
async def trigger_scan(request: ScanRequest):
    """Trigger an AI security scan.

    Pipeline mode: scan_run_id provided, fetch metadata from scan_orchestration.
    Creates a K8s Job on spot node.
    """
    scan_run_id = request.scan_run_id
    if not scan_run_id:
        raise HTTPException(status_code=400, detail="scan_run_id is required")

    # Verify orchestration metadata exists
    metadata = get_orchestration_metadata(scan_run_id)
    if not metadata:
        raise HTTPException(
            status_code=404,
            detail=f"No orchestration metadata for {scan_run_id}",
        )

    tenant_id = metadata.get("tenant_id", request.tenant_id)
    provider = (metadata.get("provider") or request.csp).lower()

    logger.info(f"Triggering AI security scan: scan_run_id={scan_run_id} tenant={tenant_id}")

    try:
        job_name = create_engine_job(
            engine_name="ai-security",
            scan_id=scan_run_id,
            scan_run_id=scan_run_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU_REQUEST,
            mem_request=SCANNER_MEM_REQUEST,
            cpu_limit=SCANNER_CPU_LIMIT,
            mem_limit=SCANNER_MEM_LIMIT,
        )
        return {
            "status": "submitted",
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "provider": provider,
            "job_name": job_name,
        }
    except Exception as e:
        logger.error(f"Failed to create AI security scan job: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scan job: {e}")


# -- Status -------------------------------------------------------------------

@app.get("/api/v1/ai-security/{scan_run_id}/status")
async def get_scan_status(scan_run_id: str):
    """Get AI security scan status and summary from ai_security_report."""
    import psycopg2
    from psycopg2.extras import RealDictCursor

    try:
        conn = psycopg2.connect(
            host=os.getenv("AI_SECURITY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("AI_SECURITY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("AI_SECURITY_DB_NAME", "threat_engine_ai_security"),
            user=os.getenv("AI_SECURITY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("AI_SECURITY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            connect_timeout=5,
        )
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT scan_run_id, status,
                          risk_score, total_findings, error_message
                   FROM ai_security_report
                   WHERE scan_run_id = %s""",
                (scan_run_id,),
            )
            row = cur.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("AI_SECURITY_ENGINE_PORT", "8032"))
    uvicorn.run(app, host="0.0.0.0", port=port)
