"""
FastAPI server for Container Security Engine.
Port: 8008
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

logger = setup_logger(__name__, engine_name="engine-container-sec")

SCANNER_IMAGE = os.getenv("CSEC_SCANNER_IMAGE", "yadavanup84/engine-container-sec:v-std-cols")
SCANNER_CPU_REQUEST = os.getenv("SCANNER_CPU_REQUEST", "100m")
SCANNER_MEM_REQUEST = os.getenv("SCANNER_MEM_REQUEST", "512Mi")
SCANNER_CPU_LIMIT = os.getenv("SCANNER_CPU_LIMIT", "250m")
SCANNER_MEM_LIMIT = os.getenv("SCANNER_MEM_LIMIT", "1Gi")

app = FastAPI(
    title="Container Security Engine API",
    description="Container & K8s security posture — EKS/ECS/ECR cluster, workload, image, RBAC, network analysis",
    version="1.0.0",
)
configure_telemetry("engine-container-sec", app)

app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="engine-container-sec")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

from .api.ui_data_router import router as ui_data_router
app.include_router(ui_data_router)


class ScanRequest(BaseModel):
    csp: str = Field(..., description="Cloud service provider")
    scan_run_id: Optional[str] = Field(None)
    tenant_id: str = Field(default="default-tenant")


@app.get("/api/v1/health/live")
async def liveness():
    return {"status": "ok"}

@app.get("/api/v1/health/ready")
async def readiness():
    return {"status": "ok"}

@app.get("/api/v1/health")
async def health():
    import psycopg2
    try:
        conn = psycopg2.connect(
            host=os.getenv("CSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("CSEC_DB_NAME", "threat_engine_container_security"),
            user=os.getenv("CSEC_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            connect_timeout=5,
        )
        conn.close()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "degraded", "database": str(e)}


@app.post("/api/v1/container-security/scan")
async def trigger_scan(request: ScanRequest):
    if not request.scan_run_id:
        raise HTTPException(status_code=400, detail="scan_run_id is required")
    metadata = get_orchestration_metadata(request.scan_run_id)
    if not metadata:
        raise HTTPException(status_code=404, detail=f"No orchestration metadata for {request.scan_run_id}")

    try:
        job_name = create_engine_job(
            engine_name="container-security",
            scan_id=request.scan_run_id,
            scan_run_id=request.scan_run_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU_REQUEST,
            mem_request=SCANNER_MEM_REQUEST,
            cpu_limit=SCANNER_CPU_LIMIT,
            mem_limit=SCANNER_MEM_LIMIT,
        )
        return {"status": "submitted", "scan_run_id": request.scan_run_id, "job_name": job_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/container-security/{scan_run_id}/status")
async def get_scan_status(scan_run_id: str):
    import psycopg2
    from psycopg2.extras import RealDictCursor
    try:
        conn = psycopg2.connect(
            host=os.getenv("CSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("CSEC_DB_NAME", "threat_engine_container_security"),
            user=os.getenv("CSEC_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            connect_timeout=5,
        )
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT scan_run_id, status, posture_score, total_findings, error_message FROM container_sec_report WHERE scan_run_id = %s",
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
