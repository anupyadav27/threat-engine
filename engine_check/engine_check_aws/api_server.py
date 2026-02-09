"""
FastAPI server for Check Engine
Handles compliance check scans only
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import asyncio
from datetime import datetime
from pathlib import Path
import sys
import os

# Add project root for engine_common
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import setup_logger, LogContext, log_duration

from engine.check_engine import CheckEngine
from engine.database_manager import DatabaseManager
from engine.service_scanner import load_enabled_services_with_scope

logger = setup_logger(__name__, engine_name="engine-check-aws")

app = FastAPI(
    title="AWS Check Engine API",
    description="API for running AWS compliance checks",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared DatabaseManager for health checks (avoids creating new pools per request)
_health_db_manager = None

def _get_health_db_manager():
    global _health_db_manager
    if _health_db_manager is None:
        try:
            _health_db_manager = DatabaseManager()
        except Exception:
            pass
    return _health_db_manager

# In-memory scan storage (use Redis/DB in production)
scans = {}
scan_tasks = {}  # Track running scan tasks for cancellation
metrics = {
    "total_scans": 0,
    "successful_scans": 0,
    "failed_scans": 0,
    "cancelled_scans": 0,
    "total_duration_seconds": 0,
    "service_counts": {}
}


class CheckRequest(BaseModel):
    discovery_scan_id: str  # Required - from discovery endpoint
    customer_id: Optional[str] = None
    tenant_id: Optional[str] = None
    provider: str = "aws"
    hierarchy_id: Optional[str] = None
    hierarchy_type: str = "account"
    include_services: Optional[List[str]] = None
    check_source: str = "default"
    use_ndjson: Optional[bool] = None  # If None, auto-detect


class CheckResponse(BaseModel):
    check_scan_id: str
    status: str
    message: str


@app.post("/api/v1/check", response_model=CheckResponse)
async def create_check(request: CheckRequest, background_tasks: BackgroundTasks):
    """Run check scan on discoveries - runs compliance checks"""
    check_scan_id = str(uuid.uuid4())
    
    with LogContext(tenant_id=request.tenant_id, scan_run_id=check_scan_id):
        logger.info("Received check request", extra={
            "extra_fields": {
                "discovery_scan_id": request.discovery_scan_id,
                "provider": request.provider,
                "services": request.include_services
            }
        })
    
    # Store check scan info
    scans[check_scan_id] = {
        "status": "running",
        "type": "check",
        "discovery_scan_id": request.discovery_scan_id,
        "results": None,
        "error": None,
        "started_at": datetime.utcnow(),
        "progress": {
            "services_completed": 0,
            "services_total": 0,
            "checks_completed": 0,
            "percentage": 0
        }
    }
    
    metrics["total_scans"] += 1
    
    # Run check in background
    task = background_tasks.add_task(run_check, check_scan_id, request)
    scan_tasks[check_scan_id] = task
    
    return CheckResponse(
        check_scan_id=check_scan_id,
        status="running",
        message="Check scan started"
    )


def _run_check_sync(check_scan_id: str, request: CheckRequest):
    """Run check scan synchronously (called in a thread pool)"""
    with LogContext(tenant_id=request.tenant_id, scan_run_id=check_scan_id):
        try:
            # Initialize database manager and check engine
            db_manager = None
            if request.use_ndjson is not True:
                env_mode = (os.getenv("CHECK_MODE") or "").lower()
                if env_mode not in ("ndjson", "file", "local"):
                    try:
                        db_manager = DatabaseManager()
                    except Exception:
                        logger.warning("DatabaseManager init failed; will attempt NDJSON fallback", exc_info=True)
            check_engine = CheckEngine(db_manager, use_ndjson=request.use_ndjson)

            # Get services
            services = request.include_services
            if not services:
                services_with_scope = load_enabled_services_with_scope()
                services = [s[0] for s in services_with_scope]

            # Run checks
            customer_id = request.customer_id or "default"
            tenant_id = request.tenant_id or "default-tenant"
            hierarchy_id = request.hierarchy_id or request.discovery_scan_id

            check_results = check_engine.run_check_scan(
                discovery_scan_id=request.discovery_scan_id,
                check_scan_id=check_scan_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=request.provider,
                hierarchy_id=hierarchy_id,
                hierarchy_type=request.hierarchy_type,
                services=services,
                check_source=request.check_source,
                use_ndjson=request.use_ndjson
            )

            scans[check_scan_id]["status"] = "completed"
            scans[check_scan_id]["check_scan_id"] = check_results.get('check_scan_id', check_scan_id)
            scans[check_scan_id]["results"] = check_results
            scans[check_scan_id]["completed_at"] = datetime.utcnow()
            metrics["successful_scans"] += 1

            logger.info("Check scan completed", extra={
                "extra_fields": {
                    "check_scan_id": check_scan_id,
                    "total_checks": check_results.get('total_checks', 0)
                }
            })

        except Exception as e:
            logger.error("Check scan failed", exc_info=True, extra={
                "extra_fields": {"error": str(e)}
            })
            scans[check_scan_id]["status"] = "failed"
            scans[check_scan_id]["error"] = str(e)
            scans[check_scan_id]["completed_at"] = datetime.utcnow()
            metrics["failed_scans"] += 1


async def run_check(check_scan_id: str, request: CheckRequest):
    """Run check scan in a thread pool to avoid blocking the event loop"""
    await asyncio.to_thread(_run_check_sync, check_scan_id, request)


@app.get("/api/v1/check/{check_scan_id}/status")
async def get_check_status(check_scan_id: str):
    """Get check scan status"""
    if check_scan_id not in scans:
        raise HTTPException(status_code=404, detail="Check scan not found")
    
    scan_data = scans[check_scan_id]
    return {
        "check_scan_id": check_scan_id,
        "status": scan_data["status"],
        "type": scan_data.get("type", "check"),
        "discovery_scan_id": scan_data.get("discovery_scan_id"),
        "error": scan_data.get("error"),
        "started_at": scan_data.get("started_at"),
        "completed_at": scan_data.get("completed_at"),
        "progress": scan_data.get("progress", {})
    }


@app.get("/api/v1/checks")
async def list_checks(
    tenant_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    discovery_scan_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000)
):
    """List all check scans"""
    filtered_scans = []
    for scan_id, scan_data in scans.items():
        if scan_data.get("type") != "check":
            continue
        if tenant_id and scan_data.get("tenant_id") != tenant_id:
            continue
        if status and scan_data.get("status") != status:
            continue
        if discovery_scan_id and scan_data.get("discovery_scan_id") != discovery_scan_id:
            continue
        filtered_scans.append({
            "check_scan_id": scan_id,
            "discovery_scan_id": scan_data.get("discovery_scan_id"),
            "status": scan_data.get("status"),
            "started_at": scan_data.get("started_at"),
            "completed_at": scan_data.get("completed_at")
        })
    
    return {
        "scans": filtered_scans[:limit],
        "total": len(filtered_scans)
    }


@app.get("/api/v1/health")
async def health():
    """Health check endpoint"""
    try:
        db_manager = _get_health_db_manager()
        db_info = db_manager.get_database_info() if db_manager and hasattr(db_manager, 'get_database_info') else {}
        return {
            "status": "healthy",
            "provider": "aws",
            "version": "1.0.0",
            "database": "connected" if db_manager else "disconnected",
            "database_details": db_info
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "provider": "aws",
            "version": "1.0.0",
            "database": "disconnected",
            "error": str(e)
        }


@app.get("/api/v1/health/ready")
async def health_ready():
    """Readiness check endpoint"""
    try:
        db_manager = _get_health_db_manager()
        if not db_manager:
            raise HTTPException(status_code=503, detail="Database not initialized")
        conn = db_manager._get_connection()
        db_manager._return_connection(conn)
        return {"status": "ready"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Not ready: {str(e)}")


@app.get("/api/v1/health/live")
async def health_live():
    """Liveness check endpoint"""
    return {"status": "alive"}


@app.get("/api/v1/metrics")
async def get_metrics():
    """Get engine metrics"""
    return metrics
