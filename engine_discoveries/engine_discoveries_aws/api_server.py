"""
FastAPI server for Discoveries Engine
Handles discovery scans only
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime
from pathlib import Path
import sys
import os

# Add project root for engine_common
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import setup_logger, LogContext, log_duration

from engine.discovery_engine import DiscoveryEngine
from engine.database_manager import DatabaseManager
from engine.service_scanner import load_enabled_services_with_scope
from auth.aws_auth import get_session_for_account
import boto3

logger = setup_logger(__name__, engine_name="engine-discoveries-aws")

app = FastAPI(
    title="AWS Discoveries Engine API",
    description="API for running AWS discovery scans",
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


class DiscoveryRequest(BaseModel):
    customer_id: Optional[str] = None
    tenant_id: Optional[str] = None
    provider: str = "aws"
    hierarchy_id: Optional[str] = None
    hierarchy_type: str = "account"
    include_services: Optional[List[str]] = None
    include_regions: Optional[List[str]] = None
    credentials: Optional[Dict[str, Any]] = None
    use_database: Optional[bool] = None  # If None, auto-detect


class DiscoveryResponse(BaseModel):
    discovery_scan_id: str
    status: str
    message: str


@app.post("/api/v1/discovery", response_model=DiscoveryResponse)
async def create_discovery(request: DiscoveryRequest, background_tasks: BackgroundTasks):
    """Run discovery scan only - discovers AWS resources"""
    discovery_scan_id = str(uuid.uuid4())
    
    with LogContext(tenant_id=request.tenant_id, scan_run_id=discovery_scan_id):
        logger.info("Received discovery request", extra={
            "extra_fields": {
                "provider": request.provider,
                "hierarchy_id": request.hierarchy_id,
                "services": request.include_services,
                "regions": request.include_regions
            }
        })
    
    # Store discovery scan info
    scans[discovery_scan_id] = {
        "status": "running",
        "type": "discovery",
        "results": None,
        "error": None,
        "started_at": datetime.utcnow(),
        "progress": {
            "services_completed": 0,
            "services_total": 0,
            "resources_scanned": 0,
            "percentage": 0
        }
    }
    
    metrics["total_scans"] += 1
    
    # Run discovery in background
    task = background_tasks.add_task(run_discovery, discovery_scan_id, request)
    scan_tasks[discovery_scan_id] = task
    
    return DiscoveryResponse(
        discovery_scan_id=discovery_scan_id,
        status="running",
        message="Discovery scan started"
    )


async def run_discovery(discovery_scan_id: str, request: DiscoveryRequest):
    """Run discovery scan in background"""
    with LogContext(tenant_id=request.tenant_id, scan_run_id=discovery_scan_id):
        try:
            import os
            
            # Set credentials in environment
            if request.credentials:
                cred_type = request.credentials.get('credential_type')
                if cred_type in ('aws_access_key', 'access_key'):
                    os.environ['AWS_ACCESS_KEY_ID'] = request.credentials.get('access_key_id')
                    os.environ['AWS_SECRET_ACCESS_KEY'] = request.credentials.get('secret_access_key')
                    if 'AWS_ROLE_ARN' in os.environ:
                        os.environ.pop('AWS_ROLE_ARN')
            
            # Get account ID if not provided
            hierarchy_id = request.hierarchy_id
            if not hierarchy_id:
                import boto3
                sts = boto3.client('sts')
                hierarchy_id = sts.get_caller_identity().get('Account')
            
            # Initialize database manager and discovery engine
            db_manager = DatabaseManager() if os.getenv("DATABASE_URL") else None
            discovery_engine = DiscoveryEngine(db_manager, use_database=request.use_database)
            
            # Get services
            services = request.include_services
            if not services:
                # Returns list of tuples: [('s3', 'global'), ...]
                services_with_scope = load_enabled_services_with_scope()
                services = [s[0] for s in services_with_scope]  # Extract just service names
            
            # Run discovery
            customer_id = request.customer_id or "default"
            tenant_id = request.tenant_id or "default-tenant"
            
            result_scan_id = discovery_engine.run_discovery_scan(
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=request.provider,
                hierarchy_id=hierarchy_id,
                hierarchy_type=request.hierarchy_type,
                services=services,
                regions=request.include_regions
            )
            
            scans[discovery_scan_id]["status"] = "completed"
            scans[discovery_scan_id]["discovery_scan_id"] = result_scan_id
            scans[discovery_scan_id]["completed_at"] = datetime.utcnow()
            metrics["successful_scans"] += 1
            
            logger.info("Discovery scan completed", extra={
                "extra_fields": {"discovery_scan_id": result_scan_id}
            })
            
        except Exception as e:
            logger.error("Discovery scan failed", exc_info=True, extra={
                "extra_fields": {"error": str(e)}
            })
            scans[discovery_scan_id]["status"] = "failed"
            scans[discovery_scan_id]["error"] = str(e)
            scans[discovery_scan_id]["completed_at"] = datetime.utcnow()
            metrics["failed_scans"] += 1


@app.get("/api/v1/discovery/{discovery_scan_id}/status")
async def get_discovery_status(discovery_scan_id: str):
    """Get discovery scan status"""
    if discovery_scan_id not in scans:
        raise HTTPException(status_code=404, detail="Discovery scan not found")
    
    scan_data = scans[discovery_scan_id]
    return {
        "discovery_scan_id": discovery_scan_id,
        "status": scan_data["status"],
        "type": scan_data.get("type", "discovery"),
        "error": scan_data.get("error"),
        "started_at": scan_data.get("started_at"),
        "completed_at": scan_data.get("completed_at"),
        "progress": scan_data.get("progress", {})
    }


@app.get("/api/v1/discoveries")
async def list_discoveries(
    tenant_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000)
):
    """List all discovery scans"""
    filtered_scans = []
    for scan_id, scan_data in scans.items():
        if scan_data.get("type") != "discovery":
            continue
        if tenant_id and scan_data.get("tenant_id") != tenant_id:
            continue
        if status and scan_data.get("status") != status:
            continue
        filtered_scans.append({
            "discovery_scan_id": scan_id,
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
        db_manager = DatabaseManager()
        db_info = db_manager.get_database_info() if hasattr(db_manager, 'get_database_info') else {}
        return {
            "status": "healthy",
            "provider": "aws",
            "version": "1.0.0",
            "database": "connected",
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
        db_manager = DatabaseManager()
        # Test connection
        conn = db_manager._get_connection()
        db_manager._return_connection(conn)
        return {"status": "ready"}
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


@app.get("/api/v1/services")
async def list_services():
    """List available AWS services for discovery"""
    try:
        services = load_enabled_services_with_scope()
        return {
            "services": services,
            "total": len(services)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
