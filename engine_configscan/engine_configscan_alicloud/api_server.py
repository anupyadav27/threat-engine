"""
FastAPI server for AliCloud Compliance Engine
"""
import sys
import os
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from engine_common.logger import setup_logger, LogContext, log_duration
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

from engine.main_scanner import scan
from auth.alicloud_auth import AliCloudAuth

logger = setup_logger(__name__, engine_name="configscan-alicloud")

app = FastAPI(
    title="AliCloud Compliance Engine API",
    description="API for running AliCloud compliance scans",
    version="1.0.0"
)

# Add logging middleware
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="configscan-alicloud")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scans = {}
scan_tasks = {}
metrics = {
    "total_scans": 0,
    "successful_scans": 0,
    "failed_scans": 0,
    "cancelled_scans": 0,
    "total_duration_seconds": 0,
    "service_counts": {}
}


class ScanRequest(BaseModel):
    account: Optional[str] = None
    include_accounts: Optional[List[str]] = None
    exclude_accounts: Optional[List[str]] = None
    region: Optional[str] = None
    include_regions: Optional[List[str]] = None
    exclude_regions: Optional[List[str]] = None
    service: Optional[str] = None
    include_services: Optional[List[str]] = None
    exclude_services: Optional[List[str]] = None
    credentials: Optional[Dict[str, Any]] = None
    max_workers: int = 10
    tenant_id: Optional[str] = None  # Tenant identifier for multi-tenant support
    scan_run_id: Optional[str] = None  # Unified scan identifier from onboarding engine


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@app.post("/api/v1/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Create and run a compliance scan"""
    # Use scan_run_id if provided (from onboarding), otherwise generate new scan_id
    scan_id = request.scan_run_id if request.scan_run_id else str(uuid.uuid4())
    
    with LogContext(tenant_id=request.tenant_id, scan_run_id=scan_id):
        logger.info("Received scan request", extra={
            "extra_fields": {
                "account": request.account,
                "regions": request.include_regions,
                "services": request.include_services,
                "exclude_services": request.exclude_services
            }
        })
        
        scans[scan_id] = {
            "status": "running",
            "results": None,
            "error": None,
            "started_at": datetime.utcnow(),
            "progress": {
                "services_completed": 0,
                "services_total": 0,
                "resources_scanned": 0,
                "percentage": 0
            },
            "cancelled": False,
            "account": request.account,
            "tenant_id": request.tenant_id,
            "scan_run_id": request.scan_run_id,
            "regions": request.include_regions or [],
            "services": request.include_services or []
        }
        
        metrics["total_scans"] += 1
        task = background_tasks.add_task(run_scan, scan_id, request)
        scan_tasks[scan_id] = task
        
        logger.info("Scan started", extra={"extra_fields": {"scan_id": scan_id}})
        
        return ScanResponse(
            scan_id=scan_id,
            status="running",
            message="Scan started"
        )


async def run_scan(scan_id: str, request: ScanRequest):
    """Run scan in background"""
    with LogContext(tenant_id=request.tenant_id, scan_run_id=scan_id):
        try:
            if scans.get(scan_id, {}).get("cancelled", False):
                scans[scan_id]["status"] = "cancelled"
                scans[scan_id]["completed_at"] = datetime.utcnow()
                metrics["cancelled_scans"] += 1
                logger.info("Scan cancelled")
                return
            
            auth_override = None
            if request.credentials:
                cred_type = request.credentials.get('credential_type')
                if cred_type == 'alicloud_access_key':
                    logger.info("Using AliCloud Access Key credentials")
                    auth_override = AliCloudAuth(
                        access_key_id=request.credentials.get('access_key_id'),
                        access_key_secret=request.credentials.get('access_key_secret')
                    )
            
            if request.include_services:
                scans[scan_id]["progress"]["services_total"] = len(request.include_services)
            else:
                try:
                    from engine.service_scanner import load_enabled_services_with_scope
                    services = load_enabled_services_with_scope()
                    scans[scan_id]["progress"]["services_total"] = len(services)
                except Exception as e:
                    logger.warning("Failed to load services for progress estimate", exc_info=True)
                    scans[scan_id]["progress"]["services_total"] = 100
            
            logger.info("Starting scan", extra={
                "extra_fields": {
                    "account": request.account,
                    "regions": request.include_regions,
                    "services": request.include_services,
                    "exclude_services": request.exclude_services
                }
            })
            
            start_time = datetime.utcnow()
        results = scan(
            account=request.account,
            include_accounts=request.include_accounts,
            exclude_accounts=request.exclude_accounts,
            region=request.region,
            include_regions=request.include_regions,
            exclude_regions=request.exclude_regions,
            service=request.service,
            include_services=request.include_services,
            exclude_services=request.exclude_services,
            max_workers=request.max_workers,
            auth_override=auth_override
        )
        
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            metrics["successful_scans"] += 1
            metrics["total_duration_seconds"] += duration
            
            if results:
                for result in results:
                    service = result.get("service", "unknown")
                    metrics["service_counts"][service] = metrics["service_counts"].get(service, 0) + 1
            
            scans[scan_id].update({
                "status": "completed",
                "results": results,
                "error": None,
                "completed_at": end_time,
                "progress": {
                    "services_completed": scans[scan_id]["progress"]["services_total"],
                    "services_total": scans[scan_id]["progress"]["services_total"],
                    "percentage": 100
                },
                "duration_seconds": duration
            })
            
            log_duration(logger, "Scan completed successfully", duration * 1000, level="INFO")
            logger.info("Scan completed", extra={
                "extra_fields": {
                    "total_results": len(results) if results else 0
                }
            })
            
        except Exception as e:
            end_time = datetime.utcnow()
            duration = (end_time - scans[scan_id]["started_at"]).total_seconds()
            metrics["failed_scans"] += 1
            metrics["total_duration_seconds"] += duration
            
            logger.error("Scan failed", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_seconds": duration
                }
            })
            
            scans[scan_id].update({
                "status": "failed",
                "results": None,
                "error": str(e),
                "completed_at": end_time,
                "duration_seconds": duration
            })
        finally:
            if scan_id in scan_tasks:
                del scan_tasks[scan_id]


@app.get("/api/v1/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status with progress"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans[scan_id]
    progress = scan_data.get("progress", {})
    
    estimated_completion = None
    if scan_data["status"] == "running" and progress.get("percentage", 0) > 0:
        elapsed = (datetime.utcnow() - scan_data["started_at"]).total_seconds()
        if progress["percentage"] > 0:
            total_estimated = elapsed / (progress["percentage"] / 100)
            remaining = total_estimated - elapsed
            estimated_completion = (datetime.utcnow().timestamp() + remaining)
    
    return {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "started_at": scan_data["started_at"].isoformat() if scan_data.get("started_at") else None,
        "completed_at": scan_data.get("completed_at").isoformat() if scan_data.get("completed_at") else None,
        "error": scan_data.get("error"),
        "progress": {
            "percentage": progress.get("percentage", 0),
            "services_completed": progress.get("services_completed", 0),
            "services_total": progress.get("services_total", 0),
            "resources_scanned": progress.get("resources_scanned", 0)
        },
        "estimated_completion": datetime.fromtimestamp(estimated_completion).isoformat() if estimated_completion else None
    }


@app.get("/api/v1/scan/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000)
):
    """Get scan results with pagination"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans[scan_id]
    
    if scan_data["status"] == "running":
        raise HTTPException(status_code=202, detail="Scan still running")
    
    if scan_data["status"] == "failed":
        raise HTTPException(status_code=500, detail=scan_data.get("error", "Scan failed"))
    
    results = scan_data.get("results", [])
    total = len(results)
    start = (page - 1) * page_size
    end = start + page_size
    paginated_results = results[start:end]
    
    return {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "results": paginated_results,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": (total + page_size - 1) // page_size
        },
        "started_at": scan_data["started_at"].isoformat() if scan_data.get("started_at") else None,
        "completed_at": scan_data.get("completed_at").isoformat() if scan_data.get("completed_at") else None
    }


@app.get("/api/v1/services")
async def list_services():
    """List available AliCloud services"""
    try:
        from engine.service_scanner import load_enabled_services_with_scope
        services = load_enabled_services_with_scope()
        return {
            "services": [
                {"name": s[0], "scope": s[1]} for s in services
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@app.post("/api/v1/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running scan"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans[scan_id]
    
    if scan_data["status"] not in ["running", "pending"]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan with status: {scan_data['status']}")
    
    scan_data["cancelled"] = True
    scan_data["status"] = "cancelled"
    scan_data["completed_at"] = datetime.utcnow()
    metrics["cancelled_scans"] += 1
    
    return {
        "scan_id": scan_id,
        "status": "cancelled",
        "message": "Scan cancellation requested"
    }


@app.get("/api/v1/scan/{scan_id}/progress")
async def get_scan_progress(scan_id: str):
    """Get real-time scan progress"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans[scan_id]
    progress = scan_data.get("progress", {})
    
    return {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "progress": {
            "percentage": progress.get("percentage", 0),
            "services_completed": progress.get("services_completed", 0),
            "services_total": progress.get("services_total", 0),
            "resources_scanned": progress.get("resources_scanned", 0)
        },
        "elapsed_seconds": (datetime.utcnow() - scan_data["started_at"]).total_seconds() if scan_data.get("started_at") else 0
    }


@app.get("/api/v1/scans")
async def list_scans(
    status: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """List all scans with filters"""
    filtered_scans = []
    
    for scan_id, scan_data in scans.items():
        if status and scan_data.get("status") != status:
            continue
        if account and scan_data.get("account") != account:
            continue
        filtered_scans.append({
            "scan_id": scan_id,
            "status": scan_data.get("status"),
            "account": scan_data.get("account"),
            "started_at": scan_data.get("started_at").isoformat() if scan_data.get("started_at") else None,
            "completed_at": scan_data.get("completed_at").isoformat() if scan_data.get("completed_at") else None
        })
    
    filtered_scans.sort(key=lambda x: x.get("started_at") or "", reverse=True)
    
    return {
        "scans": filtered_scans[offset:offset+limit],
        "total": len(filtered_scans),
        "limit": limit,
        "offset": offset
    }


@app.delete("/api/v1/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete scan and its results"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scans[scan_id]["status"] == "running":
        scans[scan_id]["cancelled"] = True
        scans[scan_id]["status"] = "cancelled"
    
    del scans[scan_id]
    if scan_id in scan_tasks:
        del scan_tasks[scan_id]
    
    return {
        "scan_id": scan_id,
        "status": "deleted",
        "message": "Scan deleted successfully"
    }


@app.get("/api/v1/scan/{scan_id}/summary")
async def get_scan_summary(scan_id: str):
    """Get scan summary with statistics"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans[scan_id]
    results = scan_data.get("results", [])
    
    total_checks = len(results)
    passed_checks = sum(1 for r in results if r.get("status") == "PASS" or r.get("compliant", False))
    failed_checks = total_checks - passed_checks
    
    failed_results = [r for r in results if r.get("status") != "PASS" and not r.get("compliant", False)]
    top_issues = {}
    for result in failed_results[:10]:
        rule_id = result.get("rule_id", "unknown")
        top_issues[rule_id] = top_issues.get(rule_id, 0) + 1
    
    return {
        "scan_id": scan_id,
        "status": scan_data.get("status"),
        "summary": {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "pass_rate": (passed_checks / total_checks * 100) if total_checks > 0 else 0
        },
        "top_issues": [{"rule_id": k, "count": v} for k, v in sorted(top_issues.items(), key=lambda x: x[1], reverse=True)],
        "duration_seconds": scan_data.get("duration_seconds", 0),
        "started_at": scan_data.get("started_at").isoformat() if scan_data.get("started_at") else None,
        "completed_at": scan_data.get("completed_at").isoformat() if scan_data.get("completed_at") else None
    }


@app.get("/api/v1/metrics")
async def get_metrics():
    """Get engine metrics"""
    avg_duration = 0
    if metrics["total_scans"] > 0:
        avg_duration = metrics["total_duration_seconds"] / metrics["total_scans"]
    
    success_rate = 0
    if metrics["total_scans"] > 0:
        success_rate = (metrics["successful_scans"] / metrics["total_scans"]) * 100
    
    return {
        "total_scans": metrics["total_scans"],
        "successful_scans": metrics["successful_scans"],
        "failed_scans": metrics["failed_scans"],
        "cancelled_scans": metrics["cancelled_scans"],
        "average_duration_seconds": round(avg_duration, 2),
        "success_rate_percent": round(success_rate, 2),
        "top_services": dict(sorted(metrics["service_counts"].items(), key=lambda x: x[1], reverse=True)[:10])
    }

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    import time
    start = time.time()
    
    health_status = {
        "status": "healthy",
        "provider": "alicloud",
        "version": "1.0.0"
    }
    
    duration_ms = (time.time() - start) * 1000
    logger.info("Health check", extra={
        "extra_fields": {
            "status": "healthy",
            "duration_ms": duration_ms
        }
    })
    
    return health_status


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

