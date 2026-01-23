"""
FastAPI server for AWS Compliance Engine
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import asyncio
from datetime import datetime
import threading

from engine.main_scanner import scan
from engine.service_scanner import load_enabled_services_with_scope
from auth.aws_auth import get_session_for_account
import boto3

app = FastAPI(
    title="AWS Compliance Engine API",
    description="API for running AWS compliance scans",
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
    max_account_workers: int = 3  # Allow parallel account scanning (default: 3)
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
    
    # Log received parameters for debugging
    print(f"[Scan {scan_id}] Received scan request:")
    print(f"  Account: {request.account}")
    print(f"  Tenant ID: {request.tenant_id}")
    print(f"  Scan Run ID: {request.scan_run_id}")
    print(f"  Include Regions: {request.include_regions}")
    print(f"  Include Services: {request.include_services}")
    print(f"  Exclude Services: {request.exclude_services}")
    if request.credentials:
        print(f"  Credential Type: {request.credentials.get('credential_type')}")
        if request.credentials.get('role_arn'):
            print(f"  Role ARN: {request.credentials.get('role_arn')}")
        if request.credentials.get('role_name'):
            print(f"  Role Name: {request.credentials.get('role_name')}")
    
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
    
    # Run scan in background
    task = background_tasks.add_task(run_scan, scan_id, request)
    scan_tasks[scan_id] = task
    
    # Create response with explicit headers to ensure connection stays open
    from fastapi import Response
    response_data = ScanResponse(
        scan_id=scan_id,
        status="running",
        message="Scan started"
    )
    
    # Return response - FastAPI will handle serialization
    # The response is sent immediately, scan continues in background
    return response_data


async def run_scan(scan_id: str, request: ScanRequest):
    """Run scan in background"""
    try:
        import os
        
        # Check if cancelled
        if scans.get(scan_id, {}).get("cancelled", False):
            scans[scan_id]["status"] = "cancelled"
            scans[scan_id]["completed_at"] = datetime.utcnow()
            metrics["cancelled_scans"] += 1
            return
        
        # Set credentials in environment for scan function
        role_name = None
        external_id = None
        
        if request.credentials:
            cred_type = request.credentials.get('credential_type')
            # Be tolerant: some callers store/send "access_key" instead of "aws_access_key"
            if cred_type in ('aws_access_key', 'access_key'):
                # User chose access keys - use them and clear AWS_ROLE_ARN to prevent role assumption
                os.environ['AWS_ACCESS_KEY_ID'] = request.credentials.get('access_key_id')
                os.environ['AWS_SECRET_ACCESS_KEY'] = request.credentials.get('secret_access_key')
                if 'AWS_ROLE_ARN' in os.environ:
                    removed_arn = os.environ.pop('AWS_ROLE_ARN')
                    print(f"[Scan {scan_id}] Using AWS Access Key credentials - cleared AWS_ROLE_ARN={removed_arn}")
                else:
                    print(f"[Scan {scan_id}] Using AWS Access Key credentials")
            elif cred_type == 'aws_iam_role':
                # Handle both role_arn (from onboarding) and role_name
                role_arn = request.credentials.get('role_arn')
                if role_arn:
                    # Extract role name from ARN format: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
                    if role_arn.startswith('arn:aws:iam::') and ':role/' in role_arn:
                        role_name = role_arn.split(':role/')[-1]
                        print(f"[Scan {scan_id}] Extracted role_name '{role_name}' from role_arn '{role_arn}'")
                    else:
                        # If ARN format is invalid, try to use as-is
                        role_name = role_arn
                        print(f"[Scan {scan_id}] Using role_arn as role_name (invalid format): {role_arn}")
                else:
                    # Fallback to role_name if role_arn not provided
                    role_name = request.credentials.get('role_name')
                    if role_name:
                        print(f"[Scan {scan_id}] Using provided role_name: {role_name}")
                external_id = request.credentials.get('external_id')
                print(f"[Scan {scan_id}] IAM Role credentials - role_name: {role_name}, external_id: {external_id}")
        
        # Update progress - estimate total services
        if request.include_services:
            scans[scan_id]["progress"]["services_total"] = len(request.include_services)
        else:
            # Estimate based on available services
            try:
                services = load_enabled_services_with_scope()
                scans[scan_id]["progress"]["services_total"] = len(services)
            except:
                scans[scan_id]["progress"]["services_total"] = 100  # Default estimate
        
        # Run scan
        print(f"[Scan {scan_id}] Starting scan with parameters:")
        print(f"  Account: {request.account}")
        print(f"  Include Regions: {request.include_regions}")
        print(f"  Include Services: {request.include_services}")
        print(f"  Exclude Services: {request.exclude_services}")
        print(f"  Role Name: {role_name}")
        print(f"  External ID: {external_id}")
        
        # Note: If using access keys, AWS_ROLE_ARN was already cleared above
        # If using IAM role, role_name is set and will be passed to scan()
        # scan() will use role_name if provided, otherwise get_boto3_session() will check AWS_ROLE_ARN
        
        start_time = datetime.utcnow()
        # IMPORTANT:
        # `scan(...)` is CPU/network heavy and synchronous. If we run it directly here,
        # it blocks the event loop thread and causes /health to miss the very strict
        # Kubernetes probe timeouts (default timeoutSeconds=1), leading to pod restarts.
        # That’s the primary cause of "server disconnected" / "connection attempts failed"
        # observed by the onboarding engine client.
        #
        # Run the scan in a worker thread to keep the FastAPI event loop responsive.
        scan_summary = await asyncio.to_thread(
            scan,
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
            max_account_workers=request.max_account_workers,
            role_name=role_name,
            external_id=external_id,
            # Stream results to disk to avoid OOM for full scans
            stream_results=True,
            output_scan_id=scan_id
        )
        
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        # Update metrics
        metrics["successful_scans"] += 1
        metrics["total_duration_seconds"] += duration
        
        scans[scan_id].update({
            "status": "completed",
            "results": None,
            "summary": scan_summary,
            "error": None,
            "completed_at": end_time,
            "progress": {
                "services_completed": scans[scan_id]["progress"]["services_total"],
                "services_total": scans[scan_id]["progress"]["services_total"],
                "percentage": 100
            },
            "duration_seconds": duration
        })
        
    except Exception as e:
        end_time = datetime.utcnow()
        duration = (end_time - scans[scan_id]["started_at"]).total_seconds()
        metrics["failed_scans"] += 1
        metrics["total_duration_seconds"] += duration
        
        scans[scan_id].update({
            "status": "failed",
            "results": None,
            "error": str(e),
            "completed_at": end_time,
            "duration_seconds": duration
        })
    finally:
        # Clean up task tracking
        if scan_id in scan_tasks:
            del scan_tasks[scan_id]


@app.get("/api/v1/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status with progress"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans[scan_id]
    progress = scan_data.get("progress", {})
    
    # Calculate estimated completion time if running
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
    
    results = scan_data.get("results") or []

    # If results were streamed to disk (results.ndjson), load the requested page from the file
    if not results:
        import os
        summary = scan_data.get("summary") or {}
        scan_folder = summary.get("report_folder") or os.path.join(os.getenv("OUTPUT_DIR", "/output"), scan_id)
        results_file = summary.get("results_file") or os.path.join(scan_folder, "results.ndjson")

        if os.path.exists(results_file):
            start = (page - 1) * page_size
            end = start + page_size
            paginated_results = []
            total = 0
            with open(results_file, "r", encoding="utf-8") as fh:
                for idx, line in enumerate(fh):
                    if not line.strip():
                        continue
                    if idx >= start and idx < end:
                        try:
                            import json
                            paginated_results.append(json.loads(line))
                        except Exception:
                            # Skip malformed lines
                            pass
                    total += 1
            results = paginated_results
        else:
            total = 0
            results = []
    else:
    total = len(results)
    start = (page - 1) * page_size
    end = start + page_size
        results = results[start:end]
    
    return {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "results": results,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": (total + page_size - 1) // page_size
        },
        "started_at": scan_data["started_at"].isoformat() if scan_data.get("started_at") else None,
        "completed_at": scan_data.get("completed_at").isoformat() if scan_data.get("completed_at") else None
    }


@app.post("/api/v1/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running scan"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans[scan_id]
    
    if scan_data["status"] not in ["running", "pending"]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan with status: {scan_data['status']}")
    
    # Mark as cancelled
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
    
    # Sort by started_at descending
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
    
    # Cancel if running
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
    summary = scan_data.get("summary") or {}
    # Backward compatibility: if older scans stored results in memory, keep the old behavior.
    results = scan_data.get("results") or []
    if not summary and results:
        total_checks = len(results)
        passed_checks = sum(1 for r in results if r.get("status") == "PASS" or r.get("compliant", False))
        failed_checks = total_checks - passed_checks
        summary = {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "pass_rate": (passed_checks / total_checks * 100) if total_checks > 0 else 0
        }
    
    top_issues = []
    
    return {
        "scan_id": scan_id,
        "status": scan_data.get("status"),
        "summary": {
            "total_checks": summary.get("total_checks", 0),
            "passed_checks": summary.get("passed_checks", 0),
            "failed_checks": summary.get("failed_checks", 0),
            "pass_rate": summary.get("pass_rate", 0)
        },
        "top_issues": top_issues,
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


@app.get("/api/v1/services")
async def list_services():
    """List available AWS services"""
    try:
        services = load_enabled_services_with_scope()
        return {
            "services": [
                {"name": s[0], "scope": s[1]} for s in services
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "provider": "aws",
        "version": "1.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.getenv("PORT", "8000"))
    # Configure uvicorn with keep-alive settings to prevent premature connection closure
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        timeout_keep_alive=75,  # Keep connections alive for 75 seconds
        timeout_graceful_shutdown=30,  # Graceful shutdown timeout
        log_level="info"
    )

