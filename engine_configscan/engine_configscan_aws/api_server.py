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
from pathlib import Path
import sys
import os

# Add project root for engine_common
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import setup_logger, LogContext, log_duration

from engine.main_scanner import scan
from engine.service_scanner import load_enabled_services_with_scope
from engine.discovery_engine import DiscoveryEngine
from engine.check_engine import CheckEngine
from engine.database_manager import DatabaseManager
from auth.aws_auth import get_session_for_account
import boto3

logger = setup_logger(__name__, engine_name="engine-configscan-aws")

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
    customer_id: Optional[str] = None  # Customer (engine_shared.customers); default used if missing
    scan_run_id: Optional[str] = None  # Unified scan identifier from onboarding engine


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


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


def _sync_ingest_to_db(
    scan_id: str,
    request: "ScanRequest",
    scan_summary: Dict[str, Any],
) -> None:
    """Synchronous NDJSON-to-PG ingest: create scan, upload discoveries, update status."""
    if not os.getenv("DATABASE_URL") or not request.tenant_id:
        return
    try:
        from engine.database_manager import DatabaseManager
        from engine.database_upload_engine import DatabaseUploadEngine
        
        # Initialize with centralized database preference
        db_manager = DatabaseManager()
        logger.info(f"Database manager initialized - Centralized: {db_manager.use_centralized}")
        
    except Exception as e:
        logger.warning("Sync ingest skipped: could not load DB modules: %s", e)
        return

    report_folder = scan_summary.get("report_folder")
    if not report_folder:
        logger.warning("Sync ingest skipped: no report_folder in scan summary")
        return

    customer_id = request.customer_id or "default"
    tenant_id = request.tenant_id
    hierarchy_id = request.account or scan_id
    hierarchy_type = "account"
    provider = "aws"
    output_dir = Path(report_folder)

    db = None
    try:
        db = DatabaseManager()
        db.create_customer(customer_id, customer_name=customer_id)
        db.create_tenant(tenant_id, customer_id, provider, tenant_name=tenant_id)
        db.create_scan(
            scan_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            scan_type="full",
        )
        uploader = DatabaseUploadEngine(db)
        stats = uploader.upload_scan_to_database(
            scan_id=scan_id,
            output_dir=output_dir,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
        )
        if stats.get("total_files", 0) == 0 and stats.get("total_uploaded", 0) == 0:
            db.update_scan_status(scan_id, "completed")
        logger.info(
            "Sync ingest done: %s",
            {"scan_id": scan_id, "uploaded": stats.get("total_uploaded", 0)},
            extra={"extra_fields": stats},
        )
    except Exception as e:
        logger.error("Sync ingest failed: %s", e, exc_info=True)
        if db:
            try:
                db.update_scan_status(scan_id, "failed")
            except Exception:
                pass
        raise
    finally:
        if db and hasattr(db, "close"):
            db.close()


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
                services = load_enabled_services_with_scope()
            
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


async def run_check(check_scan_id: str, request: CheckRequest):
    """Run check scan in background"""
    with LogContext(tenant_id=request.tenant_id, scan_run_id=check_scan_id):
        try:
            # Initialize database manager and check engine
            db_manager = DatabaseManager() if os.getenv("DATABASE_URL") else None
            check_engine = CheckEngine(db_manager, use_ndjson=request.use_ndjson)
            
            # Get services
            services = request.include_services
            if not services:
                services = load_enabled_services_with_scope()
            
            # Run checks
            customer_id = request.customer_id or "default"
            tenant_id = request.tenant_id or "default-tenant"
            hierarchy_id = request.hierarchy_id or request.discovery_scan_id
            
            check_results = check_engine.run_check_scan(
                scan_id=request.discovery_scan_id,
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
                "exclude_services": request.exclude_services,
                "credential_type": request.credentials.get('credential_type') if request.credentials else None,
                "role_arn": request.credentials.get('role_arn') if request.credentials else None,
                "role_name": request.credentials.get('role_name') if request.credentials else None
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
    with LogContext(tenant_id=request.tenant_id, scan_run_id=scan_id):
        try:
            import os
            
            # Check if cancelled
            if scans.get(scan_id, {}).get("cancelled", False):
                scans[scan_id]["status"] = "cancelled"
                scans[scan_id]["completed_at"] = datetime.utcnow()
                metrics["cancelled_scans"] += 1
                logger.info("Scan cancelled")
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
                        logger.info("Using AWS Access Key credentials - cleared AWS_ROLE_ARN", extra={
                            "extra_fields": {"removed_arn": removed_arn}
                        })
                    else:
                        logger.info("Using AWS Access Key credentials")
                elif cred_type == 'aws_iam_role':
                    # Handle both role_arn (from onboarding) and role_name
                    role_arn = request.credentials.get('role_arn')
                    if role_arn:
                        # Extract role name from ARN format: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
                        if role_arn.startswith('arn:aws:iam::') and ':role/' in role_arn:
                            role_name = role_arn.split(':role/')[-1]
                            logger.info("Extracted role_name from role_arn", extra={
                                "extra_fields": {"role_name": role_name, "role_arn": role_arn}
                            })
                        else:
                            # If ARN format is invalid, try to use as-is
                            role_name = role_arn
                            logger.warning("Using role_arn as role_name (invalid format)", extra={
                                "extra_fields": {"role_arn": role_arn}
                            })
                    else:
                        # Fallback to role_name if role_arn not provided
                        role_name = request.credentials.get('role_name')
                        if role_name:
                            logger.info("Using provided role_name", extra={
                                "extra_fields": {"role_name": role_name}
                            })
                    external_id = request.credentials.get('external_id')
                    logger.info("IAM Role credentials configured", extra={
                        "extra_fields": {"role_name": role_name, "has_external_id": bool(external_id)}
                    })
            
            # Update progress - estimate total services
            if request.include_services:
                scans[scan_id]["progress"]["services_total"] = len(request.include_services)
            else:
                # Estimate based on available services
                try:
                    services = load_enabled_services_with_scope()
                    scans[scan_id]["progress"]["services_total"] = len(services)
                except Exception as e:
                    logger.warning("Failed to load services for progress estimate", exc_info=True)
                    scans[scan_id]["progress"]["services_total"] = 100  # Default estimate
            
            # Run scan
            logger.info("Starting scan", extra={
                "extra_fields": {
                    "account": request.account,
                    "regions": request.include_regions,
                    "services": request.include_services,
                    "exclude_services": request.exclude_services,
                    "role_name": role_name,
                    "has_external_id": bool(external_id)
                }
            })
            
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
                stream_results=True,
                output_scan_id=scan_id,
            )

            if os.getenv("DATABASE_URL") and request.tenant_id:
                await asyncio.to_thread(
                    _sync_ingest_to_db, scan_id, request, scan_summary
                )

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

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
                    "percentage": 100,
                },
                "duration_seconds": duration,
            })

            log_duration(logger, "Scan completed successfully", duration * 1000, level="INFO")
            logger.info("Scan completed", extra={
                "extra_fields": {
                    "total_checks": scan_summary.get("total_checks", 0),
                    "passed_checks": scan_summary.get("passed_checks", 0),
                    "failed_checks": scan_summary.get("failed_checks", 0),
                }
            })

        except Exception as e:
            end_time = datetime.utcnow()
            duration = (end_time - scans[scan_id]["started_at"]).total_seconds()
            metrics["failed_scans"] += 1
            metrics["total_duration_seconds"] += duration

            logger.error("Scan failed", exc_info=True, extra={
                "extra_fields": {"error": str(e), "duration_seconds": duration}
            })

            scans[scan_id].update({
                "status": "failed",
                "results": None,
                "error": str(e),
                "completed_at": end_time,
                "duration_seconds": duration,
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
    include_muted: bool = Query(False, description="Include muted scans in results"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """List all scans with filters (excludes muted by default)"""
    filtered_scans = []
    
    for scan_id, scan_data in scans.items():
        # Skip muted scans unless explicitly requested
        if not include_muted and scan_data.get("muted", False):
            continue
        if status and scan_data.get("status") != status:
            continue
        if account and scan_data.get("account") != account:
            continue
        filtered_scans.append({
            "scan_id": scan_id,
            "status": scan_data.get("status"),
            "account": scan_data.get("account"),
            "muted": scan_data.get("muted", False),
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
async def mute_scan(scan_id: str):
    """Mute scan (hide from list without deleting data)"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Mark as muted instead of deleting
    scans[scan_id]["muted"] = True
    scans[scan_id]["muted_at"] = datetime.utcnow().isoformat()
    
    return {
        "scan_id": scan_id,
        "status": "muted",
        "message": "Scan muted successfully (hidden from list but data preserved)"
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
    """Health check endpoint with database connectivity verification"""
    db_status = "not_configured"
    db_details = None
    
    # Check database connectivity if DATABASE_URL is set
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        try:
            from engine.database_manager import DatabaseManager
            db_manager = DatabaseManager()
            # Try to get a connection
            conn = db_manager._get_connection()
            if conn:
                db_status = "connected"
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT version()")
                    version = cursor.fetchone()[0]
                    db_details = {
                        "status": "connected",
                        "version": version.split(',')[0] if version else "unknown",
                        "database": db_manager.db_config.get("database", "unknown")
                    }
                    cursor.close()
                    db_manager.connection_pool.putconn(conn)
                except Exception as e:
                    db_details = {"status": "connected", "error": str(e)}
                    db_manager.connection_pool.putconn(conn)
        except Exception as e:
            db_status = "disconnected"
            db_details = {"status": "disconnected", "error": str(e)}
    
    # Overall health: healthy if database is connected or not required
    overall_status = "healthy" if db_status in ["connected", "not_configured"] else "unhealthy"
    
    return {
        "status": overall_status,
        "provider": "aws",
        "version": "1.0.0",
        "database": db_status,
        "database_details": db_details
    }


@app.get("/api/v1/health/ready")
async def readiness_check():
    """Kubernetes readiness probe - checks if service is ready to accept traffic"""
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        try:
            from engine.database_manager import DatabaseManager
            db_manager = DatabaseManager()
            conn = db_manager._get_connection()
            if conn:
                db_manager.connection_pool.putconn(conn)
                return {"status": "ready", "database": "connected"}
            else:
                return {"status": "not_ready", "database": "disconnected"}, 503
        except Exception as e:
            return {"status": "not_ready", "error": str(e)}, 503
    # If no database configured, service is always ready
    return {"status": "ready", "database": "not_configured"}


@app.get("/api/v1/health/live")
async def liveness_check():
    """Kubernetes liveness probe - checks if service is alive"""
    return {"status": "alive", "provider": "aws"}


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

