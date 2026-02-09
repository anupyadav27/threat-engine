"""
Inventory Engine API Server

FastAPI server for inventory scanning and querying.

=== DATABASE & TABLE MAP ===
This module connects to THREE databases:

1. threat_engine_inventory (INVENTORY DB) — via get_database_config("inventory")
   Env: INVENTORY_DB_HOST / INVENTORY_DB_PORT / INVENTORY_DB_NAME / INVENTORY_DB_USER / INVENTORY_DB_PASSWORD
   Tables READ:
     - inventory_report      : Scan-level summaries (get_scan_summary, get_latest_scan_id)
     - inventory_findings     : Asset records (list_assets, get_asset)
     - inventory_relationships: Resource edges (list_relationships, get_asset_relationships)
   Tables WRITTEN (via orchestrator → PostgresIndexWriter):
     - inventory_report       : INSERT on scan completion
     - inventory_findings     : UPSERT per asset
     - inventory_relationships: INSERT per relationship

2. threat_engine_discoveries (DISCOVERIES DB) — via get_discovery_reader()
   Env: DISCOVERIES_DB_HOST / DISCOVERIES_DB_PORT / DISCOVERIES_DB_NAME / DISCOVERIES_DB_USER / DISCOVERIES_DB_PASSWORD
   Tables READ:
     - discovery_report   : List scans, get latest scan ID
     - discovery_findings  : Read discovery records for normalization

3. threat_engine_check (CHECK DB) — via CheckDBReader (optional enrichment)
   Env: CHECK_DB_HOST / CHECK_DB_PORT / CHECK_DB_NAME / CHECK_DB_USER / CHECK_DB_PASSWORD
   Tables READ:
     - check_findings : Aggregate posture (PASS/FAIL/ERROR counts per resource_uid)

4. LOCAL FILES (legacy, for drift/graph/summary endpoints that haven't been migrated to DB)
   Path: INVENTORY_OUTPUT_DIR or engine_output/engine_inventory/output/{tenant_id}/{scan_run_id}/normalized/
   Files: assets.ndjson, relationships.ndjson, drift.ndjson, summary.json
===
"""

import os
import json
import sys
import time
import random
import threading
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

# Add consolidated_services to path
_consolidated_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "consolidated_services")
sys.path.insert(0, _consolidated_path)

from engine_common.logger import setup_logger, LogContext, log_duration, audit_log
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

# Import local database config
from ..database.connection.database_config import get_database_config

from ..api.orchestrator import ScanOrchestrator
from ..api.data_loader import DataLoader
from ..api.inventory_db_loader import InventoryDBLoader
from ..schemas.asset_schema import Provider
from ..connectors.discovery_reader_factory import get_discovery_reader

logger = setup_logger(__name__, engine_name="engine-inventory")

app = FastAPI(
    title="Inventory Engine API",
    description="Cloud Resource Inventory Discovery and Graph Building",
    version="1.0.0"
)

# Lightweight in-memory job tracker for async scans.
# NOTE: This is per-pod memory; for HA move to Redis/DB.
inventory_jobs: Dict[str, Dict[str, Any]] = {}

# Add logging middleware
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="engine-inventory")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    """Request model for inventory scan"""
    tenant_id: str
    providers: List[str] = ["aws"]
    accounts: List[str]
    regions: List[str]
    services: Optional[List[str]] = None
    previous_scan_id: Optional[str] = None
    # DB-first inputs
    discovery_scan_id: str = Field(default="latest", description="Discovery scan id from Discoveries DB (or 'latest')")
    check_scan_id: Optional[str] = Field(default=None, description="Optional check scan id to enrich assets with posture")


class DiscoveryScanRequest(BaseModel):
    """Request model for discovery-based inventory scan"""
    tenant_id: str
    discovery_scan_id: str = Field(..., alias="configscan_scan_id")
    providers: Optional[List[str]] = None
    accounts: Optional[List[str]] = None
    previous_scan_id: Optional[str] = None
    check_scan_id: Optional[str] = None

    model_config = {"populate_by_name": True}


class ScanResponse(BaseModel):
    """Response model for scan execution"""
    scan_run_id: str
    status: str
    started_at: str
    completed_at: str
    total_assets: int
    total_relationships: int
    total_drift: int
    artifact_paths: Dict[str, str]


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "engine-inventory",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    import time
    start = time.time()
    
    health_status = {"status": "healthy"}
    
    duration_ms = (time.time() - start) * 1000
    logger.info("Health check", extra={
        "extra_fields": {
            "status": "healthy",
            "duration_ms": duration_ms
        }
    })
    
    return health_status


@app.post("/api/v1/inventory/scan", response_model=ScanResponse)
async def run_inventory_scan(request: ScanRequest):
    """
    Run inventory scan.
    
    Collects resources, normalizes to assets/relationships, detects drift,
    and saves artifacts to S3/local storage.
    """
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=request.tenant_id, scan_run_id=request.previous_scan_id):
        logger.info("Running inventory scan", extra={
            "extra_fields": {
                "providers": request.providers,
                "accounts": request.accounts,
                "regions": request.regions,
                "services": request.services,
                "previous_scan_id": request.previous_scan_id
            }
        })
        
        try:
            # Get consolidated database URL
            try:
                db_config = get_database_config("inventory")
                db_url = db_config.connection_string
                # Add schema to connection string
                schema = os.getenv("DB_SCHEMA", "public")
                sep = "&" if "?" in db_url else "?"
                db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
            except Exception as e:
                logger.error(f"Failed to get consolidated DB config: {e}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Database configuration error: {str(e)}"
                )
            
            orchestrator = ScanOrchestrator(
                tenant_id=request.tenant_id,
                db_url=db_url,
            )
            
            # DB-first: derive inventory from discoveries DB (default latest) and optionally enrich from check DB.
            result = orchestrator.run_scan_from_discovery(
                discovery_scan_id=request.discovery_scan_id,
                check_scan_id=request.check_scan_id,
                providers=request.providers,
                accounts=request.accounts,
                previous_scan_id=request.previous_scan_id,
            )
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Inventory scan completed", duration_ms)
            audit_log(
                logger,
                "inventory_scan_completed",
                f"scan:{result.get('scan_run_id')}",
                tenant_id=request.tenant_id,
                result="success",
                details={
                    "total_assets": result.get("total_assets", 0),
                    "total_relationships": result.get("total_relationships", 0)
                }
            )
            
            logger.info("Inventory scan completed successfully", extra={
                "extra_fields": {
                    "scan_run_id": result.get("scan_run_id"),
                    "total_assets": result.get("total_assets", 0),
                    "total_relationships": result.get("total_relationships", 0)
                }
            })
            
            return ScanResponse(**result)
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to run inventory scan", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            audit_log(
                logger,
                "inventory_scan_failed",
                f"tenant:{request.tenant_id}",
                tenant_id=request.tenant_id,
                result="failure",
                details={"error": str(e)}
            )
            raise HTTPException(
                status_code=500,
                detail=f"Failed to run inventory scan: {str(e)}"
            )


@app.post("/api/v1/inventory/scan/async")
async def run_inventory_scan_async(request: ScanRequest):
    """
    Async wrapper for inventory scan (DB-first).
    Returns immediately with a job_id; poll `/api/v1/inventory/jobs/{job_id}`.
    """
    job_id = f"invjob_{int(time.time()*1000)}_{random.randint(1000,9999)}"
    inventory_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "tenant_id": request.tenant_id,
        "discovery_scan_id": request.discovery_scan_id,
        "check_scan_id": request.check_scan_id,
        "started_at": datetime.utcnow().isoformat(),
        "error": None,
        "result": None,
    }

    def _worker():
        try:
            # Get consolidated database URL
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

            orchestrator = ScanOrchestrator(
                tenant_id=request.tenant_id,
                db_url=db_url,
            )
            result = orchestrator.run_scan_from_discovery(
                discovery_scan_id=request.discovery_scan_id,
                check_scan_id=request.check_scan_id,
                providers=request.providers,
                accounts=request.accounts,
                previous_scan_id=request.previous_scan_id,
            )
            inventory_jobs[job_id]["status"] = "completed"
            inventory_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            inventory_jobs[job_id]["result"] = result
        except Exception as e:
            inventory_jobs[job_id]["status"] = "failed"
            inventory_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            inventory_jobs[job_id]["error"] = str(e)

    threading.Thread(target=_worker, daemon=True).start()
    return inventory_jobs[job_id]


@app.post("/api/v1/inventory/scan/discovery", response_model=ScanResponse)
async def run_discovery_scan(request: DiscoveryScanRequest):
    """
    Run inventory scan from discoveries (DB-first).
    
    Reads discovery records from Discoveries DB (or local files), normalizes to assets/relationships,
    optionally enriches assets with check posture from Check DB, and writes indexes to Inventory DB.
    """
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=request.tenant_id, scan_run_id=request.discovery_scan_id):
        logger.info("Running discovery-based inventory scan", extra={
            "extra_fields": {
                "discovery_scan_id": request.discovery_scan_id,
                "providers": request.providers,
                "accounts": request.accounts,
                "previous_scan_id": request.previous_scan_id,
                "check_scan_id": request.check_scan_id
            }
        })
        
        try:
            # Get consolidated database URL
            try:
                db_config = get_database_config("inventory")
                db_url = db_config.connection_string
                # Add schema to connection string
                schema = os.getenv("DB_SCHEMA", "public")
                sep = "&" if "?" in db_url else "?"
                db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
            except Exception as e:
                logger.error(f"Failed to get consolidated DB config: {e}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Database configuration error: {str(e)}"
                )
            
            orchestrator = ScanOrchestrator(
                tenant_id=request.tenant_id,
                db_url=db_url,
            )
            
            result = orchestrator.run_scan_from_discovery(
                discovery_scan_id=request.discovery_scan_id,
                check_scan_id=request.check_scan_id,
                providers=request.providers,
                accounts=request.accounts,
                previous_scan_id=request.previous_scan_id
            )
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Discovery scan completed", duration_ms)
            audit_log(
                logger,
                "inventory_discovery_scan_completed",
                f"scan:{result.get('scan_run_id')}",
                tenant_id=request.tenant_id,
                result="success",
                details={
                    "discovery_scan_id": request.discovery_scan_id,
                    "total_assets": result.get("total_assets", 0),
                    "total_relationships": result.get("total_relationships", 0)
                }
            )
            
            logger.info("Discovery scan completed successfully", extra={
                "extra_fields": {
                    "scan_run_id": result.get("scan_run_id"),
                    "total_assets": result.get("total_assets", 0),
                    "total_relationships": result.get("total_relationships", 0)
                }
            })
            
            return ScanResponse(**result)
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to run discovery scan", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "discovery_scan_id": request.discovery_scan_id,
                    "duration_ms": duration_ms
                }
            })
            audit_log(
                logger,
                "inventory_discovery_scan_failed",
                f"discovery_scan:{request.discovery_scan_id}",
                tenant_id=request.tenant_id,
                result="failure",
                details={"error": str(e)}
            )
            raise HTTPException(
                status_code=500,
                detail=f"Failed to run discovery scan: {str(e)}"
            )


@app.post("/api/v1/inventory/scan/discovery/async")
async def run_discovery_scan_async(request: DiscoveryScanRequest):
    """
    Async DB-first inventory build from discoveries.

    Returns immediately with a job_id so callers can poll `/api/v1/inventory/jobs/{job_id}`.
    """
    import time
    started_at = datetime.utcnow().isoformat()
    job_id = f"invjob_{int(time.time()*1000)}_{random.randint(1000,9999)}"
    inventory_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "tenant_id": request.tenant_id,
        "discovery_scan_id": request.discovery_scan_id,
        "check_scan_id": request.check_scan_id,
        "started_at": started_at,
        "completed_at": None,
        "error": None,
        "result": None,
    }

    def _run():
        t0 = time.time()
        try:
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

            orchestrator = ScanOrchestrator(
                tenant_id=request.tenant_id,
                db_url=db_url,
            )
            result = orchestrator.run_scan_from_discovery(
                discovery_scan_id=request.discovery_scan_id,
                check_scan_id=request.check_scan_id,
                providers=request.providers,
                accounts=request.accounts,
                previous_scan_id=request.previous_scan_id,
            )
            inventory_jobs[job_id]["status"] = "completed"
            inventory_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            inventory_jobs[job_id]["result"] = result
            inventory_jobs[job_id]["duration_ms"] = int((time.time() - t0) * 1000)
        except Exception as e:
            inventory_jobs[job_id]["status"] = "failed"
            inventory_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            inventory_jobs[job_id]["error"] = str(e)
            inventory_jobs[job_id]["duration_ms"] = int((time.time() - t0) * 1000)
    threading.Thread(target=_run, daemon=True).start()
    return inventory_jobs[job_id]


@app.get("/api/v1/inventory/jobs/{job_id}")
async def get_inventory_job(job_id: str):
    job = inventory_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/api/v1/inventory/runs/{scan_run_id}/summary")
async def get_scan_summary(scan_run_id: str, tenant_id: str = Query(...)):
    """Get scan summary"""
    with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id):
        logger.info("Retrieving scan summary")
        try:
            # DB-first only: summaries are read from local artifacts (no S3).
            from engine_common.storage_paths import get_project_root
            base = os.getenv("INVENTORY_OUTPUT_DIR") or str(get_project_root() / "engine_output" / "engine_inventory" / "output")
            base_path = base
            summary_path = os.path.join(base_path, tenant_id, scan_run_id, "normalized", "summary.json")
            
            with open(summary_path, 'r') as f:
                summary = json.load(f)
            
            logger.info("Scan summary retrieved", extra={
                "extra_fields": {
                    "total_assets": summary.get("total_assets", 0),
                    "total_relationships": summary.get("total_relationships", 0)
                }
            })
            return summary
        
        except Exception as e:
            logger.warning("Scan summary not found", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "scan_run_id": scan_run_id
                }
            })
            raise HTTPException(
                status_code=404,
                detail=f"Scan summary not found: {str(e)}"
            )


@app.get("/api/v1/inventory/runs/latest/summary")
async def get_latest_scan_summary(tenant_id: str = Query(...)):
    """Get latest scan summary"""
    try:
        loader = DataLoader()
        
        from pathlib import Path
        from engine_common.storage_paths import get_project_root
        base = os.getenv("INVENTORY_OUTPUT_DIR") or str(get_project_root() / "engine_output" / "engine_inventory" / "output")
        base_path = Path(base)
        tenant_dir = base_path / tenant_id
        
        if not tenant_dir.exists():
            raise HTTPException(status_code=404, detail=f"No scans found for tenant: {tenant_id}")
        
        # Get all scan directories, sorted by name (assuming timestamp-based naming)
        scan_dirs = sorted([d for d in tenant_dir.iterdir() if d.is_dir()], reverse=True)
        
        if not scan_dirs:
            raise HTTPException(status_code=404, detail=f"No scans found for tenant: {tenant_id}")
        
        latest_scan_id = scan_dirs[0].name
        
        # Load summary for latest scan
        summary_path = scan_dirs[0] / "normalized" / "summary.json"
        if not summary_path.exists():
            raise HTTPException(status_code=404, detail=f"Summary not found for scan: {latest_scan_id}")
        
        with open(summary_path, 'r') as f:
            summary = json.load(f)
        
        return summary
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load latest scan summary: {str(e)}"
        )


@app.get("/api/v1/inventory/assets")
async def list_assets(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """List assets with filters and pagination (DB-first)"""
    try:
        # Get DB connection
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string
        schema = os.getenv("DB_SCHEMA", "public")
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
        
        loader = InventoryDBLoader(db_url)
        
        # Auto-resolve "latest" scan_run_id
        if not scan_run_id or scan_run_id == "latest":
            scan_run_id = loader.get_latest_scan_id(tenant_id)
            if not scan_run_id:
                return {"assets": [], "total": 0, "limit": limit, "offset": offset, "has_more": False}
        
        # Load assets with filters
        assets, total = loader.load_assets(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            provider=provider,
            region=region,
            resource_type=resource_type,
            account_id=account_id,
            limit=limit,
            offset=offset
        )
        
        loader.close()
        
        return {
            "assets": assets,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(assets)) < total
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load assets: {str(e)}"
        )


@app.get("/api/v1/inventory/assets/{resource_uid:path}")
async def get_asset(resource_uid: str, tenant_id: str = Query(...), scan_run_id: Optional[str] = Query(None)):
    """Get asset details by resource_uid (DB-first)"""
    try:
        # Get DB connection
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string
        schema = os.getenv("DB_SCHEMA", "public")
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
        
        loader = InventoryDBLoader(db_url)
        
        # Auto-resolve "latest"
        if not scan_run_id or scan_run_id == "latest":
            scan_run_id = loader.get_latest_scan_id(tenant_id)
        
        asset = loader.load_asset_by_uid(
            tenant_id=tenant_id,
            resource_uid=resource_uid,
            scan_run_id=scan_run_id
        )
        
        loader.close()
        
        if not asset:
            raise HTTPException(
                status_code=404,
                detail=f"Asset not found: {resource_uid}"
            )
        
        return asset
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load asset: {str(e)}"
        )


@app.get("/api/v1/inventory/assets/{resource_uid:path}/relationships")
async def get_asset_relationships(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    depth: int = Query(1, ge=1, le=3),
    relation_type: Optional[str] = Query(None),
    direction: Optional[str] = Query(None, regex="^(inbound|outbound|both)$")
):
    """Get asset relationships with depth traversal"""
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=tenant_id):
        logger.info("Getting asset relationships", extra={
            "extra_fields": {
                "resource_uid": resource_uid,
                "depth": depth,
                "relation_type": relation_type,
                "direction": direction
            }
        })
        
        try:
            # Get DB connection
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
            
            loader = InventoryDBLoader(db_url)
            
            # Auto-resolve "latest"
            if not scan_run_id or scan_run_id == "latest":
                scan_run_id = loader.get_latest_scan_id(tenant_id)
                if not scan_run_id:
                    loader.close()
                    return {"resource_uid": resource_uid, "relationships": [], "by_type": {}, "depth": depth, "total": 0}
            
            # Load relationships based on direction
            if direction == "inbound":
                relationships, _ = loader.load_relationships(
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    to_uid=resource_uid,
                    relation_type=relation_type,
                    limit=1000,
                    offset=0
                )
            elif direction == "outbound":
                relationships, _ = loader.load_relationships(
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    from_uid=resource_uid,
                    relation_type=relation_type,
                    limit=1000,
                    offset=0
                )
            else:  # both
                rels_from, _ = loader.load_relationships(
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    from_uid=resource_uid,
                    relation_type=relation_type,
                    limit=500,
                    offset=0
                )
                rels_to, _ = loader.load_relationships(
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    to_uid=resource_uid,
                    relation_type=relation_type,
                    limit=500,
                    offset=0
                )
                relationships = rels_from + rels_to
            
            loader.close()
            
            # Group by relation type
            by_type = {}
            for rel in relationships:
                rel_type = rel.get("relation_type", "unknown")
                if rel_type not in by_type:
                    by_type[rel_type] = []
                by_type[rel_type].append(rel)
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Asset relationships retrieved", duration_ms)
            
            return {
                "resource_uid": resource_uid,
                "relationships": relationships,
                "by_type": by_type,
                "depth": depth,
                "total": len(relationships)
            }
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to load relationships", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            raise HTTPException(
                status_code=500,
                detail=f"Failed to load relationships: {str(e)}"
            )


@app.get("/api/v1/inventory/assets/{resource_uid:path}/drift")
async def get_asset_drift_history(
    resource_uid: str,
    tenant_id: str = Query(...),
    limit: int = Query(50, ge=1, le=200)
):
    """Get drift history for a specific asset"""
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=tenant_id):
        logger.info("Getting asset drift history", extra={
            "extra_fields": {
                "resource_uid": resource_uid,
                "limit": limit
            }
        })
        
        try:
            loader = DataLoader()
            
            from pathlib import Path
            from engine_common.storage_paths import get_project_root
            base = os.getenv("INVENTORY_OUTPUT_DIR") or str(get_project_root() / "engine_output" / "engine_inventory" / "output")
            base_path = Path(base)
            tenant_dir = base_path / tenant_id
            
            if not tenant_dir.exists():
                return {
                    "resource_uid": resource_uid,
                    "drift_history": [],
                    "total": 0
                }
            
            # Get all scan directories, sorted by name (newest first)
            scan_dirs = sorted([d for d in tenant_dir.iterdir() if d.is_dir()], reverse=True)
            
            drift_history = []
            for scan_dir in scan_dirs[:limit]:  # Limit number of scans to check
                scan_run_id = scan_dir.name
                drift_records = loader.load_drift_records(
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    resource_uid=resource_uid
                )
                
                for drift in drift_records:
                    drift_history.append({
                        **drift,
                        "scan_run_id": scan_run_id
                    })
            
            # Sort by detected_at (newest first)
            drift_history.sort(key=lambda x: x.get("detected_at", ""), reverse=True)
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Asset drift history retrieved", duration_ms)
            
            return {
                "resource_uid": resource_uid,
                "drift_history": drift_history[:limit],
                "total": len(drift_history)
            }
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to load asset drift history", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            raise HTTPException(
                status_code=500,
                detail=f"Failed to load asset drift history: {str(e)}"
            )


@app.get("/api/v1/inventory/graph")
async def get_graph(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    resource_uid: Optional[str] = Query(None),
    depth: int = Query(2, ge=1, le=3),
    limit: int = Query(100, ge=1, le=500)
):
    """Get graph visualization data (nodes and edges)"""
    try:
        loader = DataLoader()
        
        # Load assets (nodes)
        if resource_uid:
            # Get specific asset and its relationships
            asset = loader.load_asset_by_uid(tenant_id, scan_run_id or "latest", resource_uid)
            nodes = [asset] if asset else []
            
            # Get related assets
            relationships = loader.load_relationships(tenant_id, scan_run_id or "latest", resource_uid)
            
            # Collect related asset UIDs
            related_uids = set()
            for rel in relationships:
                if rel.get("from_uid") != resource_uid:
                    related_uids.add(rel.get("from_uid"))
                if rel.get("to_uid") != resource_uid:
                    related_uids.add(rel.get("to_uid"))
            
            # Load related assets
            for uid in related_uids:
                related_asset = loader.load_asset_by_uid(tenant_id, scan_run_id or "latest", uid)
                if related_asset:
                    nodes.append(related_asset)
        else:
            # Get all assets (limited)
            nodes = loader.load_assets(tenant_id, scan_run_id or "latest", limit=limit)
            relationships = loader.load_relationships(tenant_id, scan_run_id or "latest", limit=limit)
        
        return {
            "nodes": nodes,
            "edges": relationships,
            "depth": depth,
            "total_nodes": len(nodes),
            "total_edges": len(relationships)
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load graph: {str(e)}"
        )


@app.get("/api/v1/inventory/drift")
async def get_drift(
    tenant_id: str = Query(...),
    baseline_scan: Optional[str] = Query(None, description="Baseline scan_run_id"),
    compare_scan: Optional[str] = Query(None, description="Comparison scan_run_id"),
    scan_run_id: Optional[str] = Query(None, description="Single scan drift (deprecated, use baseline_scan/compare_scan)"),
    change_type: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None)
):
    """Get drift records - compare two scans or get drift for single scan"""
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=tenant_id):
        logger.info("Getting drift records", extra={
            "extra_fields": {
                "baseline_scan": baseline_scan,
                "compare_scan": compare_scan,
                "scan_run_id": scan_run_id
            }
        })
        
        try:
            loader = DataLoader()
            
            # If both baseline and compare are provided, compare two scans
            if baseline_scan and compare_scan:
                # Load assets from both scans
                baseline_assets = {a.get("resource_uid"): a for a in loader.load_assets(tenant_id, baseline_scan)}
                compare_assets = {a.get("resource_uid"): a for a in loader.load_assets(tenant_id, compare_scan)}
                
                # Detect changes
                drift_records = []
                
                # Added assets
                for uid, asset in compare_assets.items():
                    if uid not in baseline_assets:
                        drift_records.append({
                            "change_type": "asset_added",
                            "resource_uid": uid,
                            "resource_type": asset.get("resource_type"),
                            "provider": asset.get("provider"),
                            "account_id": asset.get("account_id"),
                            "region": asset.get("region"),
                            "detected_at": datetime.utcnow().isoformat() + "Z"
                        })
                
                # Removed assets
                for uid, asset in baseline_assets.items():
                    if uid not in compare_assets:
                        drift_records.append({
                            "change_type": "asset_removed",
                            "resource_uid": uid,
                            "resource_type": asset.get("resource_type"),
                            "provider": asset.get("provider"),
                            "account_id": asset.get("account_id"),
                            "region": asset.get("region"),
                            "detected_at": datetime.utcnow().isoformat() + "Z"
                        })
                
                # Changed assets
                for uid in set(baseline_assets.keys()) & set(compare_assets.keys()):
                    baseline = baseline_assets[uid]
                    compare = compare_assets[uid]
                    
                    # Compare metadata (simplified - can be enhanced)
                    if baseline.get("hash_sha256") != compare.get("hash_sha256"):
                        # Find what changed
                        diff = []
                        for key in ["tags", "metadata"]:
                            if baseline.get(key) != compare.get(key):
                                diff.append({
                                    "path": key,
                                    "before": baseline.get(key),
                                    "after": compare.get(key)
                                })
                        
                        if diff:
                            drift_records.append({
                                "change_type": "asset_changed",
                                "resource_uid": uid,
                                "resource_type": compare.get("resource_type"),
                                "provider": compare.get("provider"),
                                "account_id": compare.get("account_id"),
                                "region": compare.get("region"),
                                "diff": diff,
                                "detected_at": datetime.utcnow().isoformat() + "Z"
                            })
            else:
                # Load drift records from single scan
                drift_records = loader.load_drift_records(
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id or "latest",
                    change_type=change_type
                )
            
            # Apply additional filters
            if provider:
                drift_records = [d for d in drift_records if d.get("provider") == provider]
            if resource_type:
                drift_records = [d for d in drift_records if d.get("resource_type") == resource_type]
            if account_id:
                drift_records = [d for d in drift_records if d.get("account_id") == account_id]
            
            # Group by change type
            by_change_type = {}
            for drift in drift_records:
                change = drift.get("change_type", "unknown")
                if change not in by_change_type:
                    by_change_type[change] = []
                by_change_type[change].append(drift)
            
            # Group by provider
            by_provider = {}
            for drift in drift_records:
                prov = drift.get("provider", "unknown")
                if prov not in by_provider:
                    by_provider[prov] = {"added": 0, "removed": 0, "changed": 0}
                change = drift.get("change_type", "")
                if "added" in change:
                    by_provider[prov]["added"] += 1
                elif "removed" in change:
                    by_provider[prov]["removed"] += 1
                elif "changed" in change:
                    by_provider[prov]["changed"] += 1
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Drift records retrieved", duration_ms)
            
            return {
                "tenant_id": tenant_id,
                "baseline_scan": baseline_scan,
                "compare_scan": compare_scan,
                "summary": {
                    "assets_added": len([d for d in drift_records if d.get("change_type") == "asset_added"]),
                    "assets_removed": len([d for d in drift_records if d.get("change_type") == "asset_removed"]),
                    "assets_changed": len([d for d in drift_records if d.get("change_type") == "asset_changed"]),
                    "relationships_added": len([d for d in drift_records if d.get("change_type") == "relationship_added"]),
                    "relationships_removed": len([d for d in drift_records if d.get("change_type") == "relationship_removed"])
                },
                "drift_records": drift_records,
                "total": len(drift_records),
                "by_change_type": {k: len(v) for k, v in by_change_type.items()},
                "by_provider": by_provider,
                "details": by_change_type
            }
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to load drift", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            raise HTTPException(
                status_code=500,
                detail=f"Failed to load drift: {str(e)}"
            )


@app.get("/api/v1/inventory/accounts/{account_id}")
async def get_account_summary(
    account_id: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None)
):
    """Get account summary with service breakdown and regional distribution"""
    try:
        loader = DataLoader()
        
        # Load all assets for this account
        assets = loader.load_assets(tenant_id, scan_run_id or "latest")
        
        # Filter by account
        account_assets = [a for a in assets if a.get("account_id") == account_id]
        
        # Group by service
        by_service = {}
        for asset in account_assets:
            service = asset.get("resource_type", "unknown").split(".")[0]
            by_service[service] = by_service.get(service, 0) + 1
        
        # Group by region
        by_region = {}
        for asset in account_assets:
            region = asset.get("region", "unknown")
            by_region[region] = by_region.get(region, 0) + 1
        
        return {
            "account_id": account_id,
            "total_assets": len(account_assets),
            "by_service": by_service,
            "by_region": by_region,
            "provider": account_assets[0].get("provider") if account_assets else "unknown"
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load account summary: {str(e)}"
        )


@app.get("/api/v1/inventory/services/{service}")
async def get_service_summary(
    service: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None)
):
    """Get service-specific summary with configuration statistics"""
    try:
        loader = DataLoader()
        
        # Load all assets for this service
        assets = loader.load_assets(tenant_id, scan_run_id or "latest")
        
        # Filter by service (resource_type starts with service)
        service_assets = [a for a in assets if a.get("resource_type", "").startswith(f"{service}.")]
        
        # Group by account
        by_account = {}
        for asset in service_assets:
            acct = asset.get("account_id", "unknown")
            by_account[acct] = by_account.get(acct, 0) + 1
        
        # Group by region
        by_region = {}
        for asset in service_assets:
            region = asset.get("region", "unknown")
            by_region[region] = by_region.get(region, 0) + 1
        
        # Group by resource type
        by_resource_type = {}
        for asset in service_assets:
            rtype = asset.get("resource_type", "unknown")
            by_resource_type[rtype] = by_resource_type.get(rtype, 0) + 1
        
        return {
            "service": service,
            "total_assets": len(service_assets),
            "by_account": by_account,
            "by_region": by_region,
            "by_resource_type": by_resource_type
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load service summary: {str(e)}"
        )


@app.get("/api/v1/inventory/scans")
async def list_scans(tenant_id: Optional[str] = Query(None)):
    """
    List available discovery scans.
    
    Note: tenant_id is required for database mode (USE_DATABASE=true),
    optional for local file mode.
    """
    try:
        reader = get_discovery_reader(tenant_id=tenant_id)
        
        # Both readers have compatible interfaces, but DBReader methods use instance tenant_id
        scans = reader.list_available_scans()
        latest = reader.get_latest_scan_id()
        
        return {
            "scans": scans,
            "total": len(scans),
            "latest": latest
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list scans: {str(e)}"
        )


@app.get("/api/v1/inventory/runs/{scan_run_id}/drift")
async def get_scan_drift(
    scan_run_id: str,
    tenant_id: str = Query(...),
    change_type: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None)
):
    """Get drift records for a specific scan run"""
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id):
        logger.info("Getting scan drift", extra={
            "extra_fields": {
                "scan_run_id": scan_run_id,
                "change_type": change_type
            }
        })
        
        try:
            loader = DataLoader()
            
            # Load drift records for this scan
            drift_records = loader.load_drift_records(
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                change_type=change_type
            )
            
            # Apply additional filters
            if provider:
                drift_records = [d for d in drift_records if d.get("provider") == provider]
            if resource_type:
                drift_records = [d for d in drift_records if d.get("resource_type") == resource_type]
            if account_id:
                drift_records = [d for d in drift_records if d.get("account_id") == account_id]
            
            # Group by change type
            by_change_type = {}
            for drift in drift_records:
                change = drift.get("change_type", "unknown")
                if change not in by_change_type:
                    by_change_type[change] = []
                by_change_type[change].append(drift)
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Scan drift retrieved", duration_ms)
            
            return {
                "scan_run_id": scan_run_id,
                "tenant_id": tenant_id,
                "drift_records": drift_records,
                "total": len(drift_records),
                "by_change_type": {k: len(v) for k, v in by_change_type.items()},
                "details": by_change_type
            }
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to load scan drift", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            raise HTTPException(
                status_code=500,
                detail=f"Failed to load scan drift: {str(e)}"
            )


@app.get("/api/v1/inventory/relationships")
async def list_relationships(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    relation_type: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    from_uid: Optional[str] = Query(None),
    to_uid: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """List relationships with filters and pagination"""
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=tenant_id):
        logger.info("Listing relationships", extra={
            "extra_fields": {
                "scan_run_id": scan_run_id,
                "relation_type": relation_type,
                "limit": limit,
                "offset": offset
            }
        })
        
        try:
            # Get DB connection
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
            
            loader = InventoryDBLoader(db_url)
            
            # Auto-resolve "latest"
            if not scan_run_id or scan_run_id == "latest":
                scan_run_id = loader.get_latest_scan_id(tenant_id)
                if not scan_run_id:
                    loader.close()
                    return {"relationships": [], "total": 0, "limit": limit, "offset": offset, "has_more": False}
            
            # Load relationships (DB loader handles filters efficiently)
            relationships, total = loader.load_relationships(
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                from_uid=from_uid,
                to_uid=to_uid,
                relation_type=relation_type,
                limit=limit,
                offset=offset
            )
            
            loader.close()
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Relationships listed", duration_ms)
            
            return {
                "relationships": relationships,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + len(relationships)) < total
            }
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to list relationships", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            raise HTTPException(
                status_code=500,
                detail=f"Failed to list relationships: {str(e)}"
            )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

