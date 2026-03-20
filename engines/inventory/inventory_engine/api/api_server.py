"""
Inventory Engine API Server

FastAPI server for inventory scanning and querying.

=== DATABASE & TABLE MAP ===
This module connects to TWO databases:

1. threat_engine_inventory (INVENTORY DB) — via get_database_config("inventory")
   Env: INVENTORY_DB_HOST / INVENTORY_DB_PORT / INVENTORY_DB_NAME / INVENTORY_DB_USER / INVENTORY_DB_PASSWORD
   Tables READ:
     - inventory_report      : Scan-level summaries (get_scan_summary, get_latest_scan_id)
     - inventory_findings     : Asset records (list_assets, get_asset)
     - inventory_relationships: Resource edges (list_relationships, get_asset_relationships)
     - inventory_drift        : Drift history per asset
   Tables WRITTEN (via orchestrator → PostgresIndexWriter):
     - inventory_report       : INSERT on scan completion
     - inventory_findings     : UPSERT per asset
     - inventory_relationships: INSERT per relationship

2. threat_engine_discoveries (DISCOVERIES DB) — via get_discovery_reader()
   Env: DISCOVERIES_DB_HOST / DISCOVERIES_DB_PORT / DISCOVERIES_DB_NAME / DISCOVERIES_DB_USER / DISCOVERIES_DB_PASSWORD
   Tables READ:
     - discovery_report   : List scans, get latest scan ID
     - discovery_findings  : Read discovery records for normalization

NOTE: Cross-engine enrichment (check, threat, compliance findings) has been moved
to the BFF layer at shared/api_gateway/bff/inventory.py to avoid tight coupling.

3. LOCAL FILES (legacy, for drift/graph/summary endpoints that haven't been migrated to DB)
   Path: INVENTORY_OUTPUT_DIR or engine_output/engine_inventory/output/{tenant_id}/{scan_run_id}/normalized/
   Files: assets.ndjson, relationships.ndjson, drift.ndjson, summary.json
===
"""

import os
import json
import sys
import time
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timezone

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

# Add consolidated_services to path
_consolidated_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "consolidated_services")
sys.path.insert(0, _consolidated_path)

from engine_common.logger import setup_logger, LogContext, log_duration, audit_log
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.orchestration import get_orchestration_metadata
from engine_common.job_creator import create_engine_job

# Import local database config
from ..database.connection.database_config import get_database_config

from ..api.inventory_db_loader import InventoryDBLoader
from ..api.rules_router import router as rules_router
from ..api.architecture_builder import build_architecture_hierarchy
from ..schemas.asset_schema import Provider
from ..connectors.discovery_reader_factory import get_discovery_reader

logger = setup_logger(__name__, engine_name="engine-inventory")

app = FastAPI(
    title="Inventory Engine API",
    description="Cloud Resource Inventory Discovery and Graph Building",
    version="1.0.0"
)
configure_telemetry("engine-inventory", app)

# ── Scanner Job config ───────────────────────────────────────────────────────

SCANNER_IMAGE = os.getenv("INVENTORY_SCANNER_IMAGE", "yadavanup84/inventory-engine:v-job")
SCANNER_CPU_REQUEST = os.getenv("SCANNER_CPU_REQUEST", "250m")
SCANNER_MEM_REQUEST = os.getenv("SCANNER_MEM_REQUEST", "1Gi")
SCANNER_CPU_LIMIT = os.getenv("SCANNER_CPU_LIMIT", "1")
SCANNER_MEM_LIMIT = os.getenv("SCANNER_MEM_LIMIT", "2Gi")

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

def _get_inventory_conn():
    """Return a fresh psycopg2 connection to the inventory DB."""
    import psycopg2
    db_cfg = get_database_config("inventory")
    return psycopg2.connect(
        host=db_cfg.host,
        port=db_cfg.port,
        dbname=db_cfg.database,
        user=db_cfg.username,
        password=db_cfg.password,
        connect_timeout=5,
    )


# Rules admin router — DB-driven rule management (single source of truth for multi-CSP)
app.include_router(rules_router)


@app.on_event("startup")
async def _preload_arn_patterns():
    """Pre-load identifier patterns from resource_inventory_identifier table.

    Warms the in-memory cache used by shared.common.arn.normalize_resource_uid()
    so that every scan run can validate/generate ARNs without per-request DB hits.
    """
    try:
        import psycopg2
        from engine_common.arn import preload_identifier_patterns

        db_cfg = get_database_config("inventory")
        conn = psycopg2.connect(
            host=db_cfg.host,
            port=db_cfg.port,
            dbname=db_cfg.database,
            user=db_cfg.username,
            password=db_cfg.password,
            connect_timeout=5,
        )
        try:
            total = 0
            for csp in ("aws", "azure", "gcp", "oci", "ibm", "alicloud"):
                count = preload_identifier_patterns(conn, csp)
                total += count
            logger.info(
                "ARN identifier patterns preloaded",
                extra={"extra_fields": {"total_patterns": total}},
            )
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(
            "Failed to preload ARN patterns (non-fatal)",
            extra={"extra_fields": {"error": str(exc)}},
        )

# Include unified UI data router
try:
    from .ui_data_router import router as ui_data_router
    app.include_router(ui_data_router)
except ImportError as e:
    logger.warning("UI data router not available", extra={"extra_fields": {"error": str(e)}})


class ScanRequest(BaseModel):
    """Request model for inventory scan"""
    tenant_id: Optional[str] = None
    providers: List[str] = ["aws"]
    accounts: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    services: Optional[str] = None
    previous_scan_id: Optional[str] = None
    # DB-first inputs
    discovery_scan_id: Optional[str] = Field(default="latest", description="Discovery scan id from Discoveries DB (or 'latest') - for ad-hoc mode")
    orchestration_id: Optional[str] = Field(default=None, description="Orchestration ID - for pipeline mode")
    check_scan_id: Optional[str] = Field(default=None, description="Optional check scan id to enrich assets with posture")


class DiscoveryScanRequest(BaseModel):
    """Request model for discovery-based inventory scan"""
    tenant_id: str
    discovery_scan_id: Optional[str] = Field(default=None, alias="configscan_scan_id", description="Discovery scan ID - for ad-hoc mode")
    orchestration_id: Optional[str] = Field(default=None, description="Orchestration ID - for pipeline mode")
    providers: Optional[List[str]] = None
    accounts: Optional[List[str]] = None
    previous_scan_id: Optional[str] = None
    check_scan_id: Optional[str] = None

    model_config = {"populate_by_name": True}


class ScanResponse(BaseModel):
    """Response model for Job-based scan execution."""
    inventory_scan_id: str
    status: str
    message: str
    orchestration_id: Optional[str] = None
    provider: Optional[str] = None


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


@app.get("/api/v1/health/live")
async def liveness():
    """Kubernetes liveness probe — returns 200 if process is alive."""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    """Kubernetes readiness probe — DB ping."""
    try:
        import psycopg2
        db_cfg = get_database_config("inventory")
        conn = psycopg2.connect(
            host=db_cfg.host,
            port=db_cfg.port,
            dbname=db_cfg.database,
            user=db_cfg.username,
            password=db_cfg.password,
            connect_timeout=3,
        )
        conn.close()
        return {"status": "ready"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "not ready", "error": str(e)})


@app.get("/api/v1/health")
async def api_health():
    """Full health check with DB connectivity."""
    try:
        import psycopg2
        db_cfg = get_database_config("inventory")
        conn = psycopg2.connect(
            host=db_cfg.host,
            port=db_cfg.port,
            dbname=db_cfg.database,
            user=db_cfg.username,
            password=db_cfg.password,
            connect_timeout=3,
        )
        conn.close()
        return {"status": "healthy", "database": "connected", "service": "engine-inventory", "version": "1.0.0"}
    except Exception as e:
        return {"status": "degraded", "database": "disconnected", "error": str(e), "service": "engine-inventory", "version": "1.0.0"}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def run_inventory_scan(request: ScanRequest):
    """
    Start an inventory scan by creating a K8s Job on a spot node.

    **Pipeline mode** -- provide `orchestration_id`:
      Fetches metadata from scan_orchestration table.

    **Ad-hoc mode** -- provide `discovery_scan_id`:
      Uses the supplied discovery_scan_id with optional overrides.
    """
    orch_id = request.orchestration_id
    inventory_scan_id = orch_id

    if orch_id:
        # Pipeline mode
        try:
            meta = get_orchestration_metadata(orch_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        discovery_scan_id = meta.get("discovery_scan_id")
        if not discovery_scan_id:
            raise HTTPException(
                status_code=400,
                detail=f"Discovery scan not completed yet for orchestration_id={orch_id}",
            )

        provider = (meta.get("provider") or meta.get("provider_type", "aws")).lower()
        tenant_id = meta.get("tenant_id") or request.tenant_id
        logger.info(
            f"Pipeline mode: orch={orch_id} disc={discovery_scan_id} provider={provider}"
        )
    elif request.discovery_scan_id:
        # Ad-hoc mode — still need orchestration_id for Job-based execution
        if not orch_id:
            raise HTTPException(
                status_code=400,
                detail="orchestration_id is required for Job-based execution",
            )
    else:
        raise HTTPException(
            status_code=400,
            detail="orchestration_id is required",
        )

    tenant_id = request.tenant_id
    provider = request.providers[0] if request.providers else "aws"

    # Pre-create inventory_report row in DB (so status endpoint works immediately)
    try:
        import json as _json
        conn = _get_inventory_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO inventory_report
                   (inventory_scan_id, tenant_id, status, started_at, scan_metadata)
                   VALUES (%s, %s, 'running', NOW(), %s)
                   ON CONFLICT (inventory_scan_id) DO UPDATE SET status = 'running'""",
                (inventory_scan_id, tenant_id,
                 _json.dumps({"orchestration_id": orch_id, "mode": "job"})),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create inventory_report: {e}")

    # Create K8s Job on spot node
    try:
        job_name = create_engine_job(
            engine_name="inventory",
            scan_id=inventory_scan_id,
            orchestration_id=orch_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU_REQUEST,
            mem_request=SCANNER_MEM_REQUEST,
            cpu_limit=SCANNER_CPU_LIMIT,
            mem_limit=SCANNER_MEM_LIMIT,
            active_deadline_seconds=3600,
        )
    except Exception as e:
        logger.error(f"Failed to create inventory scanner Job: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scanner Job: {e}")

    return ScanResponse(
        inventory_scan_id=inventory_scan_id,
        status="running",
        message=f"Scanner Job '{job_name}' created on spot node (image={SCANNER_IMAGE})",
        orchestration_id=orch_id,
        provider=provider,
    )


@app.post("/api/v1/inventory/scan/discovery", response_model=ScanResponse)
async def run_discovery_scan(request: DiscoveryScanRequest):
    """
    Start an inventory scan from discoveries by creating a K8s Job.

    Same behaviour as POST /api/v1/scan — kept for backward compatibility.
    """
    orch_id = request.orchestration_id
    if not orch_id:
        raise HTTPException(
            status_code=400,
            detail="orchestration_id is required for Job-based execution",
        )

    inventory_scan_id = orch_id

    try:
        meta = get_orchestration_metadata(orch_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    discovery_scan_id = meta.get("discovery_scan_id")
    if not discovery_scan_id:
        raise HTTPException(
            status_code=400,
            detail=f"Discovery scan not completed yet for orchestration_id={orch_id}",
        )

    tenant_id = meta.get("tenant_id") or request.tenant_id
    provider = (meta.get("provider") or meta.get("provider_type", "aws")).lower()

    # Pre-create inventory_report row
    try:
        import json as _json
        conn = _get_inventory_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO inventory_report
                   (inventory_scan_id, tenant_id, status, started_at, scan_metadata)
                   VALUES (%s, %s, 'running', NOW(), %s)
                   ON CONFLICT (inventory_scan_id) DO UPDATE SET status = 'running'""",
                (inventory_scan_id, tenant_id,
                 _json.dumps({"orchestration_id": orch_id, "mode": "job"})),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create inventory_report: {e}")

    # Create K8s Job on spot node
    try:
        job_name = create_engine_job(
            engine_name="inventory",
            scan_id=inventory_scan_id,
            orchestration_id=orch_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU_REQUEST,
            mem_request=SCANNER_MEM_REQUEST,
            cpu_limit=SCANNER_CPU_LIMIT,
            mem_limit=SCANNER_MEM_LIMIT,
            active_deadline_seconds=3600,
        )
    except Exception as e:
        logger.error(f"Failed to create inventory scanner Job: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scanner Job: {e}")

    return ScanResponse(
        inventory_scan_id=inventory_scan_id,
        status="running",
        message=f"Scanner Job '{job_name}' created on spot node (image={SCANNER_IMAGE})",
        orchestration_id=orch_id,
        provider=provider,
    )


@app.get("/api/v1/inventory/scan/{inventory_scan_id}/status")
async def get_inventory_scan_status(inventory_scan_id: str):
    """Get inventory scan status from inventory_report DB table."""
    from psycopg2.extras import RealDictCursor
    try:
        conn = _get_inventory_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT inventory_scan_id, status, tenant_id, started_at, completed_at, scan_metadata "
                "FROM inventory_report WHERE inventory_scan_id = %s",
                (inventory_scan_id,),
            )
            row = cur.fetchone()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    if not row:
        raise HTTPException(status_code=404, detail=f"Scan {inventory_scan_id} not found")

    # Normalise datetime columns for JSON serialisation
    result = dict(row)
    for key in ("started_at", "completed_at"):
        val = result.get(key)
        if val and hasattr(val, "isoformat"):
            result[key] = val.isoformat()

    return result


@app.get("/api/v1/inventory/runs/{scan_run_id}/summary")
async def get_scan_summary(scan_run_id: str, tenant_id: str = Query(...)):
    """Get scan summary (DB-first)"""
    with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id):
        logger.info("Retrieving scan summary")
        try:
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

            loader = InventoryDBLoader(db_url)

            # Handle "latest" alias (FastAPI routes match {scan_run_id} before static "latest" route)
            if scan_run_id == "latest":
                scan_run_id = loader.get_latest_scan_id(tenant_id)
                if not scan_run_id:
                    loader.close()
                    raise HTTPException(
                        status_code=404,
                        detail=f"No completed scans found for tenant: {tenant_id}"
                    )

            summary = loader.get_scan_summary(tenant_id=tenant_id, scan_run_id=scan_run_id)
            loader.close()

            if not summary:
                raise HTTPException(
                    status_code=404,
                    detail=f"Scan summary not found for scan_run_id={scan_run_id}"
                )

            # Normalise datetime columns for JSON serialisation
            for key in ("started_at", "completed_at"):
                val = summary.get(key)
                if val and hasattr(val, "isoformat"):
                    summary[key] = val.isoformat()

            logger.info("Scan summary retrieved", extra={
                "extra_fields": {
                    "total_assets": summary.get("total_assets", 0),
                    "total_relationships": summary.get("total_relationships", 0)
                }
            })
            return summary

        except HTTPException:
            raise
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
    """Get latest scan summary (DB-first)"""
    try:
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string
        schema = os.getenv("DB_SCHEMA", "public")
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

        loader = InventoryDBLoader(db_url)
        latest_scan_id = loader.get_latest_scan_id(tenant_id)
        if not latest_scan_id:
            loader.close()
            raise HTTPException(status_code=404, detail=f"No completed scans found for tenant: {tenant_id}")

        summary = loader.get_scan_summary(tenant_id=tenant_id, scan_run_id=latest_scan_id)
        loader.close()

        if not summary:
            raise HTTPException(status_code=404, detail=f"Summary not found for scan: {latest_scan_id}")

        # Normalise datetime columns for JSON serialisation
        for key in ("started_at", "completed_at"):
            val = summary.get(key)
            if val and hasattr(val, "isoformat"):
                summary[key] = val.isoformat()

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
    account_id: Optional[str] = Query(None, description="Single account ID filter"),
    account_ids: Optional[str] = Query(None, description="Comma-separated account IDs for multi-account filter"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """List assets with filters and pagination (DB-first, multi-account support)"""
    try:
        # Parse multi-account filter
        parsed_account_ids: Optional[List[str]] = (
            [a.strip() for a in account_ids.split(",") if a.strip()]
            if account_ids else None
        )

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
                loader.close()
                return {"assets": [], "total": 0, "limit": limit, "offset": offset, "has_more": False}

        # Load assets with filters
        assets, total = loader.load_assets(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            provider=provider,
            region=region,
            resource_type=resource_type,
            account_id=account_id,
            account_ids=parsed_account_ids,
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
async def get_asset(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
):
    """Get asset details by resource_uid (DB-first) — inventory data only.

    Returns inventory-owned data:
    - Base asset from inventory_findings
    - drift_info from inventory_drift

    Cross-engine enrichment (check, threat, compliance findings) is handled
    at the BFF layer via GET /api/v1/views/inventory/asset/{resource_uid}.
    """
    # The :path converter is greedy and swallows sub-route suffixes.
    # Dispatch to the correct handler when a known suffix is detected.
    if resource_uid.endswith("/relationships"):
        return await get_asset_relationships(
            resource_uid=resource_uid[: -len("/relationships")],
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            depth=1,
            relation_type=None,
            direction=None,
        )
    if resource_uid.endswith("/drift"):
        return await get_asset_drift_history(
            resource_uid=resource_uid[: -len("/drift")],
            tenant_id=tenant_id,
            limit=50,
        )
    if resource_uid.endswith("/blast-radius"):
        return await get_asset_blast_radius(
            resource_uid=resource_uid[: -len("/blast-radius")],
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            max_depth=3,
        )

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

        if not asset:
            loader.close()
            raise HTTPException(
                status_code=404,
                detail=f"Asset not found: {resource_uid}"
            )

        # --- Cross-engine enrichment (best-effort, failures don't block response) ---

        # 1. Drift info from inventory_drift table (same DB)
        try:
            asset["drift_info"] = loader.load_asset_drift(tenant_id, resource_uid)
        except Exception as e:
            logger.warning(f"Drift enrichment failed for {resource_uid}: {e}")
            asset["drift_info"] = {"last_check": None, "has_drift": False, "changes": [], "total": 0}

        loader.close()

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
    """Get drift history for a specific asset from inventory_drift table."""
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
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

            loader = InventoryDBLoader(db_url)
            drift_info = loader.load_asset_drift(tenant_id, resource_uid, limit=limit)
            loader.close()

            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Asset drift history retrieved", duration_ms)

            return {
                "resource_uid": resource_uid,
                "drift_info": drift_info,
                "total": drift_info.get("total", 0),
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


@app.get("/api/v1/inventory/assets/{resource_uid:path}/blast-radius")
async def get_asset_blast_radius(
    resource_uid: str,
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    max_depth: int = Query(3, ge=1, le=5),
):
    """Get blast radius for a resource — multi-hop impact graph.

    Traces all paths outward from the resource through inventory_relationships
    to show how compromising this resource could impact others.

    Returns nodes and edges in the same schema as the graph endpoint so
    the frontend can reuse its graph rendering components.
    """
    import time
    start_time = time.time()

    with LogContext(tenant_id=tenant_id):
        logger.info("Computing blast radius", extra={
            "extra_fields": {
                "resource_uid": resource_uid,
                "max_depth": max_depth,
            }
        })

        try:
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

            loader = InventoryDBLoader(db_url)

            if not scan_run_id or scan_run_id == "latest":
                scan_run_id = loader.get_latest_scan_id(tenant_id)

            result = loader.get_blast_radius(
                tenant_id=tenant_id,
                resource_uid=resource_uid,
                max_depth=max_depth,
                scan_run_id=scan_run_id,
            )
            loader.close()

            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Blast radius computed", duration_ms)

            return result

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to compute blast radius", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms,
                }
            })
            raise HTTPException(
                status_code=500,
                detail=f"Failed to compute blast radius: {str(e)}"
            )


@app.get("/api/v1/inventory/graph")
async def get_graph(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    resource_uid: Optional[str] = Query(None),
    depth: int = Query(5, ge=1, le=10),
    limit: int = Query(2000, ge=1, le=5000)
):
    """Get graph visualization data using recursive BFS traversal.

    When resource_uid is provided, loads that asset + neighbors.
    Otherwise, seeds from VPC/VNet root containers and walks structural
    edges up to `depth` hops, discovering all contained resources.
    """
    try:
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string
        schema = os.getenv("DB_SCHEMA", "public")
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

        loader = InventoryDBLoader(db_url)

        if resource_uid:
            # Single-asset mode: load asset + direct neighbors
            if not scan_run_id or scan_run_id == "latest":
                scan_run_id = loader.get_latest_scan_id(tenant_id)
            if not scan_run_id:
                loader.close()
                return {"nodes": [], "edges": [], "depth": depth,
                        "total_nodes": 0, "total_edges": 0}

            asset = loader.load_asset_by_uid(tenant_id, resource_uid, scan_run_id)
            nodes = [asset] if asset else []

            rels_from, _ = loader.load_relationships(
                tenant_id=tenant_id, scan_run_id=scan_run_id,
                from_uid=resource_uid, limit=500
            )
            rels_to, _ = loader.load_relationships(
                tenant_id=tenant_id, scan_run_id=scan_run_id,
                to_uid=resource_uid, limit=500
            )
            relationships = rels_from + rels_to

            related_uids = set()
            for rel in relationships:
                if rel.get("from_uid") != resource_uid:
                    related_uids.add(rel.get("from_uid"))
                if rel.get("to_uid") != resource_uid:
                    related_uids.add(rel.get("to_uid"))

            for uid in related_uids:
                related_asset = loader.load_asset_by_uid(tenant_id, uid, scan_run_id)
                if related_asset:
                    nodes.append(related_asset)

            loader.close()
            return {
                "nodes": nodes,
                "edges": relationships,
                "exposure": [],
                "depth": depth,
                "total_nodes": len(nodes),
                "total_edges": len(relationships)
            }
        else:
            # Full graph mode: BFS traversal from VPC roots
            result = loader.load_graph_bfs(
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                max_depth=depth,
                max_nodes=limit,
            )
            loader.close()
            return {
                "nodes": result["nodes"],
                "edges": result["relationships"],
                "exposure": result["exposure"],
                "depth": depth,
                "total_nodes": len(result["nodes"]),
                "total_edges": len(result["relationships"])
            }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load graph: {str(e)}"
        )


_PROVIDER_COLORS = {
    "aws": "#FF9900", "azure": "#0078D4", "gcp": "#4285F4",
    "oci": "#F80000", "alicloud": "#FF6A00", "ibm": "#1F70C1",
}


_RELATION_FAMILY_MAP = {
    "contained_by": "structural", "contains": "structural", "member_of": "structural",
    "attached_to": "structural", "associated_with": "structural", "references": "structural",
    "peers_with": "network", "connected_to": "network", "routes_to": "network",
    "forwards_to": "network", "serves_traffic_for": "network", "resolves_to": "network",
    "allows_traffic_from": "security", "allows_traffic_to": "security",
    "restricted_to": "security", "exposed_through": "security",
    "internet_connected": "security", "protected_by": "security",
    "uses": "identity", "assumes": "identity", "has_policy": "identity",
    "grants_access_to": "identity", "controlled_by": "identity", "authenticated_by": "identity",
    "encrypted_by": "data", "stores_data_in": "data", "backs_up_to": "data", "replicates_to": "data",
    "runs_on": "execution", "invokes": "execution", "triggers": "execution",
    "triggered_by": "execution", "publishes_to": "execution", "subscribes_to": "execution",
    "scales_with": "execution", "cached_by": "execution", "depends_on": "execution",
    "manages": "governance", "deployed_by": "governance", "applies_to": "governance",
    "complies_with": "governance", "logging_enabled_to": "governance",
    "monitored_by": "governance", "scanned_by": "governance",
}


def _classify_link_type(relation_type: str) -> str:
    """Classify a relation_type into a taxonomy family for graph rendering."""
    return _RELATION_FAMILY_MAP.get(relation_type, "default")


@app.get("/api/v1/inventory/runs/latest/graph")
async def get_graph_ui(
    tenant_id: str = Query(...),
    resource_uid: Optional[str] = Query(None),
    depth: int = Query(5, ge=1, le=10),
    limit: int = Query(2000, ge=1, le=5000),
    service: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
):
    """UI-friendly graph endpoint — returns nodes/links with field names matching the frontend.

    Uses BFS traversal from VPC root containers to discover the full
    containment hierarchy (VPC → AZ → Subnet → Resource → Attachments).

    Field mapping:
      nodes[].id            ← resource_uid
      nodes[].name          ← resource_name
      nodes[].type          ← resource_type
      nodes[].service       ← extracted from resource_type
      nodes[].provider      ← provider
      nodes[].color         ← derived from provider
      links[].source        ← from_uid
      links[].target        ← to_uid
      links[].label         ← relation_type
      links[].type          ← classified from relation_type
      exposure[]            ← internet_connected / exposed_through relationships
    """
    # Delegate to the core graph endpoint for data fetching
    raw = await get_graph(
        tenant_id=tenant_id,
        scan_run_id="latest",
        resource_uid=resource_uid,
        depth=depth,
        limit=limit,
    )

    # Transform nodes to UI schema
    ui_nodes = []
    for node in raw.get("nodes") or []:
        rt = node.get("resource_type") or ""
        prov = node.get("provider") or ""
        svc = node.get("service") or (rt.split(".")[0] if "." in rt else rt)

        # Apply optional filters
        if service and svc.lower() != service.lower():
            continue
        if provider and prov.lower() != provider.lower():
            continue

        ui_nodes.append({
            "id": node.get("resource_uid"),
            "name": node.get("resource_name") or node.get("name") or node.get("resource_uid", "").rsplit("/", 1)[-1],
            "type": rt,
            "service": svc,
            "provider": prov,
            "color": _PROVIDER_COLORS.get(prov.lower(), "#6b7280"),
            "region": node.get("region"),
            "account_id": node.get("account_id"),
        })

    # Build set of visible node IDs
    visible_ids = {n["id"] for n in ui_nodes}

    # Transform edges to UI links — and create synthetic nodes for
    # relationship endpoints missing from the initial asset set.
    ui_links = []
    synthetic_nodes = {}
    for edge in raw.get("edges") or []:
        src = edge.get("from_uid")
        tgt = edge.get("to_uid")
        if not src or not tgt:
            continue
        rel_type = edge.get("relation_type") or ""

        # Create synthetic nodes for endpoints not in the visible set
        for uid, rtype_key in ((src, "from_resource_type"), (tgt, "to_resource_type")):
            if uid not in visible_ids and uid not in synthetic_nodes:
                rt = edge.get(rtype_key) or ""
                svc = rt.split(".")[0] if "." in rt else rt
                if service and svc.lower() != service.lower():
                    continue
                if provider:
                    continue
                name = uid.rsplit("/", 1)[-1] if "/" in uid else uid.rsplit(":", 1)[-1]
                synthetic_nodes[uid] = {
                    "id": uid,
                    "name": name,
                    "type": rt,
                    "service": svc,
                    "provider": edge.get("provider", "aws"),
                    "color": _PROVIDER_COLORS.get(edge.get("provider", "aws").lower(), "#6b7280"),
                    "region": edge.get("region"),
                    "account_id": edge.get("account_id"),
                    "synthetic": True,
                }

        # Include link if both endpoints are now visible (original + synthetic)
        all_ids = visible_ids | set(synthetic_nodes.keys())
        if src in all_ids and tgt in all_ids:
            ui_links.append({
                "source": src,
                "target": tgt,
                "label": rel_type,
                "type": _classify_link_type(rel_type),
            })

    # Merge synthetic nodes into output
    all_nodes = ui_nodes + list(synthetic_nodes.values())

    # ── VPC Endpoint → Service target synthetic nodes ──────────────────
    # For VPC endpoints (ec2.vpc-endpoint, network.private-endpoint, etc.),
    # parse the target service name and create synthetic service nodes + edges.
    _VPC_ENDPOINT_TYPES = {
        "ec2.vpc-endpoint", "network.private-endpoint",
        "compute.service-attachment", "core.service-gateway",
        "is.endpoint-gateway",
    }
    vpc_endpoint_links = []
    vpc_endpoint_service_nodes = {}
    for node in all_nodes:
        if node.get("type") not in _VPC_ENDPOINT_TYPES:
            continue
        node_id = node.get("id", "")
        node_name = node.get("name", "")
        # Try to parse service name from VPC endpoint name/id
        # AWS format: com.amazonaws.us-east-1.s3 → s3
        # Also: vpce-xxx-s3, vpce-xxx-dynamodb etc.
        target_svc = None
        # Check for AWS ServiceName pattern in name/id
        parts = node_name.split(".")
        if len(parts) >= 4 and parts[0] == "com" and parts[1] == "amazonaws":
            target_svc = parts[-1]  # last segment = service name
        elif "vpce-" in node_name.lower():
            # Try to extract from vpce name
            segments = node_name.lower().replace("vpce-", "").split("-")
            if segments:
                target_svc = segments[-1]
        # Fallback: try the node id
        if not target_svc and "." in node_id:
            id_parts = node_id.split(".")
            if len(id_parts) >= 4 and id_parts[0] == "com":
                target_svc = id_parts[-1]

        if target_svc:
            svc_key = f"__svc__{target_svc}"
            if svc_key not in vpc_endpoint_service_nodes:
                vpc_endpoint_service_nodes[svc_key] = {
                    "id": svc_key,
                    "name": target_svc.upper(),
                    "type": f"{target_svc}.service",
                    "service": target_svc,
                    "provider": node.get("provider", "aws"),
                    "color": _PROVIDER_COLORS.get(
                        node.get("provider", "aws").lower(), "#6b7280"
                    ),
                    "region": "global",
                    "account_id": node.get("account_id"),
                    "synthetic": True,
                }
            vpc_endpoint_links.append({
                "source": node_id,
                "target": svc_key,
                "label": "connected_to",
                "type": "network",
            })

    if vpc_endpoint_service_nodes:
        all_nodes.extend(vpc_endpoint_service_nodes.values())
        ui_links.extend(vpc_endpoint_links)

    # Pass through exposure data for public-facing detection
    exposure = raw.get("exposure") or []
    ui_exposure = []
    for exp in exposure:
        ui_exposure.append({
            "source": exp.get("from_uid"),
            "target": exp.get("to_uid"),
            "type": exp.get("relation_type"),
            "properties": exp.get("properties") or {},
        })

    return {
        "nodes": all_nodes,
        "links": ui_links,
        "exposure": ui_exposure,
        "depth": depth,
        "total_nodes": len(all_nodes),
        "total_links": len(ui_links),
    }


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
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
            loader = InventoryDBLoader(db_url)

            # If both baseline and compare are provided, compare two scans
            if baseline_scan and compare_scan:
                # Load assets from both scans (DB-first)
                _base_assets, _ = loader.load_assets(tenant_id=tenant_id, scan_run_id=baseline_scan, limit=50000)
                _cmp_assets, _ = loader.load_assets(tenant_id=tenant_id, scan_run_id=compare_scan, limit=50000)
                baseline_assets = {a.get("resource_uid"): a for a in _base_assets}
                compare_assets = {a.get("resource_uid"): a for a in _cmp_assets}
                
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
                            "detected_at": datetime.now(timezone.utc).isoformat() + "Z"
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
                            "detected_at": datetime.now(timezone.utc).isoformat() + "Z"
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
                                "detected_at": datetime.now(timezone.utc).isoformat() + "Z"
                            })
            else:
                # No baseline/compare → load pre-computed drift from inventory_drift table.
                # Uses load_drift_records() which returns UI-ready flat records with
                # resource_name, severity, previous_value, new_value from DB.
                effective_scan = scan_run_id
                if not effective_scan or effective_scan == "latest":
                    effective_scan = loader.get_latest_scan_id(tenant_id)

                drift_records = loader.load_drift_records(
                    tenant_id=tenant_id,
                    scan_run_id=effective_scan,
                    provider=provider,
                    change_type=change_type,
                    limit=500,
                )

            loader.close()

            # Apply additional filters (for two-scan comparison mode only;
            # load_drift_records already filters by provider/change_type)
            if baseline_scan and compare_scan:
                if provider:
                    drift_records = [d for d in drift_records if d.get("provider") == provider]
                if resource_type:
                    drift_records = [d for d in drift_records if d.get("resource_type") == resource_type]
                if account_id:
                    drift_records = [d for d in drift_records if d.get("account_id") == account_id]

            # Group by change/drift type
            type_key = "drift_type" if not baseline_scan else "change_type"
            by_change_type: Dict[str, List] = {}
            for drift in drift_records:
                change = drift.get(type_key, drift.get("change_type", "unknown"))
                if change not in by_change_type:
                    by_change_type[change] = []
                by_change_type[change].append(drift)

            # Group by provider
            by_provider: Dict[str, Dict] = {}
            for drift in drift_records:
                prov = drift.get("provider", "unknown")
                if prov not in by_provider:
                    by_provider[prov] = {"added": 0, "removed": 0, "changed": 0}
                change = drift.get(type_key, drift.get("change_type", ""))
                if "added" in change:
                    by_provider[prov]["added"] += 1
                elif "removed" in change:
                    by_provider[prov]["removed"] += 1
                else:
                    by_provider[prov]["changed"] += 1

            # Severity summary (for pre-computed drift records)
            by_severity: Dict[str, int] = {}
            for drift in drift_records:
                sev = drift.get("severity", "medium")
                by_severity[sev] = by_severity.get(sev, 0) + 1

            # Unique affected resources
            affected_resources = len({d.get("resource_uid") for d in drift_records if d.get("resource_uid")})

            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Drift records retrieved", duration_ms)

            return {
                "tenant_id": tenant_id,
                "baseline_scan": baseline_scan,
                "compare_scan": compare_scan,
                "summary": {
                    "total_drift": len(drift_records),
                    "affected_resources": affected_resources,
                    "assets_added": len([d for d in drift_records if "added" in (d.get(type_key) or d.get("change_type") or "")]),
                    "assets_removed": len([d for d in drift_records if "removed" in (d.get(type_key) or d.get("change_type") or "")]),
                    "assets_changed": len([d for d in drift_records if "changed" in (d.get(type_key) or d.get("change_type") or "") or "modified" in (d.get(type_key) or d.get("change_type") or "")]),
                    "by_severity": by_severity,
                },
                "drift_records": drift_records,
                "total": len(drift_records),
                "by_change_type": {k: len(v) for k, v in by_change_type.items()},
                "by_provider": by_provider,
                "details": by_change_type,
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
    """Get account summary with service breakdown and regional distribution (DB-first)"""
    try:
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string
        schema = os.getenv("DB_SCHEMA", "public")
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

        loader = InventoryDBLoader(db_url)

        if not scan_run_id or scan_run_id == "latest":
            scan_run_id = loader.get_latest_scan_id(tenant_id)
            if not scan_run_id:
                loader.close()
                return {"account_id": account_id, "total_assets": 0, "by_service": {}, "by_region": {}, "provider": "unknown"}

        # Load all assets for this specific account (no pagination - aggregate query)
        account_assets, _ = loader.load_assets(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            account_id=account_id,
            limit=10000
        )
        loader.close()

        # Group by service
        by_service: Dict[str, int] = {}
        for asset in account_assets:
            service = asset.get("resource_type", "unknown").split(".")[0]
            by_service[service] = by_service.get(service, 0) + 1

        # Group by region
        by_region: Dict[str, int] = {}
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
    """Get service-specific summary with configuration statistics (DB-first)"""
    try:
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string
        schema = os.getenv("DB_SCHEMA", "public")
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"

        loader = InventoryDBLoader(db_url)

        if not scan_run_id or scan_run_id == "latest":
            scan_run_id = loader.get_latest_scan_id(tenant_id)
            if not scan_run_id:
                loader.close()
                return {"service": service, "total_assets": 0, "by_account": {}, "by_region": {}, "by_resource_type": {}}

        # Load assets filtered by resource_type prefix (DB LIKE query)
        service_assets, _ = loader.load_assets(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            resource_type_prefix=service,
            limit=10000
        )
        loader.close()

        # Group by account
        by_account: Dict[str, int] = {}
        for asset in service_assets:
            acct = asset.get("account_id", "unknown")
            by_account[acct] = by_account.get(acct, 0) + 1

        # Group by region
        by_region: Dict[str, int] = {}
        for asset in service_assets:
            region = asset.get("region", "unknown")
            by_region[region] = by_region.get(region, 0) + 1

        # Group by resource type
        by_resource_type: Dict[str, int] = {}
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
            db_config = get_database_config("inventory")
            db_url = db_config.connection_string
            schema = os.getenv("DB_SCHEMA", "public")
            sep = "&" if "?" in db_url else "?"
            db_url = f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"
            loader = InventoryDBLoader(db_url)

            effective_scan = scan_run_id
            if effective_scan == "latest":
                effective_scan = loader.get_latest_scan_id(tenant_id)

            drift_records = loader.load_drift_records(
                tenant_id=tenant_id,
                scan_run_id=effective_scan,
                provider=provider,
                change_type=change_type,
                limit=500,
            )
            loader.close()

            # Apply additional filters
            if resource_type:
                drift_records = [d for d in drift_records if d.get("resource_type") == resource_type]
            if account_id:
                drift_records = [d for d in drift_records if d.get("account_id") == account_id]

            # Group by change type
            by_change_type: Dict[str, List] = {}
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
                "details": by_change_type,
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


# ─────────────────────────────────────────────────────────────────────────────
# TAXONOMY & ARCHITECTURE DIAGRAM ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/inventory/taxonomy")
async def get_taxonomy(
    csp: Optional[str] = Query(None, description="Filter by CSP (aws, azure, gcp, oci, alicloud, ibm, k8s)"),
    category: Optional[str] = Query(None, description="Filter by category (compute, database, storage, ...)"),
    min_priority: int = Query(5, ge=1, le=5, description="Include resources with priority <= this value"),
):
    """
    Return the service classification taxonomy from service_classification table.

    Used by the UI to:
    - Know how to group/color/nest resources in architecture diagrams
    - Filter resources by category/subcategory/service_model
    - Determine container hierarchy (what nests inside what)
    """
    try:
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string

        import psycopg2
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                conditions = []
                params = []

                if csp:
                    conditions.append("csp = %s")
                    params.append(csp)
                if category:
                    conditions.append("category = %s")
                    params.append(category)
                if min_priority < 5:
                    conditions.append("diagram_priority <= %s")
                    params.append(min_priority)

                where = " AND ".join(conditions) if conditions else "TRUE"

                cur.execute(f"""
                    SELECT csp, resource_type, service, resource_name,
                           display_name, scope, category, subcategory,
                           service_model, managed_by, access_pattern,
                           encryption_scope, is_container, container_parent,
                           diagram_priority, csp_category
                    FROM service_classification
                    WHERE {where}
                    ORDER BY csp, diagram_priority, category, service, resource_type
                """, params)

                columns = [desc[0] for desc in cur.description]
                rows = [dict(zip(columns, row)) for row in cur.fetchall()]

                # Build summary
                categories_summary = {}
                for r in rows:
                    cat = r["category"]
                    if cat not in categories_summary:
                        categories_summary[cat] = {"count": 0, "subcategories": set()}
                    categories_summary[cat]["count"] += 1
                    if r.get("subcategory"):
                        categories_summary[cat]["subcategories"].add(r["subcategory"])

                # Convert sets to sorted lists for JSON
                for cat_info in categories_summary.values():
                    cat_info["subcategories"] = sorted(cat_info["subcategories"])

                return {
                    "total": len(rows),
                    "classifications": rows,
                    "categories_summary": categories_summary,
                    "filters_applied": {
                        "csp": csp, "category": category, "min_priority": min_priority
                    }
                }
        finally:
            conn.close()

    except Exception as e:
        logger.error("Failed to get taxonomy", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get taxonomy: {str(e)}")


@app.get("/api/v1/inventory/architecture")
async def get_architecture_diagram(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    max_priority: int = Query(2, ge=1, le=5, description="Show resources up to this priority level"),
    include_relationships: bool = Query(True, description="Include relationship edges"),
    csp: Optional[str] = Query(None, description="Filter by CSP"),
):
    """
    Return a pre-nested hierarchy for architecture diagram rendering.

    Combines:
    - inventory_findings (WHAT exists)
    - inventory_relationships (WHO connects to WHOM)
    - resource_inventory_identifier classifications (HOW to organize)

    Returns nested JSON:
    {
      accounts: [{
        account_id, name, provider,
        global_services: { identity: [...], storage: [...], ... },
        regions: [{
          name,
          regional_services: { compute: [...], encryption: [...], ... },
          vpcs: [{
            vpc_id, name,
            edge: [...],
            security: [...],
            subnets: [{
              subnet_id, name,
              resources_by_category: { compute: [...], database: [...] }
            }]
          }]
        }]
      }],
      relationships: [{ from_uid, to_uid, relation_type, ... }]
    }
    """
    import psycopg2
    import psycopg2.extras

    try:
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string

        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # ── Step 1: Resolve scan_run_id(s) ──
                # Architecture needs ALL resources across ALL providers/scans.
                # If "latest", find ALL distinct scan_run_ids for this tenant.
                use_all_scans = False
                scan_run_ids = []

                if not scan_run_id or scan_run_id == "latest":
                    cur.execute("""
                        SELECT DISTINCT latest_scan_run_id
                        FROM inventory_findings
                        WHERE tenant_id = %s AND latest_scan_run_id IS NOT NULL
                    """, (tenant_id,))
                    rows = cur.fetchall()
                    if not rows:
                        return {"accounts": [], "relationships": [], "message": "No inventory data found"}
                    scan_run_ids = [r["latest_scan_run_id"] for r in rows]
                    scan_run_id = scan_run_ids[0]  # primary for response
                    use_all_scans = True
                else:
                    scan_run_ids = [scan_run_id]

                # ── Step 2: Load taxonomy from service_classification ──
                # Load ALL taxonomy entries (not filtered by priority).
                # Priority filtering happens in the asset query instead.
                # This ensures _classify() can properly categorize every
                # asset that passed the priority-filtered asset query.
                csp_condition = ""
                tax_params = []
                if csp:
                    csp_condition = "WHERE csp = %s"
                    tax_params.append(csp)

                cur.execute(f"""
                    SELECT csp, resource_type, service, resource_name,
                           display_name, scope, category, subcategory,
                           service_model, managed_by, access_pattern,
                           is_container, container_parent, diagram_priority,
                           resource_role
                    FROM service_classification
                    {csp_condition}
                """, tax_params)

                taxonomy = {}
                for row in cur.fetchall():
                    # Key by csp.resource_type (dotted format matches inventory_findings)
                    key = f"{row['csp']}.{row['resource_type']}"
                    taxonomy[key] = dict(row)

                # ── Step 3: Load assets (across all scan_run_ids) ──
                csp_filter = ""
                params = [tenant_id]
                if csp:
                    csp_filter = "AND provider = %s"
                    params.append(csp)

                if use_all_scans and len(scan_run_ids) > 1:
                    # Load ALL assets across all scans
                    placeholders = ", ".join(["%s"] * len(scan_run_ids))
                    params.extend(scan_run_ids)
                    scan_filter = f"AND latest_scan_run_id IN ({placeholders})"
                else:
                    params.append(scan_run_ids[0])
                    scan_filter = "AND latest_scan_run_id = %s"

                # Only load assets whose resource_type has taxonomy
                # diagram_priority <= max_priority (or is a VPC/subnet
                # container, or has no taxonomy entry at all — to avoid
                # dropping unknown types silently).
                params.append(max_priority)
                cur.execute(f"""
                    SELECT i.asset_id, i.resource_uid, i.provider,
                           i.account_id, i.region, i.resource_type,
                           i.resource_id, i.name, i.display_name,
                           i.tags, i.risk_score, i.criticality,
                           i.compliance_status, i.latest_scan_run_id,
                           i.properties, i.configuration
                    FROM inventory_findings i
                    LEFT JOIN service_classification sc
                      ON sc.csp = i.provider
                     AND sc.resource_type = i.resource_type
                    WHERE i.tenant_id = %s
                      {csp_filter}
                      {scan_filter}
                      AND (
                          sc.diagram_priority <= %s
                          OR sc.resource_type IS NULL
                          OR i.resource_type IN (
                              'ec2.vpc', 'vpc.vpc', 'ec2.subnet', 'vpc.subnet',
                              'network.virtual-network', 'network.subnet',
                              'core.vcn', 'core.subnet', 'vpc.network',
                              'vpc.subnetwork', 'is.vpc', 'is.subnet'
                          )
                      )
                    ORDER BY i.account_id, i.region, i.resource_type
                """, params)

                assets = [dict(r) for r in cur.fetchall()]

                # ── Step 4: Load relationships (ALL for tenant) ──
                # Architecture diagrams need ALL containment relationships
                # regardless of scan_run_id, because relationship scans
                # and asset scans may have different IDs.  Loading only
                # matching scan_ids drops most contained_by edges.
                relationships = []
                if include_relationships:
                    cur.execute("""
                        SELECT DISTINCT ON (from_uid, to_uid, relation_type)
                               from_uid, to_uid, relation_type,
                               from_resource_type, to_resource_type,
                               relationship_strength, bidirectional
                        FROM inventory_relationships
                        WHERE tenant_id = %s
                        ORDER BY from_uid, to_uid, relation_type
                    """, [tenant_id])
                    relationships = [dict(r) for r in cur.fetchall()]

                # ── Step 5: Build nested hierarchy (v2 — modular builder) ──
                hierarchy = build_architecture_hierarchy(assets, taxonomy, relationships)

                return {
                    **hierarchy,
                    "scan_run_id": scan_run_id,
                    "filters": {
                        "max_priority": max_priority,
                        "include_relationships": include_relationships,
                        "csp": csp,
                    },
                    "stats": {
                        "total_assets": len(assets),
                        "total_relationships": len(relationships),
                        "taxonomy_entries": len(taxonomy),
                    }
                }

        finally:
            conn.close()

    except Exception as e:
        logger.error("Failed to build architecture diagram", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to build architecture: {str(e)}")


def _build_architecture_hierarchy_REMOVED():
    """REMOVED: This function has been replaced by architecture_builder.build_architecture_hierarchy."""
    raise NotImplementedError("Use build_architecture_hierarchy from architecture_builder module")




@app.get("/api/v1/inventory/taxonomy/coverage")
async def get_taxonomy_coverage():
    """
    Show classification coverage stats: how many inventory resource_types
    have a matching entry in service_classification.
    """
    try:
        db_config = get_database_config("inventory")
        db_url = db_config.connection_string

        import psycopg2
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    WITH inv_types AS (
                        SELECT DISTINCT provider AS csp, resource_type, COUNT(*) AS asset_count
                        FROM inventory_findings
                        GROUP BY provider, resource_type
                    )
                    SELECT
                        i.csp,
                        i.resource_type,
                        i.asset_count,
                        sc.category,
                        sc.diagram_priority,
                        CASE WHEN sc.id IS NOT NULL THEN true ELSE false END AS classified
                    FROM inv_types i
                    LEFT JOIN service_classification sc
                        ON sc.csp = i.csp AND sc.resource_type = i.resource_type
                    ORDER BY i.csp, classified, i.asset_count DESC
                """)

                columns = [desc[0] for desc in cur.description]
                rows = [dict(zip(columns, row)) for row in cur.fetchall()]

                # Summary
                by_csp = {}
                for r in rows:
                    c = r["csp"]
                    if c not in by_csp:
                        by_csp[c] = {"total_types": 0, "classified": 0, "unclassified": 0,
                                     "total_assets": 0, "classified_assets": 0}
                    by_csp[c]["total_types"] += 1
                    by_csp[c]["total_assets"] += r["asset_count"]
                    if r["classified"]:
                        by_csp[c]["classified"] += 1
                        by_csp[c]["classified_assets"] += r["asset_count"]
                    else:
                        by_csp[c]["unclassified"] += 1

                for v in by_csp.values():
                    v["coverage_pct"] = round(v["classified"] / v["total_types"] * 100, 1) if v["total_types"] > 0 else 0

                return {
                    "summary": by_csp,
                    "details": rows,
                }
        finally:
            conn.close()
    except Exception as e:
        logger.error("Failed to get taxonomy coverage", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

