"""
engine-di FastAPI server

Endpoints:
  GET  /api/v1/health/live
  GET  /api/v1/health/ready
  GET  /api/v1/di/assets         — paginated asset list (discoveries:read)
  GET  /api/v1/di/assets/{uid}   — single asset detail (discoveries:read)
  GET  /api/v1/di/assets/count   — count per provider (discoveries:read)
  GET  /api/v1/di/relationships  — paginated relationships (discoveries:read)
  GET  /api/v1/di/errors         — di_scan_errors for a scan_run_id (discoveries:read)
  GET  /api/v1/di/status/{id}    — scan status (discoveries:read)

All data endpoints:
  - Require X-Auth-Context (require_permission("discoveries:read"))
  - Always scope by tenant_id from AuthContext — never from query params
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("engine-di.api")

# ── Auth ───────────────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.fastapi.middleware import AuthMiddleware
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    require_permission = None  # type: ignore

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="engine-di",
    description="Unified Discovery + Inventory engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)


# ── DB connection ──────────────────────────────────────────────────────────────
def _get_di_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("DI_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _auth_dep():
    if _AUTH_AVAILABLE and require_permission:
        return Depends(require_permission("discoveries:read"))
    return Depends(lambda: None)


# ── Request models ────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    scan_run_id: str
    tenant_id: str
    account_id: str
    provider: str = "aws"
    credential_type: str = "access_key"
    credential_ref: str = ""
    include_regions: str = ""


# ── Scan trigger ───────────────────────────────────────────────────────────────
@app.post("/api/v1/di/scan")
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    auth: Any = _auth_dep(),
):
    """Trigger an async DI scan. Called by Argo pipeline step."""
    from di_engine.phase2.writer import update_scan_status
    tenant_id = request.tenant_id

    update_scan_status(
        scan_run_id=request.scan_run_id,
        tenant_id=tenant_id,
        status="queued",
        phase=0,
    )

    background_tasks.add_task(
        _run_scan_background,
        request.scan_run_id,
    )

    return {
        "status": "queued",
        "scan_run_id": request.scan_run_id,
        "message": "DI scan queued",
    }


async def _run_scan_background(scan_run_id: str) -> None:
    """Launch run_scan.py as a subprocess (mirrors K8s Job behavior)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "/app/run_scan.py", "--scan-run-id", scan_run_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            logger.error(
                "run_scan.py failed: scan_run_id=%s code=%d output=%s",
                scan_run_id, proc.returncode,
                (stdout or b"").decode()[:500],
            )
    except Exception as e:
        logger.error("Background scan failed: scan_run_id=%s: %s", scan_run_id, e)


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "ok", "engine": "di"}


@app.get("/api/v1/health/ready")
async def health_ready():
    try:
        conn = _get_di_conn()
        conn.close()
        return {"status": "ok", "db": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"DB unavailable: {e}")


# ── Assets ─────────────────────────────────────────────────────────────────────
@app.get("/api/v1/di/assets")
async def list_assets(
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    auth: Any = _auth_dep(),
):
    """Paginated asset list scoped by tenant_id from AuthContext."""
    tenant_id = _get_tenant_id(auth)
    offset = (page - 1) * page_size

    conditions = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]

    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)
    if provider:
        conditions.append("provider = %s")
        params.append(provider)
    if service:
        conditions.append("service = %s")
        params.append(service)
    if resource_type:
        conditions.append("resource_type = %s")
        params.append(resource_type)
    if region:
        conditions.append("region = %s")
        params.append(region)

    where = " AND ".join(conditions)
    params.extend([page_size, offset])

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    id, scan_run_id, tenant_id, account_id, provider, region,
                    resource_uid, resource_type, resource_name, service,
                    discovery_id, phase, severity, status,
                    drift_detected, first_seen_at, last_seen_at
                FROM asset_inventory
                WHERE {where}
                ORDER BY last_seen_at DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            rows = cur.fetchall()

            cur.execute(
                f"SELECT COUNT(*) FROM asset_inventory WHERE {where}",
                params[:-2],
            )
            total = cur.fetchone()["count"]
    finally:
        conn.close()

    return {
        "data": [dict(r) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@app.get("/api/v1/di/assets/count")
async def count_assets(
    scan_run_id: Optional[str] = Query(None),
    auth: Any = _auth_dep(),
):
    """Count assets by provider for a scan."""
    tenant_id = _get_tenant_id(auth)

    conditions = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]
    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)

    where = " AND ".join(conditions)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT provider, service, COUNT(*) AS count
                FROM asset_inventory
                WHERE {where}
                GROUP BY provider, service
                ORDER BY count DESC
                """,
                params,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return {"data": [dict(r) for r in rows]}


@app.get("/api/v1/di/assets/{resource_uid:path}")
async def get_asset(
    resource_uid: str,
    scan_run_id: Optional[str] = Query(None),
    auth: Any = _auth_dep(),
):
    """Get single asset by resource_uid."""
    tenant_id = _get_tenant_id(auth)

    conditions = ["tenant_id = %s", "resource_uid = %s"]
    params: List[Any] = [tenant_id, resource_uid]
    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)

    where = " AND ".join(conditions)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT *
                FROM asset_inventory
                WHERE {where}
                ORDER BY last_seen_at DESC
                LIMIT 1
                """,
                params,
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    return dict(row)


# ── Relationships ──────────────────────────────────────────────────────────────
@app.get("/api/v1/di/relationships")
async def list_relationships(
    scan_run_id: Optional[str] = Query(None),
    source_uid: Optional[str] = Query(None),
    relation_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    auth: Any = _auth_dep(),
):
    """Paginated asset relationships."""
    tenant_id = _get_tenant_id(auth)
    offset = (page - 1) * page_size

    conditions = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]

    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)
    if source_uid:
        conditions.append("source_uid = %s")
        params.append(source_uid)
    if relation_type:
        conditions.append("relation_type = %s")
        params.append(relation_type)

    where = " AND ".join(conditions)
    params.extend([page_size, offset])

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT *
                FROM asset_relationships
                WHERE {where}
                ORDER BY last_seen_at DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return {"data": [dict(r) for r in rows], "page": page, "page_size": page_size}


# ── Errors ─────────────────────────────────────────────────────────────────────
@app.get("/api/v1/di/errors")
async def list_errors(
    scan_run_id: Optional[str] = Query(None),
    error_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    auth: Any = _auth_dep(),
):
    """List di_scan_errors for a tenant."""
    tenant_id = _get_tenant_id(auth)
    offset = (page - 1) * page_size

    conditions = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]
    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)
    if error_type:
        conditions.append("error_type = %s")
        params.append(error_type)

    where = " AND ".join(conditions)
    params.extend([page_size, offset])

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT *
                FROM di_scan_errors
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return {"data": [dict(r) for r in rows], "page": page, "page_size": page_size}


# ── Status ─────────────────────────────────────────────────────────────────────
@app.get("/api/v1/di/status/{scan_run_id}")
async def get_status(
    scan_run_id: str,
    auth: Any = _auth_dep(),
):
    """Get scan status from di_scan_status."""
    tenant_id = _get_tenant_id(auth)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM di_scan_status
                WHERE scan_run_id = %s AND tenant_id = %s
                """,
                (scan_run_id, tenant_id),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan status not found")
    return dict(row)


# ── Helper ─────────────────────────────────────────────────────────────────────
def _get_tenant_id(auth: Any) -> str:
    """Extract tenant_id from AuthContext. Raises 401 if not present."""
    if auth is None:
        return "dev-tenant"  # only reachable when _AUTH_AVAILABLE=False

    tenant_id = getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="tenant_id not in auth context")
    return tenant_id
