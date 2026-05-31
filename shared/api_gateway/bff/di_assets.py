"""
BFF view: /api/v1/views/di/*

Provides aggregated DI asset views for the CSPM portal.
All queries are tenant-scoped from AuthContext — never from request params.

DI_ENGINE_ENABLED env var gates these endpoints (returns 404 if false).
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger("bff.di_assets")

DI_ENGINE_ENABLED = os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true"

router = APIRouter(prefix="/api/v1/views/di", tags=["di-assets"])


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


def _require_di_enabled():
    if not DI_ENGINE_ENABLED:
        raise HTTPException(
            status_code=404,
            detail="DI engine not enabled. Set DI_ENGINE_ENABLED=true.",
        )


def _get_tenant_id(auth: Any) -> str:
    if auth is None:
        return "dev-tenant"
    tenant_id = getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="tenant_id not in auth context")
    return tenant_id


# ── Provider summary ───────────────────────────────────────────────────────────
@router.get("/summary")
async def get_di_summary(
    scan_run_id: Optional[str] = Query(None),
    auth: Any = None,
):
    """Asset counts by provider + service for the latest or specific scan."""
    _require_di_enabled()
    tenant_id = _get_tenant_id(auth)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if not scan_run_id:
                # Get latest scan_run_id for this tenant
                cur.execute(
                    """
                    SELECT scan_run_id FROM asset_inventory
                    WHERE tenant_id = %s
                    ORDER BY last_seen_at DESC LIMIT 1
                    """,
                    (tenant_id,),
                )
                row = cur.fetchone()
                if not row:
                    return {"data": [], "total": 0, "scan_run_id": None}
                scan_run_id = row["scan_run_id"]

            cur.execute(
                """
                SELECT
                    provider,
                    service,
                    COUNT(*) AS asset_count,
                    COUNT(*) FILTER (WHERE drift_detected) AS drifted_count,
                    COUNT(*) FILTER (WHERE phase = 1) AS enriched_count
                FROM asset_inventory
                WHERE tenant_id = %s AND scan_run_id = %s
                GROUP BY provider, service
                ORDER BY asset_count DESC
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()

            cur.execute(
                "SELECT COUNT(*) FROM asset_inventory WHERE tenant_id = %s AND scan_run_id = %s",
                (tenant_id, scan_run_id),
            )
            total = cur.fetchone()["count"]
    finally:
        conn.close()

    return {
        "scan_run_id": scan_run_id,
        "total": total,
        "data": [dict(r) for r in rows],
    }


# ── Drift report ───────────────────────────────────────────────────────────────
@router.get("/drift")
async def get_di_drift(
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    auth: Any = None,
):
    """Assets with configuration drift detected in the latest scan."""
    _require_di_enabled()
    tenant_id = _get_tenant_id(auth)
    offset = (page - 1) * page_size

    conditions = ["tenant_id = %s", "drift_detected = TRUE"]
    params: List[Any] = [tenant_id]

    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)
    if provider:
        conditions.append("provider = %s")
        params.append(provider)

    where = " AND ".join(conditions)
    params.extend([page_size, offset])

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    resource_uid, resource_type, resource_name, service,
                    provider, region, account_id,
                    config_hash, previous_config_hash,
                    first_seen_at, last_seen_at
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


# ── Error summary ──────────────────────────────────────────────────────────────
@router.get("/errors/summary")
async def get_error_summary(
    scan_run_id: Optional[str] = Query(None),
    auth: Any = None,
):
    """Error counts by error_type + service for a scan."""
    _require_di_enabled()
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
                SELECT
                    error_type,
                    service,
                    provider,
                    COUNT(*) AS count
                FROM di_scan_errors
                WHERE {where}
                GROUP BY error_type, service, provider
                ORDER BY count DESC
                """,
                params,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return {"data": [dict(r) for r in rows]}
