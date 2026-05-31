"""
engine-di FastAPI server

Endpoints:
  GET  /api/v1/health/live
  GET  /api/v1/health/ready
  GET  /api/v1/di/assets                        — paginated asset list (discoveries:read)
  GET  /api/v1/di/assets/count                  — count per provider (discoveries:read)
  GET  /api/v1/di/assets/{uid}/posture          — RSP row for one asset (discoveries:read)
  GET  /api/v1/di/assets/{uid}/findings         — paginated security_findings (discoveries:read)
  GET  /api/v1/di/assets/{uid}                  — single asset detail (discoveries:read)
  POST /api/v1/di/batch-posture                 — bulk RSP lookup by resource_uid list
  GET  /api/v1/di/relationships                 — paginated relationships (discoveries:read)
  GET  /api/v1/di/errors                        — di_scan_errors for a scan_run_id (discoveries:read)
  GET  /api/v1/di/status/{id}                   — scan status (discoveries:read)

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
    allow_methods=["GET", "POST"],
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


class BatchPostureRequest(BaseModel):
    resource_uids: List[str]


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


# ── Batch posture lookup ───────────────────────────────────────────────────────
@app.post("/api/v1/di/batch-posture")
async def batch_posture(
    body: BatchPostureRequest,
    auth: Any = _auth_dep(),
) -> Dict[str, Any]:
    """Batch-fetch RSP signals for up to 500 resource_uids."""
    tenant_id = _get_tenant_id(auth)
    if not body.resource_uids:
        return {"posture": {}}

    uids = body.resource_uids[:500]
    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    resource_uid,
                    overall_posture_score, posture_vector,
                    is_internet_exposed, is_on_attack_path, is_crown_jewel, is_choke_point,
                    attack_path_count, highest_path_severity,
                    blast_radius_count, reachable_pii_store_count,
                    is_in_private_subnet, network_exposure_score,
                    can_access_pii,
                    is_admin_role, role_has_wildcard_policy, mfa_enforced,
                    is_encrypted_at_rest, has_kms_managed_key,
                    data_classification, has_exfil_path,
                    has_active_cdr_actor, cdr_actor_count,
                    vuln_critical_count, vuln_high_count, has_known_exploit,
                    unencrypted_pii_store, internet_exposed_with_pii,
                    admin_role_without_mfa, exploitable_exposed_resource,
                    has_priv_escalation_path,
                    api_publicly_accessible, api_public_no_waf, api_public_no_auth,
                    check_critical, check_high, check_medium, check_low
                FROM resource_security_posture
                WHERE tenant_id = %s AND resource_uid = ANY(%s)
                """,
                (tenant_id, uids),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    posture_map = {
        r["resource_uid"]: {k: v for k, v in dict(r).items() if k != "resource_uid"}
        for r in rows
    }
    return {"posture": posture_map}


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


@app.get("/api/v1/di/assets/{resource_uid:path}/posture")
async def get_asset_posture(
    resource_uid: str,
    auth: Any = _auth_dep(),
) -> Dict[str, Any]:
    """Full RSP row for a single asset (all 6 dimensions + attack-path signals)."""
    tenant_id = _get_tenant_id(auth)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM resource_security_posture
                WHERE tenant_id = %s AND resource_uid = %s
                """,
                (tenant_id, resource_uid),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Posture data not found for asset")
    return dict(row)


@app.get("/api/v1/di/assets/{resource_uid:path}/findings")
async def get_asset_findings(
    resource_uid: str,
    status: Optional[str] = Query("open"),
    finding_type: Optional[str] = Query(None),
    source_engine: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    auth: Any = _auth_dep(),
) -> Dict[str, Any]:
    """Paginated security_findings for a single asset (default: open findings only)."""
    tenant_id = _get_tenant_id(auth)
    offset = (page - 1) * page_size

    conditions = ["tenant_id = %s", "resource_uid = %s"]
    params: List[Any] = [tenant_id, resource_uid]

    if status:
        conditions.append("status = %s")
        params.append(status.lower())
    if finding_type:
        conditions.append("finding_type = %s")
        params.append(finding_type)
    if source_engine:
        conditions.append("source_engine = %s")
        params.append(source_engine)
    if severity:
        conditions.append("severity = %s")
        params.append(severity.lower())

    where = " AND ".join(conditions)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    finding_id, source_engine, source_finding_id, finding_type,
                    severity, status, rule_id, title, description,
                    mitre_technique_id, mitre_tactic, epss_score, cvss_score, in_kev,
                    first_seen_at, last_seen_at
                FROM security_findings
                WHERE {where}
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high'     THEN 2
                        WHEN 'medium'   THEN 3
                        WHEN 'low'      THEN 4
                        ELSE 5
                    END,
                    last_seen_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [page_size, offset],
            )
            rows = cur.fetchall()

            cur.execute(
                f"SELECT COUNT(*) FROM security_findings WHERE {where}", params
            )
            total = cur.fetchone()["count"]
    finally:
        conn.close()

    return {
        "data": [dict(r) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "resource_uid": resource_uid,
    }


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


# ── Inventory-compat endpoints ─────────────────────────────────────────────────
# These mirror the old inventory + discoveries engine response shapes so BFF
# callers can switch engine key from "inventory"/"discoveries" to "di" without
# changing response-parsing code.

def _resolve_scan_run_id(cur: Any, tenant_id: str, scan_run_id: Optional[str]) -> Optional[str]:
    """Return the actual scan_run_id, resolving 'latest' to the most recent one."""
    if not scan_run_id or scan_run_id == "latest":
        cur.execute(
            "SELECT scan_run_id FROM di_scan_status "
            "WHERE tenant_id = %s ORDER BY started_at DESC LIMIT 1",
            (tenant_id,),
        )
        row = cur.fetchone()
        return row["scan_run_id"] if row else None
    return scan_run_id


def _extract_tags(emitted_fields: Any) -> Dict[str, str]:
    """Normalize tags from emitted_fields JSONB into a flat {key: value} dict.

    Handles three common formats:
      - AWS list: [{"Key": "env", "Value": "prod"}, ...]
      - GCP/Azure dict: {"env": "prod", ...}
      - Nested under "tags" or "Labels" key
    """
    if not emitted_fields:
        return {}
    ef = emitted_fields if isinstance(emitted_fields, dict) else {}
    # Try common nesting keys only — never fall back to raw emitted_fields
    raw = ef.get("Tags") or ef.get("tags") or ef.get("Labels") or ef.get("labels")
    if raw is None:
        return {}
    if isinstance(raw, list):
        result = {}
        for item in raw:
            if isinstance(item, dict):
                k = item.get("Key") or item.get("key") or item.get("Name") or item.get("name")
                v = item.get("Value") or item.get("value") or ""
                if k:
                    result[str(k)] = str(v)
        return result
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if k and v is not None}
    return {}


@app.get("/api/v1/di/ui-data")
async def di_ui_data(
    scan_run_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    auth: Any = _auth_dep(),
) -> Dict[str, Any]:
    """Asset list + summary — inventory /ui-data compat."""
    tenant_id = _get_tenant_id(auth)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            sid = _resolve_scan_run_id(cur, tenant_id, scan_run_id)

            base_cond = "tenant_id = %s" + (" AND scan_run_id = %s" if sid else "")
            base_params: List[Any] = [tenant_id] + ([sid] if sid else [])

            # Aggregations
            cur.execute(
                f"SELECT COUNT(*) FROM asset_inventory WHERE {base_cond}", base_params
            )
            total = cur.fetchone()["count"]

            cur.execute(
                f"SELECT provider, COUNT(*) AS cnt FROM asset_inventory "
                f"WHERE {base_cond} GROUP BY provider",
                base_params,
            )
            by_provider = {r["provider"]: r["cnt"] for r in cur.fetchall()}

            cur.execute(
                f"SELECT service, COUNT(*) AS cnt FROM asset_inventory "
                f"WHERE {base_cond} GROUP BY service ORDER BY cnt DESC LIMIT 50",
                base_params,
            )
            by_service = [{"service": r["service"], "count": r["cnt"]} for r in cur.fetchall()]

            cur.execute(
                f"SELECT region, COUNT(*) AS cnt FROM asset_inventory "
                f"WHERE {base_cond} GROUP BY region ORDER BY cnt DESC LIMIT 50",
                base_params,
            )
            by_region = [{"region": r["region"], "count": r["cnt"]} for r in cur.fetchall()]

            # Paginated asset list
            page_params = base_params + [limit, offset]
            cur.execute(
                f"""
                SELECT resource_uid, resource_type, resource_name, provider,
                       account_id, region, service, status, severity,
                       drift_detected, emitted_fields, first_seen_at, last_seen_at
                FROM asset_inventory
                WHERE {base_cond}
                ORDER BY last_seen_at DESC
                LIMIT %s OFFSET %s
                """,
                page_params,
            )
            assets = []
            for r in cur.fetchall():
                assets.append({
                    "id": r["resource_uid"],
                    "resource_uid": r["resource_uid"],
                    "resource_type": r["resource_type"],
                    "resource_name": r["resource_name"],
                    "provider": r["provider"],
                    "account_id": r["account_id"],
                    "region": r["region"],
                    "service": r["service"],
                    "status": r["status"],
                    "severity": r["severity"],
                    "drift_detected": r["drift_detected"],
                    "tags": _extract_tags(r["emitted_fields"]),
                    "created_at": r["first_seen_at"].isoformat() if r["first_seen_at"] else None,
                    "last_scanned": r["last_seen_at"].isoformat() if r["last_seen_at"] else None,
                })
    finally:
        conn.close()

    return {
        "summary": {
            "total_assets": total,
            "total_relationships": 0,
            "total_drift": 0,
            "drift_by_type": {},
            "assets_by_provider": by_provider,
            "assets_by_service": by_service,
            "assets_by_region": by_region,
            "relationships_by_type": {},
        },
        "assets": assets,
        "total": total,
        "has_more": (offset + limit) < total,
        "scan_id": sid,
    }


@app.get("/api/v1/di/taxonomy")
async def di_taxonomy(
    csp: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    min_priority: int = Query(5, ge=1, le=5),
    auth: Any = _auth_dep(),
) -> Dict[str, Any]:
    """Resource type taxonomy from di_resource_catalog — inventory /taxonomy compat."""
    _get_tenant_id(auth)  # auth check only

    conditions = ["show_in_inventory = TRUE"]
    params: List[Any] = []
    if csp:
        conditions.append("csp = %s")
        params.append(csp)
    if category:
        conditions.append("asset_category = %s")
        params.append(category)

    where = " AND ".join(conditions)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT csp, service, resource_type, asset_category, access_pattern,
                       identifier_type, canonical_type
                FROM di_resource_catalog
                WHERE {where}
                ORDER BY asset_category, service, resource_type
                """,
                params,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    classifications = []
    categories_summary: Dict[str, Any] = {}
    for r in rows:
        cat = r["asset_category"] or "Other"
        classifications.append({
            "csp": r["csp"],
            "resource_type": r["resource_type"],
            "service": r["service"],
            "resource_name": r["resource_type"],
            "display_name": r["canonical_type"] or r["resource_type"],
            "scope": "regional",
            "category": cat,
            "subcategory": r["service"],
            "service_model": r["access_pattern"] or "managed",
            "managed_by": r["csp"],
            "access_pattern": r["access_pattern"] or "",
            "encryption_scope": "",
            "is_container": False,
            "container_parent": None,
            "diagram_priority": 3,
            "csp_category": cat,
        })
        if cat not in categories_summary:
            categories_summary[cat] = {"count": 0, "subcategories": []}
        categories_summary[cat]["count"] += 1
        if r["service"] not in categories_summary[cat]["subcategories"]:
            categories_summary[cat]["subcategories"].append(r["service"])

    return {
        "total": len(classifications),
        "classifications": classifications,
        "categories_summary": categories_summary,
        "filters_applied": {"csp": csp, "category": category, "min_priority": min_priority},
    }



@app.get("/api/v1/di/graph")
async def di_graph(
    scan_run_id: Optional[str] = Query(None),
    depth: int = Query(5, ge=1, le=10),
    limit: int = Query(2000, ge=1, le=5000),
    provider: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    auth: Any = _auth_dep(),
) -> Dict[str, Any]:
    """Asset graph (nodes + links) — inventory /runs/latest/graph compat."""
    tenant_id = _get_tenant_id(auth)

    _SERVICE_COLORS: Dict[str, str] = {
        "ec2": "#FF9900", "s3": "#3F8624", "rds": "#527FFF",
        "iam": "#DD344C", "vpc": "#8C4FFF", "lambda": "#FF9900",
        "eks": "#FF9900", "default": "#888888",
    }

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            sid = _resolve_scan_run_id(cur, tenant_id, scan_run_id)

            conds = ["tenant_id = %s"]
            params: List[Any] = [tenant_id]
            if sid:
                conds.append("scan_run_id = %s")
                params.append(sid)
            if provider:
                conds.append("provider = %s")
                params.append(provider)
            if service:
                conds.append("service = %s")
                params.append(service)
            where = " AND ".join(conds)

            cur.execute(
                f"""
                SELECT resource_uid, resource_name, resource_type, service, provider,
                       region, account_id
                FROM asset_inventory
                WHERE {where}
                ORDER BY last_seen_at DESC
                LIMIT %s
                """,
                params + [limit],
            )
            asset_rows = cur.fetchall()

            uid_set = {r["resource_uid"] for r in asset_rows}

            link_rows: List[Any] = []
            if sid:
                cur.execute(
                    "SELECT source_uid, target_uid, relation_type FROM asset_relationships "
                    "WHERE tenant_id = %s AND scan_run_id = %s LIMIT 10000",
                    (tenant_id, sid),
                )
                link_rows = [
                    r for r in cur.fetchall()
                    if r["source_uid"] in uid_set and r["target_uid"] in uid_set
                ]
    finally:
        conn.close()

    nodes = [
        {
            "id": r["resource_uid"],
            "name": r["resource_name"] or r["resource_uid"],
            "type": r["resource_type"],
            "service": r["service"],
            "provider": r["provider"],
            "color": _SERVICE_COLORS.get(r["service"], _SERVICE_COLORS["default"]),
            "region": r["region"],
            "account_id": r["account_id"],
        }
        for r in asset_rows
    ]
    links = [
        {
            "source": r["source_uid"],
            "target": r["target_uid"],
            "label": r["relation_type"],
            "type": r["relation_type"],
        }
        for r in link_rows
    ]

    return {
        "nodes": nodes,
        "links": links,
        "exposure": [],
        "depth": depth,
        "total_nodes": len(nodes),
        "total_links": len(links),
    }


@app.get("/api/v1/di/timing/{scan_run_id}")
async def di_timing(
    scan_run_id: str,
    auth: Any = _auth_dep(),
) -> Dict[str, Any]:
    """Scan timing from di_scan_status — discoveries /timing compat."""
    tenant_id = _get_tenant_id(auth)

    conn = _get_di_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM di_scan_status WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Scan {scan_run_id} not found")

    row = dict(row)
    started = row.get("started_at")
    completed = row.get("completed_at")
    total_s: Optional[float] = None
    if started and completed:
        total_s = (completed - started).total_seconds()

    return {
        "scan_run_id": scan_run_id,
        "scan_status": row.get("status", "unknown"),
        "timing_available": total_s is not None,
        "timing": {
            "scan_start": started.isoformat() if started else None,
            "scan_end": completed.isoformat() if completed else None,
            "total_s": total_s,
            "phase1_scan_s": total_s,
            "phase2_upload_s": 0,
            "totals": {
                "accounts": 1,
                "regions": 0,
                "total_discoveries": row.get("resources_written", 0),
                "work_items_per_account": row.get("resources_enumerated", 0),
            },
        } if total_s is not None else {},
    }


# ── Helper ─────────────────────────────────────────────────────────────────────
def _get_tenant_id(auth: Any) -> str:
    """Extract tenant_id from AuthContext. Raises 401 if not present."""
    if auth is None:
        return "dev-tenant"  # only reachable when _AUTH_AVAILABLE=False

    tenant_id = getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="tenant_id not in auth context")
    return tenant_id
