"""
BFF view: GET /api/v1/views/resource/{resource_uid}

Step 3 resource context panel for all posture security pages.
Aggregates three DI tables in parallel:
  1. asset_inventory        — asset identity, config, tags
  2. resource_security_posture — per-dimension posture scores
  3. asset_relationships    — inbound + outbound graph edges (limit 50)

Findings summary is read from security_findings via the existing
read_findings() helper in _shared.py.

Security:
  - tenant_id always from AuthContext via resolve_tenant_id() (never from URL/query)
  - resource_uid validated 1–2048 chars
  - No mock/fallback data — DB unreachable → 503 immediately
  - require_permission("discoveries:read") on this endpoint
  - RBAC field stripping: iam_detail, credential_ref removed for analyst/viewer

DB: threat_engine_di (direct psycopg2 — same pattern as asset_posture.py)
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from ._auth import _parse_auth_context, resolve_tenant_id

logger = logging.getLogger("api-gateway.bff.resource_detail")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Auth ──────────────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.dependencies import require_permission
except ImportError:
    def require_permission(_perm: str):  # type: ignore[misc]
        def _ok():
            pass
        return _ok


# ── DI DB connection ──────────────────────────────────────────────────────────

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
        connect_timeout=5,
    )


# ── Field stripping ───────────────────────────────────────────────────────────

_SENSITIVE_POSTURE = frozenset({"iam_detail", "network_detail"})
_SENSITIVE_ASSET   = frozenset({"credential_ref"})

def _strip_posture(row: Dict[str, Any], role_level: int) -> Dict[str, Any]:
    """Remove IAM/network detail JSONB for analyst (4) and viewer roles."""
    if role_level <= 2:
        return row
    return {k: v for k, v in row.items() if k not in _SENSITIVE_POSTURE}

def _strip_asset(row: Dict[str, Any], role_level: int) -> Dict[str, Any]:
    """Remove credential_ref for all non-platform roles."""
    if role_level <= 2:
        return row
    return {k: v for k, v in row.items() if k not in _SENSITIVE_ASSET}

def _role_level(request: Request) -> int:
    ctx = _parse_auth_context(request)
    if ctx is None:
        return 4
    return getattr(ctx, "role_level", 4)


# ── Queries ───────────────────────────────────────────────────────────────────

def _fetch_asset(conn, tenant_id: str, resource_uid: str) -> Optional[Dict[str, Any]]:
    sql = """
        SELECT
            resource_uid, resource_type, resource_name, service,
            provider, account_id, region,
            emitted_fields->'Tags' AS tags,
            emitted_fields AS config,
            first_seen_at, last_seen_at
        FROM asset_inventory
        WHERE tenant_id = %s AND resource_uid = %s
        ORDER BY last_seen_at DESC
        LIMIT 1
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (tenant_id, resource_uid))
        row = cur.fetchone()
    return dict(row) if row else None


def _fetch_posture(conn, tenant_id: str, resource_uid: str) -> Optional[Dict[str, Any]]:
    sql = """
        SELECT
            overall_posture_score, posture_band,
            critical_count, high_count, medium_count, low_count,
            is_internet_exposed_with_critical, is_encrypted_at_rest,
            is_encrypted_in_transit, has_kms_managed_key,
            iam_score, iam_detail,
            network_score, is_internet_exposed, is_in_private_subnet, network_detail,
            encryption_score, api_security_score,
            container_security_score, ai_security_score, dbsec_score,
            reachable_pii_store_count, data_classification,
            last_updated_at
        FROM resource_security_posture
        WHERE tenant_id = %s AND resource_uid = %s
        ORDER BY last_updated_at DESC
        LIMIT 1
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (tenant_id, resource_uid))
        row = cur.fetchone()
    return dict(row) if row else None


def _fetch_relationships(conn, tenant_id: str, resource_uid: str) -> List[Dict[str, Any]]:
    sql = """
        SELECT
            CASE WHEN source_uid = %s THEN 'outbound' ELSE 'inbound' END AS direction,
            relation_type,
            CASE WHEN source_uid = %s THEN target_uid  ELSE source_uid  END AS peer_uid,
            CASE WHEN source_uid = %s THEN target_type ELSE source_type END AS peer_type,
            relation_metadata,
            last_seen_at
        FROM asset_relationships
        WHERE tenant_id = %s AND (source_uid = %s OR target_uid = %s)
        ORDER BY last_seen_at DESC
        LIMIT 50
    """
    params = (resource_uid, resource_uid, resource_uid, tenant_id, resource_uid, resource_uid)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def _fetch_findings_summary(conn, tenant_id: str, resource_uid: str) -> Dict[str, Any]:
    """Count findings by engine and severity from security_findings."""
    sql = """
        SELECT source_engine, severity, COUNT(*) AS cnt
        FROM security_findings
        WHERE tenant_id = %s AND resource_uid = %s AND status = 'open'
        GROUP BY source_engine, severity
    """
    with conn.cursor() as cur:
        cur.execute(sql, (tenant_id, resource_uid))
        rows = cur.fetchall()

    by_engine: Dict[str, int] = {}
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total = 0

    for engine, sev, cnt in rows:
        by_engine[engine] = by_engine.get(engine, 0) + cnt
        sev_lower = (sev or "").lower()
        if sev_lower in by_severity:
            by_severity[sev_lower] += cnt
        total += cnt

    return {"total": total, "by_engine": by_engine, "by_severity": by_severity}


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get(
    "/resource/{resource_uid:path}",
    summary="Step 3 resource context panel",
    description=(
        "Returns asset identity, cross-engine posture dimensions, "
        "graph relationships, and findings summary for a single resource. "
        "Used by all posture engine pages to populate the slide-in detail panel."
    ),
    dependencies=[Depends(require_permission("discoveries:read"))],
)
async def get_resource_detail(
    request: Request,
    resource_uid: str = Path(..., min_length=1, max_length=2048),
    provider: Optional[str] = Query(None),
    account:  Optional[str] = Query(None),
    region:   Optional[str] = Query(None),
) -> Dict[str, Any]:
    tenant_id  = resolve_tenant_id(request)
    role_level = _role_level(request)

    try:
        conn = _get_di_conn()
    except Exception as exc:
        logger.error("resource_detail: DI DB connection failed: %s", exc)
        raise HTTPException(status_code=503, detail="DI database unavailable")

    try:
        # Run all four queries in parallel threads (psycopg2 is thread-safe per-connection)
        results: Dict[str, Any] = {}

        def run(fn, *args):
            return fn(conn, tenant_id, resource_uid, *args)

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(run, _fetch_asset):             "asset",
                pool.submit(run, _fetch_posture):           "posture",
                pool.submit(run, _fetch_relationships):     "relationships",
                pool.submit(run, _fetch_findings_summary):  "findings_summary",
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    logger.warning("resource_detail: %s query failed: %s", key, exc)
                    results[key] = None

    except Exception as exc:
        logger.error("resource_detail: query error for %s: %s", resource_uid, exc)
        raise HTTPException(status_code=503, detail="Failed to load resource detail")
    finally:
        conn.close()

    asset   = results.get("asset")
    posture = results.get("posture")

    if asset is None:
        # Resource not in inventory — may not have been scanned yet
        raise HTTPException(status_code=404, detail="Resource not found in inventory")

    return {
        "resource":         _strip_asset(asset, role_level),
        "posture":          _strip_posture(posture, role_level) if posture else None,
        "relationships":    results.get("relationships") or [],
        "findings_summary": results.get("findings_summary") or {
            "total": 0, "by_engine": {}, "by_severity": {}
        },
    }
