"""
Scans API — recent orchestration runs for dashboard "Recent Scan Activity" section.

Endpoints:
  GET /api/v1/scans/recent   — last N scans for a tenant (legacy, used by dashboard)
  GET /api/v1/scans/history  — paginated scan history per account (BFF D-6)
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Any, Optional
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

    def require_permission(perm: str):  # type: ignore[misc]
        async def _noop() -> None:
            return None
        return _noop

    async def get_auth_context() -> None:  # type: ignore[misc]
        return None

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.get(
    "/scans/recent",
    dependencies=[Depends(require_permission("scans:read"))],
)
async def get_recent_scans(
    limit: int = Query(10, ge=1, le=50, description="Number of scans to return"),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", description="Fallback for legacy BFF callers"),
    auth: Any = Depends(get_auth_context),
):
    """Return recent scan orchestration runs ordered by started_at descending.

    tenant_id is resolved from AuthContext when available (preferred path via gateway).
    Falls back to the tenant_id query param for legacy BFF callers that do not forward
    X-Auth-Context in internal service-to-service calls.
    """
    tenant_id: str = (getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None) or tenant_id_param or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=422, detail="tenant_id could not be resolved")

    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        from engine_onboarding.database.connection_config.database_config import get_connection_string

        conn_str = get_connection_string("shared")
        conn = psycopg2.connect(conn_str)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        scan_run_id,
                        tenant_id,
                        provider,
                        account_id,
                        scan_type,
                        trigger_type,
                        overall_status  AS status,
                        started_at,
                        completed_at,
                        EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at))::int
                            AS duration_seconds,
                        engines_requested,
                        engines_completed
                    FROM scan_runs
                    WHERE tenant_id = %s
                    ORDER BY started_at DESC
                    LIMIT %s
                    """,
                    (tenant_id, limit),
                )
                rows = cur.fetchall()
        finally:
            conn.close()

        scans = []
        for r in rows:
            row = dict(r)
            for ts_key in ("started_at", "completed_at"):
                val = row.get(ts_key)
                if val and hasattr(val, "isoformat"):
                    row[ts_key] = val.isoformat()
            scans.append(row)

        return {"scans": scans, "total": len(scans)}

    except Exception as exc:
        logger.error("scans/recent failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


# Standard pipeline stage order
_PIPELINE_ORDER = [
    "discovery", "check", "inventory", "threat",
    "compliance", "iam", "datasec", "secops", "risk",
]


@router.get("/scans/{scan_run_id}/pipeline")
async def get_scan_pipeline_status(
    scan_run_id: str,
    tenant_id: Optional[str] = Query(None, description="Tenant identifier (platform admins only; scoped users use their session tenant)"),
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:read")),
):
    """
    Return per-engine pipeline status for a scan run.

    Tenant isolation: the tenant_id is resolved from the authenticated session
    (engine_tenant_id) and is never trusted from the query string for scoped
    users. Platform-level users (no engine_tenant_id) may pass tenant_id to
    target a specific tenant.

    Derives stage status from scan_orchestration.engines_requested /
    engines_completed columns. The first non-completed engine is marked
    'running' when overall_status == 'running'; everything after is 'pending'.
    """
    import json as _json

    # Resolve tenant from the authenticated session; query param only honoured
    # for platform-level users with no engine_tenant_id of their own.
    auth_tenant = None
    if auth is not None:
        auth_tenant = (
            getattr(auth, "engine_tenant_id", None)
            or getattr(auth, "tenant_id", None)
        )
    tenant_id = auth_tenant or tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="No tenant in session; tenant_id required")

    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        from engine_onboarding.database.connection_config.database_config import get_connection_string

        conn_str = get_connection_string("shared")
        conn = psycopg2.connect(conn_str)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        scan_run_id,
                        overall_status,
                        started_at,
                        completed_at,
                        engines_requested,
                        engines_completed
                    FROM scan_runs
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                    LIMIT 1
                    """,
                    (scan_run_id, tenant_id),
                )
                row = cur.fetchone()
        finally:
            conn.close()

        if not row:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_run_id}")

        row = dict(row)
        overall_status = row.get("overall_status", "unknown")

        def _to_list(val):
            if not val:
                return []
            if isinstance(val, list):
                return val
            if isinstance(val, str):
                try:
                    return _json.loads(val)
                except Exception:
                    return [v.strip() for v in val.split(",") if v.strip()]
            return list(val)

        engines_requested = _to_list(row.get("engines_requested"))
        engines_completed = _to_list(row.get("engines_completed"))
        completed_set = set(e.lower() for e in engines_completed)

        # Determine which engines to show (requested ∪ default pipeline)
        requested_set = set(e.lower() for e in engines_requested)
        show_engines = [e for e in _PIPELINE_ORDER if e in requested_set] or _PIPELINE_ORDER[:5]

        stages = []
        found_running = False
        for engine in show_engines:
            if engine in completed_set:
                stage_status = "completed"
            elif not found_running and overall_status == "running":
                stage_status = "running"
                found_running = True
            elif overall_status in ("failed", "error") and not found_running:
                stage_status = "failed"
                found_running = True
            else:
                stage_status = "pending"

            stages.append({"name": engine.capitalize(), "engine": engine, "status": stage_status})

        # Serialize timestamps
        started_at = row.get("started_at")
        completed_at = row.get("completed_at")
        if started_at and hasattr(started_at, "isoformat"):
            started_at = started_at.isoformat()
        if completed_at and hasattr(completed_at, "isoformat"):
            completed_at = completed_at.isoformat()

        return {
            "scan_run_id": scan_run_id,
            "overall_status": overall_status,
            "started_at": started_at,
            "completed_at": completed_at,
            "stages": stages,
            "total_stages": len(stages),
            "completed_stages": len(completed_set & set(show_engines)),
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("scans pipeline failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/scans/history")
async def get_scan_history(
    account_id: Optional[str] = Query(None, description="Filter by cloud account UUID"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:read")),
) -> dict:
    """Return paginated scan run history for a tenant, optionally filtered by account.

    Reads from ``scan_orchestration`` and enforces tenant isolation via the
    authenticated ``AuthContext`` — the ``tenant_id`` is never accepted from
    the query string.

    Args:
        account_id: Optional UUID of a specific cloud account to filter by.
        page:       1-based page number.
        page_size:  Number of rows per page (max 100).
        auth:       Resolved ``AuthContext`` from the gateway X-Auth-Context header.
        _:          RBAC guard — ``scans:read`` permission required.

    Returns:
        Dict with ``scans`` list, ``total``, ``page``, and ``page_size``.

    Raises:
        HTTPException 500: Database query failure.
    """
    # Tenant isolation — resolved from authenticated session, never from query string.
    tenant_id: Optional[str] = None
    if auth is not None:
        tenant_id = (
            getattr(auth, "engine_tenant_id", None)
            or getattr(auth, "tenant_id", None)
        )

    try:
        from engine_onboarding.database.scan_run_operations import list_scan_runs, count_scan_runs

        offset = (page - 1) * page_size
        rows = list_scan_runs(
            account_id=account_id,
            tenant_id=tenant_id,
            limit=page_size,
            offset=offset,
        )

        # Serialize datetime fields and pass JSONB columns through as-is
        # (psycopg2 already deserialised JSONB to Python lists/dicts).
        scans = []
        for r in rows:
            for ts_key in ("started_at", "completed_at", "created_at", "updated_at"):
                val = r.get(ts_key)
                if val and hasattr(val, "isoformat"):
                    r[ts_key] = val.isoformat()
            scans.append(r)

        total = count_scan_runs(account_id=account_id, tenant_id=tenant_id)

        return {
            "scans":     scans,
            "total":     total,
            "page":      page,
            "page_size": page_size,
        }

    except Exception as exc:
        logger.error("scans/history failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
