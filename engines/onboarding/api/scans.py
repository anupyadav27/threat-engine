"""
Scans API — recent orchestration runs for dashboard "Recent Scan Activity" section.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.get("/scans/recent")
async def get_recent_scans(
    tenant_id: str = Query(..., description="Tenant identifier"),
    limit: int = Query(10, ge=1, le=50, description="Number of scans to return"),
):
    """Return recent scan orchestration runs ordered by started_at descending."""
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
                        orchestration_id,
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
                    FROM scan_orchestration
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
    tenant_id: str = Query(..., description="Tenant identifier"),
):
    """
    Return per-engine pipeline status for a scan run.

    Derives stage status from scan_orchestration.engines_requested /
    engines_completed columns. The first non-completed engine is marked
    'running' when overall_status == 'running'; everything after is 'pending'.
    """
    import json as _json

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
                        orchestration_id,
                        overall_status,
                        started_at,
                        completed_at,
                        engines_requested,
                        engines_completed
                    FROM scan_orchestration
                    WHERE orchestration_id = %s
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
