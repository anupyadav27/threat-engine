"""
Onboarding Engine - Unified UI Data Endpoint

Provides a single GET endpoint that returns all onboarding data needed
by the frontend in one request: cloud accounts, recent scans, and
scan statistics.

Endpoint: GET /api/v1/onboarding/ui-data?tenant_id=X
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import psycopg2.extras
from fastapi import APIRouter, HTTPException, Query

from engine_onboarding.database.connection import get_db_connection

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])


def _serialize_datetime(val: Any) -> Optional[str]:
    """Safely serialize a datetime or similar value to an ISO string.

    Args:
        val: A datetime, string, or None value.

    Returns:
        ISO-formatted string or None.
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _get_cloud_accounts(
    cur: Any,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Retrieve all cloud accounts for a tenant.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.

    Returns:
        A list of account dicts.
    """
    cur.execute(
        """
        SELECT account_id, account_name, provider, tenant_id,
               account_status, credential_validation_status,
               schedule_last_run_at, schedule_cron_expression, schedule_enabled,
               schedule_name, schedule_run_count, schedule_success_count,
               schedule_failure_count, schedule_engines_requested
        FROM cloud_accounts
        WHERE tenant_id = %s
        ORDER BY account_name ASC
        """,
        (tenant_id,),
    )
    rows = cur.fetchall()

    accounts = []
    for row in rows:
        accounts.append(
            {
                "account_id": row["account_id"],
                "account_name": row["account_name"],
                "provider": row["provider"],
                "tenant_id": row["tenant_id"],
                "account_status": row["account_status"],
                "credential_validation_status": row["credential_validation_status"],
                "last_scan_at": _serialize_datetime(row.get("schedule_last_run_at")),
                "schedule_cron_expression": row.get("schedule_cron_expression"),
                "schedule_enabled": row.get("schedule_enabled", False),
                "schedule_name": row.get("schedule_name"),
                "schedule_run_count": row.get("schedule_run_count", 0),
                "schedule_success_count": row.get("schedule_success_count", 0),
                "schedule_failure_count": row.get("schedule_failure_count", 0),
                "schedule_engines_requested": row.get("schedule_engines_requested") or [],
            }
        )
    return accounts


def _get_recent_scans(
    cur: Any,
    tenant_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Retrieve recent scan orchestration records for a tenant.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: The tenant identifier.
        limit: Maximum number of scans to return.

    Returns:
        A list of scan dicts.
    """
    cur.execute(
        """
        SELECT orchestration_id, scan_name, scan_type, trigger_type,
               provider, account_id, overall_status,
               started_at, completed_at,
               engines_requested, engines_completed,
               results_summary
        FROM scan_orchestration
        WHERE tenant_id = %s
        ORDER BY started_at DESC
        LIMIT %s
        """,
        (tenant_id, limit),
    )
    rows = cur.fetchall()

    scans = []
    for row in rows:
        # results_summary is JSONB -- psycopg2 auto-deserializes it
        results_summary = row.get("results_summary")
        if not isinstance(results_summary, dict):
            results_summary = {}

        scans.append(
            {
                "orchestration_id": row["orchestration_id"],
                "scan_name": row.get("scan_name"),
                "scan_type": row.get("scan_type"),
                "trigger_type": row.get("trigger_type"),
                "provider": row.get("provider"),
                "account_id": row.get("account_id"),
                "overall_status": row.get("overall_status"),
                "started_at": _serialize_datetime(row.get("started_at")),
                "completed_at": _serialize_datetime(row.get("completed_at")),
                "engines_requested": row.get("engines_requested") or [],
                "engines_completed": row.get("engines_completed") or [],
                "results_summary": results_summary,
            }
        )
    return scans


def _compute_scan_stats(scans: List[Dict[str, Any]]) -> Dict[str, int]:
    """Compute aggregate scan statistics from a list of scans.

    Args:
        scans: A list of scan dicts (as returned by _get_recent_scans).

    Returns:
        A dict with total_scans, completed, failed, and running counts.
    """
    total = len(scans)
    completed = 0
    failed = 0
    running = 0

    for scan in scans:
        status = (scan.get("overall_status") or "").lower()
        if status == "completed":
            completed += 1
        elif status in ("failed", "error"):
            failed += 1
        elif status in ("running", "in_progress", "pending"):
            running += 1

    return {
        "total_scans": total,
        "completed": completed,
        "failed": failed,
        "running": running,
    }


@router.get("/api/v1/onboarding/ui-data")
async def get_onboarding_ui_data(
    tenant_id: str = Query(..., description="Tenant identifier"),
) -> Dict[str, Any]:
    """Return all onboarding data needed by the frontend in a single response.

    Assembles cloud accounts, recent scan orchestration records, and
    computed scan statistics into one payload.

    Args:
        tenant_id: The tenant to query data for.

    Returns:
        A dict with accounts, total_accounts, recent_scans, and scan_stats.

    Raises:
        HTTPException 500: On unexpected database or processing errors.
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # 1. Cloud accounts
        accounts = _get_cloud_accounts(cur, tenant_id)

        # 2. Recent scans
        recent_scans = _get_recent_scans(cur, tenant_id)

        # 3. Scan stats (computed from recent scans)
        scan_stats = _compute_scan_stats(recent_scans)

        cur.close()

        return {
            "accounts": accounts,
            "total_accounts": len(accounts),
            "recent_scans": recent_scans,
            "scan_stats": scan_stats,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error fetching onboarding UI data",
            exc_info=True,
            extra={"extra_fields": {"tenant_id": tenant_id}},
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch onboarding UI data: {str(e)}",
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
