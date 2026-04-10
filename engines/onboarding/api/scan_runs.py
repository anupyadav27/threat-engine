"""
Scan Runs API — status polling and history for scan_runs table.
"""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from engine_onboarding.database.scan_run_operations import (
    get_scan_run,
    list_scan_runs,
    update_scan_run,
)

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except Exception:
    import logging
    logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/v1/scan-runs", tags=["scan-runs"])


# ── List / Get ────────────────────────────────────────────────────────────────

@router.get("")
async def list_runs(
    account_id:  Optional[str] = Query(None),
    tenant_id:   Optional[str] = Query(None),
    customer_id: Optional[str] = Query(None),
    status:      Optional[str] = Query(None, description="pending|running|completed|failed|cancelled"),
    limit:       int           = Query(50, ge=1, le=200),
    offset:      int           = Query(0, ge=0),
):
    """List scan runs with optional filters, newest first."""
    try:
        runs = list_scan_runs(
            account_id=account_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        return {"scan_runs": runs, "count": len(runs)}
    except Exception as e:
        logger.error(f"Error listing scan runs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_run_id}")
async def get_run(scan_run_id: str):
    """Get full details of a single scan run."""
    run = get_scan_run(scan_run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"scan_run {scan_run_id} not found")
    return run


@router.get("/{scan_run_id}/status")
async def get_run_status(scan_run_id: str):
    """
    Lightweight status endpoint for UI polling.
    Returns: overall_status, engine_statuses, started_at, completed_at, error_details.
    """
    run = get_scan_run(scan_run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"scan_run {scan_run_id} not found")
    return {
        "scan_run_id":      scan_run_id,
        "overall_status":   run.get("overall_status"),
        "engines_requested": run.get("engines_requested"),
        "engines_completed": run.get("engines_completed"),
        "engine_statuses":  run.get("engine_statuses"),
        "started_at":       run.get("started_at"),
        "completed_at":     run.get("completed_at"),
        "error_details":    run.get("error_details"),
        "results_summary":  run.get("results_summary"),
    }


# ── Webhook receiver (called by Argo step containers) ────────────────────────

@router.post("/{scan_run_id}/engine-status")
async def update_engine_status(scan_run_id: str, body: dict):
    """
    Called by individual engine containers at completion.

    Expected body:
    {
      "engine":   "discovery",
      "status":   "completed",          // pending | running | completed | failed
      "findings": 120,
      "duration_seconds": 45,
      "error":    null
    }

    Updates engine_statuses JSONB and appends to engines_completed list.
    If all requested engines have completed, marks overall_status = completed.
    """
    run = get_scan_run(scan_run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"scan_run {scan_run_id} not found")

    engine  = body.get("engine")
    status  = body.get("status", "completed")
    if not engine:
        raise HTTPException(status_code=400, detail="'engine' field required")

    # Merge into engine_statuses
    engine_statuses = run.get("engine_statuses") or {}
    engine_statuses[engine] = {
        "status":           status,
        "findings":         body.get("findings"),
        "duration_seconds": body.get("duration_seconds"),
        "error":            body.get("error"),
        "updated_at":       datetime.now(timezone.utc).isoformat(),
    }

    # Append to engines_completed if terminal
    engines_completed = list(run.get("engines_completed") or [])
    if status in ("completed", "failed") and engine not in engines_completed:
        engines_completed.append(engine)

    updates = {
        "engine_statuses":  engine_statuses,
        "engines_completed": engines_completed,
    }

    # Check if all requested engines are now done
    requested = set(run.get("engines_requested") or [])
    completed = set(engines_completed)
    if requested and requested <= completed:
        all_ok = all(
            engine_statuses.get(e, {}).get("status") == "completed"
            for e in requested
        )
        updates["overall_status"] = "completed" if all_ok else "failed"
        if "overall_status" in updates and updates["overall_status"] in ("completed", "failed"):
            updates["completed_at"] = datetime.now(timezone.utc)

    updated = update_scan_run(scan_run_id, updates)
    logger.info(f"Engine status update: scan_run={scan_run_id} engine={engine} status={status}")
    return updated
