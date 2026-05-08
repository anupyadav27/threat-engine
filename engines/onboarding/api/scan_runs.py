"""
Scan Runs API — status polling and history for scan_runs table.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query

try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    def require_permission(perm: str):  # type: ignore[misc]
        async def _noop():
            return None
        return _noop
    async def get_auth_context():  # type: ignore[misc]
        return None

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
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:read")),
):
    """List scan runs with optional filters, newest first. Scoped to authenticated tenant."""
    # Enforce tenant isolation — authenticated context overrides query param
    if auth and getattr(auth, "engine_tenant_id", None):
        tenant_id = auth.engine_tenant_id
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


# ── Re-run (D-6) ─────────────────────────────────────────────────────────────

@router.post("/{scan_run_id}/re-run", status_code=202)
async def rerun_scan(
    scan_run_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """
    Create a new scan run with the same parameters as a previous run.

    Tenant isolation: the original scan_run must belong to the authenticated tenant.
    Returns the new scan_run_id so the caller can poll for progress.
    """
    original = get_scan_run(scan_run_id)
    if not original:
        raise HTTPException(status_code=404, detail=f"scan_run {scan_run_id} not found")

    # Tenant isolation check
    if auth and getattr(auth, "engine_tenant_id", None):
        if original.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=404, detail=f"scan_run {scan_run_id} not found")

    from engine_onboarding.database.cloud_accounts_operations import get_cloud_account
    account = get_cloud_account(original.get("account_id"))
    if not account or not account.get("credential_ref"):
        raise HTTPException(status_code=409, detail="Account has no stored credentials")

    new_scan_run_id = str(uuid.uuid4())

    try:
        from engine_onboarding.database.scan_run_operations import create_scan_run
        create_scan_run({
            "scan_run_id":       new_scan_run_id,
            "customer_id":       original.get("customer_id"),
            "tenant_id":         original.get("tenant_id"),
            "account_id":        original.get("account_id"),
            "provider":          original.get("provider"),
            "credential_type":   account.get("credential_type"),
            "credential_ref":    account.get("credential_ref"),
            "engines_requested": original.get("engines_requested"),
            "include_regions":   original.get("include_regions"),
            "include_services":  original.get("include_services"),
            "exclude_services":  original.get("exclude_services"),
            "scan_type":         original.get("scan_type", "full"),
            "trigger_type":      "manual",
            "scan_name":         f"Re-run of {scan_run_id[:8]}",
        })
    except Exception as exc:
        logger.error("re-run: failed to create scan_run: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to create scan record")

    try:
        from engine_onboarding.scheduler.argo_client import ArgoClient
        ArgoClient().submit_pipeline(
            scan_run_id=new_scan_run_id,
            tenant_id=original.get("tenant_id"),
            account_id=original.get("account_id"),
            provider=original.get("provider"),
            credential_type=account.get("credential_type"),
            credential_ref=account.get("credential_ref"),
        )
    except Exception as exc:
        logger.warning("re-run: Argo submit failed for %s: %s", new_scan_run_id, exc)

    return {
        "scan_run_id":      new_scan_run_id,
        "original_run_id":  scan_run_id,
        "status":           "pending",
        "trigger_type":     "manual",
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
