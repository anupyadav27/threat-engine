"""
BFF view: GET /api/v1/views/scan-status/{scan_run_id}
         GET /api/v1/views/scan-status?tenant_id=X&limit=N

Single endpoint that aggregates full scan run status from all sources:
  - scan_runs (onboarding engine):  overall_status, engines_completed, timing
  - discovery_report (discoveries engine): phase status, findings count, timing

Replaces the need to run multiple kubectl/psql commands to check scan state.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query, HTTPException, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many

logger = logging.getLogger("api-gateway.bff.scan_status")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _elapsed_seconds(started_at, completed_at=None) -> Optional[float]:
    """Compute elapsed wall-clock seconds between two timestamps."""
    if not started_at:
        return None
    end = completed_at or datetime.now(timezone.utc)
    try:
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        if isinstance(end, str):
            end = datetime.fromisoformat(end.replace("Z", "+00:00"))
        s = started_at if started_at.tzinfo else started_at.replace(tzinfo=timezone.utc)
        e = end if hasattr(end, "tzinfo") and end.tzinfo else end.replace(tzinfo=timezone.utc)
        return round((e - s).total_seconds(), 1)
    except Exception:
        return None


def _parse_discovery_info(disc_resp: Optional[dict]) -> dict:
    """Map discoveries engine GET /api/v1/discovery/{id} response to discovery_info shape."""
    if not disc_resp:
        return {"status": None, "findings_count": 0, "has_timing": False, "timing_summary": None}
    meta = disc_resp.get("metadata") or {}
    timing = meta.get("timing") if isinstance(meta, dict) else None
    totals = (timing or {}).get("totals", {})
    return {
        "status": disc_resp.get("status"),
        "findings_count": totals.get("total_discoveries", 0),
        "has_timing": bool(timing),
        "timing_summary": {
            "total_s":         timing.get("total_s"),
            "phase1_scan_s":   timing.get("phase1_scan_s"),
            "phase2_upload_s": timing.get("phase2_upload_s"),
            "scan_start":      timing.get("scan_start"),
            "scan_end":        timing.get("scan_end"),
            "totals":          totals,
        } if timing else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/scan-status/{scan_run_id}")
async def get_scan_status(request: Request, scan_run_id: str):
    """
    Return aggregated status for a specific scan run.

    Combines:
      - scan_runs (orchestration status + engines completed)
      - discovery_report (discovery phase + findings count)
      - timing summary (if available)
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("onboarding",  f"/api/v1/scan-runs/{scan_run_id}", {}),
        ("discoveries", f"/api/v1/discovery/{scan_run_id}", {}),
    ], auth_headers=fwd_headers)

    scan = results[0]
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan run {scan_run_id} not found")

    engines_requested = scan.get("engines_requested") or []
    engines_completed = scan.get("engines_completed") or []
    if isinstance(engines_requested, str):
        import json
        engines_requested = json.loads(engines_requested)
    if isinstance(engines_completed, str):
        import json
        engines_completed = json.loads(engines_completed)

    engines_pending = [e for e in engines_requested if e not in engines_completed]
    discovery_info = _parse_discovery_info(results[1])

    return {
        "scan_run_id":        scan_run_id,
        "overall_status":     scan.get("overall_status"),
        "provider":           scan.get("provider"),
        "account_id":         scan.get("account_id"),
        "tenant_id":          scan.get("tenant_id"),
        "scan_type":          scan.get("scan_type"),
        "trigger_type":       scan.get("trigger_type"),
        "started_at":         scan.get("started_at"),
        "completed_at":       scan.get("completed_at"),
        "elapsed_s":          _elapsed_seconds(scan.get("started_at"), scan.get("completed_at")),
        "engines_requested":  engines_requested,
        "engines_completed":  engines_completed,
        "engines_pending":    engines_pending,
        "engines_progress":   f"{len(engines_completed)}/{len(engines_requested)}",
        "discovery":          discovery_info,
        "results_summary":    scan.get("results_summary") or {},
        "error_details":      scan.get("error_details") or {},
    }


@router.get("/scan-status")
async def list_scan_statuses(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
):
    """
    Return status summary for the N most recent scans for a tenant.

    Lightweight — reads only from scan_runs via the onboarding engine.
    Used by the Scans UI table to show status, progress, and duration.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("onboarding", "/api/v1/scan-runs", {"tenant_id": tenant_id, "limit": str(limit)}),
    ], auth_headers=fwd_headers)

    scans = (results[0] or {}).get("scan_runs", [])

    summaries = []
    for s in scans:
        engines_requested = s.get("engines_requested") or []
        engines_completed = s.get("engines_completed") or []
        if isinstance(engines_requested, str):
            import json
            engines_requested = json.loads(engines_requested)
        if isinstance(engines_completed, str):
            import json
            engines_completed = json.loads(engines_completed)

        summaries.append({
            "scan_run_id":       str(s.get("scan_run_id", "")),
            "overall_status":    s.get("overall_status"),
            "provider":          s.get("provider"),
            "account_id":        s.get("account_id"),
            "scan_type":         s.get("scan_type"),
            "trigger_type":      s.get("trigger_type"),
            "started_at":        s.get("started_at"),
            "completed_at":      s.get("completed_at"),
            "elapsed_s":         _elapsed_seconds(s.get("started_at"), s.get("completed_at")),
            "engines_progress":  f"{len(engines_completed)}/{len(engines_requested)}",
            "engines_completed": engines_completed,
        })

    return {
        "tenant_id": tenant_id,
        "count":     len(summaries),
        "scans":     summaries,
    }
