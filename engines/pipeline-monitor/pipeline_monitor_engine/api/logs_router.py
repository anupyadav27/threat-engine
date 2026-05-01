"""
CloudWatch Insights endpoints — admin portal log analysis.

All endpoints require logs to be flowing via Fluent-bit → CW.
Queries are async-safe: CW Insights runs server-side, we poll for results.

GET  /api/v1/admin/logs/errors/{scan_run_id}         all ERRORs for a scan
GET  /api/v1/admin/logs/timeline/{scan_run_id}       full chronological log timeline
GET  /api/v1/admin/logs/tenant/{tenant_id}/issues    WARN+ERROR for a tenant (24h)
GET  /api/v1/admin/logs/engines/error-rate           error count per engine (24h)
GET  /api/v1/admin/logs/patterns                     top recurring error patterns
GET  /api/v1/admin/logs/slow-engines                 engines with highest scan duration
POST /api/v1/admin/logs/query                        run a custom CW Insights query
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel

from ..sources.cw_client import (
    query_errors_by_scan,
    query_error_rate_by_engine,
    query_issues_by_tenant,
    query_recent_error_patterns,
    query_scan_timeline,
    query_slow_engines,
    run_custom_query,
    LOG_GROUP_ENGINES,
    LOG_GROUP_ARGO,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin/logs", tags=["admin-logs"])


class CustomQueryRequest(BaseModel):
    query: str
    hours_back: int = 24
    log_groups: Optional[List[str]] = None


@router.get("/errors/{scan_run_id}")
def errors_for_scan(
    scan_run_id: str,
    hours_back: int = Query(48, description="Look-back window in hours"),
):
    """
    All ERROR log lines for a specific scan_run_id across all engines.
    Useful for debugging why a customer scan failed.
    """
    results = query_errors_by_scan(scan_run_id, hours_back=hours_back)
    return {
        "scan_run_id": scan_run_id,
        "error_count": len(results),
        "hours_back":  hours_back,
        "errors":      results,
    }


@router.get("/timeline/{scan_run_id}")
def scan_log_timeline(
    scan_run_id: str,
    hours_back: int = Query(48, description="Look-back window in hours"),
):
    """
    Full chronological log stream for a scan across all engines.
    Shows exactly what happened and in what order — useful for root-cause analysis.
    """
    results = query_scan_timeline(scan_run_id, hours_back=hours_back)
    return {
        "scan_run_id": scan_run_id,
        "event_count": len(results),
        "hours_back":  hours_back,
        "events":      results,
    }


@router.get("/tenant/{tenant_id}/issues")
def tenant_issues(
    tenant_id: str,
    hours_back: int = Query(24, description="Look-back window in hours"),
):
    """
    All WARNING and ERROR log lines for a tenant's scans in the past N hours.
    Admin-facing: quickly see if a customer's pipeline is having repeated issues.
    """
    results = query_issues_by_tenant(tenant_id, hours_back=hours_back)
    errors   = [r for r in results if r.get("level") == "ERROR"]
    warnings = [r for r in results if r.get("level") == "WARNING"]
    return {
        "tenant_id":     tenant_id,
        "hours_back":    hours_back,
        "total_issues":  len(results),
        "error_count":   len(errors),
        "warning_count": len(warnings),
        "issues":        results,
    }


@router.get("/engines/error-rate")
def engine_error_rate(
    hours_back: int = Query(24, description="Look-back window in hours"),
):
    """
    Error and warning counts grouped by engine over the past N hours.
    Identifies which engines are noisiest or most failure-prone.
    """
    results = query_error_rate_by_engine(hours_back=hours_back)
    return {
        "hours_back": hours_back,
        "engines":    results,
    }


@router.get("/patterns")
def error_patterns(
    hours_back: int = Query(24, description="Look-back window in hours"),
):
    """
    Top recurring ERROR message patterns (deduplicated, count + last_seen).
    Use to identify systemic issues affecting multiple customers.
    """
    results = query_recent_error_patterns(hours_back=hours_back)
    return {
        "hours_back": hours_back,
        "pattern_count": len(results),
        "patterns": results,
    }


@router.get("/slow-engines")
def slow_engines(
    hours_back: int = Query(168, description="Look-back window in hours (default 7 days)"),
):
    """
    Engines ranked by average and max scan duration.
    Use to spot performance regressions or resource-starved engines.
    """
    results = query_slow_engines(hours_back=hours_back)
    return {
        "hours_back": hours_back,
        "engines":    results,
    }


@router.post("/query")
def custom_insights_query(body: CustomQueryRequest):
    """
    Run an arbitrary CloudWatch Insights query against engine or Argo log groups.
    For power users / ad-hoc debugging in the admin portal.

    Available log groups:
      /threat-engine/engines  — all engine pod logs
      /threat-engine/argo     — Argo workflow step logs

    Example query:
      fields @timestamp, @logStream, @message
      | filter @message like "OOMKilled"
      | sort @timestamp desc
      | limit 50
    """
    if not body.query or len(body.query.strip()) < 10:
        raise HTTPException(status_code=400, detail="Query too short")
    if body.hours_back > 720:  # 30 days max
        raise HTTPException(status_code=400, detail="hours_back max is 720 (30 days)")

    log_groups = body.log_groups or [LOG_GROUP_ENGINES]
    # Validate log group names
    allowed = {LOG_GROUP_ENGINES, LOG_GROUP_ARGO}
    invalid = [g for g in log_groups if g not in allowed]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown log groups: {invalid}. Allowed: {list(allowed)}",
        )

    results = run_custom_query(
        query=body.query,
        hours_back=body.hours_back,
        log_groups=log_groups,
    )
    return {
        "query":      body.query,
        "hours_back": body.hours_back,
        "log_groups": log_groups,
        "row_count":  len(results),
        "results":    results,
    }
