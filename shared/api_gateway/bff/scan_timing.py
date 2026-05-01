"""
BFF view: GET /api/v1/views/scan-timing/{scan_run_id}

Proxies to the discoveries engine's /api/v1/discovery/{scan_id}/timing endpoint
and returns the structured ScanTimer report.

The report breaks down:
  - total scan time
  - phase1 (API calls) vs phase2 (DB upload) time
  - per-account: global pool elapsed vs regional pool elapsed
  - top-5 slowest services per pool per account

Also exposes GET /api/v1/views/scan-timing to list recent scan timings from
the discovery_report.metadata JSONB column (for the Scans UI table).
"""

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Query, HTTPException, Request

from ._shared import ENGINE_URLS, fetch_many, safe_get

logger = logging.getLogger("api-gateway.bff.scan_timing")

DISCOVERIES_URL = ENGINE_URLS["discoveries"]

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


async def _get_timing(scan_run_id: str) -> dict:
    """Fetch timing report from discoveries engine."""
    url = f"{DISCOVERIES_URL}/api/v1/discovery/{scan_run_id}/timing"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail=f"Scan {scan_run_id} not found")
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"Discoveries engine returned HTTP {resp.status_code}",
                )
            return resp.json()
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Could not reach discoveries engine for timing ({e})")
        raise HTTPException(status_code=503, detail="Discoveries engine unavailable")


@router.get("/scan-timing/{scan_run_id}")
async def view_scan_timing(request: Request, scan_run_id: str):
    """
    Return the full ScanTimer timing report for a specific scan.

    Response shape:
    {
      "scan_run_id": "...",
      "scan_status": "completed",
      "timing_available": true,
      "timing": {
        "scan_start":        "2026-04-22T10:00:00Z",
        "scan_end":          "2026-04-22T10:30:47Z",
        "total_s":           1847,
        "phase1_scan_s":     1820,
        "phase2_upload_s":   27,
        "accounts": {
          "588989875114": {
            "account_start":  "2026-04-22T10:00:00Z",
            "account_s":      1820,
            "global_pool": {
              "elapsed_s":   48,
              "services":    18,
              "discoveries": 1250,
              "slowest_top5": [
                {"service":"iam","region":"us-east-1","duration_ms":12400,"discoveries":890,"status":"scanned"},
                ...
              ]
            },
            "regional_pool": {
              "elapsed_s":    1820,
              "services":     362,
              "regions":      20,
              "work_items":   7240,
              "discoveries":  23250,
              "slowest_top5": [...]
            }
          }
        },
        "totals": {
          "accounts":             1,
          "global_services":      18,
          "regional_services":    362,
          "regions":              20,
          "work_items_per_account": 7258,
          "total_discoveries":    24500
        }
      }
    }
    """
    return await _get_timing(scan_run_id)


@router.get("/scan-timing")
async def list_scan_timings(
    request: Request,
    tenant_id: str = Query(...),
    limit: int = Query(20, ge=1, le=100),
):
    """
    Return timing summaries for the N most recent scans for a tenant.

    Fetches recent scan_run_ids from the onboarding engine, then fans out
    to the discoveries engine's /api/v1/discovery/{id}/timing for each.

    Used by the Scans UI to show phase1/phase2 breakdown and top-slow-service
    annotations in the scan history table.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # Fetch more than requested — non-discovery scans won't have timing data so we over-fetch
    fetch_limit = min(limit * 4, 200)
    scan_runs_resp = await fetch_many([
        ("onboarding", "/api/v1/scan-runs", {"tenant_id": tenant_id, "limit": str(fetch_limit)}),
    ], auth_headers=fwd_headers)
    scan_runs = (scan_runs_resp[0] or {}).get("scan_runs", [])
    # Only fan-out to discoveries engine for scans that included the discovery engine
    discovery_runs = [
        s for s in scan_runs
        if "discovery" in (s.get("engines_requested") or [])
    ]
    scan_run_ids = [s["scan_run_id"] for s in discovery_runs[:limit] if s.get("scan_run_id")]

    if not scan_run_ids:
        return {"tenant_id": tenant_id, "count": 0, "scans": []}

    timing_results = await fetch_many([
        ("discoveries", f"/api/v1/discovery/{sid}/timing", {})
        for sid in scan_run_ids
    ], auth_headers=fwd_headers)

    summaries = []
    for resp in timing_results:
        if not resp or not resp.get("timing_available"):
            continue
        t = resp.get("timing") or {}
        totals = t.get("totals", {})
        summaries.append({
            "scan_run_id":       resp.get("scan_run_id"),
            "scan_status":       resp.get("scan_status"),
            "scan_start":        t.get("scan_start"),
            "scan_end":          t.get("scan_end"),
            "total_s":           t.get("total_s"),
            "phase1_scan_s":     t.get("phase1_scan_s"),
            "phase2_upload_s":   t.get("phase2_upload_s"),
            "accounts":          totals.get("accounts", 1),
            "regions":           totals.get("regions", 0),
            "total_discoveries": totals.get("total_discoveries", 0),
            "work_items":        totals.get("work_items_per_account", 0),
            "slowest_services":  _extract_slowest(t),
        })

    return {
        "tenant_id": tenant_id,
        "count": len(summaries),
        "scans": summaries,
    }


def _extract_slowest(timing: dict, n: int = 3) -> list:
    """Pull top-n slowest regional services across all accounts for quick display."""
    slowest = []
    for acct_data in timing.get("accounts", {}).values():
        rp = acct_data.get("regional_pool", {})
        slowest.extend(rp.get("slowest_top5", []))
    return sorted(slowest, key=lambda x: x.get("duration_ms", 0), reverse=True)[:n]
