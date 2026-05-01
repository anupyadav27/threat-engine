"""
Pipeline status endpoints — real-time scan status and history.

GET  /api/v1/pipeline/status/{scan_run_id}         full stage breakdown
GET  /api/v1/pipeline/status/{scan_run_id}/stream  SSE stream (polls DB every 5s)
GET  /api/v1/pipeline/history                      recent scans
GET  /api/v1/pipeline/running                      scans currently in flight
"""

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from ..sources.db_reader import (
    get_full_pipeline_status,
    get_orchestration,
    get_scan_history,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/pipeline", tags=["pipeline-status"])

TERMINAL_STATES = {"completed", "failed", "cancelled"}


@router.get("/status/{scan_run_id}")
def pipeline_status(scan_run_id: str):
    """Full real-time status of a scan — all engine stages in one response."""
    return get_full_pipeline_status(scan_run_id)


@router.get("/status/{scan_run_id}/stream")
async def pipeline_status_stream(scan_run_id: str, interval_s: int = 5):
    """
    Server-Sent Events stream — pushes updated status every {interval_s} seconds.
    Client receives JSON events until scan reaches a terminal state.

    Usage (JS):
        const es = new EventSource('/api/v1/pipeline/status/{id}/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    async def event_generator():
        while True:
            try:
                status = get_full_pipeline_status(scan_run_id)
                yield f"data: {json.dumps(status)}\n\n"
                if status.get("overall_status") in TERMINAL_STATES:
                    # Send final state and close stream
                    yield f"event: done\ndata: {json.dumps({'status': 'stream_closed'})}\n\n"
                    break
            except Exception as e:
                logger.error("SSE error for %s: %s", scan_run_id, e)
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                break
            await asyncio.sleep(interval_s)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


@router.get("/history")
def scan_history(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant"),
    limit: int = Query(20, le=100),
):
    """Recent scan history — newest first."""
    return {"scans": get_scan_history(tenant_id=tenant_id, limit=limit)}


@router.get("/running")
def running_scans():
    """All scans currently in flight (overall_status = 'running')."""
    all_scans = get_scan_history(limit=100)
    running = [s for s in all_scans if s.get("overall_status") == "running"]
    return {"running": running, "count": len(running)}


@router.get("/status/{scan_run_id}/summary")
def scan_summary(scan_run_id: str):
    """Lightweight summary — overall status + stage counts only (no per-engine detail)."""
    orch = get_orchestration(scan_run_id)
    if not orch:
        return {"scan_run_id": scan_run_id, "error": "not found"}
    return {
        "scan_run_id":      scan_run_id,
        "overall_status":   orch.get("overall_status"),
        "tenant_id":        orch.get("tenant_id"),
        "started_at":       orch.get("started_at"),
        "duration_s":       orch.get("duration_s"),
        "engines_completed": orch.get("engines_completed", []),
    }
