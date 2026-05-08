"""
Platform Admin Engine — Health check endpoints.

/api/v1/health/live   — liveness probe (no DB required)
/api/v1/health/ready  — readiness probe (confirms billing DB connectivity)
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from db import get_conn, put_conn
from _schemas import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/api/v1/health/live", response_model=HealthResponse, response_model_exclude_none=False)
async def liveness() -> Dict[str, Any]:
    """Liveness probe — always returns ok if the process is running.

    Returns:
        JSON body with status 'ok'.
    """
    return {"status": "ok"}


@router.get("/api/v1/health/ready", response_model=HealthResponse, response_model_exclude_none=False)
async def readiness() -> JSONResponse:
    """Readiness probe — confirms billing DB connectivity.

    Returns HTTP 503 if the DB check fails so Kubernetes does not route
    traffic to a pod that cannot serve operator requests.

    Returns:
        JSON body with status 'ok' and db 'connected' on success, or
        status 'error' with the exception message on failure.
    """
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
    except Exception as exc:
        logger.error("Readiness probe DB check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"status": "error", "db": str(exc)},
        )
    finally:
        if conn is not None:
            put_conn(conn)

    return JSONResponse(content={"status": "ok", "db": "connected"})
