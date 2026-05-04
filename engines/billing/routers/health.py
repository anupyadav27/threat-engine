"""
Billing Engine — Health check endpoints.

/api/v1/health/live   — liveness probe (no DB required)
/api/v1/health/ready  — readiness probe (confirms DB + Stripe secrets)

The readiness probe returns HTTP 503 if either the DB or the Stripe
secret cannot be reached.  This prevents silent mis-configuration when
the pod starts without Stripe credentials in AWS Secrets Manager.
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from db import get_conn, put_conn

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/api/v1/health/live")
async def liveness() -> Dict[str, Any]:
    """Liveness probe — always returns ok if the process is running.

    Returns:
        JSON body with status 'ok'.
    """
    return {"status": "ok"}


@router.get("/api/v1/health/ready")
async def readiness() -> JSONResponse:
    """Readiness probe — confirms DB connectivity and Stripe secrets are loaded.

    Returns HTTP 503 if either check fails so Kubernetes does not route
    traffic to a pod that would silently reject payment operations.

    Returns:
        JSON body with status 'ok', db 'connected', stripe 'configured'
        on full success, or status 'error' with the failing check's
        exception message on failure.
    """
    # Check 1 — database
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

    # Check 2 — Stripe secrets
    try:
        from stripe_client import load_stripe_secrets

        load_stripe_secrets()
    except Exception as exc:
        logger.error("Readiness probe Stripe secrets check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"status": "error", "stripe": str(exc)},
        )

    return JSONResponse(
        content={"status": "ok", "db": "connected", "stripe": "configured"}
    )
