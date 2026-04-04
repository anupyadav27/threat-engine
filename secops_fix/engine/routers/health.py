"""
Health endpoints — liveness and readiness probes.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from db.db_config import get_db_config
from core.rule_loader import rule_loader

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/live")
async def liveness():
    """Kubernetes liveness probe — 200 if process is alive."""
    return {"status": "alive"}


@router.get("/ready")
async def readiness():
    """Kubernetes readiness probe — checks DB and rule loader."""
    errors = []

    # DB check
    try:
        import psycopg2
        cfg = get_db_config()
        conn = psycopg2.connect(
            host=cfg["host"], port=cfg["port"], database=cfg["database"],
            user=cfg["user"], password=cfg["password"], connect_timeout=3,
        )
        conn.close()
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {e}"
        errors.append(f"db: {e}")

    # Rule loader check
    rules_loaded = rule_loader.total
    if rules_loaded == 0:
        errors.append("rule_loader: no rules loaded")

    if errors:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "errors": errors},
        )
    return {
        "status": "ready",
        "database": db_status,
        "rules_loaded": rules_loaded,
    }


@router.get("")
@router.get("/")
async def full_health():
    """Full health check with details."""
    try:
        import psycopg2
        cfg = get_db_config()
        conn = psycopg2.connect(
            host=cfg["host"], port=cfg["port"], database=cfg["database"],
            user=cfg["user"], password=cfg["password"], connect_timeout=3,
        )
        conn.close()
        db_ok = True
    except Exception as e:
        db_ok = False

    return {
        "service": "secops-fix-engine",
        "version": "1.0.0",
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "rules_loaded": rule_loader.total,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
