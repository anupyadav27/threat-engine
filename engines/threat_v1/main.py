"""
Threat Engine v1 — FastAPI application entry point.

Port: 8021
Title: Threat Engine v1

Health endpoints:
  GET /api/v1/health/live  — liveness probe (no external dependencies)
  GET /api/v1/health/ready — readiness probe (checks Postgres + Neo4j)

Auth: all non-health endpoints require require_permission() from engine_common.
      Health endpoints are exempt.

Build context: repo root
  docker build -f engines/threat_v1/Dockerfile .
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict

import psycopg2
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Structured JSON logging (python-json-logger) ─────────────────────────────
from pythonjsonlogger import jsonlogger  # type: ignore[import]

_log_handler = logging.StreamHandler(sys.stdout)
_log_handler.setFormatter(
    jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
)
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    handlers=[_log_handler],
)
logger = logging.getLogger("engine-threat-v1")

# ── Auth imports ──────────────────────────────────────────────────────────────
# engine_auth is available in Docker (COPY shared/auth/ engine_auth/ in
# Dockerfile).  Import is optional so the engine starts without engine_auth
# during local unit-testing of individual routers.
try:
    from engine_auth.fastapi.middleware import AuthMiddleware  # type: ignore[import]
    from engine_auth.fastapi.dependencies import require_permission  # type: ignore[import]
    from engine_auth.core.models import AuthContext  # type: ignore[import]

    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]
    logger.warning(
        "engine_auth not found — running WITHOUT auth enforcement",
        extra={"engine": "engine-threat-v1"},
    )

    def require_permission(_perm: str):  # type: ignore[no-redef]
        """Stub: raises 401 when auth module is unavailable (never reaches prod)."""
        from fastapi import HTTPException

        def _denied() -> None:
            raise HTTPException(status_code=401, detail="auth module unavailable")

        return _denied


# ── Neo4j lazy import ─────────────────────────────────────────────────────────
# Imported only in the readiness check so the app boots even if neo4j package
# is temporarily unavailable (e.g. pip install race on startup).
try:
    from neo4j import GraphDatabase  # type: ignore[import]

    _NEO4J_AVAILABLE = True
except ImportError:
    _NEO4J_AVAILABLE = False
    logger.warning(
        "neo4j driver not found — readiness check will report Neo4j as unavailable",
        extra={"engine": "engine-threat-v1"},
    )


# ── Application lifecycle ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Log startup and shutdown events.

    Args:
        app: The FastAPI application instance.

    Yields:
        Control to the request-handling loop.
    """
    logger.info(
        "Threat Engine v1 started",
        extra={"port": 8021, "engine": "engine-threat-v1"},
    )
    yield
    logger.info(
        "Threat Engine v1 shutting down",
        extra={"engine": "engine-threat-v1"},
    )


# ── FastAPI application ───────────────────────────────────────────────────────

app = FastAPI(
    title="Threat Engine v1",
    description=(
        "3-tier pattern-driven threat detection engine. "
        "GraphBuilder → PatternExecutor → IncidentWriter. "
        "Port 8021 (8020 = existing threat engine — parallel operation)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow all origins (gateway handles auth, not CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# AuthMiddleware validates access_token / X-Auth-Context for every non-health
# path.  Per CLAUDE.md feedback_gateway_middleware_order: add_middleware must
# come AFTER the @app.middleware decorator(s) so Auth runs first.
if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _check_postgres() -> Dict[str, Any]:
    """Attempt a Postgres connection using THREAT_DB_* env vars.

    Returns:
        Dict with keys ``ok`` (bool) and ``detail`` (str).
    """
    try:
        conn = psycopg2.connect(
            host=os.environ.get(
                "THREAT_DB_HOST",
                os.environ.get("DB_HOST", "localhost"),
            ),
            port=int(
                os.environ.get(
                    "THREAT_DB_PORT",
                    os.environ.get("DB_PORT", "5432"),
                )
            ),
            dbname=os.environ.get("THREAT_DB_NAME", "threat_engine_threat"),
            user=os.environ.get(
                "THREAT_DB_USER",
                os.environ.get("DB_USER", "postgres"),
            ),
            password=(
                os.environ.get("THREAT_DB_PASSWORD")
                or os.environ.get("DB_PASSWORD", "")
            ),
            sslmode=os.environ.get("DB_SSLMODE", "prefer"),
            connect_timeout=5,
        )
        conn.close()
        return {"ok": True, "detail": "connected"}
    except psycopg2.OperationalError as exc:
        logger.error(
            "Postgres connectivity check failed",
            extra={"error": str(exc), "engine": "engine-threat-v1"},
        )
        return {"ok": False, "detail": str(exc)}


def _check_neo4j() -> Dict[str, Any]:
    """Attempt a Neo4j Bolt connection using NEO4J_* env vars.

    Returns:
        Dict with keys ``ok`` (bool) and ``detail`` (str).
    """
    if not _NEO4J_AVAILABLE:
        return {"ok": False, "detail": "neo4j driver not installed"}

    uri = os.environ.get("NEO4J_URI", "")
    username = os.environ.get("NEO4J_USERNAME", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "")

    if not uri:
        return {"ok": False, "detail": "NEO4J_URI not set"}

    try:
        driver = GraphDatabase.driver(uri, auth=(username, password))
        with driver.session(database="threat_v1") as session:
            session.run("RETURN 1")
        driver.close()
        return {"ok": True, "detail": "connected"}
    except Exception as exc:  # noqa: BLE001 — broad catch intentional for health check
        logger.error(
            "Neo4j connectivity check failed",
            extra={"error": str(exc), "engine": "engine-threat-v1"},
        )
        return {"ok": False, "detail": str(exc)}


# ── API router ────────────────────────────────────────────────────────────────

from threat_v1.api.routes import router as threat_router  # noqa: E402
app.include_router(threat_router)


# ── Health endpoints (override router's versions with simpler async versions) ─

@app.get("/api/v1/health/live", tags=["health"], summary="Liveness probe")
async def health_live() -> Dict[str, str]:
    """Liveness probe — no external dependencies checked.

    Returns:
        ``{"status": "ok"}`` always (process is alive).
    """
    return {"status": "ok"}


@app.get("/api/v1/health/ready", tags=["health"], summary="Readiness probe")
async def health_ready(request: Request) -> JSONResponse:
    """Readiness probe — checks Postgres and Neo4j connectivity.

    Returns HTTP 200 with ``{"status": "ready", "checks": {...}}`` when all
    dependencies are reachable, or HTTP 503 with details when any check fails.

    Returns:
        JSONResponse with status 200 (ready) or 503 (not ready).
    """
    postgres_check = _check_postgres()
    neo4j_check = _check_neo4j()

    checks: Dict[str, Any] = {
        "postgres": postgres_check,
        "neo4j": neo4j_check,
    }

    all_ok: bool = postgres_check["ok"] and neo4j_check["ok"]

    if all_ok:
        return JSONResponse(
            status_code=200,
            content={"status": "ready", "checks": checks},
        )

    logger.warning(
        "Readiness check failed",
        extra={"checks": checks, "engine": "engine-threat-v1"},
    )
    return JSONResponse(
        status_code=503,
        content={"status": "not_ready", "checks": checks},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8021, log_level="info")
